//! Property test for cyclic relationship graphs beneath exclusions.
//!
//! Group membership may form arbitrary cycles. Exclusions sit above it in
//! strata that never lead back to themselves, so every check has one answer:
//! the least fixed point of membership, with each exclusion applied on top.
//! The engine must return that answer and never an indeterminate exclusion.

use std::sync::Arc;

use proptest::prelude::*;
use vera_zanzibar::{
    store::{MemoryZanzibarStore, ZanzibarStore},
    Did, PermissionEngine, Policy, Relation, RelationExpression, Relationship, Resource, Subject,
};

const GROUPS: usize = 4;

/// Whether the actor is named directly, and which groups' members are included.
#[derive(Debug, Clone, Copy)]
struct Grants {
    direct: bool,
    groups: u8,
}

impl Grants {
    fn groups(self) -> impl Iterator<Item = usize> {
        (0..GROUPS).filter(move |group| self.groups >> group & 1 == 1)
    }

    fn holds(self, members: &[bool; GROUPS]) -> bool {
        self.direct || self.groups().any(|group| members[group])
    }
}

#[derive(Debug, Clone)]
struct World {
    member: [Grants; GROUPS],
    banned: [Grants; GROUPS],
    reader: Grants,
    /// Groups whose `active` members, rather than all members, may read.
    reader_active: u8,
    blocked: Grants,
}

struct Expected {
    member: [bool; GROUPS],
    active: [bool; GROUPS],
    read: bool,
}

fn reference(world: &World) -> Expected {
    let mut member = [false; GROUPS];
    loop {
        let next: [bool; GROUPS] = std::array::from_fn(|group| world.member[group].holds(&member));
        if next == member {
            break;
        }
        member = next;
    }
    let active: [bool; GROUPS] =
        std::array::from_fn(|group| member[group] && !world.banned[group].holds(&member));
    let reader = world.reader.holds(&member)
        || (0..GROUPS).any(|group| world.reader_active >> group & 1 == 1 && active[group]);
    Expected {
        member,
        active,
        read: reader && !world.blocked.holds(&member),
    }
}

fn policy() -> Policy {
    let policy = Policy::new("p", "cycles")
        .with_resource(
            Resource::new("group")
                .with_relation(Relation::direct("member"))
                .with_relation(Relation::direct("banned"))
                .with_relation(Relation::computed(
                    "active",
                    RelationExpression::parse("member - banned").unwrap(),
                )),
        )
        .with_resource(
            Resource::new("document")
                .with_relation(Relation::direct("reader"))
                .with_relation(Relation::direct("blocked"))
                .with_relation(Relation::computed(
                    "read",
                    RelationExpression::parse("reader - blocked").unwrap(),
                )),
        );
    policy.validate().unwrap();
    policy
}

fn relationships(world: &World, actor: &Did) -> Vec<Relationship> {
    let mut relationships = Vec::new();
    let mut grant = |resource: &str, object: String, relation: &str, grants: Grants| {
        if grants.direct {
            relationships.push(Relationship::with_entity(
                resource,
                object.clone(),
                relation,
                actor.clone(),
            ));
        }
        for group in grants.groups() {
            relationships.push(Relationship::new(
                resource,
                object.clone(),
                relation,
                Subject::entity_set("group", group.to_string(), "member"),
            ));
        }
    };
    for group in 0..GROUPS {
        grant("group", group.to_string(), "member", world.member[group]);
        grant("group", group.to_string(), "banned", world.banned[group]);
    }
    grant("document", "report".into(), "reader", world.reader);
    grant("document", "report".into(), "blocked", world.blocked);
    for group in (0..GROUPS).filter(|group| world.reader_active >> group & 1 == 1) {
        relationships.push(Relationship::new(
            "document",
            "report",
            "reader",
            Subject::entity_set("group", group.to_string(), "active"),
        ));
    }
    relationships
}

fn grants() -> impl Strategy<Value = Grants> {
    (prop::bool::weighted(0.25), 0u8..1 << GROUPS)
        .prop_map(|(direct, groups)| Grants { direct, groups })
}

fn world() -> impl Strategy<Value = World> {
    (
        prop::array::uniform4(grants()),
        prop::array::uniform4(grants()),
        grants(),
        0u8..1 << GROUPS,
        grants(),
    )
        .prop_map(|(member, banned, reader, reader_active, blocked)| World {
            member,
            banned,
            reader,
            reader_active,
            blocked,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn cyclic_membership_resolves_to_its_least_fixed_point(world in world()) {
        let actor = Did::new("did:key:actor").unwrap();
        let store = Arc::new(MemoryZanzibarStore::new());
        let mut engine = PermissionEngine::new(store.clone());
        engine.add_policy(&policy());
        for relationship in relationships(&world, &actor) {
            futures::executor::block_on(store.store_relationship("p", &relationship)).unwrap();
        }
        let expected = reference(&world);
        let check = |resource: &str, object: &str, relation: &str| {
            engine.check_blocking("p", resource, object, relation, &actor)
        };
        prop_assert_eq!(check("document", "report", "read").unwrap(), expected.read);
        for group in 0..GROUPS {
            let object = group.to_string();
            prop_assert_eq!(check("group", &object, "member").unwrap(), expected.member[group]);
            prop_assert_eq!(check("group", &object, "active").unwrap(), expected.active[group]);
        }
    }
}
