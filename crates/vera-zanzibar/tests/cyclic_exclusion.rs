use std::sync::Arc;

use vera_zanzibar::{
    error::Error,
    store::{MemoryZanzibarStore, ZanzibarStore},
    Did, PermissionEngine, Policy, Relation, RelationExpression, Relationship, Resource, Subject,
};

#[tokio::test]
async fn an_exclusion_cycle_cannot_authorize_the_actor_it_excludes() {
    let store = Arc::new(MemoryZanzibarStore::new());
    let mut engine = PermissionEngine::new(store.clone());
    let policy = Policy::new("policy", "cyclic exclusion").with_resource(
        Resource::new("document")
            .with_relation(Relation::direct("reader"))
            .with_relation(Relation::computed(
                "read",
                RelationExpression::parse("reader - excluded").unwrap(),
            ))
            .with_relation(Relation::computed(
                "excluded",
                RelationExpression::parse("read").unwrap(),
            )),
    );
    policy.validate().unwrap();
    engine.add_policy(&policy);
    let actor = Did::new("did:key:reader").unwrap();
    store
        .store_relationship(
            "policy",
            &Relationship::with_entity("document", "report", "reader", actor.clone()),
        )
        .await
        .unwrap();
    assert!(engine
        .check("policy", "document", "report", "read", &actor)
        .await
        .is_err());
    assert!(engine
        .check_blocking("policy", "document", "report", "read", &actor)
        .is_err());
}

fn groups_policy() -> Policy {
    let policy = Policy::new("policy", "blocked groups")
        .with_resource(
            Resource::new("document")
                .with_relation(Relation::direct("reader"))
                .with_relation(Relation::direct("blocked"))
                .with_relation(Relation::computed(
                    "read",
                    RelationExpression::parse("reader - blocked").unwrap(),
                )),
        )
        .with_resource(Resource::new("group").with_relation(Relation::direct("member")));
    policy.validate().unwrap();
    policy
}

fn member_of(group: &str) -> Subject {
    Subject::entity_set("group", group, "member")
}

async fn blocked_groups(
    memberships: &[(&str, Subject)],
) -> (PermissionEngine<MemoryZanzibarStore>, Did) {
    let store = Arc::new(MemoryZanzibarStore::new());
    let mut engine = PermissionEngine::new(store.clone());
    engine.add_policy(&groups_policy());
    let reader = Did::new("did:key:reader").unwrap();
    let mut relationships = vec![
        Relationship::with_entity("document", "report", "reader", reader.clone()),
        Relationship::new("document", "report", "blocked", member_of("a")),
    ];
    for (group, subject) in memberships {
        relationships.push(Relationship::new(
            "group",
            *group,
            "member",
            subject.clone(),
        ));
    }
    for relationship in relationships {
        store
            .store_relationship("policy", &relationship)
            .await
            .unwrap();
    }
    (engine, reader)
}

#[tokio::test]
async fn a_membership_cycle_beneath_an_exclusion_is_a_definite_absence() {
    for memberships in [
        vec![("a", member_of("a"))],
        vec![("a", member_of("b")), ("b", member_of("a"))],
        vec![
            ("a", member_of("b")),
            ("b", member_of("c")),
            ("c", member_of("a")),
            ("c", member_of("b")),
        ],
    ] {
        let (engine, reader) = blocked_groups(&memberships).await;
        assert!(engine
            .check("policy", "document", "report", "read", &reader)
            .await
            .unwrap());
    }
}

#[tokio::test]
async fn a_member_reached_past_a_membership_cycle_stays_excluded() {
    let reader = Did::new("did:key:reader").unwrap();
    let (engine, _) = blocked_groups(&[
        ("a", member_of("b")),
        ("b", member_of("a")),
        ("b", Subject::Entity(reader.clone())),
    ])
    .await;
    assert!(!engine
        .check("policy", "document", "report", "read", &reader)
        .await
        .unwrap());
}

#[tokio::test]
async fn an_exclusion_reached_through_its_own_cycle_stays_indeterminate() {
    let store = Arc::new(MemoryZanzibarStore::new());
    let mut engine = PermissionEngine::new(store.clone());
    let policy = Policy::new("policy", "nested exclusion").with_resource(
        Resource::new("group")
            .with_relation(Relation::direct("member"))
            .with_relation(Relation::direct("blocked"))
            .with_relation(Relation::computed(
                "allowed",
                RelationExpression::parse("member - blocked").unwrap(),
            )),
    );
    policy.validate().unwrap();
    engine.add_policy(&policy);
    let actor = Did::new("did:key:reader").unwrap();
    for relationship in [
        Relationship::with_entity("group", "a", "member", actor.clone()),
        Relationship::new(
            "group",
            "a",
            "blocked",
            Subject::entity_set("group", "b", "allowed"),
        ),
        Relationship::with_entity("group", "b", "member", actor.clone()),
        Relationship::new(
            "group",
            "b",
            "blocked",
            Subject::entity_set("group", "a", "allowed"),
        ),
    ] {
        store
            .store_relationship("policy", &relationship)
            .await
            .unwrap();
    }
    assert!(matches!(
        engine
            .check("policy", "group", "a", "allowed", &actor)
            .await,
        Err(Error::IndeterminateExclusion)
    ));
}
