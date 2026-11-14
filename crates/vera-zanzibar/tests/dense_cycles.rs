//! Groups that are all members of each other have one path per ordering of
//! the groups. A check must walk the cycle once, not once per path.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use vera_zanzibar::{
    engine::EvaluationMeter,
    error::Result,
    store::{MemoryZanzibarStore, ZanzibarStore},
    Did, PermissionEngine, Policy, Relation, RelationExpression, Relationship, Resource, Subject,
};

#[derive(Debug, Default)]
struct Steps(AtomicUsize);

impl EvaluationMeter for Steps {
    fn charge_step(&self) -> Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn policy() -> Policy {
    let policy = Policy::new("policy", "dense groups")
        .with_resource(
            Resource::new("document")
                .with_relation(Relation::direct("reader"))
                .with_relation(Relation::direct("blocked"))
                .with_relation(Relation::computed(
                    "read",
                    RelationExpression::parse("reader - blocked").unwrap(),
                )),
        )
        .with_resource(
            Resource::new("group")
                .with_relation(Relation::direct("member"))
                .with_relation(Relation::direct("gate"))
                .with_relation(Relation::computed(
                    "both",
                    RelationExpression::parse("member & gate").unwrap(),
                )),
        );
    policy.validate().unwrap();
    policy
}

fn members_of(group: &str) -> Subject {
    Subject::entity_set("group", group, "member")
}

struct World {
    engine: PermissionEngine<MemoryZanzibarStore>,
    store: Arc<MemoryZanzibarStore>,
    steps: Arc<Steps>,
    reader: Did,
}

impl World {
    async fn new() -> Self {
        let store = Arc::new(MemoryZanzibarStore::new());
        let steps = Arc::new(Steps::default());
        let mut engine = PermissionEngine::new(store.clone()).with_evaluation_meter(steps.clone());
        engine.add_policy(&policy());
        Self {
            engine,
            store,
            steps,
            reader: Did::new("did:key:reader").unwrap(),
        }
    }

    async fn store(&self, relationship: Relationship) {
        self.store
            .store_relationship("policy", &relationship)
            .await
            .unwrap();
    }

    /// A document the reader may read unless blocked through the first of
    /// `groups` groups, each of which has every other group as a member.
    async fn mutual_groups(groups: usize) -> Self {
        let world = Self::new().await;
        world
            .store(Relationship::with_entity(
                "document",
                "report",
                "reader",
                world.reader.clone(),
            ))
            .await;
        world
            .store(Relationship::new(
                "document",
                "report",
                "blocked",
                members_of("0"),
            ))
            .await;
        for group in 0..groups {
            for member in (0..groups).filter(|member| *member != group) {
                world
                    .store(Relationship::new(
                        "group",
                        group.to_string(),
                        "member",
                        members_of(&member.to_string()),
                    ))
                    .await;
            }
        }
        world
    }

    async fn reads(&self) -> bool {
        self.engine
            .check("policy", "document", "report", "read", &self.reader)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn seven_mutually_member_groups_beneath_an_exclusion_are_a_definite_absence() {
    let world = World::mutual_groups(7).await;
    assert!(world.reads().await);
    assert!(world.steps.0.load(Ordering::Relaxed) < 200);
    assert!(world
        .engine
        .check_blocking("policy", "document", "report", "read", &world.reader)
        .unwrap());
}

#[tokio::test]
async fn a_member_of_one_of_seven_mutually_member_groups_stays_excluded() {
    let world = World::mutual_groups(7).await;
    world
        .store(Relationship::with_entity(
            "group",
            "6",
            "member",
            world.reader.clone(),
        ))
        .await;
    assert!(!world.reads().await);
    for group in 0..7 {
        assert!(world
            .engine
            .check(
                "policy",
                "group",
                &group.to_string(),
                "member",
                &world.reader
            )
            .await
            .unwrap());
    }
}

#[tokio::test]
async fn the_work_for_mutually_member_groups_grows_with_their_relationships() {
    let world = World::mutual_groups(40).await;
    assert!(world.reads().await);
    assert!(world.steps.0.load(Ordering::Relaxed) < 4 * 40 * 40);
}

/// `inner` is denied while `middle` and `root` are open above it, and
/// `middle` is then granted through `granting`. The denial must not outlive
/// the assumption that `middle` was empty, whatever order the store returns
/// the groups in.
#[tokio::test]
async fn a_denial_does_not_outlive_a_group_it_assumed_empty() {
    let names = ["a", "b", "c"];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let [middle, inner, granting] = order.map(|index| names[index]);
        let world = World::new().await;
        for (group, relation, subject) in [
            (
                "root",
                "member",
                Subject::entity_set("group", middle, "both"),
            ),
            ("root", "member", members_of(inner)),
            (middle, "member", members_of(inner)),
            (middle, "member", members_of(granting)),
            (inner, "member", members_of(middle)),
            (inner, "member", members_of("root")),
            (granting, "member", Subject::Entity(world.reader.clone())),
        ] {
            world
                .store(Relationship::new("group", group, relation, subject))
                .await;
        }
        assert!(
            world
                .engine
                .check("policy", "group", "root", "member", &world.reader)
                .await
                .unwrap(),
            "{order:?}"
        );
    }
}
