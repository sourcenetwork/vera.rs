use std::sync::Arc;
use vera_zanzibar::{
    engine::{MAX_EVALUATION_DEPTH, MAX_EVALUATION_STEPS},
    error::Error,
    store::{MemoryZanzibarStore, ZanzibarStore},
    Did, PermissionEngine, Policy, Relation, RelationExpression, Relationship, Resource, Subject,
};

#[tokio::test]
async fn deep_entity_sets_fail_instead_of_denying() {
    let store = Arc::new(MemoryZanzibarStore::new());
    let mut engine = PermissionEngine::new(store.clone());
    engine.add_policy(
        &Policy::new("p", "p")
            .with_resource(Resource::new("group").with_relation(Relation::direct("member"))),
    );
    let actor = Did::new("did:key:actor").unwrap();
    for index in 0..MAX_EVALUATION_DEPTH {
        store
            .store_relationship(
                "p",
                &Relationship::new(
                    "group",
                    index.to_string(),
                    "member",
                    Subject::entity_set("group", (index + 1).to_string(), "member"),
                ),
            )
            .await
            .unwrap();
    }
    store
        .store_relationship(
            "p",
            &Relationship::with_entity(
                "group",
                MAX_EVALUATION_DEPTH.to_string(),
                "member",
                actor.clone(),
            ),
        )
        .await
        .unwrap();
    assert!(matches!(
        engine.check("p", "group", "0", "member", &actor).await,
        Err(Error::EvaluationLimitExceeded("depth"))
    ));
    assert!(matches!(
        engine.check_blocking("p", "group", "0", "member", &actor),
        Err(Error::EvaluationLimitExceeded("depth"))
    ));
    assert!(engine
        .check("p", "group", "1", "member", &actor)
        .await
        .unwrap());
}

#[tokio::test]
async fn wide_expression_work_is_bounded_without_becoming_a_denial() {
    let store = Arc::new(MemoryZanzibarStore::new());
    let mut engine = PermissionEngine::new(store);
    engine.add_policy(
        &Policy::new("p", "p").with_resource(Resource::new("group").with_relation(
            Relation::computed(
                "member",
                RelationExpression::Union(vec![RelationExpression::This; MAX_EVALUATION_STEPS]),
            ),
        )),
    );
    let actor = Did::new("did:key:actor").unwrap();
    assert!(matches!(
        engine.check("p", "group", "0", "member", &actor).await,
        Err(Error::EvaluationLimitExceeded("steps"))
    ));
}

#[tokio::test]
async fn each_check_starts_with_a_full_work_limit() {
    let mut engine = PermissionEngine::new(Arc::new(MemoryZanzibarStore::new()));
    engine.add_policy(
        &Policy::new("p", "p").with_resource(Resource::new("group").with_relation(
            Relation::computed(
                "member",
                RelationExpression::Union(vec![RelationExpression::This; MAX_EVALUATION_STEPS - 1]),
            ),
        )),
    );
    let actor = Did::new("did:key:actor").unwrap();
    for _ in 0..2 {
        assert!(!engine
            .check("p", "group", "0", "member", &actor)
            .await
            .unwrap());
    }
}

#[tokio::test]
async fn a_parent_chain_closing_a_cycle_is_denied_within_the_work_limit() {
    const DEPTH: usize = 12;
    let store = Arc::new(MemoryZanzibarStore::new());
    let mut engine = PermissionEngine::new(store.clone());
    let policy = Policy::new("p", "p").with_resource(
        Resource::new("folder")
            .with_relation(Relation::direct("parent"))
            .with_relation(Relation::direct("reader"))
            .with_relation(Relation::computed(
                "read",
                RelationExpression::parse("reader + parent->read").unwrap(),
            )),
    );
    policy.validate().unwrap();
    engine.add_policy(&policy);
    for index in 0..DEPTH {
        store
            .store_relationship(
                "p",
                &Relationship::new(
                    "folder",
                    index.to_string(),
                    "parent",
                    Subject::entity_set("folder", ((index + 1) % DEPTH).to_string(), ""),
                ),
            )
            .await
            .unwrap();
    }
    let actor = Did::new("did:key:actor").unwrap();
    assert!(!engine
        .check("p", "folder", "0", "read", &actor)
        .await
        .unwrap());
    store
        .store_relationship(
            "p",
            &Relationship::with_entity("folder", (DEPTH - 1).to_string(), "reader", actor.clone()),
        )
        .await
        .unwrap();
    assert!(engine
        .check("p", "folder", "0", "read", &actor)
        .await
        .unwrap());
}
