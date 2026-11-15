use std::sync::Arc;

use vera_zanzibar::{
    store::{MemoryZanzibarStore, ZanzibarStore},
    Did, PermissionEngine, Policy, Relation, RelationExpression, Relationship, Resource, Subject,
};

async fn engine(relationships: &[Relationship]) -> PermissionEngine<MemoryZanzibarStore> {
    let store = Arc::new(MemoryZanzibarStore::new());
    let mut engine = PermissionEngine::new(store.clone());
    engine.add_policy(
        &Policy::new("p", "p").with_resource(
            Resource::new("document")
                .with_relation(Relation::direct("reader"))
                .with_relation(Relation::direct("parent"))
                .with_relation(Relation::computed(
                    "inherited",
                    RelationExpression::tuple_to_userset("parent", "reader"),
                )),
        ),
    );
    for relationship in relationships {
        store.store_relationship("p", relationship).await.unwrap();
    }
    engine
}

fn actor() -> Did {
    Did::new("did:key:actor").unwrap()
}

/// A userset naming a relation the policy does not declare fails evaluation.
fn failing_userset() -> Subject {
    Subject::entity_set("document", "other", "undeclared")
}

#[tokio::test]
async fn a_typed_wildcard_grants_every_subject() {
    let grant = Relationship::new(
        "document",
        "report",
        "reader",
        Subject::typed_wildcard("document"),
    );
    let engine = engine(std::slice::from_ref(&grant)).await;
    assert!(engine
        .check("p", "document", "report", "reader", &actor())
        .await
        .unwrap());
    assert!(!engine
        .check("p", "document", "other", "reader", &actor())
        .await
        .unwrap());
}

#[tokio::test]
async fn a_typed_wildcard_grants_before_a_failing_userset_is_followed() {
    let failing = Relationship::new("document", "report", "reader", failing_userset());
    let engine_without = engine(std::slice::from_ref(&failing)).await;
    assert!(engine_without
        .check("p", "document", "report", "reader", &actor())
        .await
        .is_err());

    let engine = engine(&[
        failing,
        Relationship::new(
            "document",
            "report",
            "reader",
            Subject::typed_wildcard("document"),
        ),
    ])
    .await;
    assert!(engine
        .check("p", "document", "report", "reader", &actor())
        .await
        .unwrap());
}

#[tokio::test]
async fn a_wildcard_on_the_tuple_relation_grants_the_computed_permission() {
    for wildcard in [Subject::Wildcard, Subject::typed_wildcard("document")] {
        let engine = engine(&[Relationship::new("document", "report", "parent", wildcard)]).await;
        assert!(engine
            .check("p", "document", "report", "inherited", &actor())
            .await
            .unwrap());
    }
}
