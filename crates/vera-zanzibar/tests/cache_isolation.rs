use std::sync::Arc;
use vera_zanzibar::{
    store::{MemoryZanzibarStore, ZanzibarStore},
    Did, PermissionEngine, Policy, Relation, Relationship, Resource,
};

#[tokio::test]
async fn checks_keep_policy_authority_separate_in_both_orders() {
    let store = Arc::new(MemoryZanzibarStore::new());
    let mut engine = PermissionEngine::new(store.clone());
    for policy in ["allowed", "denied"] {
        engine
            .add_policy(&Policy::new(policy, policy).with_resource(
                Resource::new("document").with_relation(Relation::direct("reader")),
            ));
    }
    let actor = Did::new("did:key:reader").unwrap();
    store
        .store_relationship(
            "allowed",
            &Relationship::with_entity("document", "report", "reader", actor.clone()),
        )
        .await
        .unwrap();
    for policies in [["allowed", "denied"], ["denied", "allowed"]] {
        for policy in policies {
            let granted = engine
                .check(policy, "document", "report", "reader", &actor)
                .await
                .unwrap();
            assert_eq!(granted, policy == "allowed");
        }
    }
}
