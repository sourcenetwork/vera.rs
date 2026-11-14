use vera_zanzibar::{
    store::{MemoryZanzibarStore, ZanzibarStore},
    Did, Relationship, Subject,
};

fn subjects() -> Vec<Subject> {
    let mut subjects = vec![
        Subject::Wildcard,
        Subject::typed_wildcard("group"),
        Subject::entity_set("group", "a", "member"),
        Subject::entity_set("group", "a", ""),
    ];
    for index in 0..32 {
        subjects.push(Subject::Entity(
            Did::new(format!("did:key:actor{index}")).unwrap(),
        ));
    }
    subjects
}

#[tokio::test]
async fn subjects_are_listed_in_one_order_whatever_the_insertion_order() {
    let forward = MemoryZanzibarStore::new();
    let backward = MemoryZanzibarStore::new();
    let subjects = subjects();
    for subject in &subjects {
        let relationship = Relationship::new("document", "report", "reader", subject.clone());
        forward
            .store_relationship("p", &relationship)
            .await
            .unwrap();
    }
    for subject in subjects.iter().rev() {
        let relationship = Relationship::new("document", "report", "reader", subject.clone());
        backward
            .store_relationship("p", &relationship)
            .await
            .unwrap();
    }
    let listed = forward
        .get_relation_subjects("p", "document", "report", "reader")
        .await
        .unwrap();
    assert_eq!(listed.len(), subjects.len());
    assert_eq!(
        listed,
        backward
            .get_relation_subjects("p", "document", "report", "reader")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn path_like_identifiers_name_distinct_tuples() {
    let store = MemoryZanzibarStore::new();
    let actor = Did::new("did:key:actor").unwrap();
    let nested = Relationship::with_entity("document", "parent/path", "reader", actor.clone());
    store.store_relationship("p", &nested).await.unwrap();
    assert!(!store
        .has_relationship(
            "p",
            "document",
            "parent",
            "path/reader",
            &Subject::Entity(actor.clone())
        )
        .await
        .unwrap());
    assert!(store
        .get_relation_subjects("p", "document", "parent", "path")
        .await
        .unwrap()
        .is_empty());
    store
        .delete_object_relationships("p", "document", "parent")
        .await
        .unwrap();
    assert!(store
        .check_permission_direct("p", "document", "parent/path", "reader", &actor)
        .await
        .unwrap());
    assert!(store.delete_relationship("p", &nested).await.unwrap());
    assert!(!store
        .check_permission_direct("p", "document", "parent/path", "reader", &actor)
        .await
        .unwrap());
}
