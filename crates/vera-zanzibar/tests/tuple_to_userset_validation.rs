use vera_zanzibar::{Policy, Relation, RelationExpression, Resource, SubjectRestriction};

fn object_edge(resource: &str) -> SubjectRestriction {
    SubjectRestriction::EntitySet {
        resource: resource.into(),
        relation: String::new(),
    }
}

fn policy(parent: Relation, directory: Resource) -> Policy {
    Policy::new("p", "p")
        .with_resource(
            Resource::new("file")
                .with_relation(Relation::direct("reader"))
                .with_relation(parent)
                .with_relation(Relation::computed(
                    "read",
                    RelationExpression::parse("reader + parent->viewer").unwrap(),
                )),
        )
        .with_resource(directory)
        .with_resource(Resource::new("group").with_relation(Relation::direct("member")))
}

fn directory(relation: &str) -> Resource {
    Resource::new("directory").with_relation(Relation::direct(relation))
}

#[test]
fn every_restricted_target_must_declare_the_computed_relation() {
    let restricted = |restriction| Relation::direct("parent").with_restriction(restriction);
    policy(restricted(object_edge("directory")), directory("viewer"))
        .validate()
        .unwrap();
    assert!(
        policy(restricted(object_edge("directory")), directory("editor"))
            .validate()
            .is_err()
    );
    let mixed = |targets: Vec<SubjectRestriction>| restricted(SubjectRestriction::AnyOf(targets));
    assert!(policy(
        mixed(vec![object_edge("directory"), object_edge("group")]),
        directory("viewer")
    )
    .validate()
    .is_err());
    policy(
        mixed(vec![SubjectRestriction::Actor, object_edge("directory")]),
        directory("viewer"),
    )
    .validate()
    .unwrap();
}

#[test]
fn an_unrestricted_tuple_relation_needs_one_declaring_resource() {
    policy(Relation::direct("parent"), directory("viewer"))
        .validate()
        .unwrap();
    assert!(policy(Relation::direct("parent"), directory("editor"))
        .validate()
        .is_err());
    let any = Relation::direct("parent").with_restriction(SubjectRestriction::AnyOf(vec![
        object_edge("group"),
        SubjectRestriction::Any,
    ]));
    policy(any, directory("viewer")).validate().unwrap();
}

/// A relation typed `[actor]` accepts an actor written as an object of the
/// actor resource, which the policy need not give the computed relation.
#[tokio::test]
async fn a_tuple_naming_an_actor_without_the_computed_relation_grants_nothing() {
    use std::sync::Arc;
    use vera_zanzibar::{
        store::{MemoryZanzibarStore, ZanzibarStore},
        Did, PermissionEngine, Relationship, Subject,
    };

    let delegate = Did::new("did:key:delegate").unwrap();
    let reader = Did::new("did:key:reader").unwrap();
    for actor_relation in ["viewer", "editor"] {
        let mut policy = Policy::new("p", "p").with_resource(
            Resource::new("file")
                .with_relation(
                    Relation::direct("delegate").with_restriction(SubjectRestriction::Actor),
                )
                .with_relation(Relation::computed(
                    "read",
                    RelationExpression::parse("delegate->viewer").unwrap(),
                )),
        );
        policy.actor = Some(Resource::new("actor").with_relation(Relation::direct(actor_relation)));
        policy.validate().unwrap();

        let store = Arc::new(MemoryZanzibarStore::new());
        let mut engine = PermissionEngine::new(store.clone());
        engine.add_policy(&policy);
        for relationship in [
            Relationship::new(
                "file",
                "report",
                "delegate",
                Subject::entity_set("actor", delegate.as_str(), ""),
            ),
            Relationship::with_entity("actor", delegate.as_str(), actor_relation, reader.clone()),
        ] {
            relationship.validate(&policy).unwrap();
            store.store_relationship("p", &relationship).await.unwrap();
        }
        let reads = engine
            .check("p", "file", "report", "read", &reader)
            .await
            .unwrap();
        assert_eq!(reads, actor_relation == "viewer");
    }
}
