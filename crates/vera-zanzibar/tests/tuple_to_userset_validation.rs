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
