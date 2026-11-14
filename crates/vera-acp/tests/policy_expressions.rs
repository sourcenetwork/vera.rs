use vera_acp::{
    policy_yaml::{build_policy, parse_policy_yaml},
    Policy, RelationExpression,
};

const BLOCKED: &str = r#"
name: public_except_blocked
resources:
- name: document
  permissions:
  - name: read
    expr: reader - blocked
  - name: update
    expr: (reader + writer) - blocked
  - name: delete
    expr: admin
  relations:
  - name: reader
    types: [actor]
  - name: writer
    types: [actor]
  - name: blocked
    types: [actor]
  - name: admin
    manages: [reader, writer, blocked]
    types: [actor]
"#;

const FILESYSTEM: &str = r#"
name: filesystem
resources:
- name: file
  permissions:
  - name: read
    expr: reader + parent->read
  - name: update
    expr: parent->update
  relations:
  - name: parent
    types: [directory]
  - name: reader
    types: [actor]
- name: directory
  permissions:
  - name: read
    expr: reader + writer
  - name: update
    expr: writer
  relations:
  - name: reader
    types: [actor]
  - name: writer
    types: [actor]
"#;

const COMPUTED: &str = r#"
name: computed_permission_reference
resources:
- name: site
  permissions:
  - name: local_read
    expr: site_operator + site_manager
  - name: audit_read
    expr: local_read + compliance
  - name: read
    expr: audit_read
  - name: delete
  relations:
  - name: site_operator
    types: [actor]
  - name: site_manager
    types: [actor]
  - name: compliance
    types: [actor]
"#;

fn build(definition: &str) -> vera_acp::Result<Policy> {
    build_policy(&parse_policy_yaml(definition).unwrap(), 1)
}

#[test]
fn exclusions_tuple_references_and_computed_permissions_build() {
    for definition in [BLOCKED, FILESYSTEM, COMPUTED] {
        build(definition).unwrap();
    }
}

#[test]
fn every_permission_grants_its_owner_first() {
    let policy = build(BLOCKED).unwrap();
    let owner = RelationExpression::computed_userset("owner");
    for permission in ["read", "update", "delete"] {
        let relation = policy.get_relation("document", permission).unwrap();
        let RelationExpression::Union(operands) = &relation.expression else {
            panic!("{permission} is not a union with the owner");
        };
        assert_eq!(operands[0], owner);
    }
}

#[test]
fn a_tuple_reference_must_resolve_on_every_target_type() {
    assert!(build(&FILESYSTEM.replace("expr: parent->update", "expr: parent->delete")).is_err());
    let mixed = FILESYSTEM.replace("types: [directory]", "types: [directory, file]");
    build(&mixed).unwrap();
    let unresolved_on_file = mixed
        .replace(
            "expr: reader + writer",
            "expr: reader + writer\n  - name: list\n    expr: reader",
        )
        .replace("expr: parent->update", "expr: parent->list");
    assert!(build(&unresolved_on_file).is_err());
    build(&FILESYSTEM.replace("types: [directory]", "types: [actor, directory]")).unwrap();
}

fn subtractions(count: usize) -> String {
    format!("reader{}", " - blocked".repeat(count))
}

#[test]
fn stored_expressions_are_bounded_and_always_decode_again() {
    use vera_zanzibar::expression::MAX_EXPRESSION_DEPTH;

    for (specification, permission, wrappers) in [("none", "read", 1), ("defra", "read", 2)] {
        let definition = format!(
            "spec: {specification}\n{}",
            BLOCKED
                .replace("name: update", "name: write")
                .replace("expr: reader - blocked", "expr: EXPRESSION")
        );
        let with = |count| definition.replace("EXPRESSION", &subtractions(count));
        let deepest = MAX_EXPRESSION_DEPTH - wrappers;
        let policy = build(&with(deepest)).unwrap();
        let stored = &policy
            .get_relation("document", permission)
            .unwrap()
            .expression;
        assert_eq!(stored.depth(), MAX_EXPRESSION_DEPTH);
        let encoded = serde_json::to_vec(&policy).unwrap();
        serde_json::from_slice::<Policy>(&encoded).unwrap();

        for count in [deepest + 1, 60, 4096] {
            assert!(build(&with(count)).is_err(), "{specification} {count}");
        }
    }
}

#[test]
fn long_flat_unions_are_one_level() {
    let union = format!("reader{}", " + writer".repeat(1024));
    build(&BLOCKED.replace("expr: reader - blocked", &format!("expr: {union}"))).unwrap();
}
