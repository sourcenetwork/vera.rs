use super::*;
use zanzibar::{Relation, RelationExpression, Resource};

fn policy() -> Policy {
    let mut policy = Policy::new("policy", "generations")
        .with_resource(
            Resource::new("file")
                .with_relation(Relation::direct("owner"))
                .with_relation(Relation::direct("reader")),
        )
        .with_resource(
            Resource::new("group")
                .with_relation(Relation::direct("owner"))
                .with_relation(Relation::direct("member")),
        );
    policy.actor = Some(Resource::new("actor").with_relation(Relation::direct("admin")));
    policy
}

fn edge(target: &str, subject: &str) -> Relationship {
    Relationship::new(
        "file",
        "report",
        target,
        Subject::EntitySet {
            resource: "group".into(),
            object_id: "staff".into(),
            relation: subject.into(),
        },
    )
}

#[test]
fn removal_and_recreation_never_reuse_target_or_subject_generations() {
    let original = policy();
    let state = RelationGenerations::new(&original).unwrap();
    let old = state.pair(&edge("reader", "member")).unwrap();
    let mut stripped = original.clone();
    for resource in &mut stripped.resources {
        resource.relations.retain(|r| r.name == "owner");
    }
    let (retired, removed) = state.updated(&original, &stripped).unwrap();
    assert_eq!(removed, BTreeSet::from([old.target, old.subject]));
    assert!(!retired.contains(old.target));
    assert!(!retired.contains(old.subject));
    assert!(retired.pair(&edge("reader", "member")).is_err());
    let (recreated, removed) = retired.updated(&stripped, &original).unwrap();
    assert!(removed.is_empty());
    let fresh = recreated.pair(&edge("reader", "member")).unwrap();
    assert!(fresh.target >= state.next && fresh.subject >= state.next);
    assert_ne!(fresh.target, fresh.subject);
    recreated.validate(&original).unwrap();
    assert!(state.contains(old.target));
}

#[test]
fn owner_generations_and_surviving_names_are_stable() {
    let original = policy();
    let state = RelationGenerations::new(&original).unwrap();
    let mut changed = original.clone();
    changed.resources.reverse();
    let file = changed
        .resources
        .iter_mut()
        .find(|r| r.name == "file")
        .unwrap();
    file.relations[1] = Relation::computed("reader", RelationExpression::computed_userset("owner"))
        .with_manages(vec!["owner"])
        .with_restriction(zanzibar::SubjectRestriction::Actor);
    changed
        .resources
        .push(Resource::new("extra").with_relation(Relation::direct("owner")));
    let (updated, removed) = state.updated(&original, &changed).unwrap();
    assert!(removed.is_empty());
    assert_eq!(state.next, updated.next);
    assert_eq!(
        updated.generation("file", "reader"),
        state.generation("file", "reader")
    );
    for name in ["file", "group", "extra"] {
        assert_eq!(updated.generation(name, "owner"), Some(0));
    }
    assert_eq!(
        updated.pair(&edge("owner", "owner")).unwrap(),
        RelationPair {
            target: 0,
            subject: 0
        }
    );
    assert_eq!(updated.pair(&edge("reader", "")).unwrap().subject, 0);
    assert!(updated.contains(0));
    updated.validate(&changed).unwrap();
}

#[test]
fn actor_roles_get_distinct_retirable_ids_and_resource_identity_is_preserved() {
    let original = policy();
    let state = RelationGenerations::new(&original).unwrap();
    let admin = state.generation("actor", "admin").unwrap();
    assert!(admin > 0);
    let actor_target = Relationship::new("actor", "alice", "admin", Subject::wildcard());
    let actor_subject = Relationship::new(
        "file",
        "report",
        "reader",
        Subject::entity_set("actor", "alice", "admin"),
    );
    assert_eq!(
        state.pair(&actor_target).unwrap(),
        RelationPair {
            target: admin,
            subject: 0
        }
    );
    assert_eq!(state.pair(&actor_subject).unwrap().subject, admin);
    let mut without_role = original.clone();
    without_role.actor.as_mut().unwrap().relations.clear();
    let (updated, removed) = state.updated(&original, &without_role).unwrap();
    assert_eq!(removed, BTreeSet::from([admin]));
    assert!(updated.pair(&actor_target).is_err());
    assert!(updated.pair(&actor_subject).is_err());
    let (recreated, _) = updated.updated(&without_role, &original).unwrap();
    assert!(recreated.generation("actor", "admin").unwrap() > admin);
    let mut invalid = original.clone();
    invalid.actor.as_mut().unwrap().name = "person".into();
    assert!(state.updated(&original, &invalid).is_err());
    invalid = original.clone();
    invalid.resources.pop();
    assert!(state.updated(&original, &invalid).is_err());
}

#[test]
fn malformed_maps_counters_and_duplicate_policy_names_are_rejected() {
    let policy = policy();
    let state = RelationGenerations::new(&policy).unwrap();
    for case in 0..6 {
        let mut invalid = state.clone();
        match case {
            0 => invalid.next = 0,
            1 => invalid.next = *invalid.active["file"].get("reader").unwrap(),
            2 => {
                invalid
                    .active
                    .get_mut("file")
                    .unwrap()
                    .insert("owner".into(), 1);
            }
            3 => {
                invalid
                    .active
                    .get_mut("file")
                    .unwrap()
                    .insert("reader".into(), 0);
            }
            4 => {
                let id = invalid.active["group"]["member"];
                invalid
                    .active
                    .get_mut("file")
                    .unwrap()
                    .insert("reader".into(), id);
            }
            5 => {
                invalid.active.remove("actor");
            }
            _ => unreachable!(),
        }
        assert!(invalid.validate(&policy).is_err(), "case {case}");
        assert!(invalid.updated(&policy, &policy).is_err(), "case {case}");
    }
    let mut duplicate = policy.clone();
    duplicate.resources.push(duplicate.resources[0].clone());
    assert!(RelationGenerations::new(&duplicate).is_err());
    duplicate = policy.clone();
    duplicate.resources[0]
        .relations
        .push(Relation::direct("reader"));
    assert!(RelationGenerations::new(&duplicate).is_err());
    let mut missing_owner = policy.clone();
    missing_owner.resources[0]
        .relations
        .retain(|r| r.name != "owner");
    assert!(RelationGenerations::new(&missing_owner).is_err());
    let mut actor_owner = policy;
    actor_owner
        .actor
        .as_mut()
        .unwrap()
        .relations
        .push(Relation::direct("owner"));
    assert!(RelationGenerations::new(&actor_owner).is_err());
}

#[test]
fn overflow_leaves_original_metadata_unchanged_and_noop_edit_still_works() {
    let original = policy();
    let mut state = RelationGenerations::new(&original).unwrap();
    state.next = u64::MAX - 1;
    let mut final_allocation = original.clone();
    final_allocation.resources[0]
        .relations
        .push(Relation::direct("last"));
    let (exhausted, _) = state.updated(&original, &final_allocation).unwrap();
    assert_eq!(exhausted.generation("file", "last"), Some(u64::MAX - 1));
    assert_eq!(exhausted.next, u64::MAX);
    exhausted.validate(&final_allocation).unwrap();
    state.next = u64::MAX;
    state.validate(&original).unwrap();
    let before = state.clone();
    assert_eq!(state.updated(&original, &original).unwrap().0, state);
    let mut changed = original.clone();
    changed.resources[0]
        .relations
        .push(Relation::direct("writer"));
    assert!(state.updated(&original, &changed).is_err());
    assert_eq!(state, before);
}

#[test]
fn json_requires_metadata_and_rejects_duplicate_names() {
    for invalid in [
        "{}",
        r#"{"next":1}"#,
        r#"{"active":{}}"#,
        r#"{"next":1,"next":2,"active":{}}"#,
        r#"{"next":1,"active":{"file":{},"file":{}}}"#,
        r#"{"next":2,"active":{"file":{"reader":1,"reader":1}}}"#,
    ] {
        assert!(serde_json::from_str::<RelationGenerations>(invalid).is_err());
    }
    let state = RelationGenerations::new(&policy()).unwrap();
    let encoded = serde_json::to_vec(&state).unwrap();
    let decoded: RelationGenerations = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, state);
    decoded.validate(&policy()).unwrap();
}

#[test]
fn permanent_zero_requires_existing_resources_when_used_as_an_owner() {
    let state = RelationGenerations::new(&Policy::new("empty", "empty")).unwrap();
    assert_eq!(state.next, 1);
    assert!(state.contains(0));
    assert_eq!(state.active_ids(), BTreeSet::from([0]));
    assert!(state.pair(&edge("owner", "owner")).is_err());
    let state = RelationGenerations::new(&policy()).unwrap();
    for relation in ["owner", ""] {
        let edge = Relationship::new(
            "file",
            "report",
            "owner",
            Subject::entity_set("missing", "object", relation),
        );
        assert!(state.pair(&edge).is_err());
    }
}

#[test]
fn durable_descriptors_roundtrip_without_changing_generations() {
    let state = RelationGenerations::new(&policy()).unwrap();
    let encoded = borsh::to_vec(&state).unwrap();
    assert_eq!(
        borsh::from_slice::<RelationGenerations>(&encoded).unwrap(),
        state
    );
    let pair = state.pair(&edge("reader", "member")).unwrap();
    let encoded = borsh::to_vec(&pair).unwrap();
    assert_eq!(borsh::from_slice::<RelationPair>(&encoded).unwrap(), pair);
}
