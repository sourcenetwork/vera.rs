use super::*;
use crate::acp::relationship_values::{actor_set, object_subject, relationship};

const POLICY: &str = "
name: generations
resources:
  - name: file
    relations:
      - name: reader
        types: [actor, group->member, group]
    permissions:
      - name: read
        expr: reader
  - name: group
    relations:
      - name: member
";

fn policy() -> ProcessedPolicy {
    ::acp::policy::compile_text(POLICY, None, 1).unwrap().policy
}

fn edge(target: &str, subject: &str) -> Relationship {
    relationship(
        "file",
        "report",
        target,
        actor_set("group", "staff", subject),
    )
}

fn renamed(relation: &::acp::domain::Relation, name: &str) -> ::acp::domain::Relation {
    ::acp::domain::Relation {
        name: name.into(),
        ..relation.clone()
    }
}

#[test]
fn removal_and_recreation_never_reuse_target_or_subject_generations() {
    let original = policy();
    let state = RelationGenerations::new(&original).unwrap();
    let old = state.pair(&edge("reader", "member")).unwrap();
    let read = state.generation("file", "read").unwrap();
    let mut stripped = original.clone();
    for resource in &mut stripped.resources {
        resource.relations.clear();
        resource.permissions.clear();
    }
    let (retired, removed) = state.updated(&original, &stripped).unwrap();
    assert_eq!(removed, BTreeSet::from([old.target, old.subject, read]));
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
    let mut extra = changed.resources[0].clone();
    extra.name = "extra".into();
    extra.relations.clear();
    extra.permissions.clear();
    changed.resources.push(extra);
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
    let link = relationship("file", "report", "reader", object_subject("group", "staff"));
    assert_eq!(updated.pair(&link).unwrap().subject, 0);
    assert!(updated.contains(0));
    updated.validate(&changed).unwrap();
}

#[test]
fn permissions_get_retirable_ids_and_actors_need_none() {
    let original = policy();
    let state = RelationGenerations::new(&original).unwrap();
    let read = state.generation("file", "read").unwrap();
    assert!(read > 0);
    let through_permission = relationship(
        "file",
        "report",
        "reader",
        actor_set("file", "other", "read"),
    );
    assert_eq!(state.pair(&through_permission).unwrap().subject, read);
    let actor = relationship("file", "report", "reader", Subject::AllActors);
    assert_eq!(state.pair(&actor).unwrap().subject, 0);
    assert!(state.generation("actor", "member").is_none());
    let mut without = original.clone();
    without.resources[0].permissions.clear();
    let (updated, removed) = state.updated(&original, &without).unwrap();
    assert_eq!(removed, BTreeSet::from([read]));
    assert!(updated.pair(&through_permission).is_err());
    let (recreated, _) = updated.updated(&without, &original).unwrap();
    assert!(recreated.generation("file", "read").unwrap() > read);
    let mut invalid = original.clone();
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
                invalid.active.remove("group");
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
    let reader = duplicate.resources[0].relations[0].clone();
    duplicate.resources[0].relations.push(reader);
    assert!(RelationGenerations::new(&duplicate).is_err());
    let mut missing_owner = policy;
    missing_owner.resources[0].owner.name = "boss".into();
    assert!(RelationGenerations::new(&missing_owner).is_err());
}

#[test]
fn overflow_leaves_original_metadata_unchanged_and_noop_edit_still_works() {
    let original = policy();
    let mut state = RelationGenerations::new(&original).unwrap();
    state.next = u64::MAX - 1;
    let mut final_allocation = original.clone();
    let last = renamed(&final_allocation.resources[0].relations[0], "last");
    final_allocation.resources[0].relations.push(last);
    let (exhausted, _) = state.updated(&original, &final_allocation).unwrap();
    assert_eq!(exhausted.generation("file", "last"), Some(u64::MAX - 1));
    assert_eq!(exhausted.next, u64::MAX);
    exhausted.validate(&final_allocation).unwrap();
    state.next = u64::MAX;
    state.validate(&original).unwrap();
    let before = state.clone();
    assert_eq!(state.updated(&original, &original).unwrap().0, state);
    let mut changed = original.clone();
    let writer = renamed(&changed.resources[0].relations[0], "writer");
    changed.resources[0].relations.push(writer);
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
    let mut empty = policy();
    empty.resources.clear();
    let state = RelationGenerations::new(&empty).unwrap();
    assert_eq!(state.next, 1);
    assert!(state.contains(0));
    assert_eq!(state.active_ids(), BTreeSet::from([0]));
    assert!(state.pair(&edge("owner", "owner")).is_err());
    let state = RelationGenerations::new(&policy()).unwrap();
    for subject in [
        actor_set("missing", "object", "owner"),
        object_subject("missing", "object"),
    ] {
        let edge = relationship("file", "report", "owner", subject);
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
