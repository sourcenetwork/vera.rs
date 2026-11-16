use super::*;
use crate::acp::read_capture::{ReadCapture, ReadLimits, RecordRead};

#[test]
fn owner_evaluation_keeps_policy_evidence_without_repeated_reads() {
    let mut kv = InMemoryKvStore::default();
    let owner = alice("document", "doc1", "owner");
    seed(&mut kv, &owner, false);
    let owner_key = physical_key(&kv, &owner);
    let capture = ReadCapture::new(
        kv,
        ReadLimits {
            reads: 3,
            records: 3,
            bytes: 64 << 10,
        },
    );
    assert!(evaluate_access_request(capture.clone(), POLICY, &request("owner")).unwrap());
    let reads: std::collections::BTreeSet<_> = capture.requests().unwrap().into_iter().collect();
    assert_eq!(
        reads,
        [
            RecordRead::Key(keys::policy_key(POLICY)),
            RecordRead::Key(owner_key),
        ]
        .into(),
        "acp answers an owner's check with one read of the owner relationship"
    );
}

#[test]
fn evaluations_keep_generation_metadata_within_their_snapshot() {
    for resource in ["document", "collection"] {
        let mut kv = InMemoryKvStore::default();
        let link = relationship(
            "document",
            "doc1",
            "reader",
            actor_set("collection", "col1", "reader"),
        );
        let member = alice("collection", "col1", "reader");
        seed(&mut kv, &link, false);
        seed(&mut kv, &member, false);
        let original = kv.clone();
        let old_key = physical_key(&kv, &link);
        assert!(evaluate_access_request(kv.clone(), POLICY, &request("reader")).unwrap());

        edit_fixture(
            &mut kv,
            without_relation(fixture_policy(), resource, "reader"),
        );
        edit_fixture(&mut kv, fixture_policy());
        assert!(kv.has(&old_key));
        assert!(!evaluate_access_request(kv.clone(), POLICY, &request("reader")).unwrap());
        assert!(evaluate_access_request(original, POLICY, &request("reader")).unwrap());

        seed(&mut kv, &member, false);
        seed(&mut kv, &link, false);
        assert!(evaluate_access_request(kv.clone(), POLICY, &request("reader")).unwrap());
        kv.delete(&keys::policy_key(POLICY));
        assert!(!evaluate_access_request(kv, POLICY, &request("reader")).unwrap());
    }
}

#[test]
fn evaluation_rejects_unavailable_policy_and_invalid_metadata() {
    struct UnavailablePolicy(InMemoryKvStore);
    impl RecordStore for UnavailablePolicy {
        fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            if key == keys::policy_key(POLICY) {
                return Err(RecordError::unavailable("policy proof unavailable"));
            }
            self.0.read_record(key)
        }

        fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            self.0.scan_records(prefix)
        }
    }

    let mut kv = InMemoryKvStore::default();
    let owner = alice("document", "doc1", "owner");
    seed(&mut kv, &owner, false);
    assert!(
        evaluate_access_request(UnavailablePolicy(kv.clone()), POLICY, &request("owner")).is_err()
    );
    let mut invalid_policy = kv.clone();
    let mut policy = read_policy(&invalid_policy, POLICY).unwrap().unwrap();
    policy
        .relations
        .active
        .get_mut("document")
        .unwrap()
        .insert("owner".into(), 1);
    invalid_policy.put(
        &keys::policy_key(POLICY),
        serde_json::to_vec(&policy).unwrap(),
    );
    assert!(evaluate_access_request(invalid_policy, POLICY, &request("owner")).is_err());

    let owner_key = physical_key(&kv, &owner);
    let mut record: RelationshipRecord =
        serde_json::from_slice(kv.get_ref(&owner_key).unwrap()).unwrap();
    record.generations.subject = 1;
    kv.put(&owner_key, serde_json::to_vec(&record).unwrap());
    assert!(evaluate_access_request(kv, POLICY, &request("owner")).is_err());
}

const TTU: &str = "
name: ttu
resources:
  - name: collection
    relations:
      - name: reader
  - name: document
    relations:
      - name: parent
        types: [collection]
    permissions:
      - name: read
        expr: parent->reader
";

#[test]
fn evaluation_follows_cross_object_tuple_to_userset() {
    let mut kv = InMemoryKvStore::default();
    seed_policy(&mut kv, crate::acp::test_policy(POLICY, TTU));
    seed(
        &mut kv,
        &relationship(
            "document",
            "doc1",
            "parent",
            object_subject("collection", "col1"),
        ),
        false,
    );
    seed(&mut kv, &alice("collection", "col1", "reader"), false);
    assert!(
        evaluate_access_request(kv.clone(), POLICY, &request("read")).unwrap(),
        "alice inherits read on doc1 via reader on its parent collection"
    );
    let mut doc2 = request("read");
    doc2.operations[0].object.id = "doc2".into();
    assert!(
        !evaluate_access_request(kv, POLICY, &doc2).unwrap(),
        "doc2 has no parent edge, so nothing is inherited"
    );
}

const EXCLUSION: &str = "
name: exclusion
resources:
  - name: collection
    relations:
      - name: blocked
  - name: document
    relations:
      - name: reader
      - name: blocked
        types: [actor, collection->blocked]
    permissions:
      - name: read
        expr: reader - blocked
";

#[test]
fn corrupt_exclusion_records_cannot_grant_access() {
    for subject in [
        crate::acp::relationship_values::actor_subject(&did(ALICE)).unwrap(),
        Subject::AllActors,
        actor_set("collection", "col1", "blocked"),
    ] {
        let mut kv = InMemoryKvStore::default();
        seed_policy(&mut kv, crate::acp::test_policy(POLICY, EXCLUSION));
        let blocked = relationship("document", "doc1", "blocked", subject.clone());
        seed(&mut kv, &alice("document", "doc1", "reader"), false);
        seed(&mut kv, &blocked, false);
        seed(&mut kv, &alice("collection", "col1", "blocked"), false);
        assert!(!evaluate_access_request(kv.clone(), POLICY, &request("read")).unwrap());

        kv.put(&physical_key(&kv, &blocked), b"{".to_vec());
        let result = evaluate_access_request(kv, POLICY, &request("read"));
        assert!(
            result.is_err(),
            "corrupt {subject:?} exclusion must fail: {result:?}"
        );
    }
}

#[test]
fn metered_steps_are_charged_and_exhaustion_is_an_error() {
    let mut kv = InMemoryKvStore::default();
    seed(&mut kv, &alice("document", "doc1", "reader"), false);
    let object = Object {
        resource: "document".into(),
        id: "doc1".into(),
    };
    let budget = PermissionBudget::new(u64::MAX);
    let evaluation = evaluation(kv.clone(), POLICY, None, Some(budget.clone()))
        .unwrap()
        .unwrap();
    assert!(evaluation.check(&object, "reader", &did(ALICE)).unwrap());
    let steps = budget.consumed();
    assert!(steps > 0 && steps % 32 == 0);

    let short = PermissionBudget::new(steps - 1);
    let evaluation = evaluation_for_policy(
        kv.clone(),
        read_policy(&kv, POLICY).unwrap().unwrap(),
        None,
        Some(short.clone()),
    )
    .unwrap();
    assert!(matches!(
        evaluation.check(&object, "reader", &did(ALICE)),
        Err(RecordError::Unavailable(_))
    ));
    assert!(short.is_exhausted());
}

#[test]
fn a_cached_model_is_used_only_for_its_own_policy() {
    let mut kv = InMemoryKvStore::default();
    seed(&mut kv, &alice("document", "doc1", "reader"), false);
    let record = read_policy(&kv, POLICY).unwrap().unwrap();
    let cached = Arc::new(compile(&record).unwrap());
    let reused = evaluation(kv.clone(), POLICY, Some(&cached), None)
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(&reused.compiled, &cached));
    let mut other = record.clone();
    other.policy.name = "another".into();
    let stale = Arc::new(compile(&other).unwrap());
    let fresh = evaluation(kv, POLICY, Some(&stale), None).unwrap().unwrap();
    assert!(!Arc::ptr_eq(&fresh.compiled, &stale));
    assert_eq!(fresh.compiled.policy, record.policy);
}
