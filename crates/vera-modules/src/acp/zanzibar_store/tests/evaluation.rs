use super::*;
use crate::acp::{
    read_capture::{ReadCapture, ReadLimits, RecordRead},
    types::{Actor, Object, Operation},
};

fn request(relation: &str) -> AccessRequest {
    AccessRequest {
        actor: Actor(did(ALICE)),
        operations: vec![Operation {
            object: Object {
                resource: "document".into(),
                id: "doc1".into(),
            },
            permission: relation.into(),
        }],
    }
}

#[test]
fn owner_evaluation_keeps_policy_evidence_without_repeated_reads() {
    let mut kv = InMemoryKvStore::default();
    let owner = Relationship::with_entity("document", "doc1", "owner", did(ALICE));
    seed(&mut kv, &owner, false);
    let owner_key = physical_key(&kv, &owner);
    let capture = ReadCapture::new(
        kv,
        ReadLimits {
            reads: 2,
            records: 2,
            bytes: 64 << 10,
        },
    );
    assert!(evaluate_access_request(capture.clone(), POLICY, &request("owner")).unwrap());
    let reads = capture.requests().unwrap();
    assert_eq!(reads.len(), 2);
    assert!(reads.contains(&RecordRead::Key(keys::policy_key(POLICY))));
    assert!(reads.contains(&RecordRead::Key(owner_key)));
}

#[test]
fn evaluations_keep_generation_metadata_within_their_snapshot() {
    for resource in ["document", "collection"] {
        let mut kv = InMemoryKvStore::default();
        let link = Relationship::new(
            "document",
            "doc1",
            "reader",
            Subject::entity_set("collection", "col1", "reader"),
        );
        let member = Relationship::with_entity("collection", "col1", "reader", did(ALICE));
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
                return Err(invalid("policy proof unavailable"));
            }
            self.0.read_record(key)
        }

        fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            self.0.scan_records(prefix)
        }
    }

    let mut kv = InMemoryKvStore::default();
    let owner = Relationship::with_entity("document", "doc1", "owner", did(ALICE));
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
