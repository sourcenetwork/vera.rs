//! Permission read coverage, failure propagation and capture limits.

use std::collections::BTreeMap;

use identity::Did;
use vera_modules::{
    acp::{
        AcpModule, keys,
        read_capture::{ReadCapture, ReadLimits, RecordRead},
        record_store::RecordStore,
        types::{
            AccessRequest, Actor, Object, Operation, PolicyMarshalingType, PolicyRecord,
            RecordMetadata, RelationshipRecord,
        },
        zanzibar_store::evaluate_access_request,
    },
    kv_store::{InMemoryKvStore, ModuleKvStore},
    types::Timestamp,
};
use zanzibar::{
    Policy, Relation, RelationExpression, Relationship, Resource, Subject,
    error::{Error, Result},
};

const POLICY: &str = "policy";
const ALICE: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const LIMITS: ReadLimits = ReadLimits {
    reads: 128,
    records: 128,
    bytes: 1 << 20,
};

fn metadata() -> RecordMetadata {
    RecordMetadata {
        creation_ts: Timestamp::default(),
        tx_hash: vec![],
        tx_signer: String::new(),
        owner_did: String::new(),
    }
}

fn fixture(subject: Subject, archived: bool) -> InMemoryKvStore {
    let excluded = if matches!(subject, Subject::EntitySet { .. }) {
        RelationExpression::tuple_to_userset("blocked", "blocked")
    } else {
        RelationExpression::computed_userset("blocked")
    };
    let policy = Policy::new(POLICY, "exclusion")
        .with_resource(Resource::new("group").with_relation(Relation::direct("blocked")))
        .with_resource(
            Resource::new("document")
                .with_relation(Relation::direct("reader"))
                .with_relation(Relation::direct("blocked"))
                .with_relation(Relation::computed(
                    "read",
                    RelationExpression::difference(
                        RelationExpression::computed_userset("reader"),
                        excluded,
                    ),
                )),
        );
    let mut store = InMemoryKvStore::default();
    store.put(
        &keys::policy_key(POLICY),
        serde_json::to_vec(&PolicyRecord {
            supplied_metadata: Default::default(),
            last_modified: None,
            policy,
            raw_policy: String::new(),
            marshal_type: PolicyMarshalingType::ShortYaml,
            metadata: metadata(),
        })
        .unwrap(),
    );
    let alice = Did::new(ALICE).unwrap();
    for (relationship, archived) in [
        (
            Relationship::with_entity("document", "report", "reader", alice.clone()),
            false,
        ),
        (
            Relationship::new("document", "report", "blocked", subject),
            archived,
        ),
        (
            Relationship::with_entity("group", "staff", "blocked", alice),
            false,
        ),
    ] {
        let key = keys::relationship_key(POLICY, &keys::relationship_storage_key(&relationship));
        store.put(
            &key,
            serde_json::to_vec(&RelationshipRecord {
                supplied_metadata: Default::default(),
                policy_id: POLICY.into(),
                relationship,
                archived,
                metadata: metadata(),
            })
            .unwrap(),
        );
    }
    store
}

fn request() -> AccessRequest {
    AccessRequest {
        actor: Actor(Did::new(ALICE).unwrap()),
        operations: vec![Operation {
            object: Object {
                resource: "document".into(),
                id: "report".into(),
            },
            permission: "read".into(),
        }],
    }
}

type Entries = Vec<(Vec<u8>, Vec<u8>)>;

struct CoveredRecords {
    points: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    prefixes: BTreeMap<Vec<u8>, Entries>,
}

impl CoveredRecords {
    fn new(store: &InMemoryKvStore, reads: &[RecordRead]) -> Self {
        let mut records = Self {
            points: BTreeMap::new(),
            prefixes: BTreeMap::new(),
        };
        for read in reads {
            match read {
                RecordRead::Key(key) => {
                    records.points.insert(key.clone(), store.get(key));
                }
                RecordRead::Prefix(prefix) => {
                    records
                        .prefixes
                        .insert(prefix.clone(), store.prefix_scan(prefix));
                }
            }
        }
        records
    }
}

impl RecordStore for CoveredRecords {
    fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.points
            .get(key)
            .cloned()
            .ok_or_else(|| Error::Serialization("missing point coverage".into()))
    }
    fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.prefixes
            .get(prefix)
            .cloned()
            .ok_or_else(|| Error::Serialization("missing prefix coverage".into()))
    }
}

#[test]
fn replay_requires_every_read_used_by_exclusions() {
    for subject in [
        Subject::Entity(Did::new(ALICE).unwrap()),
        Subject::Wildcard,
        Subject::typed_wildcard("document"),
        Subject::entity_set("group", "staff", "blocked"),
    ] {
        for archived in [false, true] {
            let store = fixture(subject.clone(), archived);
            let capture = ReadCapture::new(store.clone(), LIMITS);
            assert_eq!(
                evaluate_access_request(capture.clone(), POLICY, &request()).unwrap(),
                archived
            );
            assert_eq!(
                AcpModule::from_store(store.clone())
                    .query_verify_access_request(POLICY, &request())
                    .unwrap(),
                archived
            );
            let reads = capture.requests().unwrap();
            assert!(reads.contains(&RecordRead::Key(keys::policy_key(POLICY))));
            assert_eq!(
                evaluate_access_request(CoveredRecords::new(&store, &reads), POLICY, &request())
                    .unwrap(),
                archived
            );
            for index in 0..reads.len() {
                let mut incomplete = reads.clone();
                incomplete.remove(index);
                assert!(
                    evaluate_access_request(
                        CoveredRecords::new(&store, &incomplete),
                        POLICY,
                        &request()
                    )
                    .is_err(),
                    "omitted {:?}, archived={archived}, subject={subject:?}",
                    reads[index]
                );
            }
        }
    }
}

#[test]
fn capture_keeps_a_snapshot_and_rejects_mutation() {
    let mut store = fixture(Subject::typed_wildcard("document"), false);
    let mut capture = ReadCapture::new(store.clone(), LIMITS);
    let blocked = Relationship::new(
        "document",
        "report",
        "blocked",
        Subject::typed_wildcard("document"),
    );
    let key = keys::relationship_key(POLICY, &keys::relationship_storage_key(&blocked));
    store.delete(&key);
    assert!(evaluate_access_request(store, POLICY, &request()).unwrap());
    assert!(capture.remove_record(&key).is_err());
    assert!(capture.write_record(&key, vec![]).is_err());
    assert!(!evaluate_access_request(capture.clone(), POLICY, &request()).unwrap());
    let prefix = keys::relationship_storage_prefix(
        POLICY,
        &keys::relation_prefix("document", "report", "blocked"),
    );
    assert!(
        capture
            .requests()
            .unwrap()
            .contains(&RecordRead::Prefix(prefix))
    );
}

#[test]
fn read_limits_are_shared_and_cannot_yield_partial_coverage() {
    let store =
        InMemoryKvStore::from_pairs(vec![(b"a".to_vec(), vec![1]), (b"ab".to_vec(), vec![2])]);
    let capture = ReadCapture::new(store.clone(), ReadLimits { reads: 1, ..LIMITS });
    assert_eq!(capture.read_record(b"a").unwrap(), Some(vec![1]));
    let sibling = capture.clone();
    assert!(sibling.read_record(b"missing").is_err());
    assert!(sibling.requests().is_err());
    assert!(capture.requests().is_err());
    assert!(capture.read_record(b"a").is_err());

    let capture = ReadCapture::new(
        store.clone(),
        ReadLimits {
            records: 1,
            ..LIMITS
        },
    );
    assert!(capture.scan_records(b"a").is_err());
    assert!(capture.requests().is_err());
    assert!(capture.scan_records(b"missing").is_err());

    let capture = ReadCapture::new(store.clone(), ReadLimits { bytes: 1, ..LIMITS });
    assert!(capture.read_record(b"a").is_err());
    assert!(capture.requests().is_err());
    let capture = ReadCapture::new(store, ReadLimits { bytes: 2, ..LIMITS });
    assert_eq!(capture.read_record(b"a").unwrap(), Some(vec![1]));
}

#[test]
fn empty_reads_are_captured_and_still_consume_budget() {
    let capture = ReadCapture::new(
        InMemoryKvStore::default(),
        ReadLimits {
            reads: 2,
            records: 0,
            bytes: 0,
        },
    );
    assert_eq!(capture.read_record(b"").unwrap(), None);
    assert!(capture.scan_records(b"").unwrap().is_empty());
    assert_eq!(
        capture.requests().unwrap(),
        [RecordRead::Key(vec![]), RecordRead::Prefix(vec![])]
    );
    assert!(capture.read_record(b"").is_err());
}

#[test]
fn policy_reads_distinguish_absence_from_invalid_records() {
    let capture = ReadCapture::new(InMemoryKvStore::default(), LIMITS);
    assert!(!evaluate_access_request(capture.clone(), POLICY, &request()).unwrap());
    assert_eq!(
        capture.requests().unwrap(),
        [RecordRead::Key(keys::policy_key(POLICY))]
    );

    let mut store = fixture(Subject::Wildcard, true);
    let key = keys::policy_key(POLICY);
    let mut record: PolicyRecord = serde_json::from_slice(&store.get(&key).unwrap()).unwrap();
    record.policy.id = "another-policy".into();
    store.put(&key, serde_json::to_vec(&record).unwrap());
    assert!(evaluate_access_request(store.clone(), POLICY, &request()).is_err());
    store.put(&key, b"{".to_vec());
    assert!(evaluate_access_request(store, POLICY, &request()).is_err());
}

#[test]
fn evaluation_propagates_capture_exhaustion() {
    for limits in [
        ReadLimits { reads: 1, ..LIMITS },
        ReadLimits {
            records: 1,
            ..LIMITS
        },
        ReadLimits { bytes: 1, ..LIMITS },
    ] {
        let capture = ReadCapture::new(fixture(Subject::Wildcard, true), limits);
        assert!(evaluate_access_request(capture.clone(), POLICY, &request()).is_err());
        assert!(capture.requests().is_err());
    }
}
