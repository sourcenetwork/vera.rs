//! Permission read coverage, failure propagation and capture limits.

use std::collections::BTreeMap;

use vera_identity::Did;
use vera_modules::acp::types::{Relationship, Subject};
use vera_modules::{
    acp::{
        AcpModule,
        evaluation::evaluate_access_request,
        keys,
        read_capture::{ReadCapture, ReadLimits, RecordRead},
        record_error::{RecordError, Result},
        record_store::RecordStore,
        relationship_values::{actor_relationship, actor_set, actor_subject, relationship},
        types::{
            AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType, PolicyRecord,
            RelationshipRecord,
        },
    },
    kv_store::{InMemoryKvStore, ModuleKvStore},
};

const DEFINITION: &str = "
name: exclusion
resources:
  - name: group
    relations:
      - name: blocked
  - name: document
    relations:
      - name: reader
      - name: blocked
        types: [actor, group->blocked]
    permissions:
      - name: read
        expr: reader - blocked
";
const OWNER: &str = "did:key:owner";
const ALICE: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const LIMITS: ReadLimits = ReadLimits {
    reads: 128,
    records: 128,
    bytes: 1 << 20,
};

fn policy() -> String {
    AcpModule::predict_policy_id(DEFINITION, &PolicyMarshalingType::ShortYaml, 1).unwrap()
}

fn owner() -> Did {
    Did::new(OWNER).unwrap()
}

fn relationship_key(store: &InMemoryKvStore, relationship: &Relationship) -> Vec<u8> {
    let record: PolicyRecord =
        PolicyRecord::from_json(&store.get(&keys::policy_key(&policy())).unwrap()).unwrap();
    keys::relationship_generation_key(
        &policy(),
        record.relations.pair(relationship).unwrap(),
        &keys::relationship_storage_key(relationship, 0),
    )
}

/// A policy with `document:report` and `group:staff` registered by the owner.
fn registered() -> AcpModule {
    let mut module = AcpModule::new();
    let record = module
        .create_policy(&owner(), DEFINITION, PolicyMarshalingType::ShortYaml)
        .unwrap();
    assert_eq!(record.policy.id.as_str(), policy());
    for (resource, id) in [("document", "report"), ("group", "staff")] {
        module
            .direct_policy_cmd(
                &owner(),
                &policy(),
                PolicyCmd::RegisterObject(Object {
                    resource: resource.into(),
                    id: id.into(),
                }),
            )
            .unwrap();
    }
    module
}

fn grant(module: &mut AcpModule, relationship: Relationship) {
    module
        .direct_policy_cmd(
            &owner(),
            &policy(),
            PolicyCmd::SetRelationship(relationship),
        )
        .unwrap();
}

fn revoke(module: &mut AcpModule, relationship: Relationship) {
    module
        .direct_policy_cmd(
            &owner(),
            &policy(),
            PolicyCmd::DeleteRelationship(relationship),
        )
        .unwrap();
}

/// Alice reads `document:report` unless `subject` blocks her; the block is
/// archived in place when `archived`.
fn fixture_module(subject: Subject, archived: bool) -> AcpModule {
    let mut module = registered();
    let alice = Did::new(ALICE).unwrap();
    let blocked = relationship("document", "report", "blocked", subject);
    grant(
        &mut module,
        actor_relationship("document", "report", "reader", &alice).unwrap(),
    );
    grant(&mut module, blocked.clone());
    grant(
        &mut module,
        actor_relationship("group", "staff", "blocked", &alice).unwrap(),
    );
    if archived {
        // This fixture models an archived tuple directly. Its generation stamps and
        // physical counts stay unchanged because the index includes archived rows.
        let mut store = module.store().clone();
        let key = relationship_key(&store, &blocked);
        let mut record: RelationshipRecord =
            serde_json::from_slice(&store.get(&key).unwrap()).unwrap();
        record.archived = true;
        store.put(&key, serde_json::to_vec(&record).unwrap());
        module = AcpModule::from_store(store);
    }
    module
}

fn fixture(subject: Subject, archived: bool) -> InMemoryKvStore {
    fixture_module(subject, archived).store().clone()
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
            .ok_or_else(|| RecordError::unavailable("missing point coverage"))
    }
    fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.prefixes
            .get(prefix)
            .cloned()
            .ok_or_else(|| RecordError::unavailable("missing prefix coverage"))
    }
}

#[test]
fn replay_requires_every_read_used_by_exclusions() {
    for subject in [
        actor_subject(&Did::new(ALICE).unwrap()).unwrap(),
        Subject::AllActors,
        actor_set("group", "staff", "blocked"),
    ] {
        for archived in [false, true] {
            let store = fixture(subject.clone(), archived);
            let capture = ReadCapture::new(store.clone(), LIMITS);
            assert_eq!(
                evaluate_access_request(capture.clone(), &policy(), &request()).unwrap(),
                archived
            );
            assert_eq!(
                AcpModule::from_store(store.clone())
                    .query_verify_access_request(&policy(), &request())
                    .unwrap(),
                archived
            );
            let reads = capture.requests().unwrap();
            assert!(reads.contains(&RecordRead::Key(keys::policy_key(&policy()))));
            assert_eq!(
                evaluate_access_request(CoveredRecords::new(&store, &reads), &policy(), &request())
                    .unwrap(),
                archived
            );
            for index in 0..reads.len() {
                let mut incomplete = reads.clone();
                incomplete.remove(index);
                assert!(
                    evaluate_access_request(
                        CoveredRecords::new(&store, &incomplete),
                        &policy(),
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
    let mut module = fixture_module(Subject::AllActors, false);
    let store = module.store().clone();
    let mut capture = ReadCapture::new(store.clone(), LIMITS);
    let blocked = relationship("document", "report", "blocked", Subject::AllActors);
    let key = relationship_key(&store, &blocked);
    revoke(&mut module, blocked);
    assert!(evaluate_access_request(module.store().clone(), &policy(), &request()).unwrap());
    assert!(capture.remove_record(&key).is_err());
    assert!(capture.write_record(&key, vec![]).is_err());
    assert!(capture.apply_records(vec![(key.clone(), None)]).is_err());
    assert!(!evaluate_access_request(capture.clone(), &policy(), &request()).unwrap());
    assert!(capture.requests().unwrap().contains(&RecordRead::Key(key)));
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
    assert!(!evaluate_access_request(capture.clone(), &policy(), &request()).unwrap());
    assert_eq!(
        capture.requests().unwrap(),
        [RecordRead::Key(keys::policy_key(&policy()))]
    );

    let mut store = fixture(Subject::AllActors, true);
    let key = keys::policy_key(&policy());
    let mut record: PolicyRecord = PolicyRecord::from_json(&store.get(&key).unwrap()).unwrap();
    record.policy.id = ::acp::domain::PolicyId::new("another-policy");
    store.put(&key, serde_json::to_vec(&record).unwrap());
    assert!(evaluate_access_request(store.clone(), &policy(), &request()).is_err());
    store.put(&key, b"{".to_vec());
    assert!(evaluate_access_request(store, &policy(), &request()).is_err());
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
        let capture = ReadCapture::new(fixture(Subject::AllActors, true), limits);
        assert!(evaluate_access_request(capture.clone(), &policy(), &request()).is_err());
        assert!(capture.requests().is_err());
    }
}

/// Compressed and uncompressed points of one secp256k1 key, in Base58BTC and Base64URL.
fn spellings(seed: u8) -> [Did; 4] {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let key = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    let bytes = |compressed| {
        let mut bytes = vec![0xe7, 0x01];
        bytes.extend_from_slice(key.verifying_key().to_encoded_point(compressed).as_bytes());
        bytes
    };
    [
        format!("did:key:z{}", bs58::encode(bytes(true)).into_string()),
        format!("did:key:z{}", bs58::encode(bytes(false)).into_string()),
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes(true))),
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes(false))),
    ]
    .map(|spelling| Did::new(spelling).unwrap())
}

#[test]
fn every_spelling_of_an_actor_captures_and_replays_the_same_reads() {
    let (reader, stranger) = (spellings(42), spellings(43));
    let request = |actor: &Did| AccessRequest {
        actor: Actor(actor.clone()),
        ..request()
    };
    let mut stores = Vec::new();
    for granted in &reader {
        let mut module = fixture_module(Subject::AllActors, true);
        grant(
            &mut module,
            actor_relationship("document", "report", "reader", granted).unwrap(),
        );
        let store = module.store().clone();
        let capture = |actor: &Did| {
            let capture = ReadCapture::new(store.clone(), LIMITS);
            let allowed = evaluate_access_request(capture.clone(), &policy(), &request(actor));
            (allowed.unwrap(), capture.requests().unwrap())
        };
        for (actors, expected) in [(&reader, true), (&stranger, false)] {
            let (allowed, reads) = capture(&actors[0]);
            assert_eq!(allowed, expected);
            for actor in actors {
                assert_eq!(capture(actor), (allowed, reads.clone()));
                assert_eq!(
                    evaluate_access_request(
                        CoveredRecords::new(&store, &reads),
                        &policy(),
                        &request(actor)
                    )
                    .unwrap(),
                    expected
                );
                assert_eq!(
                    AcpModule::from_store(store.clone())
                        .query_verify_access_request(&policy(), &request(actor))
                        .unwrap(),
                    expected
                );
            }
        }
        stores.push(store.serialize());
    }
    assert!(stores.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn a_direct_miss_scans_the_relation_once() {
    const READERS: usize = 100;
    let mut module = fixture_module(actor_subject(&Did::new(ALICE).unwrap()).unwrap(), true);
    for index in 0..READERS {
        let reader = Did::new(format!("did:key:reader{index}")).unwrap();
        grant(
            &mut module,
            actor_relationship("document", "report", "reader", &reader).unwrap(),
        );
    }
    let store = module.store().clone();
    let mut stranger = request();
    stranger.actor = Actor(Did::new("did:key:stranger").unwrap());
    let limits = ReadLimits {
        records: READERS + 28,
        ..LIMITS
    };
    let capture = ReadCapture::new(store, limits);
    assert!(!evaluate_access_request(capture, &policy(), &stranger).unwrap());
}
