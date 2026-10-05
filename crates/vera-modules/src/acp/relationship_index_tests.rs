use super::super::types::{PolicyMarshalingType, RecordMetadata, RelationGenerations};
use super::*;
use crate::kv_store::{InMemoryKvStore, ModuleKvStore};
use crate::types::Timestamp;
use acp::{Policy, Relationship, Subject};
use identity::Did;
use zanzibar::{Relation, Resource};

const POLICY: &str = "policy-index-test";

fn metadata() -> RecordMetadata {
    RecordMetadata {
        creation_ts: Timestamp::default(),
        tx_hash: Vec::new(),
        tx_signer: "did:key:owner".into(),
        owner_did: "did:key:owner".into(),
    }
}

fn policy(reader: bool, member: bool) -> Policy {
    let mut file = Resource::new("file").with_relation(Relation::direct("owner"));
    if reader {
        file = file.with_relation(Relation::direct("reader"));
    }
    let mut group = Resource::new("group").with_relation(Relation::direct("owner"));
    if member {
        group = group.with_relation(Relation::direct("member"));
    }
    Policy::new(POLICY, "indexes")
        .with_resource(file)
        .with_resource(group)
}

struct Fixture {
    store: InMemoryKvStore,
    policy: PolicyRecord,
}

impl Fixture {
    fn new() -> Self {
        let policy = policy(true, true);
        let policy = PolicyRecord {
            relations: RelationGenerations::new(&policy).unwrap(),
            policy,
            supplied_metadata: Default::default(),
            last_modified: None,
            raw_policy: String::new(),
            marshal_type: PolicyMarshalingType::ShortYaml,
            metadata: metadata(),
        };
        let mut fixture = Self {
            store: InMemoryKvStore::default(),
            policy,
        };
        fixture.save_policy();
        fixture
    }

    fn save_policy(&mut self) {
        self.store.put(
            &keys::policy_key(POLICY),
            serde_json::to_vec(&self.policy).unwrap(),
        );
    }

    fn record(&self, object: &str, userset: bool) -> RelationshipRecord {
        let relationship = if userset {
            Relationship::new(
                "file",
                object,
                "reader",
                Subject::EntitySet {
                    resource: "group".into(),
                    object_id: "staff".into(),
                    relation: "member".into(),
                },
            )
        } else {
            Relationship::with_entity("file", object, "reader", Did::new("did:key:owner").unwrap())
        };
        RelationshipRecord {
            generations: self.policy.relations.pair(&relationship).unwrap(),
            policy_id: POLICY.into(),
            relationship,
            archived: false,
            supplied_metadata: Default::default(),
            metadata: metadata(),
        }
    }

    fn count(&self, pair: RelationPair) -> u64 {
        relationship_index::read_pair_count(&self.store, POLICY, pair).unwrap()
    }

    fn subjects(&self, target: u64) -> Vec<u64> {
        relationship_index::live_pairs(&self.store, POLICY, target, &self.policy.relations).unwrap()
    }
}

#[test]
fn inserts_metadata_rewrites_and_archived_rows_keep_exact_physical_counts() {
    let mut f = Fixture::new();
    let mut first = f.record("first", false);
    let second = f.record("second", false);
    put(&mut f.store, &first).unwrap();
    put(&mut f.store, &second).unwrap();
    assert_eq!(f.count(first.generations), 2);
    assert_eq!(f.subjects(first.generations.target), vec![0]);
    first.archived = true;
    first.metadata.tx_hash = vec![7; 32];
    first.supplied_metadata.blob = vec![1, 2, 3];
    put(&mut f.store, &first).unwrap();
    assert_eq!(f.count(first.generations), 2);
    remove(&mut f.store, &record_key(&first)).unwrap();
    assert_eq!(f.count(first.generations), 1);
    remove(&mut f.store, &record_key(&second)).unwrap();
    assert_eq!(f.count(first.generations), 0);
    assert!(f.subjects(first.generations.target).is_empty());
    assert!(!f.store.has(&relationship_index::active_key(
        POLICY,
        first.generations.target
    )));
    assert!(
        f.store
            .prefix_scan(&relationship_index::policy_prefix(POLICY))
            .is_empty()
    );
}

#[test]
fn bulk_removal_groups_shared_counts_and_same_target_directories() {
    let mut f = Fixture::new();
    let records = [
        f.record("one", false),
        f.record("two", false),
        f.record("three", true),
    ];
    for record in &records {
        put(&mut f.store, record).unwrap();
    }
    assert_eq!(
        f.subjects(records[0].generations.target),
        vec![0, records[2].generations.subject]
    );
    let changes = prepare_removals(
        &f.store,
        &records.iter().map(record_key).collect::<Vec<_>>(),
    )
    .unwrap();
    f.store.apply_records(changes).unwrap();
    for record in &records {
        assert_eq!(f.count(record.generations), 0);
    }
    assert!(
        f.store
            .prefix_scan(&relationship_index::policy_prefix(POLICY))
            .is_empty()
    );
}

#[test]
fn malformed_rows_mirrors_and_directories_reject_before_any_change() {
    for corruption in 0..11 {
        let mut f = Fixture::new();
        let record = f.record("one", false);
        put(&mut f.store, &record).unwrap();
        let outgoing = relationship_index::outgoing_key(POLICY, record.generations);
        let incoming = relationship_index::incoming_key(POLICY, record.generations);
        let directory = relationship_index::active_key(POLICY, record.generations.target);
        match corruption {
            0 => f.store.delete(&incoming),
            1 => f.store.put(&incoming, vec![1]),
            2 => f.store.put(&incoming, 2u64.to_be_bytes().to_vec()),
            3 => {
                f.store.put(&incoming, 0u64.to_be_bytes().to_vec());
                f.store.put(&outgoing, 0u64.to_be_bytes().to_vec());
            }
            4 => f.store.delete(&directory),
            5 => f.store.put(&directory, b"[0,0]".to_vec()),
            6 => f.store.put(&directory, b"[]".to_vec()),
            7 => f.store.put(&directory, b"[18446744073709551615]".to_vec()),
            8 => f.store.put(&record_key(&record), b"{".to_vec()),
            9 => {
                let mut changed = record.clone();
                changed.generations.target += 1;
                f.store
                    .put(&record_key(&record), serde_json::to_vec(&changed).unwrap());
            }
            10 => {
                f.store.delete(&outgoing);
                f.store.delete(&incoming);
            }
            _ => unreachable!(),
        }
        let before = f.store.serialize();
        assert!(
            put(&mut f.store, &record).is_err(),
            "rewrite accepted corruption {corruption}"
        );
        assert_eq!(f.store.serialize(), before);
        assert!(
            remove(&mut f.store, &record_key(&record)).is_err(),
            "remove accepted corruption {corruption}"
        );
        assert_eq!(f.store.serialize(), before);
    }
}

#[test]
fn late_bulk_corruption_and_count_underflow_preserve_all_prior_rows() {
    for underflow in [false, true] {
        let mut f = Fixture::new();
        let first = f.record("one", false);
        let second = f.record("two", !underflow);
        put(&mut f.store, &first).unwrap();
        put(&mut f.store, &second).unwrap();
        if underflow {
            for key in [
                relationship_index::outgoing_key(POLICY, first.generations),
                relationship_index::incoming_key(POLICY, first.generations),
            ] {
                f.store.put(&key, 1u64.to_be_bytes().to_vec());
            }
        } else {
            f.store.delete(&relationship_index::incoming_key(
                POLICY,
                second.generations,
            ));
        }
        let before = f.store.serialize();
        assert!(prepare_removals(&f.store, &[record_key(&first), record_key(&second)]).is_err());
        assert_eq!(f.store.serialize(), before);
    }
}

#[test]
fn count_overflow_and_stale_generation_writes_leave_state_unchanged() {
    let mut f = Fixture::new();
    let first = f.record("one", false);
    put(&mut f.store, &first).unwrap();
    for key in [
        relationship_index::outgoing_key(POLICY, first.generations),
        relationship_index::incoming_key(POLICY, first.generations),
    ] {
        f.store.put(&key, u64::MAX.to_be_bytes().to_vec());
    }
    let before = f.store.serialize();
    let second = f.record("two", false);
    assert!(put(&mut f.store, &second).is_err());
    assert_eq!(f.store.serialize(), before);
    let mut stale = second;
    stale.generations.target += 100;
    assert!(put(&mut f.store, &stale).is_err());
    assert_eq!(f.store.serialize(), before);
}

#[test]
fn removed_and_recreated_generations_keep_independent_physical_counts() {
    let mut f = Fixture::new();
    let retired = f.record("one", true);
    put(&mut f.store, &retired).unwrap();
    let reduced = policy(true, false);
    let (relations, _) = f
        .policy
        .relations
        .updated(&f.policy.policy, &reduced)
        .unwrap();
    f.policy.policy = reduced;
    f.policy.relations = relations;
    f.save_policy();
    // Definition editing owns the current directory cutover, while physical counts remain.
    f.store.delete(&relationship_index::active_key(
        POLICY,
        retired.generations.target,
    ));
    let recreated = policy(true, true);
    let (relations, _) = f
        .policy
        .relations
        .updated(&f.policy.policy, &recreated)
        .unwrap();
    f.policy.policy = recreated;
    f.policy.relations = relations;
    f.save_policy();
    let current = f.record("one", true);
    assert_ne!(current.generations, retired.generations);
    assert_ne!(record_key(&current), record_key(&retired));
    put(&mut f.store, &current).unwrap();
    assert_eq!(f.count(current.generations), 1);
    remove(&mut f.store, &record_key(&retired)).unwrap();
    assert_eq!(f.count(retired.generations), 0);
    assert_eq!(f.count(current.generations), 1);
    assert_eq!(
        f.subjects(current.generations.target),
        vec![current.generations.subject]
    );
    f.store.delete(&keys::policy_key(POLICY));
    remove(&mut f.store, &record_key(&current)).unwrap();
    assert_eq!(f.count(current.generations), 0);
}

struct ReadOnly {
    store: InMemoryKvStore,
    directory_only: Option<Vec<u8>>,
}

impl RecordStore for ReadOnly {
    fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self
            .directory_only
            .as_ref()
            .is_some_and(|allowed| allowed != key)
        {
            return Err(invalid("missing point proof"));
        }
        Ok(self.store.get(key))
    }
    fn scan_records(&self, _: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        panic!("pair mutations and directory reads must not scan physical storage")
    }
    fn write_record(&mut self, _: &[u8], _: Vec<u8>) -> Result<()> {
        panic!("atomic mutation must not fall back to individual writes")
    }
    fn remove_record(&mut self, _: &[u8]) -> Result<()> {
        panic!("atomic mutation must not fall back to individual removals")
    }
}

#[test]
fn atomic_apply_rejection_never_falls_back_to_individual_writes() {
    let f = Fixture::new();
    let record = f.record("one", false);
    let before = f.store.serialize();
    let mut read_only = ReadOnly {
        store: f.store,
        directory_only: None,
    };
    assert!(put(&mut read_only, &record).is_err());
    assert_eq!(read_only.store.serialize(), before);
    let mut f = Fixture::new();
    put(&mut f.store, &record).unwrap();
    let before = f.store.serialize();
    let mut read_only = ReadOnly {
        store: f.store,
        directory_only: None,
    };
    assert!(remove(&mut read_only, &record_key(&record)).is_err());
    assert_eq!(read_only.store.serialize(), before);
}

#[test]
fn authenticated_directory_read_does_not_require_counter_proof_fanout() {
    let mut f = Fixture::new();
    let record = f.record("one", false);
    put(&mut f.store, &record).unwrap();
    let read_only = ReadOnly {
        store: f.store,
        directory_only: Some(relationship_index::active_key(
            POLICY,
            record.generations.target,
        )),
    };
    assert_eq!(
        relationship_index::live_pairs(
            &read_only,
            POLICY,
            record.generations.target,
            &f.policy.relations
        )
        .unwrap(),
        vec![0]
    );
    assert!(relationship_index::read_pair_count(&read_only, POLICY, record.generations).is_err());
}

#[test]
fn permanent_owner_pair_counts_both_resources_without_key_collisions() {
    let mut f = Fixture::new();
    let mut rows = Vec::new();
    for resource in ["file", "group"] {
        let relationship = Relationship::with_entity(
            resource,
            "same",
            "owner",
            Did::new("did:key:owner").unwrap(),
        );
        let mut row = f.record("same", false);
        row.generations = f.policy.relations.pair(&relationship).unwrap();
        row.relationship = relationship;
        assert_eq!(
            row.generations,
            RelationPair {
                target: 0,
                subject: 0
            }
        );
        put(&mut f.store, &row).unwrap();
        rows.push(row);
    }
    assert_ne!(record_key(&rows[0]), record_key(&rows[1]));
    assert_eq!(f.count(rows[0].generations), 2);
    assert_eq!(f.subjects(0), vec![0]);
    remove(&mut f.store, &record_key(&rows[0])).unwrap();
    assert_eq!(f.count(rows[1].generations), 1);
    assert!(f.store.has(&record_key(&rows[1])));
}
