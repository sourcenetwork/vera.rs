mod incarnations;
mod reads;

use ::acp::domain::{ProcessedPolicy, Restriction};

use super::*;
use crate::acp::relationship_values::{
    actor_relationship, actor_set, object_subject, relationship,
};
use crate::acp::types::{PolicyMarshalingType, RecordMetadata, RelationGenerations};
use crate::acp::{relationship_index, relationship_mutations};
use crate::kv_store::{InMemoryKvStore, ModuleKvStore};
use crate::types::Timestamp;

const POLICY: &str = "policy-1";
const ALICE: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

const FIXTURE: &str = "
name: adapter
resources:
  - name: document
    relations:
      - name: reader
        types: [actor, collection->reader, folder->reader]
      - name: parent
        types: [collection]
      - name: blocked
        types: [actor, collection->blocked]
      - name: a
      - name: z
  - name: collection
    relations:
      - name: reader
      - name: blocked
  - name: folder
    relations:
      - name: reader
";

fn did(s: &str) -> Did {
    Did::new(s).expect("valid did")
}

fn alice(resource: &str, id: &str, relation: &str) -> Relationship {
    actor_relationship(resource, id, relation, &did(ALICE)).unwrap()
}

fn fixture_policy() -> ProcessedPolicy {
    crate::acp::test_policy(POLICY, FIXTURE)
}

/// `policy` without `relation` of `resource`, and without the types that name it.
fn without_relation(
    mut policy: ProcessedPolicy,
    resource: &str,
    relation: &str,
) -> ProcessedPolicy {
    for declared in &mut policy.resources {
        if declared.name.as_str() == resource {
            declared
                .relations
                .retain(|item| item.name.as_str() != relation);
        }
        for item in &mut declared.relations {
            item.types.retain(|restriction| {
                !matches!(restriction, Restriction::ActorSet { resource: r, relation: n }
                    if r.as_str() == resource && n.as_str() == relation)
            });
        }
    }
    policy
}

fn metadata() -> RecordMetadata {
    RecordMetadata {
        creation_ts: Timestamp::default(),
        tx_hash: Vec::new(),
        tx_signer: String::new(),
        owner_did: String::new(),
    }
}

fn seed_policy(store: &mut InMemoryKvStore, policy: ProcessedPolicy) {
    let policy_hash = crate::acp::policy_id::policy_hash(&policy);
    let record = PolicyRecord {
        relations: RelationGenerations::new(&policy).unwrap(),
        policy,
        supplied_metadata: Default::default(),
        last_modified: None,
        raw_policy: String::new(),
        marshal_type: PolicyMarshalingType::ShortYaml,
        metadata: metadata(),
        nonce: Default::default(),
        policy_hash,
    };
    store.put(
        &keys::policy_key(record.policy.id.as_str()),
        serde_json::to_vec(&record).unwrap(),
    );
}

fn physical_key(store: &InMemoryKvStore, rel: &Relationship) -> Vec<u8> {
    let policy = read_policy(store, POLICY).unwrap().unwrap();
    keys::relationship_generation_key(
        POLICY,
        policy.relations.pair(rel).unwrap(),
        &keys::relationship_storage_key(
            rel,
            object_state::for_relationship(store, POLICY, rel).unwrap(),
        ),
    )
}

/// Populate rows through the indexed writer, including archived relationships.
fn seed(store: &mut InMemoryKvStore, rel: &Relationship, archived: bool) {
    if !store.has(&keys::policy_key(POLICY)) {
        seed_policy(store, fixture_policy());
    }
    let policy = read_policy(store, POLICY).unwrap().unwrap();
    let record = RelationshipRecord {
        incarnation: object_state::for_relationship(store, POLICY, rel).unwrap(),
        generations: policy.relations.pair(rel).unwrap(),
        supplied_metadata: Default::default(),
        policy_id: POLICY.to_string(),
        relationship: rel.clone(),
        archived,
        metadata: metadata(),
    };
    relationship_mutations::put(store, &record).unwrap();
}

/// Install a committed edit's policy and directory transition, retaining
/// physical rows and counts so reads cannot rely on eager deletion.
fn edit_fixture(store: &mut InMemoryKvStore, next_policy: ProcessedPolicy) {
    let mut record = read_policy(store, POLICY).unwrap().unwrap();
    let (relations, _) = record
        .relations
        .updated(&record.policy, &next_policy)
        .unwrap();
    for target in record.relations.active_ids() {
        let mut subjects =
            relationship_index::live_pairs(store, POLICY, target, &record.relations).unwrap();
        for subject in &subjects {
            if !relations.contains(target) || !relations.contains(*subject) {
                store.delete(&relationship_index::logical_key(
                    POLICY,
                    RelationPair {
                        target,
                        subject: *subject,
                    },
                ));
            }
        }
        subjects.retain(|subject| relations.contains(target) && relations.contains(*subject));
        let key = relationship_index::active_key(POLICY, target);
        if subjects.is_empty() {
            store.delete(&key);
        } else {
            store.put(&key, serde_json::to_vec(&subjects).unwrap());
        }
    }
    record.policy = next_policy;
    record.relations = relations;
    store.put(
        &keys::policy_key(POLICY),
        serde_json::to_vec(&record).unwrap(),
    );
}

fn grants<S: RecordStore>(store: S) -> StoredGrants<S> {
    evaluation(store, POLICY, None, None)
        .unwrap()
        .expect("policy")
        .grants
}

fn subjects<S: RecordStore>(store: S, id: &str, relation: &str) -> Result<Vec<Subject>> {
    evaluation(store, POLICY, None, None)?
        .expect("policy")
        .grants
        .subjects(
            &AcpObject::new("document", id),
            &relation.into(),
            None,
            std::num::NonZeroUsize::MAX,
        )
        .map(|page| {
            assert!(!page.more);
            page.subjects
        })
}

fn has<S: RecordStore>(store: S, relationship: &Relationship) -> Result<bool> {
    evaluation(store, POLICY, None, None)?
        .expect("policy")
        .grants
        .has(relationship)
}

fn request(permission: &str) -> AccessRequest {
    AccessRequest {
        actor: super::super::types::Actor(did(ALICE)),
        operations: vec![super::super::types::Operation {
            object: Object {
                resource: "document".into(),
                id: "doc1".into(),
            },
            permission: permission.into(),
        }],
    }
}

#[test]
fn relationship_keys_isolate_path_fields() {
    let mut kv = InMemoryKvStore::default();
    let original = alice("document", "parent/path", "reader");
    let collision = alice("document", "parent", "a");
    seed(&mut kv, &original, false);
    assert_ne!(physical_key(&kv, &original), physical_key(&kv, &collision));
    assert!(has(kv.clone(), &original).unwrap());
    assert!(!has(kv.clone(), &collision).unwrap());
    assert!(subjects(kv, "parent", "reader").unwrap().is_empty());
}

#[test]
fn permission_identity_excludes_path_descendants() {
    let mut kv = InMemoryKvStore::default();
    for subject in [
        object_subject("collection", "shared"),
        actor_set("folder", "shared", "reader"),
        crate::acp::relationship_values::actor_subject(&did(ALICE)).unwrap(),
    ] {
        seed(
            &mut kv,
            &relationship("document", "doc/reader/child", "reader", subject),
            false,
        );
    }
    assert!(!has(kv.clone(), &alice("document", "doc", "reader")).unwrap());
    assert!(subjects(kv.clone(), "doc", "reader").unwrap().is_empty());
    let own = alice("document", "doc", "reader");
    seed(&mut kv, &own, false);
    assert!(has(kv.clone(), &own).unwrap());
    assert_eq!(subjects(kv, "doc", "reader").unwrap(), vec![own.subject]);
}

#[test]
fn permission_identity_rejects_mismatched_record_keys() {
    let mut kv = InMemoryKvStore::default();
    let stored = alice("document", "other", "reader");
    let requested = alice("document", "doc", "reader");
    seed(&mut kv, &stored, false);
    let bytes = kv.get(&physical_key(&kv, &stored)).unwrap();
    kv.put(&physical_key(&kv, &requested), bytes);
    assert!(has(kv.clone(), &requested).is_err());
    assert!(subjects(kv, "doc", "reader").is_err());
}

#[test]
fn subjects_are_the_live_subjects_of_one_object_relation() {
    let mut kv = InMemoryKvStore::default();
    let actor = alice("document", "doc1", "reader");
    let userset = relationship(
        "document",
        "doc1",
        "reader",
        actor_set("collection", "col1", "reader"),
    );
    let archived = relationship(
        "document",
        "doc1",
        "reader",
        actor_set("folder", "f1", "reader"),
    );
    seed(&mut kv, &actor, false);
    seed(&mut kv, &userset, false);
    seed(&mut kv, &archived, true);
    seed(&mut kv, &alice("document", "doc2", "reader"), false);
    let found = subjects(kv.clone(), "doc1", "reader").unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.contains(&actor.subject));
    assert!(found.contains(&userset.subject));
    assert!(has(kv.clone(), &actor).unwrap());
    assert!(
        !has(kv.clone(), &archived).unwrap(),
        "archived reads as absent"
    );
    assert!(
        !has(
            kv,
            &relationship("document", "doc1", "reader", Subject::AllActors)
        )
        .unwrap(),
        "never-seeded subject reads as absent"
    );
}

#[test]
fn checks_follow_direct_all_actor_and_archived_grants() {
    let mut kv = InMemoryKvStore::default();
    seed(&mut kv, &alice("document", "doc1", "reader"), false);
    assert!(evaluate_access_request(kv.clone(), POLICY, &request("reader")).unwrap());
    assert!(!evaluate_access_request(kv.clone(), POLICY, &request("a")).unwrap());

    let mut public = InMemoryKvStore::default();
    seed(
        &mut public,
        &relationship("document", "doc1", "reader", Subject::AllActors),
        false,
    );
    assert!(evaluate_access_request(public, POLICY, &request("reader")).unwrap());

    let mut archived = InMemoryKvStore::default();
    seed(&mut archived, &alice("document", "doc1", "reader"), true);
    assert!(!evaluate_access_request(archived, POLICY, &request("reader")).unwrap());
}

#[test]
fn unknown_permissions_and_resources_are_errors_not_denials() {
    let mut kv = InMemoryKvStore::default();
    seed(&mut kv, &alice("document", "doc1", "reader"), false);
    assert!(matches!(
        evaluate_access_request(kv.clone(), POLICY, &request("write")),
        Err(RecordError::UnknownRelation { .. })
    ));
    let mut other = request("reader");
    other.operations[0].object.resource = "missing".into();
    assert!(matches!(
        evaluate_access_request(kv.clone(), POLICY, &other),
        Err(RecordError::UnknownResource(_))
    ));
    assert!(!evaluate_access_request(kv, "missing-policy", &request("reader")).unwrap());
}

#[test]
fn corrupt_records_are_errors_in_point_and_list_reads() {
    let mut kv = InMemoryKvStore::default();
    let rel = alice("document", "doc1", "reader");
    seed(&mut kv, &rel, false);
    kv.put(&physical_key(&kv, &rel), b"{".to_vec());
    assert!(has(kv.clone(), &rel).is_err());
    assert!(subjects(kv.clone(), "doc1", "reader").is_err());
    kv.put(&keys::policy_key(POLICY), b"{".to_vec());
    assert!(read_policy(&kv, POLICY).is_err());
    assert!(evaluate_access_request(kv, POLICY, &request("reader")).is_err());
}

#[test]
fn generation_metadata_mismatch_is_an_error_in_point_and_prefix_reads() {
    let mut kv = InMemoryKvStore::default();
    let rel = alice("document", "doc1", "reader");
    seed(&mut kv, &rel, false);
    let key = physical_key(&kv, &rel);
    let mut record: RelationshipRecord = serde_json::from_slice(&kv.get(&key).unwrap()).unwrap();
    record.generations.subject = u64::MAX;
    kv.put(&key, serde_json::to_vec(&record).unwrap());
    assert!(has(kv.clone(), &rel).is_err());
    assert!(subjects(kv, "doc1", "reader").is_err());
}

#[test]
fn removed_and_readded_relations_do_not_resurrect_rows() {
    for resource in ["document", "collection"] {
        let mut kv = InMemoryKvStore::default();
        let rel = relationship(
            "document",
            "doc1",
            "reader",
            actor_set("collection", "col1", "reader"),
        );
        seed(&mut kv, &rel, false);
        let old_key = physical_key(&kv, &rel);
        edit_fixture(
            &mut kv,
            without_relation(fixture_policy(), resource, "reader"),
        );
        assert!(!has(kv.clone(), &rel).unwrap());
        edit_fixture(&mut kv, fixture_policy());
        assert!(kv.has(&old_key));
        assert!(!has(kv.clone(), &rel).unwrap());
        assert!(subjects(kv.clone(), "doc1", "reader").unwrap().is_empty());
        seed(&mut kv, &rel, false);
        assert_ne!(physical_key(&kv, &rel), old_key);
        assert!(has(kv, &rel).unwrap());
    }
}

#[test]
fn current_queries_skip_retired_usersets_with_a_small_read_budget() {
    use super::super::read_capture::{ReadCapture, ReadLimits, RecordRead};
    let mut kv = InMemoryKvStore::default();
    for index in 0..128 {
        seed(
            &mut kv,
            &relationship(
                "document",
                "doc1",
                "reader",
                actor_set("collection", index.to_string(), "reader"),
            ),
            false,
        );
    }
    let live = alice("document", "doc1", "reader");
    seed(&mut kv, &live, false);
    edit_fixture(
        &mut kv,
        without_relation(fixture_policy(), "collection", "reader"),
    );
    edit_fixture(&mut kv, fixture_policy());
    assert_eq!(
        kv.prefix_scan(&keys::relationship_policy_prefix(POLICY))
            .len(),
        129
    );
    let capture = ReadCapture::new(
        kv,
        ReadLimits {
            reads: 8,
            records: 8,
            bytes: 64 << 10,
        },
    );
    assert_eq!(
        subjects(capture.clone(), "doc1", "reader").unwrap(),
        vec![live.subject]
    );
    let requests = capture.requests().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|read| matches!(read, RecordRead::Prefix(_)))
            .count(),
        1
    );
    assert!(requests.contains(&RecordRead::Key(keys::policy_key(POLICY))));
}
