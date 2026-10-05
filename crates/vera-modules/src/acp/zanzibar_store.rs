//! A [`ZanzibarStore`] backed by vera's module KV store.

use std::{borrow::Cow, sync::RwLock};

use async_trait::async_trait;
use identity::Did;
use zanzibar::error::Result;
use zanzibar::{ObjectRef, Policy, Relationship, Subject, ZanzibarStore};

use super::record_store::RecordStore;
use super::types::{
    AccessRequest, PolicyMarshalingType, PolicyRecord, RecordMetadata, RelationGenerations,
    RelationPair, RelationshipRecord,
};
use super::{keys, relationship_index, relationship_mutations};
use crate::kv_store::InMemoryKvStore;
use crate::types::Timestamp;

/// Evaluate an access request from fallible policy and relationship records.
/// Missing data and incomplete proof coverage remain errors, including on the
/// subtracting side of an exclusion. Callers must provide one coherent snapshot
/// for the whole evaluation and authenticate proof-backed records.
pub fn evaluate_access_request<S: RecordStore>(
    store: S,
    policy_id: &str,
    request: &AccessRequest,
) -> Result<bool> {
    let Some(engine) = evaluation_engine(store, policy_id, None)? else {
        return Ok(false);
    };
    for operation in &request.operations {
        if !engine.check_blocking(
            policy_id,
            &operation.object.resource,
            &operation.object.id,
            &operation.permission,
            &request.actor.0,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn evaluation_engine<S: RecordStore>(
    store: S,
    policy_id: &str,
    meter: Option<std::sync::Arc<dyn zanzibar::engine::EvaluationMeter>>,
) -> Result<Option<zanzibar::PermissionEngine<QmdbZanzibarStore<S>>>> {
    let Some(record) = read_policy(&store, policy_id)? else {
        return Ok(None);
    };
    Ok(Some(evaluation_engine_for_policy(store, record, meter)))
}

pub(super) fn evaluation_engine_for_policy<S: RecordStore>(
    store: S,
    record: PolicyRecord,
    meter: Option<std::sync::Arc<dyn zanzibar::engine::EvaluationMeter>>,
) -> zanzibar::PermissionEngine<QmdbZanzibarStore<S>> {
    // This adapter never leaves the evaluation or receives mutations. The initial
    // policy point read remains part of captured and replayed proof evidence.
    let adapter = std::sync::Arc::new(QmdbZanzibarStore {
        store: RwLock::new(store),
        evaluation_policy: Some(record),
    });
    let mut engine = zanzibar::PermissionEngine::new(adapter.clone());
    engine.add_policy(
        &adapter
            .evaluation_policy
            .as_ref()
            .expect("evaluation policy was just installed")
            .policy,
    );
    if let Some(meter) = meter {
        engine = engine.with_evaluation_meter(meter);
    }
    engine
}

/// A [`ZanzibarStore`] adapter over vera's module KV store.
///
/// Selects current relationship generation buckets using authenticated policy
/// records and subject directories, so
/// [`zanzibar::PermissionEngine`] can evaluate permissions (including
/// `TupleToUserset`) directly over committed module state instead of a
/// divergent bespoke evaluator.
///
/// Relationship reads honor the `archived` flag: an archived record is treated
/// as absent, matching vera's access-check semantics.
#[derive(Debug, Default)]
pub struct QmdbZanzibarStore<S: RecordStore = InMemoryKvStore> {
    store: RwLock<S>,
    // Populated only for immutable evaluations; generic mutable adapters read fresh.
    evaluation_policy: Option<PolicyRecord>,
}

impl<S: RecordStore> QmdbZanzibarStore<S> {
    /// Wrap a module KV store.
    pub const fn new(store: S) -> Self {
        Self {
            store: RwLock::new(store),
            evaluation_policy: None,
        }
    }

    fn policy_record<'a>(
        &'a self,
        store: &S,
        policy_id: &str,
    ) -> Result<Option<Cow<'a, PolicyRecord>>> {
        if let Some(policy) = &self.evaluation_policy
            && policy.policy.id == policy_id
        {
            return Ok(Some(Cow::Borrowed(policy)));
        }
        Ok(read_policy(store, policy_id)?.map(Cow::Owned))
    }

    fn live_records(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<RelationshipRecord>> {
        let store = self.store.read().unwrap();
        let Some(policy) = self.policy_record(&*store, policy_id)? else {
            return Ok(vec![]);
        };
        let Some(target) = policy.relations.generation(resource, relation) else {
            return Ok(vec![]);
        };
        let suffix = keys::relation_prefix(resource, object_id, relation);
        let mut records = Vec::new();
        for subject in
            relationship_index::live_pairs(&*store, policy_id, target, &policy.relations)?
        {
            let pair = RelationPair { target, subject };
            let prefix = keys::relationship_generation_prefix(policy_id, pair, &suffix);
            for (key, bytes) in store.scan_records(&prefix)? {
                let record = decode_relationship(policy_id, pair, &key, &bytes)?;
                if policy.relations.pair(&record.relationship)? != pair {
                    return Err(invalid(
                        "relationship generations differ from current policy",
                    ));
                }
                if !record.archived {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    fn is_live(&self, policy_id: &str, rel: &Relationship) -> Result<bool> {
        let store = self.store.read().unwrap();
        let Some(policy) = self.policy_record(&*store, policy_id)? else {
            return Ok(false);
        };
        let Ok(pair) = policy.relations.pair(rel) else {
            return Ok(false);
        };
        let key = keys::relationship_generation_key(
            policy_id,
            pair,
            &keys::relationship_storage_key(rel),
        );
        let Some(bytes) = store.read_record(&key)? else {
            return Ok(false);
        };
        let record = decode_relationship(policy_id, pair, &key, &bytes)?;
        if record.relationship != *rel {
            return Err(invalid(
                "relationship record does not match the requested identity",
            ));
        }
        Ok(!record.archived)
    }
}

pub(super) fn read_policy<S: RecordStore>(
    store: &S,
    policy_id: &str,
) -> Result<Option<PolicyRecord>> {
    store
        .read_record(&keys::policy_key(policy_id))?
        .map(|bytes| {
            let record: PolicyRecord = serde_json::from_slice(&bytes)?;
            if record.policy.id != policy_id {
                return Err(invalid("policy record ID does not match its key"));
            }
            record.relations.validate(&record.policy)?;
            Ok(record)
        })
        .transpose()
}

fn decode_relationship(
    policy: &str,
    pair: RelationPair,
    key: &[u8],
    bytes: &[u8],
) -> Result<RelationshipRecord> {
    let record: RelationshipRecord = serde_json::from_slice(bytes)?;
    if record.policy_id != policy
        || record.generations != pair
        || keys::relationship_generation_key(
            policy,
            pair,
            &keys::relationship_storage_key(&record.relationship),
        ) != key
    {
        return Err(invalid(
            "relationship record does not match its key or generations",
        ));
    }
    Ok(record)
}

fn deleted_policy_key(policy: &str) -> Vec<u8> {
    [b"policy/adapter_deleted/".as_slice(), policy.as_bytes()].concat()
}

fn invalid(message: &str) -> zanzibar::error::Error {
    zanzibar::error::Error::Serialization(message.into())
}

fn default_metadata() -> RecordMetadata {
    RecordMetadata {
        creation_ts: Timestamp::default(),
        tx_hash: Vec::new(),
        tx_signer: String::new(),
        owner_did: String::new(),
    }
}

#[async_trait]
impl<S: RecordStore> ZanzibarStore for QmdbZanzibarStore<S> {
    async fn store_policy(&self, policy: &Policy) -> Result<()> {
        let mut store = self.store.write().unwrap();
        if store
            .read_record(&deleted_policy_key(&policy.id))?
            .is_some()
        {
            return Err(invalid(
                "deleted adapter policy identifiers cannot be reused",
            ));
        }
        if let Some(existing) = read_policy(&*store, &policy.id)? {
            if serde_json::to_vec(&existing.policy)? != serde_json::to_vec(policy)? {
                return Err(invalid(
                    "policy edits require generation retirement through AcpModule",
                ));
            }
            return Ok(());
        }
        let record = PolicyRecord {
            relations: RelationGenerations::new(policy)?,
            supplied_metadata: Default::default(),
            last_modified: None,
            policy: policy.clone(),
            raw_policy: String::new(),
            marshal_type: PolicyMarshalingType::ShortYaml,
            metadata: default_metadata(),
        };
        store.write_record(&keys::policy_key(&policy.id), serde_json::to_vec(&record)?)
    }

    async fn get_policy(&self, policy_id: &str) -> Result<Option<Policy>> {
        Ok(read_policy(&*self.store.read().unwrap(), policy_id)?.map(|record| record.policy))
    }

    async fn list_policies(&self) -> Result<Vec<Policy>> {
        self.store
            .read()
            .unwrap()
            .scan_records(keys::POLICY_PREFIX)?
            .into_iter()
            .map(|(key, bytes)| {
                let record: PolicyRecord = serde_json::from_slice(&bytes)?;
                if key != keys::policy_key(&record.policy.id) {
                    return Err(invalid("policy record ID does not match its key"));
                }
                record.relations.validate(&record.policy)?;
                Ok(record.policy)
            })
            .collect()
    }

    async fn next_policy_counter(&self) -> Result<u64> {
        let mut guard = self.store.write().unwrap();
        let counter = guard
            .read_record(keys::POLICY_COUNTER_KEY)?
            .map(|bytes| -> Result<u64> {
                let bytes: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                    zanzibar::error::Error::Serialization(
                        "policy counter must contain 8 bytes".into(),
                    )
                })?;
                Ok(u64::from_be_bytes(bytes))
            })
            .transpose()?
            .unwrap_or(0);
        let next = counter.checked_add(1).ok_or_else(|| {
            zanzibar::error::Error::Serialization("policy counter exhausted".into())
        })?;
        guard.write_record(keys::POLICY_COUNTER_KEY, next.to_be_bytes().to_vec())?;
        Ok(next)
    }

    async fn delete_policy(&self, policy_id: &str) -> Result<bool> {
        let mut store = self.store.write().unwrap();
        if read_policy(&*store, policy_id)?.is_none() {
            return Ok(false);
        }
        // This trait operation preserves complete physical deletion. Consensus policy
        // retirement is handled separately by AcpModule's bounded cleanup scheduler.
        let mut keys_to_delete = Vec::new();
        for (key, bytes) in store.scan_records(&keys::relationship_policy_prefix(policy_id))? {
            let record: RelationshipRecord = serde_json::from_slice(&bytes)?;
            decode_relationship(policy_id, record.generations, &key, &bytes)?;
            keys_to_delete.push(key);
        }
        let mut changes = relationship_mutations::prepare_removals(&*store, &keys_to_delete)?;
        let removed: std::collections::BTreeSet<&[u8]> = changes
            .iter()
            .filter_map(|(key, value)| value.is_none().then_some(key.as_slice()))
            .collect();
        for (key, _) in store.scan_records(&relationship_index::policy_prefix(policy_id))? {
            if key.starts_with(&super::relation_edits::retired_relation_prefix(policy_id)) {
                return Err(invalid(
                    "adapter policy deletion cannot remove scheduled ACP relation retirement",
                ));
            }
            if !removed.contains(key.as_slice()) {
                return Err(invalid("policy deletion would retain relationship indexes"));
            }
        }
        changes.push((keys::policy_key(policy_id), None));
        changes.push((deleted_policy_key(policy_id), Some(vec![])));
        store.apply_records(changes)?;
        Ok(true)
    }

    async fn store_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<()> {
        let mut store = self.store.write().unwrap();
        let policy = read_policy(&*store, policy_id)?
            .ok_or_else(|| invalid("relationship policy does not exist"))?;
        let pair = policy.relations.pair(rel)?;
        let record = RelationshipRecord {
            generations: pair,
            supplied_metadata: Default::default(),
            policy_id: policy_id.to_string(),
            relationship: rel.clone(),
            archived: false,
            metadata: default_metadata(),
        };
        let key = keys::relationship_generation_key(
            policy_id,
            pair,
            &keys::relationship_storage_key(rel),
        );
        if let Some(bytes) = store.read_record(&key)? {
            let existing = decode_relationship(policy_id, pair, &key, &bytes)?;
            if existing.relationship != *rel {
                return Err(invalid("relationship key collision"));
            }
        }
        relationship_mutations::put(&mut *store, &record)
    }

    async fn delete_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<bool> {
        let mut store = self.store.write().unwrap();
        let Some(policy) = read_policy(&*store, policy_id)? else {
            return Ok(false);
        };
        let Ok(pair) = policy.relations.pair(rel) else {
            return Ok(false);
        };
        let key = keys::relationship_generation_key(
            policy_id,
            pair,
            &keys::relationship_storage_key(rel),
        );
        if let Some(bytes) = store.read_record(&key)? {
            let record = decode_relationship(policy_id, pair, &key, &bytes)?;
            if record.relationship != *rel {
                return Err(invalid("relationship key collision"));
            }
            relationship_mutations::remove(&mut *store, &key)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn has_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Subject,
    ) -> Result<bool> {
        let rel = Relationship::new(resource, object_id, relation, subject.clone());
        self.is_live(policy_id, &rel)
    }

    async fn check_permission_direct(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Did,
    ) -> Result<bool> {
        let direct = Relationship::with_entity(resource, object_id, relation, subject.clone());
        if self.is_live(policy_id, &direct)? {
            return Ok(true);
        }
        let wildcard = Relationship::new(resource, object_id, relation, Subject::Wildcard);
        if self.is_live(policy_id, &wildcard)? {
            return Ok(true);
        }
        // Any typed wildcard on this object#relation grants every subject.
        Ok(self
            .live_records(policy_id, resource, object_id, relation)?
            .iter()
            .any(|rec| rec.relationship.subject.is_typed_wildcard()))
    }

    async fn get_relation_subjects(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<Subject>> {
        Ok(self
            .live_records(policy_id, resource, object_id, relation)?
            .into_iter()
            .map(|rec| rec.relationship.subject)
            .collect())
    }

    async fn get_relation_targets(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<ObjectRef>> {
        Ok(self
            .live_records(policy_id, resource, object_id, relation)?
            .into_iter()
            .filter_map(|rec| match rec.relationship.subject {
                Subject::EntitySet {
                    resource,
                    object_id,
                    ..
                } => Some(ObjectRef::new(resource, object_id)),
                _ => None,
            })
            .collect())
    }

    async fn delete_object_relationships(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> Result<()> {
        let mut store = self.store.write().unwrap();
        let Some(policy) = read_policy(&*store, policy_id)? else {
            return Ok(());
        };
        let Some(definition) = policy.policy.get_resource(resource) else {
            return Ok(());
        };
        let suffix = keys::object_prefix(resource, object_id);
        let mut keys_to_delete = Vec::new();
        for relation in &definition.relations {
            let target = policy
                .relations
                .generation(resource, &relation.name)
                .ok_or_else(|| invalid("policy relation generation missing"))?;
            for subject in
                relationship_index::live_pairs(&*store, policy_id, target, &policy.relations)?
            {
                let pair = RelationPair { target, subject };
                let prefix = keys::relationship_generation_prefix(policy_id, pair, &suffix);
                for (key, bytes) in store.scan_records(&prefix)? {
                    let record = decode_relationship(policy_id, pair, &key, &bytes)?;
                    if policy.relations.pair(&record.relationship)? != pair {
                        return Err(invalid(
                            "relationship generations differ from current policy",
                        ));
                    }
                    keys_to_delete.push(key);
                }
            }
        }
        let changes = relationship_mutations::prepare_removals(&*store, &keys_to_delete)?;
        if changes.is_empty() {
            return Ok(());
        }
        store.apply_records(changes)
    }
}

#[cfg(test)]
mod tests {
    mod evaluation;

    use std::sync::Arc;

    use futures::executor::block_on;
    use zanzibar::{PermissionEngine, Relation, RelationExpression, Resource};

    use super::*;
    use crate::kv_store::ModuleKvStore;

    const POLICY: &str = "policy-1";

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid did")
    }

    fn fixture_policy() -> Policy {
        Policy::new(POLICY, "adapter")
            .with_resource(
                Resource::new("document")
                    .with_relation(Relation::direct("owner"))
                    .with_relation(Relation::direct("reader"))
                    .with_relation(Relation::direct("parent"))
                    .with_relation(Relation::direct("blocked"))
                    .with_relation(Relation::direct("a"))
                    .with_relation(Relation::direct("z")),
            )
            .with_resource(
                Resource::new("collection")
                    .with_relation(Relation::direct("owner"))
                    .with_relation(Relation::direct("reader"))
                    .with_relation(Relation::direct("blocked")),
            )
            .with_resource(
                Resource::new("folder")
                    .with_relation(Relation::direct("owner"))
                    .with_relation(Relation::direct("reader")),
            )
    }

    fn adapter() -> QmdbZanzibarStore {
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
        block_on(store.store_policy(&fixture_policy())).unwrap();
        store
    }

    fn seed_policy(store: &mut InMemoryKvStore, policy: Policy) {
        let record = PolicyRecord {
            relations: RelationGenerations::new(&policy).unwrap(),
            policy,
            supplied_metadata: Default::default(),
            last_modified: None,
            raw_policy: String::new(),
            marshal_type: PolicyMarshalingType::ShortYaml,
            metadata: default_metadata(),
        };
        store.put(
            &keys::policy_key(&record.policy.id),
            serde_json::to_vec(&record).unwrap(),
        );
    }

    fn physical_key(store: &InMemoryKvStore, rel: &Relationship) -> Vec<u8> {
        let policy = read_policy(store, POLICY).unwrap().unwrap();
        keys::relationship_generation_key(
            POLICY,
            policy.relations.pair(rel).unwrap(),
            &keys::relationship_storage_key(rel),
        )
    }

    /// Populate rows through the indexed writer, including archived relationships.
    fn seed(store: &mut InMemoryKvStore, rel: &Relationship, archived: bool) {
        if !store.has(&keys::policy_key(POLICY)) {
            seed_policy(store, fixture_policy());
        }
        let policy = read_policy(store, POLICY).unwrap().unwrap();
        let record = RelationshipRecord {
            generations: policy.relations.pair(rel).unwrap(),
            supplied_metadata: Default::default(),
            policy_id: POLICY.to_string(),
            relationship: rel.clone(),
            archived,
            metadata: default_metadata(),
        };
        relationship_mutations::put(store, &record).unwrap();
    }

    #[test]
    fn relationship_keys_isolate_adapter_path_fields() {
        let store = adapter();
        let original = Relationship::with_entity("document", "parent/path", "reader", did(ALICE));
        let collision = Relationship::with_entity("document", "parent", "path/reader", did(ALICE));
        assert_eq!(original.storage_key(), collision.storage_key());
        block_on(store.store_relationship(POLICY, &original)).unwrap();
        let before = store.store.read().unwrap().serialize();
        assert!(block_on(store.store_relationship(POLICY, &collision)).is_err());
        assert!(!block_on(store.delete_relationship(POLICY, &collision)).unwrap());
        assert_eq!(store.store.read().unwrap().serialize(), before);
        assert!(
            block_on(store.has_relationship(
                POLICY,
                "document",
                "parent/path",
                "reader",
                &original.subject
            ))
            .unwrap()
        );
    }

    #[test]
    fn permission_identity_excludes_path_descendants() {
        let store = adapter();
        for subject in [
            Subject::typed_wildcard("document"),
            Subject::entity_set("folder", "shared", "reader"),
            Subject::entity(did(ALICE)),
        ] {
            block_on(store.store_relationship(
                POLICY,
                &Relationship::new("document", "doc/reader/child", "reader", subject),
            ))
            .unwrap();
        }
        assert!(
            !block_on(store.check_permission_direct(
                POLICY,
                "document",
                "doc",
                "reader",
                &did(ALICE),
            ))
            .unwrap()
        );
        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc", "reader"))
                .unwrap()
                .is_empty()
        );
        assert!(
            block_on(store.get_relation_targets(POLICY, "document", "doc", "reader"))
                .unwrap()
                .is_empty()
        );
        let own = Relationship::with_entity("document", "doc", "reader", did(ALICE));
        block_on(store.store_relationship(POLICY, &own)).unwrap();
        assert!(
            block_on(store.check_permission_direct(
                POLICY,
                "document",
                "doc",
                "reader",
                &did(ALICE)
            ))
            .unwrap()
        );
        assert_eq!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc", "reader")).unwrap(),
            vec![own.subject]
        );
    }

    #[test]
    fn permission_identity_rejects_mismatched_record_keys() {
        let mut kv = InMemoryKvStore::default();
        let stored = Relationship::with_entity("document", "other", "reader", did(ALICE));
        let requested = Relationship::with_entity("document", "doc", "reader", did(ALICE));
        seed(&mut kv, &stored, false);
        let bytes = kv.get(&physical_key(&kv, &stored)).unwrap();
        kv.put(&physical_key(&kv, &requested), bytes);
        let store = QmdbZanzibarStore::new(kv);
        assert!(
            block_on(store.has_relationship(
                POLICY,
                "document",
                "doc",
                "reader",
                &requested.subject
            ))
            .is_err()
        );
        assert!(
            block_on(store.check_permission_direct(
                POLICY,
                "document",
                "doc",
                "reader",
                &did(ALICE)
            ))
            .is_err()
        );
        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc", "reader")).is_err()
        );
        assert!(block_on(store.get_relation_targets(POLICY, "document", "doc", "reader")).is_err());
    }

    #[test]
    fn get_relation_subjects_returns_live_subjects_for_object_relation() {
        let mut kv = InMemoryKvStore::default();
        let entity = Relationship::with_entity(
            "document",
            "doc1",
            "reader",
            did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        );
        let parent = Relationship::new(
            "document",
            "doc1",
            "reader",
            Subject::entity_set("collection", "col1", "reader"),
        );
        // Unrelated: same relation on a different object must not leak in.
        let other = Relationship::with_entity(
            "document",
            "doc2",
            "reader",
            did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        );
        seed(&mut kv, &entity, false);
        seed(&mut kv, &parent, false);
        seed(&mut kv, &other, false);

        let store = QmdbZanzibarStore::new(kv);
        let subjects =
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader")).unwrap();

        assert_eq!(
            subjects.len(),
            2,
            "should return both subjects on doc1#reader"
        );
        assert!(subjects.contains(&entity.subject));
        assert!(subjects.contains(&parent.subject));
    }

    #[test]
    fn get_relation_subjects_excludes_archived() {
        let mut kv = InMemoryKvStore::default();
        let live = Relationship::with_entity(
            "document",
            "doc1",
            "reader",
            did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        );
        let archived = Relationship::new(
            "document",
            "doc1",
            "reader",
            Subject::entity_set("collection", "col1", "reader"),
        );
        seed(&mut kv, &live, false);
        seed(&mut kv, &archived, true);

        let store = QmdbZanzibarStore::new(kv);
        let subjects =
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader")).unwrap();

        assert_eq!(subjects, vec![live.subject]);
    }

    #[test]
    fn get_relation_targets_returns_entityset_objectrefs_only() {
        let mut kv = InMemoryKvStore::default();
        let entity = Relationship::with_entity(
            "document",
            "doc1",
            "parent",
            did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        );
        let parent = Relationship::new(
            "document",
            "doc1",
            "parent",
            Subject::entity_set("collection", "col1", "reader"),
        );
        seed(&mut kv, &entity, false);
        seed(&mut kv, &parent, false);

        let store = QmdbZanzibarStore::new(kv);
        let targets =
            block_on(store.get_relation_targets(POLICY, "document", "doc1", "parent")).unwrap();

        assert_eq!(targets, vec![ObjectRef::new("collection", "col1")]);
    }

    const ALICE: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    #[test]
    fn check_permission_direct_matches_entity_grant() {
        let mut kv = InMemoryKvStore::default();
        seed(
            &mut kv,
            &Relationship::with_entity("document", "doc1", "reader", did(ALICE)),
            false,
        );
        let store = QmdbZanzibarStore::new(kv);

        assert!(
            block_on(store.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "reader",
                &did(ALICE)
            ))
            .unwrap()
        );
        assert!(
            !block_on(store.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "writer",
                &did(ALICE)
            ))
            .unwrap(),
            "different relation must not match"
        );
    }

    #[test]
    fn check_permission_direct_matches_wildcard_and_typed_wildcard() {
        let mut wild = InMemoryKvStore::default();
        seed(
            &mut wild,
            &Relationship::new("document", "doc1", "reader", Subject::Wildcard),
            false,
        );
        let wstore = QmdbZanzibarStore::new(wild);
        assert!(
            block_on(wstore.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "reader",
                &did(ALICE)
            ))
            .unwrap(),
            "public wildcard grants everyone"
        );

        let mut typed = InMemoryKvStore::default();
        seed(
            &mut typed,
            &Relationship::new(
                "document",
                "doc1",
                "reader",
                Subject::typed_wildcard("document"),
            ),
            false,
        );
        let tstore = QmdbZanzibarStore::new(typed);
        assert!(
            block_on(tstore.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "reader",
                &did(ALICE)
            ))
            .unwrap(),
            "typed wildcard grants everyone"
        );
    }

    #[test]
    fn check_permission_direct_ignores_archived_grant() {
        let mut kv = InMemoryKvStore::default();
        seed(
            &mut kv,
            &Relationship::with_entity("document", "doc1", "reader", did(ALICE)),
            true,
        );
        let store = QmdbZanzibarStore::new(kv);

        assert!(
            !block_on(store.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "reader",
                &did(ALICE)
            ))
            .unwrap(),
            "archived grant must not authorize"
        );
    }

    #[test]
    fn has_relationship_reflects_presence_and_archival() {
        let mut kv = InMemoryKvStore::default();
        let live = Relationship::with_entity("document", "doc1", "reader", did(ALICE));
        let arch = Relationship::new(
            "document",
            "doc1",
            "reader",
            Subject::entity_set("collection", "col1", "reader"),
        );
        seed(&mut kv, &live, false);
        seed(&mut kv, &arch, true);
        let store = QmdbZanzibarStore::new(kv);

        assert!(
            block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &live.subject))
                .unwrap()
        );
        assert!(
            !block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &arch.subject))
                .unwrap(),
            "archived relationship reads as absent"
        );
        assert!(
            !block_on(store.has_relationship(
                POLICY,
                "document",
                "doc1",
                "reader",
                &Subject::Wildcard
            ))
            .unwrap(),
            "never-seeded subject reads as absent"
        );
    }

    #[test]
    fn policy_round_trips() {
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
        let policy = Policy::new("pol-x", "test");

        block_on(store.store_policy(&policy)).unwrap();

        let got = block_on(store.get_policy("pol-x"))
            .unwrap()
            .expect("present");
        assert_eq!(got.id, "pol-x");
        assert!(block_on(store.get_policy("missing")).unwrap().is_none());

        let listed = block_on(store.list_policies()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "pol-x");
    }

    #[test]
    fn delete_policy_removes_policy_and_its_relationships() {
        let store = adapter();
        block_on(store.store_relationship(
            POLICY,
            &Relationship::with_entity("document", "doc1", "reader", did(ALICE)),
        ))
        .unwrap();

        assert!(block_on(store.delete_policy(POLICY)).unwrap());
        assert!(block_on(store.get_policy(POLICY)).unwrap().is_none());
        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader"))
                .unwrap()
                .is_empty(),
            "relationships must be removed with the policy"
        );
        assert!(
            !block_on(store.delete_policy(POLICY)).unwrap(),
            "deleting an absent policy returns false"
        );
    }

    #[test]
    fn store_and_delete_relationship_round_trip() {
        let store = adapter();
        let rel = Relationship::with_entity("document", "doc1", "reader", did(ALICE));

        block_on(store.store_relationship(POLICY, &rel)).unwrap();
        assert!(
            block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &rel.subject))
                .unwrap()
        );

        assert!(block_on(store.delete_relationship(POLICY, &rel)).unwrap());
        assert!(
            !block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &rel.subject))
                .unwrap()
        );
        assert!(
            !block_on(store.delete_relationship(POLICY, &rel)).unwrap(),
            "deleting an absent relationship returns false"
        );
    }

    #[test]
    fn relationship_mutations_preserve_corrupt_records_and_prevalidate_bulk_removal() {
        let store = adapter();
        let first = Relationship::with_entity("document", "doc1", "a", did(ALICE));
        let last = Relationship::with_entity("document", "doc1", "z", did(ALICE));
        for relationship in [&first, &last] {
            block_on(store.store_relationship(POLICY, relationship)).unwrap();
        }
        let key = physical_key(&store.store.read().unwrap(), &last);
        store.store.write().unwrap().put(&key, b"{".to_vec());
        let before = store.store.read().unwrap().serialize();
        assert!(block_on(store.store_relationship(POLICY, &last)).is_err());
        assert_eq!(store.store.read().unwrap().serialize(), before);
        assert!(block_on(store.delete_relationship(POLICY, &last)).is_err());
        assert_eq!(store.store.read().unwrap().serialize(), before);
        assert!(block_on(store.delete_object_relationships(POLICY, "document", "doc1")).is_err());
        assert_eq!(store.store.read().unwrap().serialize(), before);
    }

    #[test]
    fn delete_object_relationships_clears_only_that_object() {
        let store = adapter();
        block_on(store.store_relationship(
            POLICY,
            &Relationship::with_entity("document", "doc1", "reader", did(ALICE)),
        ))
        .unwrap();
        block_on(store.store_relationship(
            POLICY,
            &Relationship::with_entity("document", "doc1", "owner", did(ALICE)),
        ))
        .unwrap();
        let keep = Relationship::with_entity("document", "doc1/child", "reader", did(ALICE));
        block_on(store.store_relationship(POLICY, &keep)).unwrap();

        block_on(store.delete_object_relationships(POLICY, "document", "doc1")).unwrap();

        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader"))
                .unwrap()
                .is_empty()
        );
        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "owner"))
                .unwrap()
                .is_empty()
        );
        assert!(
            block_on(store.has_relationship(
                POLICY,
                "document",
                "doc1/child",
                "reader",
                &keep.subject
            ))
            .unwrap(),
            "other objects are untouched"
        );
    }

    /// A policy where `document#read` inherits from `reader` on the document's
    /// parent collection: `read = parent->reader` (a cross-object TupleToUserset).
    fn ttu_policy(id: &str) -> Policy {
        Policy::new(id, "ttu")
            .with_resource(
                Resource::new("collection")
                    .with_relation(Relation::direct("owner"))
                    .with_relation(Relation::direct("reader")),
            )
            .with_resource(
                Resource::new("document")
                    .with_relation(Relation::direct("owner"))
                    .with_relation(Relation::direct("parent"))
                    .with_relation(Relation::computed(
                        "read",
                        RelationExpression::tuple_to_userset("parent", "reader"),
                    )),
            )
    }

    #[test]
    fn engine_resolves_cross_object_tuple_to_userset() {
        let store = Arc::new(QmdbZanzibarStore::<InMemoryKvStore>::default());
        let pid = "ttu-policy";
        block_on(store.store_policy(&ttu_policy(pid))).unwrap();

        // Parent edge: doc1's parent is collection col1.
        block_on(store.store_relationship(
            pid,
            &Relationship::new(
                "document",
                "doc1",
                "parent",
                Subject::entity_set("collection", "col1", "reader"),
            ),
        ))
        .unwrap();
        // Grant on the parent: alice is a reader of col1.
        block_on(store.store_relationship(
            pid,
            &Relationship::with_entity("collection", "col1", "reader", did(ALICE)),
        ))
        .unwrap();

        let mut engine = PermissionEngine::new(store);
        engine.add_policy(&ttu_policy(pid));

        assert!(
            block_on(engine.check(pid, "document", "doc1", "read", &did(ALICE))).unwrap(),
            "alice inherits read on doc1 via reader on its parent collection"
        );
        assert!(
            !block_on(engine.check(pid, "document", "doc2", "read", &did(ALICE))).unwrap(),
            "doc2 has no parent edge, so nothing is inherited (fail closed)"
        );
    }

    #[test]
    fn engine_check_errors_on_unknown_policy_or_relation() {
        let store = Arc::new(QmdbZanzibarStore::<InMemoryKvStore>::default());
        let pid = "ttu-policy";
        block_on(store.store_policy(&ttu_policy(pid))).unwrap();
        let mut engine = PermissionEngine::new(store);
        engine.add_policy(&ttu_policy(pid));

        // Unknown policy and unknown relation both error — never silently allow.
        let unknown_policy =
            block_on(engine.check("nope", "document", "doc1", "read", &did(ALICE)));
        assert!(unknown_policy.is_err(), "unknown policy must error");
        assert!(
            !unknown_policy.unwrap_or(false),
            "error maps to deny, not allow"
        );

        let unknown_relation =
            block_on(engine.check(pid, "document", "doc1", "write", &did(ALICE)));
        assert!(unknown_relation.is_err(), "unknown relation must error");
        assert!(!unknown_relation.unwrap_or(false), "error maps to deny");
    }

    #[test]
    fn corrupt_exclusion_records_cannot_grant_access() {
        for subject in [
            Subject::Entity(did(ALICE)),
            Subject::Wildcard,
            Subject::typed_wildcard("document"),
            Subject::entity_set("collection", "col1", "blocked"),
        ] {
            let excluded = if matches!(subject, Subject::EntitySet { .. }) {
                RelationExpression::tuple_to_userset("blocked", "blocked")
            } else {
                RelationExpression::computed_userset("blocked")
            };
            let policy = Policy::new(POLICY, "exclusion")
                .with_resource(
                    Resource::new("collection")
                        .with_relation(Relation::direct("owner"))
                        .with_relation(Relation::direct("blocked")),
                )
                .with_resource(
                    Resource::new("document")
                        .with_relation(Relation::direct("owner"))
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
            let mut kv = InMemoryKvStore::default();
            seed_policy(&mut kv, policy.clone());
            let reader = Relationship::with_entity("document", "doc1", "reader", did(ALICE));
            let blocked = Relationship::new("document", "doc1", "blocked", subject.clone());
            seed(&mut kv, &reader, false);
            seed(&mut kv, &blocked, false);
            seed(
                &mut kv,
                &Relationship::with_entity("collection", "col1", "blocked", did(ALICE)),
                false,
            );
            let mut engine = PermissionEngine::new(Arc::new(QmdbZanzibarStore::new(kv.clone())));
            engine.add_policy(&policy);
            assert!(
                !engine
                    .check_blocking(POLICY, "document", "doc1", "read", &did(ALICE))
                    .unwrap()
            );

            kv.put(&physical_key(&kv, &blocked), b"{".to_vec());
            let mut engine = PermissionEngine::new(Arc::new(QmdbZanzibarStore::new(kv)));
            engine.add_policy(&policy);
            let result = engine.check_blocking(POLICY, "document", "doc1", "read", &did(ALICE));
            assert!(
                result.is_err(),
                "corrupt {subject:?} exclusion must fail: {result:?}"
            );
        }
    }

    #[test]
    fn corrupt_records_are_errors_in_point_and_list_reads() {
        let mut kv = InMemoryKvStore::default();
        let rel = Relationship::with_entity("document", "doc1", "reader", did(ALICE));
        seed_policy(&mut kv, fixture_policy());
        kv.put(&physical_key(&kv, &rel), b"{".to_vec());
        kv.put(&keys::policy_key(POLICY), b"{".to_vec());
        let store = QmdbZanzibarStore::new(kv);
        assert!(block_on(store.get_policy(POLICY)).is_err());
        assert!(block_on(store.list_policies()).is_err());
        assert!(
            block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &rel.subject))
                .is_err()
        );
        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader")).is_err()
        );
        assert!(
            block_on(store.get_relation_targets(POLICY, "document", "doc1", "reader")).is_err()
        );
    }
    // Install the same policy/directory transition as a committed edit, retaining
    // physical rows and counts so adapter reads cannot rely on eager deletion.
    fn edit_fixture(store: &mut InMemoryKvStore, next_policy: Policy) {
        let mut record = read_policy(store, POLICY).unwrap().unwrap();
        let (relations, _) = record
            .relations
            .updated(&record.policy, &next_policy)
            .unwrap();
        for target in record.relations.active_ids() {
            let mut subjects =
                relationship_index::live_pairs(store, POLICY, target, &record.relations).unwrap();
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

    fn without_relation(mut policy: Policy, resource: &str, relation: &str) -> Policy {
        policy
            .resources
            .iter_mut()
            .find(|item| item.name == resource)
            .unwrap()
            .relations
            .retain(|item| item.name != relation);
        policy
    }

    #[test]
    fn removed_and_readded_source_or_userset_relations_do_not_resurrect_rows() {
        for resource in ["document", "collection"] {
            let store = adapter();
            let rel = Relationship::new(
                "document",
                "doc1",
                "reader",
                Subject::entity_set("collection", "col1", "reader"),
            );
            block_on(store.store_relationship(POLICY, &rel)).unwrap();
            let old_key = physical_key(&store.store.read().unwrap(), &rel);
            {
                let mut kv = store.store.write().unwrap();
                edit_fixture(
                    &mut kv,
                    without_relation(fixture_policy(), resource, "reader"),
                );
            }
            assert!(
                !block_on(store.has_relationship(
                    POLICY,
                    "document",
                    "doc1",
                    "reader",
                    &rel.subject
                ))
                .unwrap()
            );
            assert!(
                block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader"))
                    .unwrap()
                    .is_empty()
            );
            edit_fixture(&mut store.store.write().unwrap(), fixture_policy());
            assert!(store.store.read().unwrap().has(&old_key));
            assert!(
                !block_on(store.has_relationship(
                    POLICY,
                    "document",
                    "doc1",
                    "reader",
                    &rel.subject
                ))
                .unwrap()
            );
            assert!(
                block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader"))
                    .unwrap()
                    .is_empty()
            );
            assert!(!block_on(store.delete_relationship(POLICY, &rel)).unwrap());
            block_on(store.store_relationship(POLICY, &rel)).unwrap();
            let new_key = physical_key(&store.store.read().unwrap(), &rel);
            assert_ne!(new_key, old_key);
            assert!(
                block_on(store.has_relationship(
                    POLICY,
                    "document",
                    "doc1",
                    "reader",
                    &rel.subject
                ))
                .unwrap()
            );
            block_on(store.delete_object_relationships(POLICY, "document", "doc1")).unwrap();
            let kv = store.store.read().unwrap();
            assert!(kv.has(&old_key));
            assert!(!kv.has(&new_key));
        }
    }

    #[test]
    fn current_queries_skip_retired_usersets_with_a_small_read_budget() {
        use super::super::read_capture::{ReadCapture, ReadLimits, RecordRead};
        let mut kv = InMemoryKvStore::default();
        for index in 0..128 {
            seed(
                &mut kv,
                &Relationship::new(
                    "document",
                    "doc1",
                    "reader",
                    Subject::entity_set("collection", index.to_string(), "reader"),
                ),
                false,
            );
        }
        let live = Relationship::with_entity("document", "doc1", "reader", did(ALICE));
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
        let store = QmdbZanzibarStore::new(capture.clone());
        assert_eq!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader")).unwrap(),
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

    #[test]
    fn generation_metadata_mismatch_is_an_error_in_point_and_prefix_reads() {
        let store = adapter();
        let rel = Relationship::with_entity("document", "doc1", "reader", did(ALICE));
        block_on(store.store_relationship(POLICY, &rel)).unwrap();
        let mut kv = store.store.write().unwrap();
        let key = physical_key(&kv, &rel);
        let mut record: RelationshipRecord =
            serde_json::from_slice(&kv.get(&key).unwrap()).unwrap();
        record.generations.subject = u64::MAX;
        kv.put(&key, serde_json::to_vec(&record).unwrap());
        drop(kv);
        assert!(
            block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &rel.subject))
                .is_err()
        );
        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader")).is_err()
        );
    }

    #[test]
    fn adapter_policy_rewrites_preserve_metadata_and_deletion_prevents_id_reuse() {
        let store = adapter();
        let rel = Relationship::with_entity("document", "doc1", "reader", did(ALICE));
        block_on(store.store_relationship(POLICY, &rel)).unwrap();
        let before = store.store.read().unwrap().serialize();
        block_on(store.store_policy(&fixture_policy())).unwrap();
        assert_eq!(store.store.read().unwrap().serialize(), before);
        assert!(
            block_on(store.store_policy(&without_relation(fixture_policy(), "document", "reader")))
                .is_err()
        );
        assert_eq!(store.store.read().unwrap().serialize(), before);
        edit_fixture(
            &mut store.store.write().unwrap(),
            without_relation(fixture_policy(), "document", "reader"),
        );
        assert!(block_on(store.delete_policy(POLICY)).unwrap());
        let kv = store.store.read().unwrap();
        assert!(
            kv.prefix_scan(&keys::relationship_policy_prefix(POLICY))
                .is_empty()
        );
        assert!(
            kv.prefix_scan(&relationship_index::policy_prefix(POLICY))
                .is_empty()
        );
        assert!(kv.has(&deleted_policy_key(POLICY)));
        drop(kv);
        let deleted = store.store.read().unwrap().serialize();
        assert!(block_on(store.store_policy(&fixture_policy())).is_err());
        assert_eq!(store.store.read().unwrap().serialize(), deleted);
    }

    #[derive(Debug)]
    struct ReadOnlyStore(InMemoryKvStore);

    impl RecordStore for ReadOnlyStore {
        fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self.0.get(key))
        }
        fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            Ok(self.0.prefix_scan(prefix))
        }
    }

    #[test]
    fn generic_store_bulk_removals_require_atomic_apply() {
        let mut kv = InMemoryKvStore::default();
        for relation in ["reader", "parent"] {
            seed(
                &mut kv,
                &Relationship::with_entity("document", "doc1", relation, did(ALICE)),
                false,
            );
        }
        let before = kv.serialize();
        let store = QmdbZanzibarStore::new(ReadOnlyStore(kv));
        assert!(block_on(store.delete_object_relationships(POLICY, "document", "doc1")).is_err());
        assert_eq!(store.store.read().unwrap().0.serialize(), before);
        assert!(block_on(store.delete_policy(POLICY)).is_err());
        assert_eq!(store.store.read().unwrap().0.serialize(), before);
    }
    #[test]
    fn adapter_policy_deletion_rejects_incomplete_pair_counts_before_writing() {
        let store = adapter();
        let rel = Relationship::with_entity("document", "doc1", "reader", did(ALICE));
        block_on(store.store_relationship(POLICY, &rel)).unwrap();
        let mut kv = store.store.write().unwrap();
        let pair = read_policy(&*kv, POLICY)
            .unwrap()
            .unwrap()
            .relations
            .pair(&rel)
            .unwrap();
        for key in [
            relationship_index::outgoing_key(POLICY, pair),
            relationship_index::incoming_key(POLICY, pair),
        ] {
            kv.put(&key, 2u64.to_be_bytes().to_vec());
        }
        let before = kv.serialize();
        drop(kv);
        assert!(block_on(store.delete_policy(POLICY)).is_err());
        assert_eq!(store.store.read().unwrap().serialize(), before);
    }

    #[test]
    fn adapter_policy_deletion_preserves_scheduled_consensus_retirement() {
        use super::super::{
            AcpModule,
            types::{Object, PolicyCmd},
        };
        let creator = did(ALICE);
        let schema =
            "name: sample\nresources:\n  - name: document\n    relations:\n      - name: reader\n";
        let mut module = AcpModule::new();
        let policy = module
            .create_policy(&creator, schema, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        module
            .direct_policy_cmd(
                &creator,
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: "document".into(),
                    id: "report".into(),
                }),
            )
            .unwrap();
        module
            .direct_policy_cmd(
                &creator,
                &policy,
                PolicyCmd::SetRelationship(Relationship::with_entity(
                    "document",
                    "report",
                    "reader",
                    creator.clone(),
                )),
            )
            .unwrap();
        module
            .edit_policy(
                &creator,
                &policy,
                "name: sample\nresources:\n  - name: document\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap();
        let store = QmdbZanzibarStore::new(module.store().clone());
        let before = store.store.read().unwrap().serialize();
        let error = block_on(store.delete_policy(&policy)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("scheduled ACP relation retirement")
        );
        assert_eq!(store.store.read().unwrap().serialize(), before);
    }
}
