//! A [`ZanzibarStore`] backed by vera's module KV store.

use std::sync::RwLock;

use async_trait::async_trait;
use identity::Did;
use zanzibar::error::Result;
use zanzibar::{ObjectRef, Policy, Relationship, Subject, ZanzibarStore};

use super::keys;
use super::record_store::RecordStore;
use super::types::{
    AccessRequest, PolicyMarshalingType, PolicyRecord, RecordMetadata, RelationshipRecord,
};
use crate::kv_store::InMemoryKvStore;
use crate::types::Timestamp;

/// Evaluate an access request from fallible policy and relationship records.
/// Missing data and incomplete proof coverage remain errors, including on the
/// subtracting side of an exclusion. Callers must authenticate proof-backed records.
pub fn evaluate_access_request<S: RecordStore>(
    store: S,
    policy_id: &str,
    request: &AccessRequest,
) -> Result<bool> {
    let Some(bytes) = store.read_record(&keys::policy_key(policy_id))? else {
        return Ok(false);
    };
    let record: PolicyRecord = serde_json::from_slice(&bytes)?;
    if record.policy.id != policy_id {
        return Err(zanzibar::error::Error::InvalidPolicy(
            "policy record ID does not match its key".into(),
        ));
    }
    let mut engine =
        zanzibar::PermissionEngine::new(std::sync::Arc::new(QmdbZanzibarStore::new(store)));
    engine.add_policy(&record.policy);
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

/// A [`ZanzibarStore`] adapter over vera's module KV store.
///
/// Maps the zanzibar engine's storage interface onto vera's existing
/// `relationship/v3/{policy_id}/{storage_key}` and `policy/objs/{id}` keyspace, so
/// [`zanzibar::PermissionEngine`] can evaluate permissions (including
/// `TupleToUserset`) directly over committed module state instead of a
/// divergent bespoke evaluator.
///
/// Relationship reads honor the `archived` flag: an archived record is treated
/// as absent, matching vera's access-check semantics.
#[derive(Debug, Default)]
pub struct QmdbZanzibarStore<S: RecordStore = InMemoryKvStore> {
    store: RwLock<S>,
}

impl<S: RecordStore> QmdbZanzibarStore<S> {
    /// Wrap a module KV store.
    pub const fn new(store: S) -> Self {
        Self {
            store: RwLock::new(store),
        }
    }

    fn live_records(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<RelationshipRecord>> {
        let scan = keys::relationship_storage_prefix(
            policy_id,
            &keys::relation_prefix(resource, object_id, relation),
        );
        let mut records = Vec::new();
        for (key, bytes) in self.store.read().unwrap().scan_records(&scan)? {
            let record: RelationshipRecord = serde_json::from_slice(&bytes)?;
            if record.policy_id != policy_id
                || keys::relationship_key(
                    policy_id,
                    &keys::relationship_storage_key(&record.relationship),
                ) != key
            {
                return Err(zanzibar::error::Error::Serialization(
                    "relationship record does not match its key".into(),
                ));
            }
            if !record.archived
                && record.relationship.resource == resource
                && record.relationship.object_id == object_id
                && record.relationship.relation == relation
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    fn is_live(&self, policy_id: &str, rel: &Relationship) -> Result<bool> {
        let Some(bytes) = self
            .store
            .read()
            .unwrap()
            .read_record(&keys::relationship_key(
                policy_id,
                &keys::relationship_storage_key(rel),
            ))?
        else {
            return Ok(false);
        };
        let record: RelationshipRecord = serde_json::from_slice(&bytes)?;
        if record.policy_id != policy_id || record.relationship != *rel {
            return Err(zanzibar::error::Error::Serialization(
                "relationship record does not match the requested identity".into(),
            ));
        }
        Ok(!record.archived)
    }
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
        let record = PolicyRecord {
            supplied_metadata: Default::default(),
            last_modified: None,
            policy: policy.clone(),
            raw_policy: String::new(),
            marshal_type: PolicyMarshalingType::ShortYaml,
            metadata: default_metadata(),
        };
        let bytes = serde_json::to_vec(&record).expect("serialize PolicyRecord");
        self.store
            .write()
            .unwrap()
            .write_record(&keys::policy_key(&policy.id), bytes)?;
        Ok(())
    }

    async fn get_policy(&self, policy_id: &str) -> Result<Option<Policy>> {
        Ok(self
            .store
            .read()
            .unwrap()
            .read_record(&keys::policy_key(policy_id))?
            .map(|bytes| serde_json::from_slice::<PolicyRecord>(&bytes))
            .transpose()?
            .map(|record| record.policy))
    }

    async fn list_policies(&self) -> Result<Vec<Policy>> {
        self.store
            .read()
            .unwrap()
            .scan_records(keys::POLICY_PREFIX)?
            .into_iter()
            .map(|(_, bytes)| {
                let record: PolicyRecord = serde_json::from_slice(&bytes)?;
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
        let mut guard = self.store.write().unwrap();
        let policy_key = keys::policy_key(policy_id);
        if guard.read_record(&policy_key)?.is_none() {
            return Ok(false);
        }
        let rel_keys: Vec<_> = guard
            .scan_records(&keys::relationship_policy_prefix(policy_id))?
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        guard.remove_record(&policy_key)?;
        for key in rel_keys {
            guard.remove_record(&key)?;
        }
        Ok(true)
    }

    async fn store_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<()> {
        let record = RelationshipRecord {
            supplied_metadata: Default::default(),
            policy_id: policy_id.to_string(),
            relationship: rel.clone(),
            archived: false,
            metadata: default_metadata(),
        };
        let bytes = serde_json::to_vec(&record).expect("serialize RelationshipRecord");
        let key = keys::relationship_key(policy_id, &keys::relationship_storage_key(rel));
        let mut guard = self.store.write().unwrap();
        if let Some(existing) = guard.read_record(&key)? {
            let existing: RelationshipRecord = serde_json::from_slice(&existing)?;
            if existing.policy_id != policy_id || existing.relationship != *rel {
                return Err(zanzibar::error::Error::Serialization(
                    "relationship key collision".into(),
                ));
            }
        }
        guard.write_record(&key, bytes)?;
        Ok(())
    }

    async fn delete_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<bool> {
        let key = keys::relationship_key(policy_id, &keys::relationship_storage_key(rel));
        let mut guard = self.store.write().unwrap();
        if let Some(bytes) = guard.read_record(&key)? {
            let record: RelationshipRecord = serde_json::from_slice(&bytes)?;
            if record.policy_id != policy_id || record.relationship != *rel {
                return Err(zanzibar::error::Error::Serialization(
                    "relationship key collision".into(),
                ));
            }
            guard.remove_record(&key)?;
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
        let prefix =
            keys::relationship_storage_prefix(policy_id, &keys::object_prefix(resource, object_id));
        let mut guard = self.store.write().unwrap();
        let mut keys_to_delete = Vec::new();
        for (key, bytes) in guard.scan_records(&prefix)? {
            let record: RelationshipRecord = serde_json::from_slice(&bytes)?;
            if record.policy_id != policy_id
                || keys::relationship_key(
                    policy_id,
                    &keys::relationship_storage_key(&record.relationship),
                ) != key
            {
                return Err(zanzibar::error::Error::Serialization(
                    "relationship record does not match its key".into(),
                ));
            }
            if record.relationship.resource == resource
                && record.relationship.object_id == object_id
            {
                keys_to_delete.push(key);
            }
        }
        for key in keys_to_delete {
            guard.remove_record(&key)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::executor::block_on;
    use zanzibar::{PermissionEngine, Relation, RelationExpression, Resource};

    use super::*;
    use crate::kv_store::ModuleKvStore;

    const POLICY: &str = "policy-1";

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid did")
    }

    /// Seed a relationship record directly into the kv store under vera's keyspace.
    fn seed(store: &mut InMemoryKvStore, rel: &Relationship, archived: bool) {
        let record = RelationshipRecord {
            supplied_metadata: Default::default(),
            policy_id: POLICY.to_string(),
            relationship: rel.clone(),
            archived,
            metadata: default_metadata(),
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        store.put(
            &keys::relationship_key(POLICY, &keys::relationship_storage_key(rel)),
            bytes,
        );
    }

    #[test]
    fn relationship_keys_isolate_adapter_path_fields() {
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
        let original = Relationship::with_entity("document", "parent/path", "reader", did(ALICE));
        let collision = Relationship::with_entity("document", "parent", "path/reader", did(ALICE));
        assert_eq!(original.storage_key(), collision.storage_key());
        block_on(store.store_relationship(POLICY, &original)).unwrap();
        let before = store.store.read().unwrap().serialize();
        block_on(store.store_relationship(POLICY, &collision)).unwrap();
        assert!(block_on(store.delete_relationship(POLICY, &collision)).unwrap());
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
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
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
        let bytes = kv
            .get(&keys::relationship_key(
                POLICY,
                &keys::relationship_storage_key(&stored),
            ))
            .unwrap();
        kv.put(
            &keys::relationship_key(POLICY, &keys::relationship_storage_key(&requested)),
            bytes,
        );
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
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
        block_on(store.store_policy(&Policy::new(POLICY, "test"))).unwrap();
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
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
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
    fn delete_object_relationships_clears_only_that_object() {
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
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
            .with_resource(Resource::new("collection").with_relation(Relation::direct("reader")))
            .with_resource(
                Resource::new("document")
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
            let mut kv = InMemoryKvStore::default();
            let reader = Relationship::with_entity("document", "doc1", "reader", did(ALICE));
            let blocked = Relationship::new("document", "doc1", "blocked", subject.clone());
            seed(&mut kv, &reader, false);
            seed(&mut kv, &blocked, false);
            seed(
                &mut kv,
                &Relationship::with_entity("collection", "col1", "blocked", did(ALICE)),
                false,
            );
            let excluded = if matches!(subject, Subject::EntitySet { .. }) {
                RelationExpression::tuple_to_userset("blocked", "blocked")
            } else {
                RelationExpression::computed_userset("blocked")
            };
            let policy = Policy::new(POLICY, "exclusion")
                .with_resource(
                    Resource::new("collection").with_relation(Relation::direct("blocked")),
                )
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
            let mut engine = PermissionEngine::new(Arc::new(QmdbZanzibarStore::new(kv.clone())));
            engine.add_policy(&policy);
            assert!(
                !engine
                    .check_blocking(POLICY, "document", "doc1", "read", &did(ALICE))
                    .unwrap()
            );

            kv.put(
                &keys::relationship_key(POLICY, &keys::relationship_storage_key(&blocked)),
                b"{".to_vec(),
            );
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
        kv.put(
            &keys::relationship_key(POLICY, &keys::relationship_storage_key(&rel)),
            b"{".to_vec(),
        );
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
}
