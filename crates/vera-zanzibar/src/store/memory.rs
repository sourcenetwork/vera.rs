use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::did::Did;

use super::traits::ZanzibarStore;
use crate::error::Result;
use crate::types::{Policy, Relationship, Subject};

/// Resource, object and relation of a tuple.
type RelationKey = (String, String, String);
/// Variant tag and fields of a subject, so distinct subjects never collide.
type SubjectKey = (u8, String, String, String);
type Relations = BTreeMap<RelationKey, BTreeMap<SubjectKey, Subject>>;

/// In-memory store with deterministic, key-ordered traversal.
pub struct MemoryZanzibarStore {
    policies: RwLock<BTreeMap<String, Policy>>,
    relationships: RwLock<BTreeMap<String, Relations>>,
    policy_counter: AtomicU64,
}

impl MemoryZanzibarStore {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(BTreeMap::new()),
            relationships: RwLock::new(BTreeMap::new()),
            policy_counter: AtomicU64::new(0),
        }
    }

    fn has(&self, policy_id: &str, relation: &RelationKey, subject: &Subject) -> bool {
        self.relationships
            .read()
            .get(policy_id)
            .and_then(|relations| relations.get(relation))
            .is_some_and(|subjects| subjects.contains_key(&subject_key(subject)))
    }
}

fn relation_key(resource: &str, object_id: &str, relation: &str) -> RelationKey {
    (resource.into(), object_id.into(), relation.into())
}

fn subject_key(subject: &Subject) -> SubjectKey {
    match subject {
        Subject::Entity(did) => (0, did.to_string(), String::new(), String::new()),
        Subject::EntitySet {
            resource,
            object_id,
            relation,
        } => (1, resource.clone(), object_id.clone(), relation.clone()),
        Subject::TypedWildcard { resource } => (2, resource.clone(), String::new(), String::new()),
        Subject::Wildcard => (3, String::new(), String::new(), String::new()),
    }
}

impl Default for MemoryZanzibarStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl ZanzibarStore for MemoryZanzibarStore {
    async fn store_policy(&self, policy: &Policy) -> Result<()> {
        self.policies
            .write()
            .insert(policy.id.clone(), policy.clone());
        Ok(())
    }

    async fn get_policy(&self, policy_id: &str) -> Result<Option<Policy>> {
        Ok(self.policies.read().get(policy_id).cloned())
    }

    async fn next_policy_counter(&self) -> Result<u64> {
        Ok(self.policy_counter.fetch_add(1, Ordering::SeqCst) + 1)
    }

    async fn list_policies(&self) -> Result<Vec<Policy>> {
        Ok(self.policies.read().values().cloned().collect())
    }

    async fn delete_policy(&self, policy_id: &str) -> Result<bool> {
        let removed = self.policies.write().remove(policy_id).is_some();
        if removed {
            self.relationships.write().remove(policy_id);
        }
        Ok(removed)
    }

    async fn store_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<()> {
        self.relationships
            .write()
            .entry(policy_id.to_string())
            .or_default()
            .entry(relation_key(&rel.resource, &rel.object_id, &rel.relation))
            .or_default()
            .insert(subject_key(&rel.subject), rel.subject.clone());
        Ok(())
    }

    async fn delete_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<bool> {
        let key = relation_key(&rel.resource, &rel.object_id, &rel.relation);
        let mut guard = self.relationships.write();
        Ok(guard
            .get_mut(policy_id)
            .and_then(|relations| relations.get_mut(&key))
            .is_some_and(|subjects| subjects.remove(&subject_key(&rel.subject)).is_some()))
    }

    async fn has_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Subject,
    ) -> Result<bool> {
        Ok(self.has(
            policy_id,
            &relation_key(resource, object_id, relation),
            subject,
        ))
    }

    async fn check_permission_direct(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Did,
    ) -> Result<bool> {
        let key = relation_key(resource, object_id, relation);
        Ok(self.has(policy_id, &key, &Subject::Entity(subject.clone()))
            || self.has(policy_id, &key, &Subject::Wildcard))
    }

    async fn get_relation_subjects(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<Subject>> {
        Ok(self
            .relationships
            .read()
            .get(policy_id)
            .and_then(|relations| relations.get(&relation_key(resource, object_id, relation)))
            .map(|subjects| subjects.values().cloned().collect())
            .unwrap_or_default())
    }

    async fn delete_object_relationships(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> Result<()> {
        if let Some(relations) = self.relationships.write().get_mut(policy_id) {
            relations.retain(|(stored_resource, stored_object, _), _| {
                stored_resource != resource || stored_object != object_id
            });
        }
        Ok(())
    }
}
