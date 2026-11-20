use async_trait::async_trait;

use crate::did::Did;
use crate::thread_bounds::MaybeSendSync;

use crate::error::Result;
use crate::types::{Policy, Relationship, Subject};

/// Trait for Zanzibar policy and relationship storage.
///
/// Provides operations for:
/// - Policy storage and retrieval
/// - Relationship tuple storage
/// - Relationship queries (for permission evaluation)
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait ZanzibarStore: MaybeSendSync {
    async fn store_policy(&self, policy: &Policy) -> Result<()>;

    async fn get_policy(&self, policy_id: &str) -> Result<Option<Policy>>;

    async fn list_policies(&self) -> Result<Vec<Policy>>;

    async fn delete_policy(&self, policy_id: &str) -> Result<bool>;

    async fn store_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<()>;

    async fn delete_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<bool>;

    async fn has_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Subject,
    ) -> Result<bool>;

    /// Whether a tuple names `subject` itself or the untyped wildcard. Typed
    /// wildcards and usersets are resolved by the engine from
    /// [`get_relation_subjects`](Self::get_relation_subjects).
    async fn check_permission_direct(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Did,
    ) -> Result<bool>;

    async fn get_relation_subjects(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<Subject>>;

    async fn delete_object_relationships(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> Result<()>;
}
