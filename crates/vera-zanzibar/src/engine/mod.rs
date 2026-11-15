mod cache;
mod evaluate;
mod limits;
mod outcome;
pub use limits::{EvaluationMeter, MAX_EVALUATION_DEPTH, MAX_EVALUATION_STEPS};

use std::sync::Arc;

use crate::did::Did;

use crate::error::Result;
use crate::lookup::PolicyLookupTable;
use crate::store::ZanzibarStore;
use crate::types::Policy;

use cache::{CheckCache, NodeTrail};
use evaluate::Goal;
use outcome::Outcome;

pub struct PermissionEngine<S: ZanzibarStore + ?Sized> {
    store: Arc<S>,
    pub lookup: PolicyLookupTable,
    meter: Option<Arc<dyn EvaluationMeter>>,
}

impl<S: ZanzibarStore + ?Sized> PermissionEngine<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            lookup: PolicyLookupTable::new(),
            meter: None,
        }
    }

    /// Attach caller accounting without changing per-check depth or step limits.
    pub fn with_evaluation_meter(mut self, meter: Arc<dyn EvaluationMeter>) -> Self {
        self.meter = Some(meter);
        self
    }

    pub fn add_policy(&mut self, policy: &Policy) {
        self.lookup.add_policy(policy);
    }

    pub fn remove_policy(&mut self, policy_id: &str) {
        self.lookup.remove_policy(policy_id);
    }

    pub fn update_policy(&mut self, policy: &Policy) {
        self.lookup.update_policy(policy);
    }

    pub async fn load_policy(&mut self, policy_id: &str) -> Result<()> {
        if let Some(policy) = self.store.get_policy(policy_id).await? {
            self.lookup.add_policy(&policy);
        }
        Ok(())
    }

    pub async fn reload_policy(&mut self, policy_id: &str) -> Result<()> {
        self.lookup.remove_policy(policy_id);
        self.load_policy(policy_id).await
    }

    pub fn clear_cache(&mut self) {
        self.lookup.clear();
    }

    /// Evaluate with deterministic depth and work limits; exhaustion returns an error.
    pub async fn check(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Did,
    ) -> Result<bool> {
        let goal = Goal {
            policy_id,
            resource,
            object_id,
            subject,
        };
        let cache = CheckCache::new(self.meter.clone());
        let outcome = self
            .evaluate_node(goal, relation, &NodeTrail::default(), &cache)
            .await?;
        Ok(matches!(outcome, Outcome::Granted))
    }

    /// Synchronous, runtime-free wrapper over [`check`](Self::check) for
    /// consensus / deterministic evaluation (e.g. on-chain or replicated-log
    /// authorization), where no async reactor is available and every validator
    /// must independently reach the identical decision.
    ///
    /// Drives the [`check`](Self::check) future to completion on the current
    /// thread via [`futures::executor::block_on`], which needs no reactor.
    ///
    /// # Contract
    ///
    /// Determinism holds only if the backing [`ZanzibarStore`] honours:
    /// - **all-Ready**: every store future resolves without yielding to a
    ///   reactor — no real I/O, timers, or network. A future that returns
    ///   `Pending` awaiting an external event parks this thread indefinitely.
    /// - **side-effect-free**: the check performs reads only and must not
    ///   mutate observable state.
    /// - **order-stable**: policy and relationship traversal is deterministically
    ///   ordered, so identical inputs yield the identical decision on every node.
    ///
    /// An adapter over an immutable in-memory snapshot with ordered keys
    /// satisfies all three, and so does `MemoryZanzibarStore`. A network- or
    /// disk-backed store generally does not and must not be used through this
    /// entry point.
    pub fn check_blocking(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Did,
    ) -> Result<bool> {
        futures::executor::block_on(self.check(policy_id, resource, object_id, relation, subject))
    }
}

#[cfg(test)]
mod check_blocking_tests {
    use std::sync::Arc;

    use crate::store::{MemoryZanzibarStore, ZanzibarStore};
    use crate::types::{Policy, Relation, Relationship, Resource};
    use crate::Did;

    use super::PermissionEngine;

    fn owner_did() -> Did {
        Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap()
    }
    fn stranger_did() -> Did {
        Did::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap()
    }

    // A plain `#[test]`, deliberately not `#[tokio::test]`: there is no async
    // runtime present. This is the consensus-evaluation contract — `check_blocking`
    // must drive an all-Ready, side-effect-free store to a decision synchronously,
    // with no reactor, so independent validators reach the same answer.
    #[test]
    fn check_blocking_resolves_decision_without_a_runtime() {
        let store = Arc::new(MemoryZanzibarStore::new());
        let mut engine = PermissionEngine::new(store.clone());

        let policy = Policy::new("policy1", "Test")
            .with_resource(Resource::new("document").with_relation(Relation::direct("owner")));
        engine.add_policy(&policy);

        let owner = owner_did();
        let rel = Relationship::with_entity("document", "doc1", "owner", owner.clone());
        futures::executor::block_on(store.store_relationship("policy1", &rel)).unwrap();

        // Same decisions `check` would return — owner granted, stranger denied —
        // produced synchronously.
        assert!(engine
            .check_blocking("policy1", "document", "doc1", "owner", &owner)
            .unwrap());
        assert!(!engine
            .check_blocking("policy1", "document", "doc1", "owner", &stranger_did())
            .unwrap());
    }
}
