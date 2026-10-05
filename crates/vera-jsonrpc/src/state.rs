//! Node state management for RPC endpoints.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Locally observed execution progress and RPC resource limits.
#[derive(Debug, Clone)]
pub struct NodeState {
    inner: Arc<NodeStateInner>,
}

#[derive(Debug)]
struct NodeStateInner {
    chain_id: u64,
    validator_index: u32,
    validator_count: u32,
    started_at: Instant,
    finalized: RwLock<Option<FinalizedProgress>>,
    finalized_count: AtomicU64,
    proposed_count: AtomicU64,
    backfilling: AtomicBool,
    snapshot_revision: AtomicU64,
    proof_requests: Arc<tokio::sync::Semaphore>,
    permission_reads: Arc<tokio::sync::Semaphore>,
    light_lookups: Arc<tokio::sync::Semaphore>,
    proof_progress: tokio::sync::watch::Sender<()>,
}

#[derive(Clone, Copy, Debug)]
struct FinalizedProgress {
    height: u64,
    epoch: u64,
    view: u64,
}

fn acquire(
    semaphore: &Arc<tokio::sync::Semaphore>,
) -> jsonrpsee::core::RpcResult<tokio::sync::OwnedSemaphorePermit> {
    semaphore.clone().try_acquire_owned().map_err(|_| {
        jsonrpsee::types::ErrorObjectOwned::owned(
            crate::error::codes::RESOURCE_UNAVAILABLE,
            "proof service busy; retry later",
            Some(serde_json::json!({"retryable": true})),
        )
    })
}

impl NodeState {
    /// Create node state with the startup configuration, not a live membership roster.
    #[must_use]
    pub fn new(chain_id: u64, validator_index: u32, validator_count: u32) -> Self {
        Self {
            inner: Arc::new(NodeStateInner {
                chain_id,
                validator_index,
                validator_count,
                started_at: Instant::now(),
                finalized: RwLock::new(None),
                finalized_count: AtomicU64::new(0),
                proposed_count: AtomicU64::new(0),
                backfilling: AtomicBool::new(false),
                snapshot_revision: AtomicU64::new(0),
                proof_requests: Arc::new(tokio::sync::Semaphore::new(8)),
                permission_reads: Arc::new(tokio::sync::Semaphore::new(8)),
                light_lookups: Arc::new(tokio::sync::Semaphore::new(8)),
                proof_progress: tokio::sync::watch::channel(()).0,
            }),
        }
    }

    pub(crate) fn proof_permit(
        &self,
    ) -> jsonrpsee::core::RpcResult<tokio::sync::OwnedSemaphorePermit> {
        acquire(&self.inner.proof_requests)
    }

    pub(crate) fn light_lookup_permit(
        &self,
    ) -> jsonrpsee::core::RpcResult<tokio::sync::OwnedSemaphorePermit> {
        acquire(&self.inner.light_lookups)
    }

    /// Bound current-permission requests while publication may block storage reads.
    /// These requests also need a shared proof permit before allocating evidence.
    pub(crate) fn permission_read_permit(
        &self,
    ) -> jsonrpsee::core::RpcResult<tokio::sync::OwnedSemaphorePermit> {
        acquire(&self.inner.permission_reads)
    }

    /// Wake proof readers after publishing an execution index or finality evidence.
    pub fn notify_proof_progress(&self) {
        self.inner.proof_progress.send_replace(());
    }

    pub(crate) fn proof_updates(&self) -> tokio::sync::watch::Receiver<()> {
        self.inner.proof_progress.subscribe()
    }

    /// Publish one finalized execution revision after its state and index are available.
    /// Recovery may supply the durable head. Replayed or older heights cannot replace
    /// it; the epoch and view are updated together and views may reset between epochs.
    pub fn record_finalized(&self, height: u64, epoch: u64, view: u64) {
        let mut finalized = self.inner.finalized.write();
        if finalized.is_none_or(|previous| height > previous.height) {
            *finalized = Some(FinalizedProgress {
                height,
                epoch,
                view,
            });
        }
    }

    /// This node's validator index in its startup configuration.
    pub fn validator_index(&self) -> u32 {
        self.inner.validator_index
    }

    /// Validator count in the startup configuration, not the active epoch roster.
    pub fn validator_count(&self) -> u32 {
        self.inner.validator_count
    }

    /// Count a finalized callback processed in this run; this is not a height.
    pub fn inc_finalized(&self) {
        self.inner.finalized_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment proposed block count.
    pub fn inc_proposed(&self) {
        self.inner.proposed_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Set whether this node is backfilling historical blocks.
    pub fn set_backfilling(&self, backfilling: bool) {
        self.inner.backfilling.store(backfilling, Ordering::Relaxed);
    }

    /// Whether this node is currently backfilling.
    pub fn is_backfilling(&self) -> bool {
        self.inner.backfilling.load(Ordering::Relaxed)
    }

    /// Record the revision recovered through snapshot transfer or its persisted startup floor.
    pub fn set_snapshot_revision(&self, revision: u64) {
        self.inner
            .snapshot_revision
            .store(revision, Ordering::Relaxed);
    }

    /// Finalized callbacks processed in this run, independent of recovered height.
    pub fn finalized_count(&self) -> u64 {
        self.inner.finalized_count.load(Ordering::Relaxed)
    }

    /// Get current node status.
    pub fn status(&self) -> NodeStatus {
        let snapshot_revision = self.inner.snapshot_revision.load(Ordering::Relaxed);
        let finalized = *self.inner.finalized.read();
        NodeStatus {
            chain_id: self.inner.chain_id,
            validator_index: self.inner.validator_index,
            validator_count: self.inner.validator_count,
            uptime_secs: self.inner.started_at.elapsed().as_secs(),
            current_view: None,
            finalized_height: finalized.map(|progress| progress.height),
            finalized_epoch: finalized.map(|progress| progress.epoch),
            finalized_view: finalized.map(|progress| progress.view),
            finalized_count: self.inner.finalized_count.load(Ordering::Relaxed),
            proposed_count: self.inner.proposed_count.load(Ordering::Relaxed),
            nullified_count: None,
            peer_count: None,
            is_leader: None,
            backfilling: self.inner.backfilling.load(Ordering::Relaxed),
            snapshot_revision: (snapshot_revision > 0).then_some(snapshot_revision),
        }
    }
}

/// Serializable node status for RPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    /// Chain ID.
    pub chain_id: u64,
    /// This node's validator index in its startup configuration.
    pub validator_index: u32,
    /// Startup validator count; membership changes do not update this field.
    pub validator_count: u32,
    /// Seconds since node started.
    pub uptime_secs: u64,
    /// Entered consensus view, or null when live consensus telemetry is unavailable.
    pub current_view: Option<u64>,
    /// Latest published finalized execution height, including restored durable history.
    pub finalized_height: Option<u64>,
    /// Epoch of `finalized_height`; reported together with its view.
    pub finalized_epoch: Option<u64>,
    /// View of `finalized_height`, not the live consensus view.
    pub finalized_view: Option<u64>,
    /// Finalized callbacks processed in this run; this is not a height.
    pub finalized_count: u64,
    /// Number of blocks proposed by this node in this run.
    pub proposed_count: u64,
    /// Number of nullified rounds, or null when unobserved.
    pub nullified_count: Option<u64>,
    /// Authenticated connected peer count, or null when unobserved.
    pub peer_count: Option<u64>,
    /// Leadership in the entered consensus view, or null when unobserved.
    pub is_leader: Option<bool>,
    /// Whether this node is backfilling historical blocks.
    pub backfilling: bool,
    /// Revision recovered through snapshot transfer, or its persisted recovery floor on restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_revision: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_status_unobserved_fields_are_null() {
        let state = NodeState::new(1337, 2, 4);
        let json = serde_json::to_value(state.status()).unwrap();
        for field in [
            "currentView",
            "isLeader",
            "nullifiedCount",
            "peerCount",
            "finalizedHeight",
            "finalizedEpoch",
            "finalizedView",
        ] {
            assert_eq!(json.get(field), Some(&serde_json::Value::Null), "{field}");
        }
        assert_eq!(json["chainId"], 1337);
        assert_eq!(json["validatorIndex"], 2);
        assert_eq!(json["validatorCount"], 4);
        assert_eq!(json["finalizedCount"], 0);
        assert!(json.get("snapshotRevision").is_none());
        let parsed: NodeStatus = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), json);
    }

    #[test]
    fn finalized_progress_survives_replay_and_epoch_view_reset() {
        let state = NodeState::new(1, 0, 4);
        state.record_finalized(50, 2, 900);
        state.record_finalized(49, 9, 999);
        state.record_finalized(50, 9, 999);
        let status = state.status();
        assert_eq!(
            (
                status.finalized_height,
                status.finalized_epoch,
                status.finalized_view
            ),
            (Some(50), Some(2), Some(900))
        );
        state.record_finalized(51, 3, 1);
        state.inc_finalized();
        state.inc_proposed();
        let status = state.status();
        assert_eq!(
            (
                status.finalized_height,
                status.finalized_epoch,
                status.finalized_view
            ),
            (Some(51), Some(3), Some(1))
        );
        assert_eq!(status.finalized_count, 1);
        assert_eq!(status.proposed_count, 1);
        assert!(status.current_view.is_none());
        assert!(status.is_leader.is_none());
    }

    #[test]
    fn finalized_status_is_one_coherent_revision() {
        let state = NodeState::new(1, 0, 4);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for height in 1..=2_000 {
                    state.record_finalized(height, height / 10, height % 10);
                }
            });
            for _ in 0..2_000 {
                let status = state.status();
                if let Some(height) = status.finalized_height {
                    assert_eq!(status.finalized_epoch, Some(height / 10));
                    assert_eq!(status.finalized_view, Some(height % 10));
                } else {
                    assert!(status.finalized_epoch.is_none());
                    assert!(status.finalized_view.is_none());
                }
            }
        });
        assert_eq!(state.status().finalized_height, Some(2_000));
    }

    #[test]
    fn snapshot_revision_is_independent_of_observed_finalization() {
        let state = NodeState::new(1, 0, 4);
        state.set_snapshot_revision(42);
        let json = serde_json::to_value(state.status()).unwrap();
        assert_eq!(json["snapshotRevision"], 42);
        assert!(json["finalizedHeight"].is_null());
        assert_eq!(json["finalizedCount"], 0);
        let parsed: NodeStatus = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.snapshot_revision, Some(42));
    }
}
