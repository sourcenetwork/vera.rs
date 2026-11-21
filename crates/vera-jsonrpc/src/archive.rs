//! Bounded reads from durable execution history.

use crate::{NodeState, RpcError};
use std::sync::Arc;
use vera_indexer::{BlockIndex, IndexQuery};

/// Reconstruct one retained revision, charging encoded bytes before decoding.
pub type IndexLookup =
    Arc<dyn Fn(IndexQuery, &mut usize) -> Result<Option<Arc<BlockIndex>>, RpcError> + Send + Sync>;

/// Archive reader sharing the node-wide blocking-history admission limit.
#[derive(Clone)]
pub struct ArchiveReader {
    state: NodeState,
    lookup: IndexLookup,
}

impl std::fmt::Debug for ArchiveReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveReader").finish_non_exhaustive()
    }
}

impl ArchiveReader {
    /// Use the same node state as the RPC server to share its admission budget.
    pub const fn new(state: NodeState, lookup: IndexLookup) -> Self {
        Self { state, lookup }
    }

    /// Read one revision without populating the global memory index.
    pub async fn read(&self, query: IndexQuery) -> Result<Option<Arc<BlockIndex>>, RpcError> {
        let permit = self
            .state
            .light_lookup_permit()
            .map_err(|_| RpcError::HistoryBusy)?;
        let lookup = self.lookup.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut remaining_bytes = 64 << 20;
            lookup(query, &mut remaining_bytes)
        })
        .await
        .map_err(|error| RpcError::Internal(error.to_string()))?
    }
}
