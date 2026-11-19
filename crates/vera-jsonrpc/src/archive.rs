//! Bounded reads from durable execution history.

use crate::{NodeState, RpcError};
use std::sync::Arc;
use vera_indexer::{BlockIndex, IndexQuery, IndexedLog, IndexerError, LogFilter, LogQuery};

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

    /// Read a range with shared scan/result budgets, decoding at most 64 MiB of
    /// encoded archive records. One admission permit covers the complete query.
    pub async fn logs(
        &self,
        index: Arc<BlockIndex>,
        filter: LogFilter,
    ) -> Result<Vec<IndexedLog>, RpcError> {
        let mut query = LogQuery::new(filter, index.head_block_number()).map_err(log_error)?;
        let permit = self
            .state
            .light_lookup_permit()
            .map_err(|_| RpcError::HistoryBusy)?;
        let lookup = self.lookup.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut remaining_bytes = 64 << 20;
            for height in query.from..=query.to {
                if index
                    .collect_revision_logs(height, &mut query)
                    .map_err(log_error)?
                {
                    continue;
                }
                if let Some(retained) = lookup(IndexQuery::Revision(height), &mut remaining_bytes)?
                    && !retained
                        .collect_revision_logs(height, &mut query)
                        .map_err(log_error)?
                {
                    return Err(RpcError::StateError(
                        "historical revision cannot be indexed".into(),
                    ));
                }
            }
            Ok(query.finish())
        })
        .await
        .map_err(|error| RpcError::Internal(error.to_string()))?
    }
}

pub(crate) fn log_error(error: IndexerError) -> RpcError {
    if matches!(error, IndexerError::InvalidBlockRange { .. }) {
        RpcError::InvalidBlockNumber(error.to_string())
    } else {
        RpcError::LimitExceeded(error.to_string())
    }
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
