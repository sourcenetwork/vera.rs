//! Node-side handling of proposals and finalized blocks: indexing,
//! subscriptions, gossip headers, node status, and mempool recheck.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
};

use commonware_codec::Encode as _;
use commonware_cryptography::Digestible as _;
use tokio::sync::broadcast;
use tracing::trace;
use vera_app::FinalizedSink;
use vera_consensus::components::InMemoryMempool;
use vera_domain::{Block, GossipHeader};
use vera_executor::{ExecutionReceipt, VeraExecutor};
use vera_indexer::{BlockIndex, LightBlockIndex, StoredFinalization};
use vera_jsonrpc::{NodeState, RpcBlock, RpcLog};

use vera_backend::VeraStateSet;

use crate::{
    CommittedState, FinalizedHistory,
    finalize::{index_finalized_block, subscription_data},
    history::restore_epoch,
    tx_gossip::{SharedValidator, recheck},
};

/// Encoded finalization artifacts fetched from marshal after a block commits.
#[derive(Clone, Debug)]
pub struct FinalizationArtifacts {
    /// Epoch whose public material verifies the certificate.
    pub epoch: u64,
    /// Canonical full finalization bytes served to light clients.
    pub finalization: Vec<u8>,
    /// Canonical recovered certificate bytes gossiped with the header.
    pub certificate: Vec<u8>,
}

/// Async lookup for the finalization marshal persisted at a block height.
pub type FinalizationLookup = Arc<
    dyn Fn(u64) -> Pin<Box<dyn Future<Output = Option<FinalizationArtifacts>> + Send>>
        + Send
        + Sync,
>;

/// Everything the node does with a finalized block once its state is readable.
#[derive(Clone)]
pub struct NodeSink {
    history: Arc<FinalizedHistory>,
    index: Arc<BlockIndex>,
    light_index: Arc<LightBlockIndex>,
    heads: broadcast::Sender<RpcBlock>,
    logs: broadcast::Sender<Vec<RpcLog>>,
    headers: broadcast::Sender<GossipHeader>,
    node_state: NodeState,
    finalization_lookup: FinalizationLookup,
    chain_id: u64,
    publisher_index: u32,
    gas_limit: u64,
    executor: VeraExecutor,
    mempool: InMemoryMempool,
    validator: SharedValidator,
    state: Arc<OnceLock<VeraStateSet>>,
}

impl std::fmt::Debug for NodeSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeSink").finish_non_exhaustive()
    }
}

/// Inputs to [`NodeSink::new`].
pub struct SinkParts {
    /// Durable execution history used to restore the query indexes.
    pub history: Arc<FinalizedHistory>,
    /// Block, transaction, and receipt index served over RPC.
    pub index: Arc<BlockIndex>,
    /// Public consensus artifacts served to light clients.
    pub light_index: Arc<LightBlockIndex>,
    /// `newHeads` subscribers.
    pub heads: broadcast::Sender<RpcBlock>,
    /// `logs` subscribers.
    pub logs: broadcast::Sender<Vec<RpcLog>>,
    /// `headers` subscribers.
    pub headers: broadcast::Sender<GossipHeader>,
    /// Node status counters.
    pub node_state: NodeState,
    /// Retrieves marshal's canonical finalization for a committed height.
    pub finalization_lookup: FinalizationLookup,
    /// Chain id stamped on gossip headers.
    pub chain_id: u64,
    /// This node's index in the validator set.
    pub publisher_index: u32,
    /// Block gas limit for indexed headers.
    pub gas_limit: u64,
    /// Executor whose module state is read for native nonces.
    pub executor: VeraExecutor,
    /// Mempool to recheck after each finalized block.
    pub mempool: InMemoryMempool,
    /// Validator to reset after each finalized block.
    pub validator: SharedValidator,
}

impl std::fmt::Debug for SinkParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkParts").finish_non_exhaustive()
    }
}

impl NodeSink {
    /// Build the sink from its parts.
    pub fn new(parts: SinkParts) -> Self {
        Self {
            history: parts.history,
            index: parts.index,
            light_index: parts.light_index,
            heads: parts.heads,
            logs: parts.logs,
            headers: parts.headers,
            node_state: parts.node_state,
            finalization_lookup: parts.finalization_lookup,
            chain_id: parts.chain_id,
            publisher_index: parts.publisher_index,
            gas_limit: parts.gas_limit,
            executor: parts.executor,
            mempool: parts.mempool,
            validator: parts.validator,
            state: Arc::new(OnceLock::new()),
        }
    }

    /// Attach the committed database set once the stateful actor has opened it.
    pub fn attach_state(&self, set: VeraStateSet) {
        let _ = self.state.set(set);
    }
}

impl FinalizedSink for NodeSink {
    fn finalized_height(&self) -> u64 {
        self.index.head_block_number()
    }

    fn proposed(&self, _block: &Block) {
        self.node_state.inc_proposed();
    }

    async fn finalized(&self, block: &Block, receipts: Vec<ExecutionReceipt>) {
        let started =
            tracing::enabled!(target: "vera_publication_diagnostics", tracing::Level::DEBUG)
                .then(std::time::Instant::now);
        // Marshal serves lookups independently of the stateful callback.
        let artifacts = (self.finalization_lookup)(block.height).await;
        let lookup_elapsed = started.map(|started| started.elapsed());
        let history = self.history.clone();
        let persisted = block.clone();
        let gas_limit = self.gas_limit;
        let (receipts, artifacts) = ::tokio::task::spawn_blocking(move || {
            history.append_finalized(&persisted, &receipts, gas_limit, artifacts.as_ref())?;
            Ok::<_, anyhow::Error>((receipts, artifacts))
        })
        .await
        .expect("finalized history writer stopped")
        .expect("persist finalized execution before publication");
        let persisted_elapsed = started.map(|started| started.elapsed());
        self.node_state.inc_finalized();
        self.node_state.set_backfilling(false);

        let gas_used = receipts.iter().map(|r| r.gas_used).sum();
        index_finalized_block(&self.index, block, self.gas_limit, &receipts, gas_used);
        self.node_state.record_finalized(
            block.height,
            block.context.round.epoch().get(),
            block.context.round.view().get(),
        );
        self.node_state.notify_proof_progress();
        if let Some(((started, lookup), persisted)) =
            started.zip(lookup_elapsed).zip(persisted_elapsed)
        {
            tracing::debug!(target: "vera_publication_diagnostics", height = block.height,
                transactions = block.txs.len(), lookup_us = lookup.as_micros(),
                history_us = (persisted - lookup).as_micros(),
                index_us = (started.elapsed() - persisted).as_micros(),
                "finalized revision publication");
        }
        let (rpc_block, rpc_logs) = subscription_data(block, self.gas_limit, &receipts, gas_used);
        if self.heads.send(rpc_block).is_err() {
            trace!(height = block.height, "no newHeads subscribers");
        }
        if !rpc_logs.is_empty() && self.logs.send(rpc_logs).is_err() {
            trace!(height = block.height, "no logs subscribers");
        }
        restore_epoch(&self.light_index, block);
        let height = block.height;
        if let Some(artifacts) = artifacts {
            let mut header = GossipHeader::from_block(block, self.chain_id, self.publisher_index);
            header.set_signature(&artifacts.certificate);
            self.light_index.insert_finalization(
                block.digest().0,
                StoredFinalization {
                    epoch: artifacts.epoch,
                    bytes: artifacts.finalization,
                    block: block.encode().to_vec(),
                },
            );
            if self.headers.send(header).is_err() {
                trace!(height, "no headers subscribers");
            }
        } else {
            trace!(height, "no direct finalization certificate in marshal");
        }
        self.node_state.notify_proof_progress();

        let Some(set) = self.state.get() else {
            return;
        };
        let nonces = self
            .executor
            .modules()
            .read()
            .map(|m| m.nonces.clone())
            .unwrap_or_default();
        recheck(
            &self.mempool,
            &self.validator,
            CommittedState::new(set.clone()),
            nonces,
        )
        .await;
    }
}
