//! Transaction admission and gossip.
//!
//! Local RPC submissions are sent to every peer and retried while pending.
//! Transactions received from peers do not enter the local retry queue.

use std::sync::{Arc, OnceLock};

use alloy_primitives::Bytes;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Spawner};
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};
use vera_consensus::{Mempool as _, components::InMemoryMempool};
use vera_domain::{NativeTx, Tx};
use vera_executor::MempoolValidator;
use vera_modules::native_account::NativeNonceStore;

use crate::CommittedState;

/// Mempool validator over committed state, bound once the databases are open.
pub type SharedValidator = Arc<OnceLock<Mutex<MempoolValidator<CommittedState>>>>;

/// Admits transactions locally and forwards them to peers.
pub struct TxGossip<S: Sender, E: Clock> {
    clock: E,
    mempool: InMemoryMempool,
    validator: SharedValidator,
    chain_id: u64,
    sender: Arc<Mutex<S>>,
}

impl<S: Sender, E: Clock + Clone> Clone for TxGossip<S, E> {
    fn clone(&self) -> Self {
        Self {
            clock: self.clock.clone(),
            mempool: self.mempool.clone(),
            validator: self.validator.clone(),
            chain_id: self.chain_id,
            sender: self.sender.clone(),
        }
    }
}

impl<S: Sender, E: Clock> std::fmt::Debug for TxGossip<S, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxGossip").finish_non_exhaustive()
    }
}

/// Validate and insert one transaction into the mempool.
pub(crate) async fn admit(
    mempool: &InMemoryMempool,
    validator: &SharedValidator,
    chain_id: u64,
    bytes: Bytes,
) -> Result<bool, String> {
    if bytes.len() > vera_domain::MAX_TX_BYTES {
        return Err("signed request exceeds its byte limit".into());
    }
    let validator = validator
        .get()
        .ok_or_else(|| "node is still starting".to_string())?;
    let tx = Tx::new(bytes.clone());
    let is_native = !bytes.is_empty() && NativeTx::is_native_tx(bytes[0]);
    let pre = if is_native {
        Some(
            MempoolValidator::<CommittedState>::pre_validate_native(chain_id, &bytes)
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    let mut guard = validator.lock().await;
    if !mempool.can_insert(&tx) {
        return Err("pending request capacity reached".into());
    }
    if let Some(pre) = pre {
        guard.admit_native(&pre).map_err(|e| e.to_string())?;
    } else {
        guard.validate_tx(&bytes).await.map_err(|e| e.to_string())?;
    }
    Ok(mempool.insert(tx))
}

impl<S: Sender, E: Clock> TxGossip<S, E> {
    /// Build the gossip handle over the mempool channel sender.
    pub fn new(
        clock: E,
        mempool: InMemoryMempool,
        validator: SharedValidator,
        chain_id: u64,
        sender: S,
    ) -> Self {
        Self {
            clock,
            mempool,
            validator,
            chain_id,
            sender: Arc::new(Mutex::new(sender)),
        }
    }

    /// Admit a locally submitted transaction and forward it to every peer.
    pub async fn submit(&self, bytes: Bytes) -> Result<bool, String> {
        let tx = Tx::new(bytes.clone());
        let inserted = admit(&self.mempool, &self.validator, self.chain_id, bytes.clone()).await?;
        if inserted {
            self.forward_local(tx).await;
        }
        Ok(inserted)
    }

    async fn forward_local(&self, tx: Tx) {
        let id = tx.id();
        if !self.mempool.mark_local(&id, self.clock.current()) {
            return;
        }
        let mut sender = self.sender.lock().await;
        if !self.mempool.contains(&id) {
            return;
        }
        let feedback = sender.send(Recipients::All, tx.bytes.0, false);
        trace!(tx_id = ?id, ?feedback, "forwarded transaction");
    }

    pub(crate) async fn reannounce(&self) {
        if !self.mempool.has_due_local(self.clock.current()) {
            return;
        }
        let mut sender = self.sender.lock().await;
        let pending = self.mempool.local_reannouncement(
            self.clock.current(),
            crate::tx_reannouncement::MAX_TRANSACTIONS,
            vera_domain::MAX_TX_BYTES,
        );
        for tx in pending {
            let id = tx.id();
            if !self.mempool.contains(&id) {
                continue;
            }
            let feedback = sender.send(Recipients::All, tx.bytes.0, false);
            trace!(tx_id = ?id, ?feedback, "reannounced pending local transaction");
        }
    }
}

/// Reset the validator against fresh committed state after a finalized block
/// and evict transactions that no longer validate.
pub(crate) async fn recheck(
    mempool: &InMemoryMempool,
    validator: &SharedValidator,
    state: CommittedState,
    nonces: NativeNonceStore,
) {
    let Some(validator) = validator.get() else {
        return;
    };
    let mut guard = validator.lock().await;
    guard.reset(state, nonces);
    let pending = mempool.build(usize::MAX, &std::collections::BTreeSet::new());
    let mut evict = Vec::new();
    for tx in &pending {
        if let Err(e) = guard.recheck_pending_tx(&tx.bytes).await {
            trace!(tx_id = ?tx.id(), error = %e, "evicting stale tx");
            evict.push(tx.id());
        }
    }
    if !evict.is_empty() {
        debug!(count = evict.len(), "evicted stale transactions");
        mempool.prune(&evict);
    }
}

/// Receive gossiped transactions from peers and admit them.
pub fn spawn_tx_receiver<E: Spawner, R: Receiver + Send + 'static>(
    context: E,
    mut receiver: R,
    mempool: InMemoryMempool,
    validator: SharedValidator,
    chain_id: u64,
) -> commonware_runtime::Handle<()> {
    context.spawn(move |_| async move {
        loop {
            match receiver.recv().await {
                Ok((peer, message)) => {
                    let bytes = Bytes::copy_from_slice(message.as_ref());
                    let tx = Tx::new(bytes.clone());
                    match admit(&mempool, &validator, chain_id, bytes).await {
                        Ok(true) => trace!(tx_id = ?tx.id(), ?peer, "admitted gossiped transaction"),
                        Ok(false) => trace!(tx_id = ?tx.id(), ?peer, "duplicate gossiped transaction"),
                        Err(e) => {
                            debug!(tx_id = ?tx.id(), ?peer, error = %e, "rejected gossiped transaction")
                        }
                    }
                }
                Err(e) => {
                    warn!(error = ?e, "mempool channel closed");
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
#[path = "tx_reannouncement_tests.rs"]
mod reannouncement_tests;
