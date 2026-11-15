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
use vera_consensus::{Mempool as _, TxId, components::InMemoryMempool};
use vera_domain::{NativeTx, Tx};
use vera_executor::MempoolValidator;
use vera_jsonrpc::TxSubmitError;
use vera_modules::native_account::NativeNonceStore;

use crate::{CommittedState, tx_admission::Admission};

/// Admission state over committed state, bound once the databases are open.
pub type SharedValidator = Arc<OnceLock<Mutex<Admission>>>;

/// Admits transactions locally and forwards them to peers.
pub struct TxGossip<S: Sender, E: Clock> {
    clock: Arc<E>,
    mempool: InMemoryMempool,
    validator: SharedValidator,
    chain_id: u64,
    sender: Arc<Mutex<S>>,
}

impl<S: Sender, E: Clock> Clone for TxGossip<S, E> {
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
) -> Result<bool, TxSubmitError> {
    Ok(admit_identified(mempool, validator, chain_id, bytes)
        .await?
        .is_some())
}

/// As [`admit`], returning the identifier of a newly inserted transaction so
/// the caller does not hash the request again.
async fn admit_identified(
    mempool: &InMemoryMempool,
    validator: &SharedValidator,
    chain_id: u64,
    bytes: Bytes,
) -> Result<Option<TxId>, TxSubmitError> {
    if bytes.len() > vera_domain::MAX_TX_BYTES {
        return Err(TxSubmitError::Rejected(
            "signed request exceeds its byte limit".into(),
        ));
    }
    let validator = validator.get().ok_or(TxSubmitError::NotReady)?;
    let tx = Tx::new(bytes.clone());
    let id = tx.id();
    if mempool.contains(&id) {
        return Ok(None);
    }
    let is_native = !bytes.is_empty() && NativeTx::is_native_tx(bytes[0]);
    let pre = if is_native {
        Some(
            MempoolValidator::<CommittedState>::pre_validate_native(chain_id, &bytes)
                .map_err(|error| TxSubmitError::Rejected(error.to_string()))?,
        )
    } else {
        None
    };
    let mut guard = validator.lock().await;
    if mempool.contains(&id) {
        return Ok(None);
    }
    if !mempool.can_insert(&id, &tx) {
        return Err(TxSubmitError::AtCapacity);
    }
    guard
        .reserve(pre.as_ref(), &bytes)
        .await
        .map_err(|error| TxSubmitError::Rejected(error.to_string()))?;
    let inserted = mempool.insert_with_id(id, tx);
    if inserted && let Some(pre) = pre {
        guard.remember(id, pre);
    }
    Ok(inserted.then_some(id))
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
            clock: Arc::new(clock),
            mempool,
            validator,
            chain_id,
            sender: Arc::new(Mutex::new(sender)),
        }
    }

    /// Admit a locally submitted transaction and forward it to every peer.
    pub async fn submit(&self, bytes: Bytes) -> Result<bool, TxSubmitError> {
        let inserted =
            admit_identified(&self.mempool, &self.validator, self.chain_id, bytes.clone()).await?;
        if let Some(id) = inserted {
            self.forward(id, Tx::new(bytes)).await;
        }
        Ok(inserted.is_some())
    }

    async fn forward(&self, id: TxId, tx: Tx) {
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
    let evict = guard.recheck(state, nonces, &mempool.pending()).await;
    if !evict.is_empty() {
        debug!(count = evict.len(), "evicted stale transactions");
        mempool.prune(&evict);
    }
}

/// Release what admission reserved for requests the proposer dropped from
/// the pool, so their senders are not held to a nonce that will never be used
/// until the next finalized block.
pub(crate) async fn release(mempool: &InMemoryMempool, validator: &SharedValidator) {
    let Some(validator) = validator.get() else {
        return;
    };
    let mut guard = validator.lock().await;
    let evict = guard.release_evm(&mempool.pending()).await;
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

#[cfg(test)]
#[path = "tx_admission_tests.rs"]
mod admission_tests;
