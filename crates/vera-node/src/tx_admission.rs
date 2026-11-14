//! Admission state shared by RPC, gossip and the post-finalization recheck.

use std::collections::HashMap;

use tracing::trace;
use vera_consensus::TxId;
use vera_domain::Tx;
use vera_executor::{ExecutionError, MempoolValidator, PreValidatedNativeTx};
use vera_modules::native_account::NativeNonceStore;

use crate::CommittedState;

/// The mempool validator with the signer and nonce of each pending native request.
///
/// A request's bytes never change, so the signer derived at admission stays
/// valid for as long as the request is pending and a recheck only replays
/// its nonce reservation.
#[derive(Debug)]
pub struct Admission {
    validator: MempoolValidator<CommittedState>,
    native: HashMap<TxId, PreValidatedNativeTx>,
}

impl Admission {
    /// Wrap a validator that has no pending requests.
    #[must_use]
    pub fn new(validator: MempoolValidator<CommittedState>) -> Self {
        Self {
            validator,
            native: HashMap::new(),
        }
    }

    /// Reserve the sender's next nonce for a request about to enter the pool.
    pub(crate) async fn reserve(
        &mut self,
        pre: Option<&PreValidatedNativeTx>,
        bytes: &[u8],
    ) -> Result<(), ExecutionError> {
        match pre {
            Some(pre) => self.validator.admit_native(pre).map(drop),
            None => self.validator.validate_tx(bytes).await.map(drop),
        }
    }

    /// Keep a native request's admission result while it is pending.
    pub(crate) fn remember(&mut self, id: TxId, pre: PreValidatedNativeTx) {
        self.native.insert(id, pre);
    }

    /// Reset to committed state and replay `pending` in its admission order.
    ///
    /// Returns the requests that no longer validate.
    pub(crate) async fn recheck(
        &mut self,
        state: CommittedState,
        nonces: NativeNonceStore,
        pending: &[(TxId, Tx)],
    ) -> Vec<TxId> {
        self.validator.reset(state, nonces);
        let mut remembered = std::mem::take(&mut self.native);
        let mut stale = Vec::new();
        for (id, tx) in pending {
            let result = match remembered.remove(id) {
                Some(pre) => self.validator.admit_native(&pre).map(|_| {
                    self.native.insert(*id, pre);
                }),
                None => self.validator.recheck_pending_tx(&tx.bytes).await,
            };
            if let Err(error) = result {
                trace!(tx_id = ?id, %error, "evicting stale tx");
                stale.push(*id);
            }
        }
        stale
    }

    /// Rebuild EVM reservations from `pending` after requests left the pool
    /// without a finalized block. Native reservations are kept.
    ///
    /// Returns the requests that no longer validate.
    pub(crate) async fn release_evm(&mut self, pending: &[(TxId, Tx)]) -> Vec<TxId> {
        self.validator.release_evm_reservations();
        let mut stale = Vec::new();
        for (id, tx) in pending {
            if tx.is_native() {
                continue;
            }
            if let Err(error) = self.validator.recheck_pending_tx(&tx.bytes).await {
                trace!(tx_id = ?id, %error, "evicting stale tx");
                stale.push(*id);
            }
        }
        stale
    }

    #[cfg(test)]
    pub(crate) fn remembered(&self) -> usize {
        self.native.len()
    }
}
