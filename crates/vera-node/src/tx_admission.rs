//! Admission state shared by RPC, gossip and the post-finalization recheck.

use std::collections::HashMap;

use tracing::trace;
use vera_consensus::TxId;
use vera_domain::Tx;
use vera_executor::{ExecutionError, MempoolValidator, PreValidatedNativeTx};
use vera_modules::native_account::NativeNonceStore;

/// The mempool validator with the signer and nonce of each pending native request.
///
/// A request's bytes never change, so the signer derived at admission stays
/// valid for as long as the request is pending and a recheck only replays
/// its nonce reservation.
#[derive(Debug)]
pub struct Admission {
    validator: MempoolValidator,
    native: HashMap<TxId, PreValidatedNativeTx>,
}

impl Admission {
    /// Wrap a validator that has no pending requests.
    #[must_use]
    pub fn new(validator: MempoolValidator) -> Self {
        Self {
            validator,
            native: HashMap::new(),
        }
    }

    /// Reserve the signer's next nonce for a request about to enter the pool.
    pub(crate) fn reserve(&mut self, pre: &PreValidatedNativeTx) -> Result<(), ExecutionError> {
        self.validator.admit_native(pre).map(drop)
    }

    /// Keep a native request's admission result while it is pending.
    pub(crate) fn remember(&mut self, id: TxId, pre: PreValidatedNativeTx) {
        self.native.insert(id, pre);
    }

    /// Reset to committed state and replay `pending` in its admission order.
    ///
    /// Returns the requests that no longer validate.
    pub(crate) fn recheck(
        &mut self,
        nonces: NativeNonceStore,
        pending: &[(TxId, Tx)],
    ) -> Vec<TxId> {
        self.validator.reset(nonces);
        let mut remembered = std::mem::take(&mut self.native);
        let mut stale = Vec::new();
        for (id, tx) in pending {
            let result = match remembered.remove(id) {
                Some(pre) => self.validator.admit_native(&pre).map(|_| {
                    self.native.insert(*id, pre);
                }),
                None => self.validator.recheck_pending_tx(&tx.bytes),
            };
            if let Err(error) = result {
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
