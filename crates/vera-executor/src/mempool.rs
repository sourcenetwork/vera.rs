//! Mempool admission of native requests, with branched sequence state.
//!
//! Sequential validations from the same signer see each other's sequence
//! increments.

use alloy_primitives::B256;
use vera_crypto::bls;
use vera_domain::NativeTx;
use vera_modules::module_state::SharedModuleState;
use vera_modules::native_account::NativeNonceStore;
use vera_modules::vera::anchors::AnchorError;

use crate::dispatch::{ANCHOR_ADDRESS, anchor::named_deployment};
use crate::executor::native_authentication::{authenticate_native_tx, decode_native_tx};
use crate::{ExecutionConfig, ExecutionError};

/// Result of validating a request for mempool admission.
#[derive(Clone, Debug)]
pub struct TxValidationResult {
    /// The signer's `did:key:`.
    pub sender: String,
    /// Request nonce.
    pub nonce: u64,
}

/// Pre-validated native BLS transaction.
///
/// Contains the results of expensive stateless validation (BLS signature
/// verification and DID derivation) so that the stateful nonce check can
/// run separately inside the mutex without repeating the crypto work.
#[derive(Clone, Debug)]
pub struct PreValidatedNativeTx {
    /// `did:key:` identifier derived from the BLS public key.
    pub signer_did: String,
    /// Transaction nonce from the wire format.
    pub nonce: u64,
    /// The deployment an anchor request names; `None` for any other request.
    pub anchored: Option<AnchorTarget>,
}

/// What a request to the anchor module is submitted for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorTarget {
    /// A call that names this deployment.
    Deployment(B256),
    /// A call that names none: execution refuses it.
    Unknown,
}

fn anchor_target(native_tx: &NativeTx) -> Option<AnchorTarget> {
    (native_tx.target == ANCHOR_ADDRESS).then(|| {
        named_deployment(&native_tx.calldata)
            .map_or(AnchorTarget::Unknown, AnchorTarget::Deployment)
    })
}

/// Stateful request validator — mempool admission gate.
///
/// Maintains branched state across calls so sequential validations
/// from the same signer see each other's nonce increments.
/// Call [`MempoolValidator::reset`] after each block finalization.
#[derive(Clone, Debug)]
pub struct MempoolValidator {
    config: ExecutionConfig,
    native_nonces: NativeNonceStore,
    committed: Option<SharedModuleState>,
}

impl MempoolValidator {
    /// Create a new mempool validator for the deployment.
    pub fn new(config: ExecutionConfig) -> Self {
        Self {
            config,
            native_nonces: NativeNonceStore::default(),
            committed: None,
        }
    }

    /// Admit anchor requests against the submitter grants in `modules`, the
    /// committed module state. Without it, anchor requests are admitted and
    /// left to execution.
    #[must_use]
    pub fn with_committed_modules(mut self, modules: SharedModuleState) -> Self {
        self.committed = Some(modules);
        self
    }

    /// Refuse an anchor request whose signer has no grant for the deployment
    /// it names, or no quota left today by this node's clock.
    fn admit_anchor(&self, pre: &PreValidatedNativeTx) -> Result<(), ExecutionError> {
        let (Some(target), Some(committed)) = (pre.anchored, &self.committed) else {
            return Ok(());
        };
        let refused = |deployment, reason: &dyn std::fmt::Display| {
            Err(ExecutionError::AnchorNotAdmitted {
                signer: pre.signer_did.clone(),
                deployment,
                reason: reason.to_string(),
            })
        };
        let AnchorTarget::Deployment(deployment) = target else {
            return refused(B256::ZERO, &"the call names no deployment");
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let modules = committed.read().expect("module state lock poisoned");
        match modules.vera.anchor_submitter(&deployment, &pre.signer_did) {
            Ok(Some(grant)) if grant.remaining(now) > 0 => Ok(()),
            Ok(Some(grant)) => refused(
                deployment,
                &AnchorError::QuotaExceeded { quota: grant.quota },
            ),
            Ok(None) => refused(deployment, &AnchorError::NotGranted),
            Err(error) => refused(deployment, &error),
        }
    }

    /// Reset branched state after block finalization.
    ///
    /// Native nonces are loaded from the finalized module state so the
    /// validator correctly rejects replayed nonces and accepts the next
    /// valid nonce for each BLS identity. Recheck retained transactions in
    /// admission order before accepting new requests.
    pub fn reset(&mut self, native_nonces: NativeNonceStore) {
        self.native_nonces = native_nonces;
    }

    /// Recheck an immutable request already authenticated at admission.
    ///
    /// Call once per retained request, in admission order, after [`Self::reset`],
    /// so a retained request keeps its place behind the signer's earlier ones.
    /// Signature verification is skipped; a caller that kept the
    /// [`PreValidatedNativeTx`] from admission can call [`Self::admit_native`]
    /// instead and skip decoding too.
    pub fn recheck_pending_tx(&mut self, tx_bytes: &[u8]) -> Result<(), ExecutionError> {
        native_request(tx_bytes)?;
        let native_tx = decode_native_tx(self.config.chain_id, tx_bytes)?;
        let signer_did = bls::did_from_compressed_pubkey(native_tx.bls_pubkey.as_slice())
            .map_err(|e| ExecutionError::BlsVerification(format!("pubkey: {e}")))?;
        self.admit_native(&PreValidatedNativeTx {
            signer_did,
            nonce: native_tx.nonce,
            anchored: anchor_target(&native_tx),
        })?;
        Ok(())
    }

    /// Stateless pre-validation for native BLS transactions.
    ///
    /// Performs decode, chain ID check, target check, BLS signature
    /// verification, and DID derivation — all without needing mutable
    /// state. Call this **outside** the ledger mutex, then pass the
    /// result to [`admit_native`] inside the mutex for the nonce check.
    ///
    /// [`admit_native`]: Self::admit_native
    pub fn pre_validate_native(
        chain_id: u64,
        tx_bytes: &[u8],
    ) -> Result<PreValidatedNativeTx, ExecutionError> {
        native_request(tx_bytes)?;
        let authenticated = authenticate_native_tx(chain_id, tx_bytes)?;
        Ok(PreValidatedNativeTx {
            anchored: anchor_target(&authenticated.native_tx),
            signer_did: authenticated.signer_did,
            nonce: authenticated.native_tx.nonce,
        })
    }

    /// Admit a pre-validated native BLS transaction into branched state.
    ///
    /// Performs the nonce check and, for an anchor request, the grant check:
    /// all expensive crypto was already done by [`pre_validate_native`]. Call
    /// this inside the mutex.
    ///
    /// [`pre_validate_native`]: Self::pre_validate_native
    pub fn admit_native(
        &mut self,
        pre: &PreValidatedNativeTx,
    ) -> Result<TxValidationResult, ExecutionError> {
        self.admit_anchor(pre)?;
        self.native_nonces
            .check_and_increment(&pre.signer_did, pre.nonce)?;

        Ok(TxValidationResult {
            sender: pre.signer_did.clone(),
            nonce: pre.nonce,
        })
    }

    /// Validate a request for mempool admission.
    ///
    /// On success, increments the signer's nonce in the branched state.
    /// Prefer [`pre_validate_native`] + [`admit_native`] to avoid holding
    /// locks during BLS verification.
    ///
    /// [`pre_validate_native`]: Self::pre_validate_native
    /// [`admit_native`]: Self::admit_native
    pub fn validate_tx(&mut self, tx_bytes: &[u8]) -> Result<TxValidationResult, ExecutionError> {
        let pre = Self::pre_validate_native(self.config.chain_id, tx_bytes)?;
        self.admit_native(&pre)
    }
}

/// A request is admitted only in the native envelope.
fn native_request(tx_bytes: &[u8]) -> Result<(), ExecutionError> {
    match tx_bytes.first() {
        None => Err(ExecutionError::TxDecode("empty transaction".to_string())),
        Some(byte) if NativeTx::is_native_tx(*byte) => Ok(()),
        Some(_) => Err(ExecutionError::TxDecode("not a native request".to_string())),
    }
}

#[cfg(test)]
mod tests;
