//! Shared Vera proof and header types.

use std::sync::Arc;

use alloy_primitives::B256;

pub use vera_domain::{
    ConsensusPublicKey, ExecutionReceipt, GossipHeader, LightBlock, ModuleId, ReceiptResponse,
    ReceiptResponseError, Refusal, RefusalKind, RefusingModule, TermCertificate,
};

/// A value authenticated against one finalized module root.
#[derive(Debug, Clone)]
pub struct VerifiedRecord {
    /// The record's value, or `None` for authenticated absence.
    pub value: Option<Arc<[u8]>>,
    /// Module root the record was verified against.
    pub module_state_root: B256,
    /// Height of the revision that certifies the root.
    pub verified_at_height: u64,
    /// The record evidence, when it is kept with the value.
    pub proof: Option<vera_permission::RecordProof>,
}

/// A submission's receipt, committed by a revision authenticated against configured trust.
#[derive(Debug, Clone)]
pub struct VerifiedReceipt {
    /// The receipt committed by the revision.
    pub receipt: ExecutionReceipt,
    /// The revision that commits the receipt.
    pub revision: crate::SyncState,
}
