//! Core domain types used across vera nodes.
#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod simplex;
pub use simplex::SimplexParameters;

mod membership;
pub use membership::max_epoch_participants;

mod limits;
pub use limits::*;

mod aliases;
pub use aliases::{ConsensusContext, ConsensusDigest, PublicKey};

mod db_targets;
pub use db_targets::DbTarget;

mod block;
pub use block::{
    Block, BlockCfg, DKG_PAYLOAD_CFG, DkgDirectory, DkgPayload, DkgPayloadCfg, DkgSigner,
    DkgVariant, MAX_DKG_PARTICIPANTS,
};

mod term;
pub use term::term_extends;

mod term_certificate;
pub use term_certificate::{TermApproval, TermCertificate, TermChange, TermCut, TermError};

mod idents;
pub use idents::{BlockId, Idents, TxId};

mod native_tx;
pub use native_tx::{NATIVE_TX_TYPE, NativeTx, NativeTxPayload};

mod native_simulation;
pub use native_simulation::{NativeCallRequest, NativeCallSimulation, SimulatedLog};
mod view_call;
pub use view_call::ViewCallResult;

mod light_block;
pub use light_block::{
    ConsensusPublicKey, EpochMaterial, FinalityTrust, FinalizedArtifacts,
    LIGHT_BLOCK_MAX_ARTIFACT_BYTES, LIGHT_BLOCK_MAX_DESCENDANTS, LIGHT_BLOCK_MAX_PARTICIPANTS,
    LIGHT_BLOCK_NAMESPACE, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock, LightBlockError,
    LightConsensusScheme, verify_finalized_artifacts, verify_finalized_block,
    verify_finalized_block_unless, verify_light_block,
};

#[cfg(any(test, feature = "testing"))]
pub mod testing;

mod module_id;
pub use module_id::ModuleId;

mod gossip;
pub use gossip::GossipHeader;

mod tx;
pub use tx::{Tx, TxCfg};

#[cfg(feature = "evm")]
pub mod evm;

mod receipt;
pub use receipt::ExecutionReceipt;
mod refusal;
pub use refusal::{
    MAX_REFUSAL_MESSAGE_BYTES, Refusal, RefusalKind, RefusalMessageTooLong, RefusingModule,
};
mod receipt_commitment;
pub use receipt_commitment::receipt_commitment;
mod receipt_response;
pub use receipt_response::{RECEIPT_RESPONSE_BYTES, ReceiptResponse, ReceiptResponseError};
