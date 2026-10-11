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

mod commitment;
pub use commitment::{AccountChange, StateChanges, StateChangesCfg};

mod events;
pub use events::{LedgerEvent, LedgerEvents};

mod db_targets;
pub use db_targets::{DbTarget, DbTargets};

mod block;
pub use block::{
    Block, BlockCfg, DKG_PAYLOAD_CFG, DkgDirectory, DkgPayload, DkgPayloadCfg, DkgSigner,
    DkgVariant, MAX_DKG_PARTICIPANTS,
};

mod idents;
pub use idents::{BlockId, Idents, StateRoot, TxId};

mod native_tx;
pub use native_tx::{NATIVE_TX_TYPE, NativeTx, NativeTxPayload};

mod light_block;
pub use light_block::{
    ConsensusPublicKey, EpochMaterial, LIGHT_BLOCK_MAX_ARTIFACT_BYTES, LIGHT_BLOCK_MAX_DESCENDANTS,
    LIGHT_BLOCK_MAX_PARTICIPANTS, LIGHT_BLOCK_NAMESPACE, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock,
    LightBlockError, LightConsensusScheme, verify_finalized_block, verify_light_block,
};

mod module_id;
pub use module_id::ModuleId;

mod gossip;
pub use gossip::{GOSSIP_HEADER_SIZE, GossipHeader};

mod tx;
pub use tx::{Tx, TxCfg};

#[cfg(feature = "evm")]
pub mod evm;

mod receipt;
pub use receipt::ExecutionReceipt;
mod receipt_commitment;
pub use receipt_commitment::receipt_commitment;
mod receipt_response;
pub use receipt_response::{RECEIPT_RESPONSE_BYTES, ReceiptResponse, ReceiptResponseError};
