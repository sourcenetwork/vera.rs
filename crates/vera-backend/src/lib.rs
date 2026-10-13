//! Concrete storage backend for vera QMDB.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(test, recursion_limit = "256")]

mod types;
pub use types::{AccountKey, AccountValue, CodeKey, StorageKey, StorageValue};

mod batch_state;
pub use batch_state::BatchState;

mod error;
pub use error::BackendError;

mod state_set;
pub use state_set::{
    AccountsDb, CodeDb, Ctx, MerkleizedTriple, StorageDb, VeraConfig, VeraDatabases,
    VeraMerkleized, VeraReaders, VeraStateSet, VeraSyncTargets, VeraUnmerkleized, combined_root,
    state_set_config,
};

/// Ordered native module storage and logical record changes.
pub mod native;

/// Bounded peer transport for persisted state partitions.
pub mod p2p;

#[cfg(test)]
mod power_loss_tests;
