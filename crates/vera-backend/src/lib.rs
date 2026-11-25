//! Authenticated QMDB storage of the native module partitions.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(test, recursion_limit = "256")]

mod error;
pub use error::BackendError;

/// Runtime context the partitions are opened in.
pub type Ctx = commonware_runtime::tokio::Context;

/// Ordered native module storage and logical record changes.
pub mod native;

/// Bounded peer transport for persisted state partitions.
pub mod p2p;

#[cfg(test)]
mod power_loss_tests;
