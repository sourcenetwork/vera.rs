//! Read access to EVM state for vera execution and queries.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod error;
pub use error::StateDbError;

mod state;
pub use state::StateDbRead;
