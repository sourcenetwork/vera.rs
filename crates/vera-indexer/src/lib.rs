//! Revision and request indexer for vera RPC queries.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod error;
pub use error::IndexerError;

mod light_block_store;
pub use light_block_store::{
    LightBlockIndex, LightBlockStats, MAX_CACHED_EPOCHS, MAX_CACHED_FINALIZATIONS,
    StoredEpochMaterial, StoredFinalization,
};

mod store;
pub use store::{BlockIndex, IndexedRevision, MAX_CACHED_REVISIONS};

mod types;
pub use types::{
    IndexQuery, IndexStats, IndexedBlock, IndexedLog, IndexedReceipt, IndexedTransaction,
};
