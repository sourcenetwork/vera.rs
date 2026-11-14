//! Block and transaction indexer for vera RPC queries.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod error;
pub use error::IndexerError;

mod filter;
pub use filter::LogFilter;

mod light_block_store;
pub use light_block_store::{
    LightBlockIndex, LightBlockStats, MAX_CACHED_EPOCHS, MAX_CACHED_FINALIZATIONS,
    StoredEpochMaterial, StoredFinalization,
};

mod store;
pub use store::{BlockIndex, IndexedRevision, MAX_CACHED_REVISIONS};

mod log_query;
pub use log_query::{LogQuery, MAX_LOG_SELECTOR_ALTERNATIVES, MAX_LOG_TOPIC_POSITIONS};

mod types;
pub use types::{
    IndexQuery, IndexStats, IndexedBlock, IndexedLog, IndexedReceipt, IndexedTransaction,
};
