//! EVM change sets, record encodings and the combined state root for vera.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod changes;
pub use changes::{AccountUpdate, ChangeSet};

mod encoding;
pub use encoding::{AccountEncoding, StorageKey};

mod root;
pub use root::StateRoot;
