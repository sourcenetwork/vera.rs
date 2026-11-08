//! Cryptographic utilities for vera.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod did_key;

pub mod bls;
pub mod jwt;
pub mod operation;
pub mod secp256k1;
pub mod threshold;
