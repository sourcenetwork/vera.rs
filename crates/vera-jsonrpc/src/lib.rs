//! JSON-RPC server for vera nodes.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod archive;
pub use archive::{ArchiveReader, IndexLookup};

mod error;
pub use error::{RpcError, TxSubmitError, codes as error_codes};

mod tx_submit;
pub use tx_submit::TxSubmitCallback;

mod header_subscribe;

mod vera_api;
pub use vera_api::{
    AncestryProofLookup, LightBlockLookup, ReceiptProofLookup, VeraApiImpl, VeraApiServer,
};

#[cfg(feature = "nuclei-rpc")]
mod nuclei_transport;

mod local;
pub use local::{LocalRpc, LocalRpcError, LocalSubscription};

mod server;
pub use server::{RpcServer, RpcServerHandle, ServerError};

mod simulation_slots;

mod state;
pub use state::{NodeState, NodeStatus};

mod state_provider;
pub use state_provider::{NoopStateProvider, StateProvider};

mod indexed_provider;
pub use indexed_provider::IndexedStateProvider;

mod types;
pub use types::{RpcLog, RpcTransactionReceipt};

#[cfg(test)]
mod local_tests;

#[cfg(test)]
mod transport_tests;
