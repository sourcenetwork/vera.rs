//! Configuration types for vera nodes.
#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/vera.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod discovery;
pub use discovery::{DiscoveryConfig, DiscoveryConfigError, HandshakeRate};

mod error;
pub use error::ConfigError;

mod explicit;

mod execution;
pub use execution::{DEFAULT_GAS_LIMIT, ExecutionConfig};

mod network;
pub use network::{DEFAULT_LISTEN_ADDR, NetworkConfig};

mod node;
pub use node::{DEFAULT_CHAIN_ID, DEFAULT_DATA_DIR, NodeConfig, PruningConfig, SnapshotConfig};

mod rpc;
pub use rpc::{DEFAULT_HTTP_ADDR, DEFAULT_WS_ADDR, RpcConfig};
