//! Vera validator node: p2p, marshal, DKG orchestration, stateful execution, and RPC.
//!
//! [`run_node`] assembles the commonware actors around the vera application in
//! `vera-app` and runs them until one stops.

#![recursion_limit = "256"]

mod bootstrap;
pub use bootstrap::{
    BootstrapSettings, GenesisEpochInfo, epoch_info_hex, run_bootstrap, trusted_setup,
};

mod committed_state;
pub use committed_state::CommittedState;

mod config;
pub use config::{NodeSettings, PeerSet, PeerSetError, load_peers};

mod consts;
pub use consts::*;

mod diagnostics;

mod finalize;
pub use finalize::{index_finalized_block, subscription_data};

mod history;
pub use history::{
    FinalizedHistory, HISTORY_CHUNK_BYTES, HistoricalExecution, HistoryChunk, HistoryLimits,
    HistoryPeer, start_history_peer,
};

mod marshal_floor;
mod native_genesis;
mod node;

pub use node::run_node;

mod participants;
pub use participants::{RegistryParticipants, validator_address};

mod provider;
mod ready_application;
mod rejoin;
mod snapshot_refresh;
mod watchdog;
pub use provider::{DynamicProvider, Registrar};
pub(crate) use watchdog::run as run_watchdog;

mod secret_store;
pub use secret_store::FileSecretStore;

mod sink;
pub use sink::{FinalizationArtifacts, FinalizationLookup, NodeSink, SinkParts};

mod tx_gossip;
mod tx_reannouncement;
pub use tx_gossip::{SharedValidator, TxGossip, spawn_tx_receiver};

mod vrf_elector;
use vrf_elector::VrfElectorConfig;
