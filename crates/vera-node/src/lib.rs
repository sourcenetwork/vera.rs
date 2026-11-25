//! Vera validator node: p2p, marshal, DKG orchestration, stateful execution, and RPC.
//!
//! [`run_node`] assembles the commonware actors around the vera application in
//! `vera-app` and runs them until one stops.

#![recursion_limit = "256"]

mod allocator_memory;
mod bootstrap;
pub use bootstrap::{
    BootstrapSettings, GenesisEpochInfo, epoch_info_hex, run_bootstrap, trusted_setup,
};

mod config;
mod connectivity;
mod consensus_timeouts;
mod devices;
pub use config::{NodeSettings, PeerSet, PeerSetError, load_peers};

mod consts;
pub use consts::*;

mod diagnostics;
mod finalization_diagnostics;
mod finalization_metrics;

mod embedded;
pub use embedded::{
    Backup, DeviceRole, EmbedError, EmbeddedConfig, EmbeddedNode, ThreadBudget, ThreadSetup,
};

mod term;
pub use term::{Contest, Device, Switching, TermRefusal, TermSeat};

mod finalize;
pub use finalize::index_finalized_block;

mod history;
pub use history::{
    DiscardedSubmission, FinalizedHistory, HISTORY_CHUNK_BYTES, HISTORY_MAINTENANCE_INTERVAL,
    HistoricalExecution, HistoryChunk, HistoryLimits, HistoryMemory, HistoryPeer, HistoryPruned,
    RetentionTooShort, UnsupportedHistoryFormat, check_history_retention,
    minimum_history_retention, start_history_peer,
};

#[cfg(feature = "fault-injection")]
mod crash;
mod marshal;
mod native_genesis;
mod node;

pub use node::{run_node, run_node_with_options, run_node_with_rpc_listener};

mod options;
pub use options::{NodeOptions, RpcMode, SoloPacing, WatchdogMode};
mod sizing;
pub use sizing::NodeSizing;

mod participants;
pub use participants::{RegistryParticipants, validator_address};

mod peer_capacity;
mod peer_discovery;

mod proposal_hold;
pub use proposal_hold::ProposalHold;
mod epoch_replay;
mod idle_pacing;
mod provider;
mod ready_application;
mod rejoin;
mod replay;
mod snapshot_refresh;
mod watchdog;
pub use provider::{DynamicProvider, Registrar};
pub(crate) use watchdog::run as run_watchdog;

mod secret_store;
pub use secret_store::FileSecretStore;

mod solo;
pub use solo::{
    DeviceKey, SOLO_BLOCKS_PER_EPOCH, SOLO_STALL_TIMEOUT_MS, SoloDeployment, SoloError,
    SoloGenesis, SoloKeys, prepare_solo,
};

mod sink;
pub use sink::{FinalizationArtifacts, FinalizationLookup, NodeSink, SinkParts};

mod tx_admission;
mod tx_gossip;
mod tx_reannouncement;
pub use tx_admission::Admission;
pub use tx_gossip::{SharedValidator, TxGossip, spawn_tx_receiver};

mod term_elector;
