//! Glue stateful application around the vera block executor.
//!
//! [`StatefulVeraApp`] implements `commonware_glue::stateful::Application`: it
//! builds blocks from the mempool, executes them against forked QMDB batches,
//! verifies proposals by re-execution, and hands finalized receipts to a
//! [`FinalizedSink`]. State bookkeeping (pending forks, apply on finalization,
//! recovery) is owned by the glue actor.

#![recursion_limit = "256"]

mod app_state;
pub use app_state::{ApplicationState, StateExecution};

mod app;
pub use app::StatefulVeraApp;

mod vrf_cache;
pub use vrf_cache::VrfSeedCache;

mod error;
pub use error::AppError;

mod execute;
pub use execute::{Executed, execute_block};

mod genesis;
pub use genesis::{apply_genesis, genesis_block};

mod scheme;
pub use scheme::{ConsensusScheme, ReshareInput};

mod sink;
pub use sink::{FinalizedSink, NoopSink};

mod targets;
pub use targets::{db_targets_from_merkleized, db_targets_from_sync, sync_targets};

/// Ordered native storage integrated with execution and synchronized query-state publication.
pub mod ordered_state;
