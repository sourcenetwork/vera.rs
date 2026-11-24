//! Glue stateful application around the vera block executor.
//!
//! [`StatefulVeraApp`] implements `commonware_glue::stateful::Application`: it
//! builds blocks from the mempool, executes them against forked module state,
//! verifies proposals by re-execution, and hands finalized receipts to a
//! [`FinalizedSink`]. State bookkeeping (pending forks, apply on finalization,
//! recovery) is owned by the glue actor.

#![recursion_limit = "256"]

mod app_state;
pub use app_state::{ApplicationState, StateExecution};

mod app;
pub use app::{MAX_TIMESTAMP_STEP_SECS, StatefulVeraApp};

mod error;
pub use error::AppError;

mod genesis;
pub use genesis::genesis_block;

mod scheme;
pub use scheme::{ConsensusScheme, ReshareInput};

mod sink;
pub use sink::{FinalizedSink, NoopSink};

mod term;
pub use term::TermGuard;

mod targets;

/// Ordered native storage integrated with execution and synchronized query-state publication.
pub mod ordered_state;
