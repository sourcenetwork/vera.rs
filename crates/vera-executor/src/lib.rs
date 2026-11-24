//! Block execution of native requests against the vera modules.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod config;
pub use config::ExecutionConfig;

mod context;
pub use context::BlockContext;

mod error;
pub use error::ExecutionError;

mod module_snapshot;
mod outcome;
pub use module_snapshot::ModuleSnapshot;
pub use outcome::{ExecutionOutcome, ExecutionReceipt};

pub use vera_domain::receipt_commitment;

mod executor;
#[cfg(feature = "fault-injection")]
mod faults;
pub use executor::VeraExecutor;
pub use vera_modules::module_state::{ModuleState, SharedModuleState};

mod mempool;
pub use mempool::{MempoolValidator, PreValidatedNativeTx, TxValidationResult};

mod simulate;
pub use simulate::{
    MAX_SIMULATED_SIGNER_BYTES, NativeSimulateError, NativeSimulateRequest, NativeSimulateResult,
    SimulationContext, ViewCall, ViewCallError, ViewCallResult, simulate_native_call, view_call,
};

pub mod dispatch;
pub use dispatch::VALIDATOR_REGISTRY_ADDRESS;
