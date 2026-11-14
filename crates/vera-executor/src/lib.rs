//! Block execution over REVM with the vera module precompiles.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod adapter;
pub use adapter::StateDbAdapter;

mod config;
pub use config::ExecutionConfig;

mod context;
pub use context::BlockContext;

mod envelope;

mod error;
pub use error::ExecutionError;

mod module_snapshot;
mod outcome;
pub use module_snapshot::ModuleSnapshot;
pub use outcome::{ExecutionOutcome, ExecutionReceipt};

pub use vera_domain::receipt_commitment;

mod revm;
pub use revm::{
    SpecId, build_receipt, convert_access_list, convert_authorization_list, convert_tx_kind,
    decode_evm_tx, extract_changes,
};

mod validation;
pub use validation::{
    ACCESS_LIST_ADDRESS_GAS, ACCESS_LIST_STORAGE_KEY_GAS, MAX_BLOBS_PER_TX, TX_BASE_GAS,
    TX_CREATE_GAS, TX_DATA_NON_ZERO_GAS, TX_DATA_ZERO_GAS, TxValidator, ValidatedTx,
};

mod executor;
#[cfg(feature = "fault-injection")]
mod faults;
pub use executor::VeraExecutor;
pub use vera_modules::module_state::{ModuleState, SharedModuleState};

mod mempool;
pub use mempool::{MempoolValidator, PreValidatedNativeTx, TxValidationResult};

mod simulate;
pub use simulate::{SimulateRequest, SimulateResult, estimate_gas, simulate_call};

pub mod precompiles;
pub use precompiles::VALIDATOR_REGISTRY_ADDRESS;
