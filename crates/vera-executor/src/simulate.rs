//! Stateless dry runs of module calls: signed-as and signerless.

mod context;
pub use context::SimulationContext;

mod native;
pub use native::{
    MAX_SIMULATED_SIGNER_BYTES, NativeSimulateError, NativeSimulateRequest, NativeSimulateResult,
    simulate_native_call,
};

mod view;
pub use view::{ViewCall, ViewCallError, ViewCallResult, view_call};
