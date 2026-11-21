//! The executions RPC methods run against committed state.

use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;
use vera_domain::{NativeCallRequest, NativeCallSimulation, ViewCallResult};

use crate::error::RpcError;

/// Read-only executions against the committed module state at the head revision.
///
/// This abstracts away the underlying storage implementation, allowing
/// RPC methods to run them without knowing about ledger internals.
#[async_trait]
pub trait StateProvider: Send + Sync {
    /// Dry-run a native module call as the DID the request names.
    ///
    /// The DID is not authenticated and nothing is written.
    async fn simulate_native_call(
        &self,
        _request: NativeCallRequest,
    ) -> Result<NativeCallSimulation, RpcError> {
        Err(RpcError::NotImplemented)
    }

    /// Evaluate a module call that carries no signer.
    ///
    /// The answer is unauthenticated and nothing is written.
    async fn view_call(
        &self,
        _target: Address,
        _calldata: Bytes,
    ) -> Result<ViewCallResult, RpcError> {
        Err(RpcError::NotImplemented)
    }
}

/// A state provider that implements no execution.
///
/// Useful for testing or for a method table served without committed state.
#[derive(Clone, Debug, Default)]
pub struct NoopStateProvider;

#[async_trait]
impl StateProvider for NoopStateProvider {}
