//! Executions that read committed state at the head revision and write nothing.

use alloy_primitives::U64;
use vera_domain::{NativeCallRequest, NativeCallSimulation, SimulatedLog};
use vera_executor::{
    ExecutionError, ModuleState, NativeSimulateError, NativeSimulateRequest, SimulationContext,
    simulate_native_call,
};
use vera_traits::StateDbRead;

use super::IndexedStateProvider;
use crate::error::RpcError;

impl<S> IndexedStateProvider<S> {
    /// The deployment and the head revision's height and time. Before a
    /// revision is indexed the height and time are zero.
    pub(super) fn head_context(&self) -> SimulationContext {
        let head = self
            .index
            .get_block_by_number(self.index.head_block_number());
        let (number, timestamp) = head.map_or((0, 0), |block| (block.number, block.timestamp));
        SimulationContext::at_block(&self.config, self.block_gas_limit, number, timestamp)
    }
}

impl<S: StateDbRead> IndexedStateProvider<S> {
    /// Run an execution off the async workers against a module snapshot, so it
    /// neither occupies a worker nor holds the lock finalization publishes under.
    /// A caller waits briefly for a slot behind a bounded queue; the slot stays
    /// taken until the execution ends, even if the caller leaves.
    pub(super) async fn simulate<T: Send + 'static>(
        &self,
        run: impl FnOnce(&S, &ModuleState) -> Result<T, ExecutionError> + Send + 'static,
    ) -> Result<T, RpcError> {
        let permit = self.simulations.acquire().await?;
        let modules = self
            .modules
            .read()
            .map_err(|_| RpcError::Internal("lock poisoned".to_string()))?
            .clone();
        let state = self.state.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            run(&state, &modules)
        })
        .await
        .map_err(|error| RpcError::Internal(error.to_string()))?
        .map_err(|error| RpcError::ExecutionFailed(error.to_string()))
    }

    /// Dry-run a native module call under the admission `eth_call` shares.
    pub(super) async fn simulate_native(
        &self,
        request: NativeCallRequest,
    ) -> Result<NativeCallSimulation, RpcError> {
        let request = NativeSimulateRequest::new(&request.signer, request.target, request.calldata)
            .map_err(|error: NativeSimulateError| RpcError::InvalidParams(error.to_string()))?;
        let context = self.head_context();
        let result = self
            .simulate(move |state, modules| {
                simulate_native_call(state, &context, &request, modules)
            })
            .await?;
        Ok(NativeCallSimulation {
            success: result.success,
            reason: result.reason,
            gas_used: U64::from(result.gas_used),
            output: result.output,
            logs: result
                .logs
                .into_iter()
                .map(|log| SimulatedLog {
                    address: log.address,
                    topics: log.data.topics().to_vec(),
                    data: log.data.data.clone(),
                })
                .collect(),
            block_number: U64::from(context.block_number),
            timestamp: U64::from(context.timestamp),
        })
    }
}
