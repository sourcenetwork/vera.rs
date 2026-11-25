//! Indexed state provider for production RPC use.
//!
//! Runs read-only module executions against committed state at the head
//! revision the block indexer names.

use std::sync::Arc;

use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;
use vera_indexer::BlockIndex;

use vera_domain::{NativeCallRequest, NativeCallSimulation, ViewCallResult};
use vera_executor::{ExecutionConfig, SharedModuleState};

mod simulation;

use crate::{error::RpcError, simulation_slots::SimulationSlots, state_provider::StateProvider};

/// State provider that runs module executions against live committed state.
///
/// Uses [`BlockIndex`] for the head revision's height and time and the shared
/// module values for the call.
#[derive(Debug)]
pub struct IndexedStateProvider {
    index: Arc<BlockIndex>,
    config: ExecutionConfig,
    block_gas_limit: u64,
    modules: SharedModuleState,
    simulations: SimulationSlots,
}

impl IndexedStateProvider {
    /// Creates a provider that executes under the deployment's execution
    /// configuration, which binds the genesis record and the membership limit
    /// module calls observe. A view call may use `block_gas_limit` gas.
    #[must_use]
    pub fn new(
        index: Arc<BlockIndex>,
        config: ExecutionConfig,
        block_gas_limit: u64,
        modules: SharedModuleState,
    ) -> Self {
        Self {
            index,
            config,
            block_gas_limit,
            modules,
            simulations: SimulationSlots::default(),
        }
    }
}

impl Clone for IndexedStateProvider {
    fn clone(&self) -> Self {
        Self {
            index: Arc::clone(&self.index),
            config: self.config.clone(),
            block_gas_limit: self.block_gas_limit,
            modules: Arc::clone(&self.modules),
            simulations: self.simulations.clone(),
        }
    }
}

#[async_trait]
impl StateProvider for IndexedStateProvider {
    async fn simulate_native_call(
        &self,
        request: NativeCallRequest,
    ) -> Result<NativeCallSimulation, RpcError> {
        self.simulate_native(request).await
    }

    async fn view_call(
        &self,
        target: Address,
        calldata: Bytes,
    ) -> Result<ViewCallResult, RpcError> {
        self.view(target, calldata).await
    }
}

#[cfg(test)]
#[path = "indexed_provider/simulation_tests.rs"]
mod simulation_tests;

#[cfg(test)]
#[path = "indexed_provider/view_tests.rs"]
mod view_tests;

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use vera_executor::{ModuleState, VALIDATOR_REGISTRY_ADDRESS};

    use super::*;
    use crate::simulation_slots::{SIMULATION_SLOTS, SIMULATION_WAITERS};

    fn default_modules() -> SharedModuleState {
        Arc::new(RwLock::new(ModuleState::default()))
    }

    #[tokio::test]
    async fn simulations_run_off_the_module_lock_under_bounded_admission() {
        let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
        let (release, gate) = std::sync::mpsc::channel();
        let modules = default_modules();
        let provider = IndexedStateProvider::new(
            Arc::new(BlockIndex::new()),
            ExecutionConfig::new(1),
            30_000_000,
            modules.clone(),
        );
        let members = || {
            (
                VALIDATOR_REGISTRY_ADDRESS,
                Bytes::copy_from_slice(&alloy_primitives::keccak256("getValidators()")[..4]),
            )
        };
        let running = provider.clone();
        let call = tokio::spawn(async move {
            running
                .simulate(move |_, _| {
                    entered.send(()).unwrap();
                    gate.recv().unwrap();
                    Ok(())
                })
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entries.recv())
            .await
            .unwrap()
            .unwrap();
        // Finalization publishes module state while the execution is still running.
        drop(
            modules
                .try_write()
                .expect("simulation must not hold the module lock"),
        );
        let mut others = Vec::new();
        for _ in 1..SIMULATION_SLOTS {
            others.push(provider.simulations.acquire().await.unwrap());
        }
        let queued = provider.clone();
        let waiting = tokio::spawn(async move {
            let (target, calldata) = members();
            queued.view_call(target, calldata).await
        });
        wait_for_waiters(&provider.simulations, 1).await;
        assert!(!waiting.is_finished());
        let waiters: Vec<_> = (1..SIMULATION_WAITERS)
            .map(|_| {
                let slots = provider.simulations.clone();
                tokio::spawn(async move { slots.acquire().await.map(drop) })
            })
            .collect();
        wait_for_waiters(&provider.simulations, SIMULATION_WAITERS).await;
        let (target, calldata) = members();
        let busy: jsonrpsee::types::ErrorObjectOwned = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            provider.view_call(target, calldata),
        )
        .await
        .expect("a full queue must refuse without waiting for a slot")
        .unwrap_err()
        .into();
        assert_eq!(busy.code(), crate::error::codes::RESOURCE_UNAVAILABLE);
        assert_eq!(busy.data().unwrap().get(), r#"{"retryable":true}"#);
        release.send(()).unwrap();
        call.await.unwrap().unwrap();
        assert_eq!(waiting.await.unwrap().unwrap().refusal, None);
        drop(others);
        for waiter in waiters {
            waiter.await.unwrap().unwrap();
        }
    }

    /// Returns once `waiters` callers queue behind fully occupied slots.
    async fn wait_for_waiters(slots: &SimulationSlots, waiters: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while slots.free_places() != SIMULATION_WAITERS - waiters {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
