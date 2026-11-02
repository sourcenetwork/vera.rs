//! State database adapter for REVM.
//!
//! Note: REVM's `DatabaseRef` trait is synchronous, so we use `futures::executor::block_on`
//! to bridge the async StateDb traits into the sync REVM interface.

use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256, KECCAK256_EMPTY, U256};
use revm::{bytecode::Bytecode, database_interface::DatabaseRef, state::AccountInfo};
use vera_traits::{StateDbError, StateDbRead};

use crate::ExecutionError;

/// Bridge async operations into the sync REVM `DatabaseRef` interface.
///
/// Uses `tokio::task::block_in_place` when running inside a Tokio runtime
/// (e.g. RPC handlers), falling back to `futures::executor::block_on` otherwise
/// (e.g. tests without a Tokio runtime).
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(f)),
        Err(_) => futures::executor::block_on(f),
    }
}

/// Adapts a [`StateDbRead`] to REVM's [`DatabaseRef`] interface.
#[derive(Clone, Debug)]
pub struct StateDbAdapter<S> {
    state: S,
    failures: Option<Arc<Mutex<Option<StateDbError>>>>,
}

impl<S> StateDbAdapter<S> {
    /// Create a new adapter wrapping the given state.
    #[must_use]
    pub const fn new(state: S) -> Self {
        Self {
            state,
            failures: None,
        }
    }

    pub(crate) fn track_failures(mut self, failures: Arc<Mutex<Option<StateDbError>>>) -> Self {
        self.failures = Some(failures);
        self
    }

    fn record<T>(&self, result: Result<T, StateDbError>) -> Result<T, StateDbError> {
        if let Err(
            error @ (StateDbError::Storage(_)
            | StateDbError::LockPoisoned
            | StateDbError::RootComputation(_)),
        ) = &result
            && let Some(failures) = &self.failures
        {
            let mut failures = failures.lock().expect("state failure lock poisoned");
            if failures.is_none() {
                *failures = Some(error.clone());
            }
        }
        result
    }

    /// Get the underlying state reference.
    #[must_use]
    pub const fn state(&self) -> &S {
        &self.state
    }
}

impl<S: StateDbRead> DatabaseRef for StateDbAdapter<S> {
    type Error = ExecutionError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.record(block_on(self.state.nonce(&address))) {
            Ok(nonce) => {
                let balance = self.record(block_on(self.state.balance(&address)))?;
                let code_hash = self.record(block_on(self.state.code_hash(&address)))?;
                Ok(Some(AccountInfo {
                    nonce,
                    balance,
                    code_hash,
                    code: None,
                    account_id: None,
                }))
            }
            Err(StateDbError::AccountNotFound(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK256_EMPTY || code_hash == B256::ZERO {
            return Ok(Bytecode::default());
        }
        let bytes = self.record(block_on(self.state.code(&code_hash)))?;
        Ok(Bytecode::new_raw(bytes))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        match self.record(block_on(self.state.storage(&address, &index))) {
            Ok(value) => Ok(value),
            Err(StateDbError::AccountNotFound(_)) => Ok(U256::ZERO),
            Err(e) => Err(e.into()),
        }
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        // Block hash lookups not supported yet
        Ok(B256::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_new() {
        let adapter = StateDbAdapter::new(());
        assert_eq!(adapter.state(), &());
    }
}
