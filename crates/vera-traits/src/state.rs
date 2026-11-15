//! State database traits for consensus-facing operations.

use std::future::Future;

use alloy_primitives::{Address, B256, Bytes, U256};

use crate::StateDbError;

/// Read-only access to blockchain state.
///
/// Provides account, storage, and code lookups without mutation.
pub trait StateDbRead: Clone + Send + Sync + 'static {
    /// Get account nonce.
    fn nonce(&self, address: &Address) -> impl Future<Output = Result<u64, StateDbError>> + Send;

    /// Get account balance.
    fn balance(&self, address: &Address)
    -> impl Future<Output = Result<U256, StateDbError>> + Send;

    /// Get account code hash.
    fn code_hash(
        &self,
        address: &Address,
    ) -> impl Future<Output = Result<B256, StateDbError>> + Send;

    /// Get an account's nonce, balance and code hash, or `None` when it does not exist.
    ///
    /// Backends that store the three together answer with one lookup.
    fn account(
        &self,
        address: &Address,
    ) -> impl Future<Output = Result<Option<(u64, U256, B256)>, StateDbError>> + Send {
        let address = *address;
        async move {
            let nonce = match self.nonce(&address).await {
                Ok(nonce) => nonce,
                Err(StateDbError::AccountNotFound(_)) => return Ok(None),
                Err(e) => return Err(e),
            };
            let balance = self.balance(&address).await?;
            let code_hash = self.code_hash(&address).await?;
            Ok(Some((nonce, balance, code_hash)))
        }
    }

    /// Get account code by hash.
    fn code(&self, code_hash: &B256) -> impl Future<Output = Result<Bytes, StateDbError>> + Send;

    /// Get storage slot value.
    fn storage(
        &self,
        address: &Address,
        slot: &U256,
    ) -> impl Future<Output = Result<U256, StateDbError>> + Send;
}
