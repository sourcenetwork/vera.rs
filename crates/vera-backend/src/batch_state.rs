//! EVM state view over pending glue batches.
//!
//! [`BatchState`] lets the block executor read through a set of unmerkleized
//! batches (pending writes on top of committed state) and turns an executed
//! [`ChangeSet`] into batch writes ready to merkleize.

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use commonware_glue::stateful::db::Unmerkleized as _;
use tokio::sync::Mutex;
use vera_qmdb::{AccountEncoding, ChangeSet, StorageKey as StorageSlotKey};
use vera_traits::{StateDbError, StateDbRead};

use crate::{
    BackendError,
    state_set::{VeraMerkleized, VeraUnmerkleized},
    types::{AccountKey, AccountValue, CodeKey, StorageKey, StorageValue},
};

type AccountRecord = (u64, U256, B256, u64);

/// Pending EVM state: committed databases plus the batches forked for one block.
#[derive(Clone)]
pub struct BatchState {
    batches: Arc<Mutex<Option<VeraUnmerkleized>>>,
}

impl std::fmt::Debug for BatchState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchState").finish_non_exhaustive()
    }
}

const fn account_key(address: Address) -> AccountKey {
    AccountKey::new(address.into_array())
}

const fn code_key(hash: B256) -> CodeKey {
    CodeKey::new(hash.0)
}

fn storage_key(address: Address, generation: u64, slot: U256) -> StorageKey {
    StorageKey::new(StorageSlotKey::new(address, generation, slot).to_bytes())
}

fn storage_err(e: impl std::fmt::Display) -> StateDbError {
    StateDbError::Storage(e.to_string())
}

fn batches_taken() -> StateDbError {
    StateDbError::Storage("batches already taken".into())
}

fn decode_account(value: &AccountValue) -> Result<AccountRecord, StateDbError> {
    AccountEncoding::decode(&value.0)
        .ok_or_else(|| StateDbError::Storage("undecodable account record".into()))
}

impl BatchState {
    /// Wrap batches forked for one block.
    pub fn new(batches: VeraUnmerkleized) -> Self {
        Self {
            batches: Arc::new(Mutex::new(Some(batches))),
        }
    }

    /// Take the batches back out once execution is done.
    pub async fn into_batches(self) -> Result<VeraUnmerkleized, BackendError> {
        self.batches
            .lock()
            .await
            .take()
            .ok_or(BackendError::NotInitialized)
    }

    async fn record(&self, address: &Address) -> Result<Option<AccountRecord>, StateDbError> {
        let guard = self.batches.lock().await;
        let batches = guard.as_ref().ok_or_else(batches_taken)?;
        let record = batches
            .0
            .get(&account_key(*address))
            .await
            .map_err(storage_err)?;
        record.as_ref().map(decode_account).transpose()
    }

    async fn require_account(&self, address: &Address) -> Result<AccountRecord, StateDbError> {
        self.record(address)
            .await?
            .ok_or(StateDbError::AccountNotFound(*address))
    }

    /// Write an executed change set into the batches, returning them for merkleization.
    pub async fn apply_changes(
        mut batches: VeraUnmerkleized,
        changes: &ChangeSet,
    ) -> Result<VeraUnmerkleized, BackendError> {
        for (address, update) in &changes.accounts {
            let key = account_key(*address);
            let stored = match batches.0.get(&key).await {
                Ok(Some(value)) => AccountEncoding::decode(&value.0),
                Ok(None) => None,
                Err(e) => return Err(BackendError::Storage(e.to_string())),
            };
            let current_generation = stored.map_or(0, |(_, _, _, generation)| generation);
            let generation = if update.created || update.selfdestructed {
                current_generation.saturating_add(1)
            } else {
                current_generation
            };

            if update.selfdestructed {
                batches.0 = batches.0.write(key, None);
            } else {
                let encoded = AccountEncoding::encode(
                    update.nonce,
                    update.balance,
                    update.code_hash,
                    generation,
                );
                batches.0 = batches.0.write(key, Some(AccountValue(encoded)));
                let stored_code_hash = stored.map(|(_, _, code_hash, _)| code_hash);
                if let Some(code) = &update.code
                    && update.code_hash != KECCAK256_EMPTY
                    && stored_code_hash != Some(update.code_hash)
                {
                    batches.2 = batches
                        .2
                        .write(code_key(update.code_hash), Some(code.clone()));
                }

                for (slot, value) in &update.storage {
                    let key = storage_key(*address, generation, *slot);
                    let value = (!value.is_zero()).then_some(StorageValue(*value));
                    batches.1 = batches.1.write(key, value);
                }
            }
        }
        Ok(batches)
    }

    /// Merkleize the three batches.
    pub async fn merkleize(batches: VeraUnmerkleized) -> Result<VeraMerkleized, BackendError> {
        let (accounts, storage, code) = batches;
        let accounts = accounts
            .merkleize()
            .await
            .map_err(|e| BackendError::Storage(format!("{e:?}")))?;
        let storage = storage
            .merkleize()
            .await
            .map_err(|e| BackendError::Storage(format!("{e:?}")))?;
        let code = code
            .merkleize()
            .await
            .map_err(|e| BackendError::Storage(format!("{e:?}")))?;
        Ok((accounts, storage, code))
    }
}

impl StateDbRead for BatchState {
    async fn nonce(&self, address: &Address) -> Result<u64, StateDbError> {
        Ok(self.require_account(address).await?.0)
    }

    async fn balance(&self, address: &Address) -> Result<U256, StateDbError> {
        Ok(self.require_account(address).await?.1)
    }

    async fn code_hash(&self, address: &Address) -> Result<B256, StateDbError> {
        Ok(self.require_account(address).await?.2)
    }

    async fn account(&self, address: &Address) -> Result<Option<(u64, U256, B256)>, StateDbError> {
        Ok(self
            .record(address)
            .await?
            .map(|(nonce, balance, code_hash, _)| (nonce, balance, code_hash)))
    }

    async fn code(&self, code_hash: &B256) -> Result<Bytes, StateDbError> {
        let guard = self.batches.lock().await;
        let batches = guard.as_ref().ok_or_else(batches_taken)?;
        batches
            .2
            .get(&code_key(*code_hash))
            .await
            .map_err(storage_err)?
            .map(Bytes::from)
            .ok_or(StateDbError::CodeNotFound(*code_hash))
    }

    async fn storage(&self, address: &Address, slot: &U256) -> Result<U256, StateDbError> {
        let guard = self.batches.lock().await;
        let batches = guard.as_ref().ok_or_else(batches_taken)?;
        let record = batches
            .0
            .get(&account_key(*address))
            .await
            .map_err(storage_err)?;
        let Some((_, _, _, generation)) = record.as_ref().map(decode_account).transpose()? else {
            return Ok(U256::ZERO);
        };
        let value = batches
            .1
            .get(&storage_key(*address, generation, *slot))
            .await
            .map_err(storage_err)?;
        Ok(value.map_or(U256::ZERO, |v| v.0))
    }
}
