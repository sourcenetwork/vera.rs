//! Finalized operation outcomes shared by all submitting workers.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use vera_crypto::{jwt::canonical_issuer, operation::OperationId};

use super::{AcpError, AcpModule, Result};
use crate::{kv_store::ModuleKvStore as _, types::Timestamp};

#[cfg(test)]
mod tests;

const RECORD_PREFIX: &[u8] = b"operation/v1/";
const EXPIRY_PREFIX: &[u8] = b"operation-expiry/v1/";
const BYTES_KEY: &[u8] = b"operation-bytes/v1";
const BUDGET_KEY: &[u8] = b"operation-budget/v1";
/// Default encoded outcome budget, adjustable through operator approvals.
pub const DEFAULT_OPERATION_BYTES: u64 = 64 << 20;
/// Maximum encoded outcome size, matching the native value limit.
pub const MAX_OPERATION_RECORD_BYTES: usize = 1 << 20;
/// Maximum expired references removed during one finalized block.
pub const OPERATION_PRUNE_LIMIT: usize = 128;

/// Original successful outcome, retained until its immutable execution deadline.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    /// Caller identity, including its immutable deadline.
    pub id: OperationId,
    /// Exact semantic operation digest.
    pub digest: [u8; 32],
    /// Actor spelling recorded by the original operation.
    pub actor: String,
    /// Original authenticated submission identifier.
    pub submission: [u8; 32],
    /// Worker that executed the original request.
    pub worker: String,
    /// Original execution timestamp and revision.
    pub revision: Timestamp,
    /// Exact typed command result returned by the original execution.
    pub result: serde_json::Value,
}

/// Native ACP record key. Equivalent secp256k1 key encodings share one namespace.
pub fn operation_key(actor: &str, id: OperationId) -> Result<Vec<u8>> {
    identity::Did::new(actor).map_err(|error| AcpError::State(error.to_string()))?;
    let actor = if actor.starts_with("did:key:") {
        canonical_issuer(actor).map_err(|error| AcpError::State(error.to_string()))?
    } else {
        actor.to_owned()
    };
    let mut hash = Sha256::new();
    hash.update(b"vera/operation-actor/v1\0");
    hash.update(actor.as_bytes());
    let mut key = RECORD_PREFIX.to_vec();
    key.extend_from_slice(&hash.finalize());
    key.extend_from_slice(&id.0);
    Ok(key)
}

fn expiry_key(id: OperationId, key: &[u8]) -> Vec<u8> {
    let mut index = EXPIRY_PREFIX.to_vec();
    index.extend_from_slice(&id.0[..8]);
    index.extend_from_slice(&key[RECORD_PREFIX.len()..]);
    index
}

impl AcpModule {
    /// Operator-selected encoded outcome budget, or the default before configuration.
    pub fn operation_budget(&self) -> Result<u64> {
        self.store
            .get_ref(BUDGET_KEY)
            .map_or(Ok(DEFAULT_OPERATION_BYTES), |bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| AcpError::State("invalid operation storage budget".into()))
            })
    }

    pub(crate) fn set_operation_budget(&mut self, bytes: u64) -> Result<()> {
        if bytes < MAX_OPERATION_RECORD_BYTES as u64 || bytes < self.operation_bytes()? {
            return Err(AcpError::State(
                "operation budget is below the record limit or retained usage".into(),
            ));
        }
        self.store.put(BUDGET_KEY, bytes.to_be_bytes().to_vec());
        Ok(())
    }

    /// Read a retained outcome. Inclusion does not authorize a retry.
    pub fn operation(&self, actor: &str, id: OperationId) -> Result<Option<OperationRecord>> {
        self.store
            .get(&operation_key(actor, id)?)
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|error| AcpError::State(error.to_string()))
            })
            .transpose()
    }

    pub(super) fn complete_operation(
        &mut self,
        actor: &str,
        record: &OperationRecord,
        budget: Option<&super::PolicyEditBudget>,
    ) -> Result<()> {
        let key = operation_key(actor, record.id)?;
        let bytes = match budget {
            Some(budget) => budget.encode(&key, record)?,
            None => {
                serde_json::to_vec(record).map_err(|error| AcpError::State(error.to_string()))?
            }
        };
        if bytes.len() > MAX_OPERATION_RECORD_BYTES {
            return Err(AcpError::State(
                "operation outcome exceeds the record limit".into(),
            ));
        }
        if let Some(budget) = budget {
            budget.read(BYTES_KEY, self.store.get_ref(BYTES_KEY))?;
            budget.read(BUDGET_KEY, self.store.get_ref(BUDGET_KEY))?;
        }
        let retained = self
            .operation_bytes()?
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| AcpError::State("operation storage counter overflow".into()))?;
        if retained > self.operation_budget()? {
            return Err(AcpError::State(
                "operation outcome storage budget reached".into(),
            ));
        }
        let expiry = expiry_key(record.id, &key);
        if let Some(budget) = budget {
            budget.write(&expiry, Some(&key))?;
            budget.write(BYTES_KEY, Some(&retained.to_be_bytes()))?;
        }
        self.store.put(&key, bytes);
        self.store.put(&expiry, key);
        self.store.put(BYTES_KEY, retained.to_be_bytes().to_vec());
        Ok(())
    }

    fn operation_bytes(&self) -> Result<u64> {
        self.store.get_ref(BYTES_KEY).map_or(Ok(0), |bytes| {
            bytes
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| AcpError::State("invalid operation storage counter".into()))
        })
    }

    pub(super) fn prune_operations(&mut self, now: u64) -> Result<()> {
        let mut expired = Vec::new();
        let mut removed = 0u64;
        for (index, key) in self
            .store
            .prefix_iter(EXPIRY_PREFIX)
            .take(OPERATION_PRUNE_LIMIT)
        {
            let expiry = index
                .get(EXPIRY_PREFIX.len()..EXPIRY_PREFIX.len() + 8)
                .ok_or_else(|| AcpError::State("invalid operation expiry index".into()))?;
            if expiry > now.to_be_bytes().as_slice() {
                break;
            }
            if index.len() != EXPIRY_PREFIX.len() + 72
                || key.len() != RECORD_PREFIX.len() + 64
                || !key.starts_with(RECORD_PREFIX)
                || index[EXPIRY_PREFIX.len() + 8..] != key[RECORD_PREFIX.len()..]
                || expiry != &key[RECORD_PREFIX.len() + 32..RECORD_PREFIX.len() + 40]
            {
                return Err(AcpError::State("invalid operation expiry entry".into()));
            }
            let record = self.store.get_ref(key).ok_or_else(|| {
                AcpError::State("operation outcome missing from expiry index".into())
            })?;
            removed = removed
                .checked_add(record.len() as u64)
                .ok_or_else(|| AcpError::State("operation storage counter overflow".into()))?;
            expired.push((index.to_vec(), key.to_vec()));
        }
        if expired.is_empty() {
            return Ok(());
        }
        let retained = self
            .operation_bytes()?
            .checked_sub(removed)
            .ok_or_else(|| AcpError::State("operation storage counter underflow".into()))?;
        for (index, key) in expired {
            self.store.delete(&key);
            self.store.delete(&index);
        }
        self.store.put(BYTES_KEY, retained.to_be_bytes().to_vec());
        Ok(())
    }
}
