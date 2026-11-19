//! Finalized operation outcomes shared by all submitting workers.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use vera_crypto::{jwt::canonical_actor, operation::OperationId};

pub use super::operation_budget::{DEFAULT_OPERATION_BYTES, OutcomeClass};
use super::{AcpError, AcpModule, Result};
use crate::{kv_store::ModuleKvStore as _, types::Timestamp};

#[cfg(test)]
mod tests;

const RECORD_PREFIX: &[u8] = b"operation/v1/";
const EXPIRY_PREFIX: &[u8] = b"operation-expiry/v1/";
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
    /// Canonical DID of the actor that authorized the original operation.
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

/// Native ACP record key. Equivalent encodings of one key share one namespace.
pub fn operation_key(actor: &str, id: OperationId) -> Result<Vec<u8>> {
    vera_identity::Did::new(actor).map_err(|error| AcpError::State(error.to_string()))?;
    let actor = if actor.starts_with("did:key:") {
        canonical_actor(actor).map_err(|error| AcpError::State(error.to_string()))?
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
        let class = OutcomeClass::of(record.id, record.revision.seconds);
        if let Some(budget) = budget {
            budget.read(class.bytes_key(), self.store.get_ref(class.bytes_key()))?;
            budget.read(class.budget_key(), self.store.get_ref(class.budget_key()))?;
        }
        let retained = self
            .operation_bytes(class)?
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| AcpError::State("operation storage counter overflow".into()))?;
        if retained > self.class_budget(class)? {
            return Err(AcpError::State(
                "operation outcome storage budget reached".into(),
            ));
        }
        let expiry = expiry_key(record.id, &key);
        let mut index = key.clone();
        index.push(class.tag());
        if let Some(budget) = budget {
            budget.write(&expiry, Some(&index))?;
            budget.write(class.bytes_key(), Some(&retained.to_be_bytes()))?;
        }
        self.store.put(&key, bytes);
        self.store.put(&expiry, index);
        self.store
            .put(class.bytes_key(), retained.to_be_bytes().to_vec());
        Ok(())
    }

    pub(super) fn prune_operations(&mut self, now: u64) -> Result<()> {
        let mut expired = Vec::new();
        let mut removed = [0u64; 2];
        for (index, value) in self
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
            let (key, tag) = value
                .split_last_chunk::<1>()
                .ok_or_else(|| AcpError::State("invalid operation expiry entry".into()))?;
            if index.len() != EXPIRY_PREFIX.len() + 72
                || key.len() != RECORD_PREFIX.len() + 64
                || !key.starts_with(RECORD_PREFIX)
                || index[EXPIRY_PREFIX.len() + 8..] != key[RECORD_PREFIX.len()..]
                || expiry != &key[RECORD_PREFIX.len() + 32..RECORD_PREFIX.len() + 40]
            {
                return Err(AcpError::State("invalid operation expiry entry".into()));
            }
            let class = OutcomeClass::from_tag(tag[0])?;
            let record = self.store.get_ref(key).ok_or_else(|| {
                AcpError::State("operation outcome missing from expiry index".into())
            })?;
            let total = &mut removed[usize::from(class.tag())];
            *total = total
                .checked_add(record.len() as u64)
                .ok_or_else(|| AcpError::State("operation storage counter overflow".into()))?;
            expired.push((index.to_vec(), key.to_vec()));
        }
        let mut counters = Vec::new();
        for class in [OutcomeClass::Short, OutcomeClass::Long] {
            let bytes = removed[usize::from(class.tag())];
            if bytes != 0 {
                let retained = self
                    .operation_bytes(class)?
                    .checked_sub(bytes)
                    .ok_or_else(|| AcpError::State("operation storage counter underflow".into()))?;
                counters.push((class.bytes_key(), retained));
            }
        }
        for (index, key) in expired {
            self.store.delete(&key);
            self.store.delete(&index);
        }
        for (key, retained) in counters {
            self.store.put(key, retained.to_be_bytes().to_vec());
        }
        Ok(())
    }
}
