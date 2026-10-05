//! Deterministic accounting for one policy edit, outside module rollback snapshots.

use super::{AcpError, Result, record_store::RecordStore};
use crate::kv_store::InMemoryKvStore;
use serde::Serialize;
use std::{io, sync::Mutex};

const BYTE_QUANTUM: u64 = 16;

#[derive(Debug)]
struct Usage {
    consumed: u64,
    exhausted: bool,
}

/// A caller-owned work allowance for policy compilation, indexed reads and writes.
/// One point read costs 100 units plus one per 16 encoded bytes; a write costs
/// 200 plus two per 16 bytes. Definition bytes cost eight per 16 bytes and each
/// visited relation pair costs 32. This is deterministic accounting, not elapsed
/// time; parser expansion and compiler depth limits remain independently enforced.
#[derive(Debug)]
pub struct PolicyEditBudget {
    limit: u64,
    usage: Mutex<Usage>,
}

impl PolicyEditBudget {
    /// Establish a fresh allowance. Execution callers subtract their dispatch base first.
    pub const fn new(limit: u64) -> Self {
        Self {
            limit,
            usage: Mutex::new(Usage {
                consumed: 0,
                exhausted: false,
            }),
        }
    }

    /// Work already performed, including when an edit fails or rolls back.
    pub fn consumed(&self) -> u64 {
        self.usage.lock().unwrap().consumed
    }

    /// Whether any operation could not reserve its work allowance.
    pub fn is_exhausted(&self) -> bool {
        self.usage.lock().unwrap().exhausted
    }

    fn charge(&self, amount: u64) -> Result<()> {
        let mut usage = self.usage.lock().unwrap();
        let next = usage.consumed.checked_add(amount);
        if usage.exhausted || next.is_none_or(|next| next > self.limit) {
            usage.exhausted = true;
            return Err(AcpError::PolicyEditBudgetExceeded);
        }
        usage.consumed = next.unwrap();
        Ok(())
    }

    pub(super) fn definition(&self, bytes: usize) -> Result<()> {
        self.charge((bytes as u64).div_ceil(BYTE_QUANTUM).saturating_mul(8))
    }

    pub(super) fn pair(&self) -> Result<()> {
        self.charge(32)
    }

    pub(super) fn read(&self, key: &[u8], value: Option<&[u8]>) -> Result<()> {
        let bytes = (key.len() as u64).saturating_add(value.map_or(0, |value| value.len() as u64));
        self.charge(100u64.saturating_add(bytes.div_ceil(BYTE_QUANTUM)))
    }

    pub(super) fn write(&self, key: &[u8], value: Option<&[u8]>) -> Result<()> {
        let bytes = (key.len() as u64).saturating_add(value.map_or(0, |value| value.len() as u64));
        self.charge(200u64.saturating_add(bytes.div_ceil(BYTE_QUANTUM).saturating_mul(2)))
    }

    pub(super) fn encode_borsh(
        &self,
        key: &[u8],
        value: &impl borsh::BorshSerialize,
    ) -> Result<Vec<u8>> {
        self.write(key, None)?;
        let mut output = BudgetedEncoding {
            budget: self,
            key_bytes: key.len(),
            bytes: Vec::new(),
        };
        borsh::to_writer(&mut output, value).map_err(|error| {
            if self.is_exhausted() {
                AcpError::PolicyEditBudgetExceeded
            } else {
                AcpError::State(error.to_string())
            }
        })?;
        Ok(output.bytes)
    }

    pub(super) fn encode(&self, key: &[u8], value: &impl Serialize) -> Result<Vec<u8>> {
        self.write(key, None)?;
        let mut output = BudgetedEncoding {
            budget: self,
            key_bytes: key.len(),
            bytes: Vec::new(),
        };
        serde_json::to_writer(&mut output, value).map_err(|error| {
            if self.is_exhausted() {
                AcpError::PolicyEditBudgetExceeded
            } else {
                AcpError::State(error.to_string())
            }
        })?;
        Ok(output.bytes)
    }
}

struct BudgetedEncoding<'a> {
    budget: &'a PolicyEditBudget,
    key_bytes: usize,
    bytes: Vec<u8>,
}

impl io::Write for BudgetedEncoding<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let before = (self.key_bytes as u64).saturating_add(self.bytes.len() as u64);
        let after = before.saturating_add(buffer.len() as u64);
        let additional = after
            .div_ceil(BYTE_QUANTUM)
            .saturating_sub(before.div_ceil(BYTE_QUANTUM));
        if additional != 0 {
            self.budget
                .charge(additional.saturating_mul(2))
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct EditRecords<'a> {
    pub(super) store: &'a InMemoryKvStore,
    pub(super) budget: &'a PolicyEditBudget,
}

impl EditRecords<'_> {
    pub(super) fn first_exists(&self, prefix: &[u8]) -> Result<bool> {
        self.budget.read(prefix, None)?;
        let first = self.store.prefix_iter(prefix).next();
        if let Some((key, value)) = first {
            self.budget.read(key, Some(value))?;
        }
        Ok(first.is_some())
    }
}

impl RecordStore for EditRecords<'_> {
    fn read_record(&self, key: &[u8]) -> zanzibar::error::Result<Option<Vec<u8>>> {
        let value = self.store.get_ref(key);
        self.budget
            .read(key, value)
            .map_err(|error| zanzibar::error::Error::Serialization(error.to_string()))?;
        Ok(value.map(<[u8]>::to_vec))
    }

    fn scan_records(&self, _prefix: &[u8]) -> zanzibar::error::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Err(zanzibar::error::Error::Serialization(
            "policy edits require indexed point reads".into(),
        ))
    }
}

#[cfg(test)]
#[path = "policy_edit_budget_tests.rs"]
mod tests;
