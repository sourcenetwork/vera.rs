//! Deterministic read accounting shared by ACP collection queries.

use std::sync::Mutex;

use super::{AcpError, Result};

#[derive(Debug)]
struct Usage {
    consumed: u64,
    exhausted: bool,
}

/// Caller-owned read allowance retained outside module rollback snapshots.
/// A point/row read costs 100 units plus one per 16 encoded key/value bytes.
/// A planned prefix or cursor seek costs 100 plus one per 16 bytes, even when empty.
#[derive(Debug)]
pub struct QueryBudget {
    limit: u64,
    usage: Mutex<Usage>,
}

impl QueryBudget {
    /// Establish an allowance after subtracting the dispatch base cost.
    pub const fn new(limit: u64) -> Self {
        Self {
            limit,
            usage: Mutex::new(Usage {
                consumed: 0,
                exhausted: false,
            }),
        }
    }

    /// Reserved work, including when the query fails or an enclosing batch rolls back.
    pub fn consumed(&self) -> u64 {
        self.usage.lock().unwrap().consumed
    }

    /// Whether a read could not reserve its allowance; exhaustion is permanent.
    pub fn is_exhausted(&self) -> bool {
        self.usage.lock().unwrap().exhausted
    }

    pub(super) fn check(&self) -> Result<()> {
        if self.is_exhausted() {
            Err(AcpError::QueryBudgetExceeded)
        } else {
            Ok(())
        }
    }

    fn charge(&self, bytes: u64) -> Result<()> {
        let cost = 100u64.saturating_add(bytes.div_ceil(16));
        let mut usage = self.usage.lock().unwrap();
        let next = usage.consumed.checked_add(cost);
        if usage.exhausted || next.is_none_or(|next| next > self.limit) {
            usage.exhausted = true;
            return Err(AcpError::QueryBudgetExceeded);
        }
        usage.consumed = next.unwrap();
        Ok(())
    }

    pub(super) fn read(&self, key: &[u8], value: Option<&[u8]>) -> Result<()> {
        self.charge((key.len() as u64).saturating_add(value.map_or(0, |v| v.len() as u64)))
    }

    pub(super) fn prefix(&self, bytes: usize) -> Result<()> {
        self.charge(bytes as u64)
    }
}

#[cfg(test)]
#[path = "query_budget_tests.rs"]
mod tests;
