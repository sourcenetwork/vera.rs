//! Bounded policy discovery with caller-owned read accounting.

use super::{AcpError, AcpModule, Result, keys};

const MAX_IDS: usize = 128;
const MAX_BYTES: usize = 1 << 20;

/// Work allowance for policy ID listing, retained outside module rollback snapshots.
/// Each inspected record costs 100 units plus one per 16 encoded key/value bytes.
/// The lookahead beyond the record count limit charges only its key.
#[derive(Debug)]
pub struct PolicyListBudget {
    limit: u64,
    consumed: u64,
    exhausted: bool,
}

impl PolicyListBudget {
    /// Establish an allowance after subtracting the dispatch base cost.
    pub const fn new(limit: u64) -> Self {
        Self {
            limit,
            consumed: 0,
            exhausted: false,
        }
    }

    /// Reserved work, including when the listing fails or an enclosing batch rolls back.
    pub const fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Whether a read could not reserve its allowance; exhaustion is permanent.
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    fn read(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let bytes = (key.len() as u64).saturating_add(value.len() as u64);
        let cost = 100u64.saturating_add(bytes.div_ceil(16));
        let next = self.consumed.checked_add(cost);
        if self.exhausted || next.is_none_or(|next| next > self.limit) {
            self.exhausted = true;
            return Err(AcpError::PolicyListBudgetExceeded);
        }
        self.consumed = next.unwrap();
        Ok(())
    }
}

impl AcpModule {
    /// List up to 128 policy IDs within 1 MiB of stored key/value bytes.
    /// Larger listings require certified prefix pages. Runtime callers use the
    /// budgeted variant; this convenience method has no execution-work limit.
    pub fn query_policy_ids(&self) -> Result<Vec<String>> {
        self.query_policy_ids_with_budget(&mut PolicyListBudget::new(u64::MAX))
    }

    /// Bound and charge borrowed records before decoding policies and their catalogues.
    /// Errors return no partial listing and preserve consumed work in the caller's budget.
    pub fn query_policy_ids_with_budget(
        &self,
        budget: &mut PolicyListBudget,
    ) -> Result<Vec<String>> {
        if budget.is_exhausted() {
            return Err(AcpError::PolicyListBudgetExceeded);
        }
        let prefix = keys::POLICY_PREFIX;
        let mut remaining = MAX_BYTES;
        let mut records = Vec::new();
        for (key, value) in self.store.prefix_iter(prefix).take(MAX_IDS + 1) {
            if records.len() == MAX_IDS {
                budget.read(key, &[])?;
                return Err(pagination_required());
            }
            budget.read(key, value)?;
            remaining = remaining
                .checked_sub(key.len())
                .and_then(|remaining| remaining.checked_sub(value.len()))
                .ok_or_else(pagination_required)?;
            records.push((key, value));
        }
        records
            .into_iter()
            .map(|(key, value)| {
                let id = &key[prefix.len()..];
                if id.len() != 64
                    || !id
                        .iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                {
                    return Err(AcpError::State("invalid stored policy identifier".into()));
                }
                let id = String::from_utf8(id.to_vec())
                    .map_err(|_| AcpError::State("invalid stored policy identifier".into()))?;
                Self::decode_policy_record(&id, value)?;
                Ok(id)
            })
            .collect()
    }
}

fn pagination_required() -> AcpError {
    AcpError::InvalidAccessRequest {
        reason: "policy listing exceeds limit; use certified prefix pages".into(),
    }
}
