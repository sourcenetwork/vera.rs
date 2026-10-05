//! Bounded policy discovery with caller-owned read accounting.

use super::{AcpError, AcpModule, QueryBudget, Result, keys};

const MAX_IDS: usize = 128;
const MAX_BYTES: usize = 1 << 20;

impl AcpModule {
    /// List up to 128 policy IDs within 1 MiB of stored key/value bytes.
    /// Larger listings require certified prefix pages. Runtime callers use the
    /// budgeted variant; this convenience method has no execution-work limit.
    pub fn query_policy_ids(&self) -> Result<Vec<String>> {
        self.query_policy_ids_with_budget(&QueryBudget::new(u64::MAX))
    }

    /// Bound and charge borrowed records before decoding policies and their catalogues.
    /// Errors return no partial listing and preserve consumed work in the caller's budget.
    pub fn query_policy_ids_with_budget(&self, budget: &QueryBudget) -> Result<Vec<String>> {
        let prefix = keys::POLICY_PREFIX;
        budget.prefix(prefix.len())?;
        let mut remaining = MAX_BYTES;
        let mut records = Vec::new();
        for (key, value) in self.store.prefix_iter(prefix).take(MAX_IDS + 1) {
            if records.len() == MAX_IDS {
                budget.read(key, None)?;
                return Err(pagination_required());
            }
            budget.read(key, Some(value))?;
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
