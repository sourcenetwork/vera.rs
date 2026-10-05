//! Input and authorization accounting for policy commands.

use std::io;

use super::{AcpError, PermissionBudget, Result, types::SuppliedMetadata};

/// Caller-owned command allowance shared across every owner/manager evaluation.
/// Inputs cost eight units per 16 bytes; authorization reads and steps use the
/// permission prices. Relationship point storage and retained delegated outcomes
/// use the existing record prices. Archive's bulk scan/removals remain separate.
#[derive(Clone, Debug)]
pub struct CommandBudget {
    pub(super) permissions: PermissionBudget,
}

impl CommandBudget {
    /// Establish an allowance after subtracting the dispatch base cost.
    pub fn new(limit: u64) -> Self {
        Self {
            permissions: PermissionBudget::new(limit),
        }
    }

    /// Work consumed even when a command fails or its state is rolled back.
    pub fn consumed(&self) -> u64 {
        self.permissions.consumed()
    }

    /// Whether any reservation failed; exhaustion is permanent across clones.
    pub fn is_exhausted(&self) -> bool {
        self.permissions.is_exhausted()
    }

    /// Reserve raw input before owned ABI/JSON decoding or copying identifiers.
    pub fn input(&self, bytes: usize) -> Result<()> {
        self.finish(self.permissions.records.definition(bytes))
    }

    pub(super) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        if self.is_exhausted() {
            Err(AcpError::CommandBudgetExceeded)
        } else {
            result
        }
    }

    pub(super) fn encoded_input(&self, value: &impl serde::Serialize) -> Result<()> {
        self.encode_input(value, None)
    }

    pub(super) fn metadata(&self, value: &SuppliedMetadata) -> Result<()> {
        self.encode_input(value, Some(64 << 10))
    }

    fn encode_input(&self, value: &impl serde::Serialize, maximum: Option<usize>) -> Result<()> {
        let result = serde_json::to_writer(
            InputSize {
                budget: self,
                bytes: 0,
                maximum,
            },
            value,
        );
        self.finish(result.map_err(|error| {
            if maximum.is_some() {
                AcpError::InvalidAccessRequest {
                    reason: "metadata exceeds 64 KiB".into(),
                }
            } else {
                AcpError::State(error.to_string())
            }
        }))
    }
}

// Stream typed inputs into a counter, reserving each encoded quantum without an
// owned JSON validation copy. This also pays for subsequent delegated hashing.
struct InputSize<'a> {
    budget: &'a CommandBudget,
    bytes: usize,
    maximum: Option<usize>,
}
impl io::Write for InputSize<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("input size overflow"))?;
        let quanta = next.div_ceil(16) - self.bytes.div_ceil(16);
        self.budget
            .input(quanta.saturating_mul(16))
            .map_err(io::Error::other)?;
        if self.maximum.is_some_and(|maximum| next > maximum) {
            return Err(io::Error::other("metadata exceeds 64 KiB"));
        }
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "command_budget_tests.rs"]
mod tests;
