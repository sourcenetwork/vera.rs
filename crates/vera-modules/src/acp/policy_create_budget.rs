//! Caller-owned work accounting for policy creation and retained outcomes.

use std::io;

use super::{AcpError, PolicyEditBudget, Result, SuppliedMetadata};

/// Creation allowance retained outside rollback snapshots. Definition and input
/// processing cost eight units per 16 bytes; record reads and writes use policy
/// edit prices. Parser expansion limits remain independently enforced.
#[derive(Debug)]
pub struct PolicyCreateBudget {
    pub(super) records: PolicyEditBudget,
}

impl PolicyCreateBudget {
    /// Establish an allowance after subtracting the dispatch base cost.
    pub const fn new(limit: u64) -> Self {
        Self {
            records: PolicyEditBudget::new(limit),
        }
    }
    /// Work completed, including ordinary errors and rolled-back attempts.
    pub fn consumed(&self) -> u64 {
        self.records.consumed()
    }
    /// Whether a reservation failed; exhaustion is permanent.
    pub fn is_exhausted(&self) -> bool {
        self.records.is_exhausted()
    }
    /// Reserve input processing before ABI/JSON decoding or policy compilation.
    pub fn input(&self, bytes: usize) -> Result<()> {
        self.finish(self.records.definition(bytes))
    }
    pub(super) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        if self.is_exhausted() {
            Err(AcpError::PolicyCreateBudgetExceeded)
        } else {
            result
        }
    }

    pub(super) fn metadata(&self, value: &SuppliedMetadata) -> Result<()> {
        // Each entry has at least five encoded bytes, before its key/value text.
        // Reject impossible sizes before walking or serializing unbounded input.
        let mut raw = value
            .blob
            .len()
            .saturating_add(value.attributes.len().saturating_mul(5));
        self.input(raw)?;
        if raw > MAX_METADATA_BYTES {
            return Err(metadata_error());
        }
        for (key, value) in &value.attributes {
            let bytes = key.len().saturating_add(value.len());
            self.input(bytes)?;
            raw = raw.saturating_add(bytes);
            if raw > MAX_METADATA_BYTES {
                return Err(metadata_error());
            }
        }
        // Count the exact existing JSON limit without allocating a validation copy.
        serde_json::to_writer(MetadataSize(0), value).map_err(|_| metadata_error())
    }
}

const MAX_METADATA_BYTES: usize = 64 << 10;
fn metadata_error() -> AcpError {
    AcpError::InvalidAccessRequest {
        reason: "metadata exceeds 64 KiB".into(),
    }
}
struct MetadataSize(usize);
impl io::Write for MetadataSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_METADATA_BYTES)
            .ok_or_else(|| io::Error::other("metadata exceeds 64 KiB"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
