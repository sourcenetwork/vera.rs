//! Bounded read capture over an immutable module snapshot.

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use zanzibar::error::{Error, Result};

use super::{PermissionBudget, record_store::RecordStore};
use crate::kv_store::InMemoryKvStore;

/// A point read or complete prefix enumeration needed by an evaluation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordRead {
    /// Prove a key's value or absence.
    Key(Vec<u8>),
    /// Prove every record under a prefix, including archived records.
    Prefix(Vec<u8>),
}

/// Limits on evaluation reads, including repeated requests.
#[derive(Debug, Clone, Copy)]
pub struct ReadLimits {
    /// Maximum number of point reads and prefix scans.
    pub reads: usize,
    /// Maximum number of returned records across all reads.
    pub records: usize,
    /// Maximum request-key and returned record bytes; excludes proof encoding.
    pub bytes: usize,
}

/// Shared execution and proof-evaluation read budget.
pub const PERMISSION_READ_LIMITS: ReadLimits = ReadLimits {
    reads: 256,
    records: 4096,
    bytes: 1 << 20,
};

#[derive(Debug)]
struct Capture {
    remaining: ReadLimits,
    requests: BTreeSet<RecordRead>,
    failed: bool,
}

/// Captures proof requests while the shared evaluator reads one snapshot.
///
/// Clones share the capture budget and the immutable snapshot. This records
/// required reads; it does not authenticate them or produce a permission proof.
#[derive(Debug, Clone)]
pub struct ReadCapture {
    snapshot: InMemoryKvStore,
    capture: Arc<Mutex<Capture>>,
    budget: Option<PermissionBudget>,
}

impl ReadCapture {
    /// Pin a snapshot and establish a shared budget for one evaluation.
    pub fn new(snapshot: InMemoryKvStore, limits: ReadLimits) -> Self {
        Self {
            snapshot,
            budget: None,
            capture: Arc::new(Mutex::new(Capture {
                remaining: limits,
                requests: BTreeSet::new(),
                failed: false,
            })),
        }
    }

    pub(super) fn with_budget(
        snapshot: InMemoryKvStore,
        limits: ReadLimits,
        budget: PermissionBudget,
    ) -> Self {
        let mut capture = Self::new(snapshot, limits);
        capture.budget = Some(budget);
        capture
    }

    /// Return the distinct required reads, or an error if capture exceeded its budget.
    pub fn requests(&self) -> Result<Vec<RecordRead>> {
        let capture = self.capture.lock().unwrap();
        if capture.failed {
            return Err(limit_error());
        }
        Ok(capture.requests.iter().cloned().collect())
    }

    pub(crate) fn remaining_limits(&self) -> Option<ReadLimits> {
        let capture = self.capture.lock().unwrap();
        (!capture.failed).then_some(capture.remaining)
    }

    fn read<T>(
        &self,
        key: &[u8],
        request: fn(Vec<u8>) -> RecordRead,
        read: impl FnOnce(&mut ReadLimits) -> Result<T>,
    ) -> Result<T> {
        let mut capture = self.capture.lock().unwrap();
        if capture.failed {
            return Err(limit_error());
        }
        let result = (|| {
            consume(&mut capture.remaining.reads, 1)?;
            consume(&mut capture.remaining.bytes, key.len())?;
            read(&mut capture.remaining)
        })();
        match result {
            Ok(value) => {
                capture.requests.insert(request(key.to_vec()));
                Ok(value)
            }
            Err(error) => {
                capture.failed = true;
                Err(error)
            }
        }
    }
}

impl RecordStore for ReadCapture {
    fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.read(key, RecordRead::Key, |remaining| {
            let value = self.snapshot.get_ref(key);
            if let Some(budget) = &self.budget {
                budget
                    .records
                    .read(key, value)
                    .map_err(|error| Error::Serialization(error.to_string()))?;
            }
            value
                .map(|value| {
                    consume(&mut remaining.records, 1)?;
                    consume(&mut remaining.bytes, value.len())?;
                    Ok(value.to_vec())
                })
                .transpose()
        })
    }

    fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if let Some(budget) = &self.budget {
            budget
                .records
                .read(prefix, None)
                .map_err(|error| Error::Serialization(error.to_string()))?;
        }
        self.read(prefix, RecordRead::Prefix, |remaining| {
            let mut entries = Vec::new();
            for (key, value) in self.snapshot.prefix_iter(prefix) {
                if let Some(budget) = &self.budget {
                    budget
                        .records
                        .read(key, Some(value))
                        .map_err(|error| Error::Serialization(error.to_string()))?;
                }
                consume(&mut remaining.records, 1)?;
                consume(&mut remaining.bytes, key.len())?;
                consume(&mut remaining.bytes, value.len())?;
                entries.push((key.to_vec(), value.to_vec()));
            }
            Ok(entries)
        })
    }
}

fn consume(remaining: &mut usize, amount: usize) -> Result<()> {
    *remaining = remaining.checked_sub(amount).ok_or_else(limit_error)?;
    Ok(())
}

fn limit_error() -> Error {
    Error::Serialization("permission read budget exceeded".into())
}
