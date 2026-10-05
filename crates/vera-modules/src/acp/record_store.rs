//! Fallible record access for permission evaluation and proof-backed readers.

use zanzibar::error::{Error, Result};

use crate::kv_store::ModuleKvStore;

/// A prepared record replacement, or removal when its value is absent.
pub type RecordChange = (Vec<u8>, Option<Vec<u8>>);

/// Record access used by the shared permission evaluator.
///
/// A missing proof must return an error, not `None` or an empty scan. Successful
/// scans must contain every record under the prefix, in key order. Readers
/// reject writes unless they explicitly implement the mutation methods.
pub trait RecordStore: Send + Sync {
    /// Read a record, distinguishing proven absence from unavailable data.
    fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Read the complete ordered set of records under a prefix.
    fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Write a record when this store supports mutation.
    fn write_record(&mut self, _key: &[u8], _value: Vec<u8>) -> Result<()> {
        Err(Error::Serialization("record store is read-only".into()))
    }

    /// Remove a record when this store supports mutation.
    fn remove_record(&mut self, _key: &[u8]) -> Result<()> {
        Err(Error::Serialization("record store is read-only".into()))
    }

    /// Prepare a copied replacement or deletion before applying a mutation plan.
    /// Metered stores reserve the complete write before copying its key/value.
    fn prepare_write(&self, key: &[u8], value: Option<&[u8]>) -> Result<RecordChange> {
        Ok((key.to_vec(), value.map(<[u8]>::to_vec)))
    }

    /// Prepare JSON without exposing an unreserved intermediate encoded buffer.
    /// The returned write is already reserved by metered implementations; applying
    /// it must not reserve the same encoding or write a second time.
    fn prepare_json<T: serde::Serialize>(&self, key: &[u8], value: &T) -> Result<RecordChange>
    where
        Self: Sized,
    {
        Ok((key.to_vec(), Some(serde_json::to_vec(value)?)))
    }

    /// Apply prepared replacements and removals atomically.
    ///
    /// Returning an error must leave every record unchanged. Writable custom stores
    /// must implement this contract; callers never fall back to individual writes.
    fn apply_records(&mut self, _changes: Vec<RecordChange>) -> Result<()> {
        Err(Error::Serialization("record store is read-only".into()))
    }
}

impl<S: ModuleKvStore> RecordStore for S {
    fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.get(key))
    }

    fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(self.prefix_scan(prefix))
    }

    fn write_record(&mut self, key: &[u8], value: Vec<u8>) -> Result<()> {
        self.put(key, value);
        Ok(())
    }

    fn remove_record(&mut self, key: &[u8]) -> Result<()> {
        self.delete(key);
        Ok(())
    }

    fn apply_records(&mut self, changes: Vec<RecordChange>) -> Result<()> {
        for (key, value) in changes {
            match value {
                Some(value) => self.put(&key, value),
                None => self.delete(&key),
            }
        }
        Ok(())
    }
}
