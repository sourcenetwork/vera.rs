//! Regolith bindings for the history store's existing batch and snapshot operations.

use anyhow::{Result, ensure};
use std::path::Path;

#[derive(Debug)]
pub(super) struct HistoryDb(regolith::Db);

impl HistoryDb {
    pub(super) fn open_default(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        ensure!(
            rocksdb::DB::list_cf(&rocksdb::Options::default(), path).is_err(),
            "RocksDB history requires explicit migration before selecting Regolith"
        );
        match std::fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    ensure!(
                        entry.file_name() == "regolith" && entry.file_type()?.is_dir(),
                        "unrecognized history directory; explicit migration is required"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self(regolith::Db::open(
            path.join("regolith"),
            regolith::Options::default(),
        )?))
    }

    pub(super) fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key.as_ref())?)
    }

    pub(super) fn get_pinned(&self, key: impl AsRef<[u8]>) -> Result<Option<regolith::DbSlice>> {
        Ok(self.0.get_slice(key.as_ref())?)
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        Snapshot(self.0.snapshot())
    }

    pub(super) fn is_empty(&self) -> Result<bool> {
        let snapshot = self.0.snapshot();
        let mut entries = snapshot.owned_iter().into_iter();
        let empty = entries.next().is_none();
        entries.status()?;
        Ok(empty)
    }

    pub(super) fn property_int_value(&self, name: &str) -> Result<Option<u64>> {
        let property = match name {
            "rocksdb.size-all-mem-tables" => "regolith.cur-size-all-mem-tables",
            "rocksdb.block-cache-usage" => "regolith.block-cache-usage",
            "regolith.pinned-metadata-bytes" => "regolith.pinned-metadata-bytes",
            _ => return Ok(None),
        };
        Ok(self.0.get_int_property(property))
    }

    pub(super) fn write_sync(&self, batch: WriteBatch) -> Result<()> {
        self.0.write_opt(
            &regolith::WriteOptions {
                sync: true,
                ..Default::default()
            },
            batch.inner,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn compact_for_test(&self) -> std::io::Result<()> {
        self.0
            .compact_range(None, None)
            .map_err(std::io::Error::other)
    }

    #[cfg(test)]
    pub(super) fn put(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<()> {
        let mut batch = WriteBatch::default();
        batch.put(key, value);
        self.write_sync(batch)
    }

    #[cfg(test)]
    pub(super) fn delete(&self, key: impl AsRef<[u8]>) -> Result<()> {
        let mut batch = WriteBatch::default();
        batch.delete(key);
        self.write_sync(batch)
    }
}

pub(super) struct Snapshot(regolith::Snapshot);

impl Snapshot {
    pub(super) fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key.as_ref())?)
    }

    pub(super) fn get_pinned(&self, key: impl AsRef<[u8]>) -> Result<Option<regolith::DbSlice>> {
        Ok(self.0.get_slice(key.as_ref())?)
    }
}

#[derive(Default)]
pub(super) struct WriteBatch {
    inner: regolith::WriteBatch,
    bytes: usize,
}

impl WriteBatch {
    pub(super) fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        self.bytes = self
            .bytes
            .saturating_add(key.as_ref().len())
            .saturating_add(value.as_ref().len())
            .saturating_add(16);
        self.inner.put(key.as_ref(), value.as_ref());
    }

    pub(super) fn delete(&mut self, key: impl AsRef<[u8]>) {
        self.bytes = self
            .bytes
            .saturating_add(key.as_ref().len())
            .saturating_add(16);
        self.inner.delete(key.as_ref());
    }

    pub(super) fn delete_range<K: AsRef<[u8]>>(&mut self, start: K, end: K) {
        self.bytes = self
            .bytes
            .saturating_add(start.as_ref().len())
            .saturating_add(end.as_ref().len())
            .saturating_add(16);
        self.inner.delete_range(start.as_ref(), end.as_ref());
    }

    pub(super) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Payload estimate used to flush recovery batches without scanning their entries.
    pub(super) const fn size_in_bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_metadata_is_separate_from_table_reader_estimates() {
        let directory = tempfile::tempdir().unwrap();
        let db = HistoryDb::open_default(directory.path()).unwrap();
        assert_eq!(
            db.property_int_value("regolith.pinned-metadata-bytes")
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            db.property_int_value("rocksdb.estimate-table-readers-mem")
                .unwrap(),
            None
        );
    }

    #[test]
    fn existing_rocksdb_history_is_rejected_without_changes() {
        let directory = tempfile::tempdir().unwrap();
        {
            let db = rocksdb::DB::open_default(directory.path()).unwrap();
            db.put(b"history", b"retained").unwrap();
        }
        let contents = || {
            std::fs::read_dir(directory.path())
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), std::fs::read(entry.path()).unwrap())
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let before = contents();
        assert!(HistoryDb::open_default(directory.path()).is_err());
        assert_eq!(contents(), before);
    }
}
