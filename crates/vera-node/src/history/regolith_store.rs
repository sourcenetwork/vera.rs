//! Regolith bindings for the history store's existing batch and snapshot operations.

use anyhow::{Result, ensure};
use std::path::Path;

#[derive(Debug)]
pub(super) struct HistoryDb(regolith::Db);

impl HistoryDb {
    pub(super) fn open_default(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
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
        Ok(self.0.get_int_property(name))
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
    fn foreign_history_is_rejected_without_changes() {
        for name in ["CURRENT", "MANIFEST-000001", "000001.sst", "unknown"] {
            let directory = tempfile::tempdir().unwrap();
            let foreign = directory.path().join(name);
            std::fs::write(&foreign, b"retained history").unwrap();
            assert!(HistoryDb::open_default(directory.path()).is_err());
            assert_eq!(std::fs::read(foreign).unwrap(), b"retained history");
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn history_subdirectory_cannot_be_a_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), directory.path().join("regolith")).unwrap();
        assert!(HistoryDb::open_default(directory.path()).is_err());
        assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
    }
}
