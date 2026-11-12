//! Regolith bindings for the history store's existing batch and snapshot operations.

use anyhow::{Result, ensure};
use std::{path::Path, sync::Arc};

use super::{HistoryMemory, statistics::HistoryWriteStatistics};

/// Threads the store runs besides its callers: Regolith's compaction workers, which also flush.
pub(crate) const BACKGROUND_THREADS: usize = 1;

#[derive(Debug)]
pub(super) struct HistoryDb {
    db: regolith::Db,
    statistics: Option<Arc<regolith::Statistics>>,
}

impl HistoryDb {
    pub(super) fn open_default(
        path: impl AsRef<Path>,
        memory: Option<HistoryMemory>,
    ) -> Result<Self> {
        let statistics =
            crate::diagnostics::enabled().then(|| Arc::new(regolith::Statistics::new()));
        Self::open(path, memory, statistics)
    }

    /// `None` keeps Regolith's own cache and buffer sizes.
    pub(super) fn options(
        memory: Option<HistoryMemory>,
        statistics: Option<Arc<regolith::Statistics>>,
    ) -> regolith::Options {
        let mut options = regolith::Options::default()
            .max_background_compactions(BACKGROUND_THREADS)
            .statistics(statistics);
        if let Some(memory) = memory {
            options = options
                .block_cache_size(memory.block_cache_bytes)
                .write_buffer_size(memory.write_buffer_bytes);
        }
        options
    }

    fn open(
        path: impl AsRef<Path>,
        memory: Option<HistoryMemory>,
        statistics: Option<Arc<regolith::Statistics>>,
    ) -> Result<Self> {
        let path = path.as_ref();
        match std::fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    ensure!(
                        entry.file_name() == "regolith" && entry.file_type()?.is_dir(),
                        "unrecognized history directory"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let db = regolith::Db::open(
            path.join("regolith"),
            Self::options(memory, statistics.clone()),
        )?;
        Ok(Self { db, statistics })
    }

    pub(super) fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get(key.as_ref())?)
    }

    pub(super) fn get_pinned(&self, key: impl AsRef<[u8]>) -> Result<Option<regolith::DbSlice>> {
        Ok(self.db.get_slice(key.as_ref())?)
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        Snapshot(self.db.snapshot())
    }

    pub(super) fn is_empty(&self) -> Result<bool> {
        let snapshot = self.db.snapshot();
        let mut entries = snapshot.owned_iter().into_iter();
        let empty = entries.next().is_none();
        entries.status()?;
        Ok(empty)
    }

    pub(super) fn property_int_value(&self, name: &str) -> Result<Option<u64>> {
        Ok(self.db.get_int_property(name))
    }

    pub(super) fn wal_statistics(&self) -> Option<regolith::HistogramSnapshot> {
        self.statistics
            .as_ref()
            .map(|statistics| statistics.get_histogram_snapshot(regolith::Histogram::WalWriteTime))
    }

    pub(super) fn write_statistics(&self) -> Option<HistoryWriteStatistics> {
        self.statistics
            .as_deref()
            .map(HistoryWriteStatistics::sample)
    }

    pub(super) fn write_sync(&self, batch: WriteBatch) -> Result<()> {
        let options = regolith::WriteOptions {
            sync: true,
            ..Default::default()
        };
        // A stalled write consumes its batch without applying it; retain it for retry.
        regolith::through_stalls(|| self.db.write_opt(&options, batch.inner.clone()))?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn compact_for_test(&self) -> std::io::Result<()> {
        self.db
            .compact_range(None, None)
            .wait()
            .map_err(std::io::Error::other)
    }

    #[cfg(test)]
    pub(super) fn open_for_test(
        path: &Path,
        env: Arc<dyn regolith::Env>,
    ) -> std::result::Result<Self, regolith::Error> {
        let statistics = Some(Arc::new(regolith::Statistics::new()));
        let db = regolith::Db::open(
            path.join("regolith"),
            regolith::Options::default()
                .env(env)
                .max_background_compactions(0)
                .statistics(statistics.clone()),
        )?;
        Ok(Self { db, statistics })
    }

    #[cfg(test)]
    pub(super) fn flush_for_test(&self) -> std::result::Result<(), regolith::Error> {
        self.db.flush()
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
    fn synchronous_batch_waits_for_write_stall_and_survives_restart() {
        use std::{sync::mpsc, time::Duration};

        let directory = tempfile::tempdir().unwrap();
        let options = regolith::Options::default()
            .write_buffer_size(4 * 1024)
            .l0_compaction_trigger(1000)
            .level0_slowdown_writes_trigger(0)
            .level0_stop_writes_trigger(2)
            .max_write_buffer_number(0);
        let store = Arc::new(HistoryDb {
            db: regolith::Db::open(directory.path().join("regolith"), options).unwrap(),
            statistics: None,
        });
        for key in [b"fill1", b"fill2"] {
            regolith::through_stalls(|| store.db.put(key, b"v")).unwrap();
            store.db.flush().unwrap();
        }
        let probe = store.db.put(b"probe", b"not written");
        assert!(matches!(
            probe,
            Err(regolith::Error::WouldBlock(regolith::WouldBlock::Stall(_)))
        ));
        assert_eq!(store.get(b"probe").unwrap(), None);

        let (finished_tx, finished_rx) = mpsc::channel();
        let writer = Arc::clone(&store);
        let thread = std::thread::spawn(move || {
            let mut batch = WriteBatch::default();
            batch.put(b"key1", b"value1");
            batch.put(b"key2", b"value2");
            finished_tx.send(writer.write_sync(batch)).unwrap();
        });
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        store.db.compact_range(None, None).wait().unwrap();
        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        thread.join().unwrap();
        drop(store);

        let reopened = HistoryDb::open_default(directory.path(), None).unwrap();
        assert_eq!(
            reopened.get(b"key1").unwrap().as_deref(),
            Some(b"value1".as_slice())
        );
        assert_eq!(
            reopened.get(b"key2").unwrap().as_deref(),
            Some(b"value2".as_slice())
        );
    }

    #[test]
    fn write_statistics_preserve_sync_batches_and_restart_accounting() {
        let directory = tempfile::tempdir().unwrap();
        let db = HistoryDb::open(
            directory.path(),
            None,
            Some(Arc::new(regolith::Statistics::new())),
        )
        .unwrap();
        let before = db.write_statistics().unwrap();
        let mut batch = WriteBatch::default();
        batch.put(b"k1", b"value1");
        batch.put(b"k2", b"value2");
        db.write_sync(batch).unwrap();
        let written = db.write_statistics().unwrap();
        // The ticker counts committed user keys and values, excluding internal prefixes.
        assert_eq!(written.batch_input_bytes - before.batch_input_bytes, 16);
        assert!(written.wal_bytes > before.wal_bytes);
        assert!(written.wal_syncs > before.wal_syncs);
        assert_eq!(db.get(b"k1").unwrap().unwrap(), b"value1");
        db.compact_for_test().unwrap();
        assert!(db.write_statistics().unwrap().flush_bytes > written.flush_bytes);
        drop(db);

        let reopened = HistoryDb::open(
            directory.path(),
            None,
            Some(Arc::new(regolith::Statistics::new())),
        )
        .unwrap();
        assert_eq!(reopened.get(b"k1").unwrap().unwrap(), b"value1");
        assert_eq!(reopened.get(b"k2").unwrap().unwrap(), b"value2");
        assert_eq!(reopened.write_statistics().unwrap().batch_input_bytes, 0);
        drop(reopened);

        let uninstrumented = HistoryDb::open(directory.path(), None, None).unwrap();
        assert!(uninstrumented.write_statistics().is_none());
        assert_eq!(uninstrumented.get(b"k2").unwrap().unwrap(), b"value2");
    }

    #[test]
    fn pinned_metadata_is_separate_from_table_reader_estimates() {
        let directory = tempfile::tempdir().unwrap();
        let db = HistoryDb::open_default(directory.path(), None).unwrap();
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
            assert!(HistoryDb::open_default(directory.path(), None).is_err());
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
        assert!(HistoryDb::open_default(directory.path(), None).is_err());
        assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
    }
}
