use super::*;
use regolith::env::{
    Capabilities, DiskSpace, Env, FileLock, FileMeta, JoinHandle, ReadDir, ReadFile, StdEnv,
    WriteFile, WriteMode,
};
use std::{io, path::PathBuf, sync::atomic::AtomicBool};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    PartialWrite,
    TableSync,
    ManifestSync,
}

#[derive(Debug)]
struct Fault {
    phase: Phase,
    armed: AtomicBool,
    hits: AtomicUsize,
    submitted_bytes: AtomicUsize,
    retained_bytes: AtomicUsize,
}

impl Fault {
    fn inject(&self, phase: Phase) -> bool {
        if self.phase == phase && self.armed.swap(false, Ordering::SeqCst) {
            self.hits.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }
}

fn failure() -> io::Error {
    io::Error::new(
        io::ErrorKind::StorageFull,
        "injected compaction output failure",
    )
}

struct FaultFile {
    inner: Box<dyn WriteFile>,
    fault: Arc<Fault>,
    sync_phase: Phase,
}

impl WriteFile for FaultFile {
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.sync_phase == Phase::TableSync
            && bytes.len() > 1
            && self.fault.inject(Phase::PartialWrite)
        {
            let retained = bytes.len() / 2;
            self.inner.write_all(&bytes[..retained])?;
            self.fault
                .submitted_bytes
                .store(bytes.len(), Ordering::SeqCst);
            self.fault.retained_bytes.store(retained, Ordering::SeqCst);
            return Err(failure());
        }
        self.inner.write_all(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn sync_all(&mut self) -> io::Result<()> {
        if self.fault.inject(self.sync_phase) {
            return Err(failure());
        }
        self.inner.sync_all()
    }

    fn sync_data(&mut self) -> io::Result<()> {
        if self.fault.inject(self.sync_phase) {
            return Err(failure());
        }
        self.inner.sync_data()
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
}

#[derive(Debug)]
struct FaultEnv {
    inner: StdEnv,
    fault: Arc<Fault>,
}

impl Env for FaultEnv {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<ReadDir<'_>> {
        self.inner.read_dir(path)
    }

    fn open_read(&self, path: &Path) -> io::Result<Box<dyn ReadFile>> {
        self.inner.open_read(path)
    }

    fn open_write(&self, path: &Path, mode: WriteMode) -> io::Result<Box<dyn WriteFile>> {
        let inner = self.inner.open_write(path, mode)?;
        let sync_phase = if path.extension().is_some_and(|extension| extension == "sst") {
            Some(Phase::TableSync)
        } else if path.file_name().is_some_and(|name| name == "MANIFEST") {
            Some(Phase::ManifestSync)
        } else {
            None
        };
        if let Some(sync_phase) = sync_phase {
            Ok(Box::new(FaultFile {
                inner,
                fault: self.fault.clone(),
                sync_phase,
            }))
        } else {
            Ok(inner)
        }
    }

    fn metadata(&self, path: &Path) -> io::Result<FileMeta> {
        self.inner.metadata(path)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inner.remove_file(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.rename(from, to)
    }

    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.hard_link(from, to)
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        self.inner.sync_dir(path)
    }

    fn lock_file(&self, path: &Path, exclusive: bool) -> io::Result<Box<dyn FileLock>> {
        self.inner.lock_file(path, exclusive)
    }

    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn now_micros(&self) -> Option<u64> {
        self.inner.now_micros()
    }

    fn unix_secs(&self) -> Option<u64> {
        self.inner.unix_secs()
    }

    fn spawn(
        &self,
        name: &str,
        body: Box<dyn FnOnce() + Send + 'static>,
    ) -> io::Result<Box<dyn JoinHandle>> {
        self.inner.spawn(name, body)
    }

    fn disk_space(&self, path: &Path) -> io::Result<Option<DiskSpace>> {
        self.inner.disk_space(path)
    }

    fn drop_page_cache(&self, path: &Path) {
        self.inner.drop_page_cache(path);
    }
}

fn tables(directory: &Path) -> Vec<PathBuf> {
    let mut paths = std::fs::read_dir(directory.join("regolith/sst"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sst"))
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn revision(height: u64, parent: BlockId) -> (Block, ExecutionReceipt) {
    let mut block = block(height, parent);
    let transaction = Tx::new(vec![u8::try_from(height).unwrap(); 256].into());
    let receipt = ExecutionReceipt::new(transaction.id().0, height % 2 == 1, 10, 10, vec![], None);
    block.txs.push(transaction);
    block.native_targets = Some([vera_domain::DbTarget::default(); 4]);
    block.receipt_commitment = Some(vera_executor::receipt_commitment(
        100,
        std::slice::from_ref(&receipt),
    ));
    (block, receipt)
}

fn check_records(
    history: &FinalizedHistory,
    records: &[(Block, ExecutionReceipt, Vec<u8>, Vec<u8>)],
) {
    for (block, receipt, bytes, certificate) in records {
        assert_eq!(
            history.db.get(key(RECORD, block.height)).unwrap().as_ref(),
            Some(bytes)
        );
        assert_eq!(
            history
                .db
                .get(key(CERTIFICATE, block.height))
                .unwrap()
                .as_ref(),
            Some(certificate)
        );
        let execution = history
            .execution_by_submission(receipt.tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(execution.block.id(), block.id());
        assert_eq!(execution.receipts.len(), 1);
        assert_eq!(execution.receipts[0].tx_hash, receipt.tx_hash);
        assert_eq!(execution.receipts[0].success(), receipt.success());
        assert_eq!(execution.receipts[0].gas_used, receipt.gas_used);
    }
}

#[test]
fn failed_compaction_preserves_history_receipts_and_durable_reopen() {
    for phase in [Phase::PartialWrite, Phase::TableSync, Phase::ManifestSync] {
        let directory = tempfile::tempdir().unwrap();
        let genesis = block(0, BlockId(B256::ZERO));
        drop(FinalizedHistory::open(directory.path(), &genesis).unwrap());
        let fault = Arc::new(Fault {
            phase,
            armed: AtomicBool::new(false),
            hits: AtomicUsize::new(0),
            submitted_bytes: AtomicUsize::new(0),
            retained_bytes: AtomicUsize::new(0),
        });
        let env = Arc::new(FaultEnv {
            inner: StdEnv::new(),
            fault: fault.clone(),
        });
        let history = FinalizedHistory {
            db: DB::open_for_test(directory.path(), env).unwrap(),
            head: Mutex::new((0, genesis.id())),
            metrics: None,
        };
        let mut records = Vec::new();
        let mut parent = genesis.id();
        for height in 1..=3 {
            let (block, receipt) = revision(height, parent);
            history
                .append_finalized(
                    &block,
                    std::slice::from_ref(&receipt),
                    100,
                    Some(&artifacts(height)),
                )
                .unwrap();
            history.db.flush_for_test().unwrap();
            parent = block.id();
            records.push((
                block,
                receipt,
                history.db.get(key(RECORD, height)).unwrap().unwrap(),
                history.db.get(key(CERTIFICATE, height)).unwrap().unwrap(),
            ));
        }
        let inputs = tables(directory.path());
        assert_eq!(
            inputs.len(),
            3,
            "fixture requires three flushed compaction inputs"
        );
        let before = history.db.write_statistics().unwrap();
        let head = history.db.get(HEAD).unwrap().unwrap();
        let query_head = history.db.get(QUERY_HEAD).unwrap().unwrap();
        fault.armed.store(true, Ordering::SeqCst);
        let error = history.db.compact_for_test().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected compaction output failure")
        );
        assert_eq!(
            fault.hits.load(Ordering::SeqCst),
            1,
            "missing {phase:?} witness"
        );
        if phase == Phase::PartialWrite {
            let retained = fault.retained_bytes.load(Ordering::SeqCst);
            assert!(retained > 0 && retained < fault.submitted_bytes.load(Ordering::SeqCst));
        }
        if phase == Phase::ManifestSync {
            // The uncertain manifest tail may reference output; only reopen can select it.
            let survivors = tables(directory.path());
            assert!(inputs.iter().all(|path| survivors.contains(path)));
            assert!(survivors.len() > inputs.len());
        } else {
            assert_eq!(
                tables(directory.path()),
                inputs,
                "failed compaction must remove unpublished output"
            );
        }
        assert_eq!(history.head_height(), 3);
        assert_eq!(history.db.get(HEAD).unwrap().unwrap(), head);
        assert_eq!(history.db.get(QUERY_HEAD).unwrap().unwrap(), query_head);
        check_records(&history, &records);
        if phase == Phase::ManifestSync {
            assert!(history.db.compact_for_test().is_err());
            assert_eq!(fault.hits.load(Ordering::SeqCst), 1);
        } else {
            history.db.compact_for_test().unwrap();
            assert!(
                history.db.write_statistics().unwrap().compaction_bytes > before.compaction_bytes
            );
            assert!(tables(directory.path()).len() < inputs.len());
        }
        check_records(&history, &records);
        drop(history);

        let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
        assert_eq!(history.head_height(), 3);
        check_records(&history, &records);
        history.db.compact_for_test().unwrap();
        let (next, receipt) = revision(4, parent);
        history
            .append_finalized(
                &next,
                std::slice::from_ref(&receipt),
                100,
                Some(&artifacts(4)),
            )
            .unwrap();
        drop(history);
        let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
        assert_eq!(history.head_height(), 4);
        check_records(&history, &records);
        let restored = history
            .execution_by_submission(receipt.tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(restored.block.id(), next.id());
        assert!(!restored.receipts[0].success());
    }
}
