//! What a start costs against the length of an idle deployment's history.

use super::*;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{Signer as _, ed25519};
use std::{num::NonZeroU64, time::Instant};

/// Bytes of a solo deployment's encoded finalization, as marshal stores it.
const FINALIZATION_BYTES: usize = 236;

pub(super) struct Heartbeats {
    pub history: FinalizedHistory,
    pub genesis: Block,
    pub head: Block,
    pub epoch_length: NonZeroU64,
    pub directory: tempfile::TempDir,
}

impl Heartbeats {
    pub(super) fn epochs(&self) -> LightBlockIndex {
        LightBlockIndex::new(self.epoch_length)
    }

    pub(super) fn reopen(self) -> Self {
        let Self {
            history,
            genesis,
            head,
            epoch_length,
            directory,
        } = self;
        drop(history);
        let history =
            FinalizedHistory::open_with(directory.path(), &genesis, Some(HistoryMemory::EMBEDDED))
                .unwrap();
        Self {
            history,
            genesis,
            head,
            epoch_length,
            directory,
        }
    }

    pub(super) async fn recover(&self, epochs: &LightBlockIndex) -> Result<()> {
        let lookup: FinalizationLookup =
            Arc::new(|_| panic!("persisted certificates must not invoke network lookup"));
        self.history
            .recover(
                &self.genesis,
                &self.head,
                &BlockIndex::new(),
                epochs,
                &lookup,
            )
            .await
    }
}

/// An idle deployment: empty native revisions, each stored with its
/// finalization through `append_finalized`, and the epoch artifact on the
/// last revision of every epoch. Hashes and certificates are pseudo-random so
/// that they compress like real ones. Writes skip the WAL sync; reopening
/// reads back what they wrote.
pub(super) fn heartbeats(revisions: u64, epoch_length: u64) -> Heartbeats {
    let directory = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let history =
        FinalizedHistory::open_with(directory.path(), &genesis, Some(HistoryMemory::EMBEDDED))
            .unwrap();
    history.db.skip_sync_for_test();
    let (info, _) =
        crate::trusted_setup(7, [ed25519::PrivateKey::from_seed(7).public_key()]).unwrap();
    let mut parent = genesis.clone();
    for height in 1..=revisions {
        let noise =
            |salt: u8| alloy_primitives::keccak256([&height.to_be_bytes()[..], &[salt]].concat());
        let mut next = block(height, parent.id());
        next.state_root = StateRoot(noise(0));
        next.module_state_root = noise(1);
        next.prevrandao = noise(2);
        next.native_targets = Some([vera_domain::DbTarget::default(); 4]);
        next.receipt_commitment = Some(vera_executor::receipt_commitment(100, &[]));
        if (height + 1) % epoch_length == 0 {
            let mut info = info.clone();
            info.epoch = Epoch::new((height + 1) / epoch_length);
            next.payload = Some(Payload::EpochInfo(info));
        }
        let artifacts = FinalizationArtifacts {
            epoch: height / epoch_length,
            finalization: (0..FINALIZATION_BYTES.div_ceil(32) as u8)
                .flat_map(|salt| noise(salt.wrapping_add(3)).0)
                .take(FINALIZATION_BYTES)
                .collect(),
            certificate: Vec::new(),
        };
        history
            .append_finalized(&next, &[], 100, Some(&artifacts))
            .unwrap();
        parent = next;
    }
    Heartbeats {
        history,
        genesis,
        head: parent,
        epoch_length: NonZeroU64::new(epoch_length).unwrap(),
        directory,
    }
}

fn directory_bytes(path: &std::path::Path) -> u64 {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directory_bytes(&entry.path())
            } else {
                entry.metadata().unwrap().len()
            }
        })
        .sum()
}

/// `HISTORY_START_REVISIONS` lists the history lengths, 10,000 and 100,000 by default.
#[tokio::test]
#[ignore = "start-up cost is measured on demand with a release build"]
async fn start_cost_against_history_length() {
    let lengths = std::env::var("HISTORY_START_REVISIONS")
        .unwrap_or_else(|_| "10000,100000".into())
        .split(',')
        .map(|length| length.trim().parse::<u64>().unwrap())
        .collect::<Vec<_>>();
    for revisions in lengths {
        let written = Instant::now();
        let fixture = heartbeats(revisions, crate::SOLO_BLOCKS_PER_EPOCH);
        let write_seconds = written.elapsed().as_secs_f64();
        let fixture = fixture.reopen();
        let bytes = directory_bytes(fixture.directory.path());
        let epochs = fixture.epochs();
        let reads = fixture.history.db.reads();
        let started = Instant::now();
        fixture.recover(&epochs).await.unwrap();
        let seconds = started.elapsed().as_secs_f64();
        let reads = fixture.history.db.reads() - reads;
        let fixture = fixture.reopen();
        let epochs = fixture.epochs();
        let again = Instant::now();
        fixture.recover(&epochs).await.unwrap();
        let second = again.elapsed().as_secs_f64();
        println!(
            "history_start_cost={}",
            serde_json::json!({
                "revisions": revisions,
                "history_bytes": bytes,
                "write_seconds": write_seconds,
                "recover_seconds": seconds,
                "recover_microseconds_per_revision": seconds * 1e6 / revisions as f64,
                "store_reads": reads,
                "second_recover_seconds": second,
            })
        );
    }
}
