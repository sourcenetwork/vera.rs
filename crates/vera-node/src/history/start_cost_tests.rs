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

    pub(super) async fn recover(&self, index: &BlockIndex, epochs: &LightBlockIndex) -> Result<()> {
        let lookup: FinalizationLookup =
            Arc::new(|_| panic!("persisted certificates must not invoke network lookup"));
        self.history
            .recover(&self.genesis, &self.head, index, epochs, &lookup)
            .await
    }
}

/// The idle revision at `height` after `parent`: an empty native revision
/// with its finalization, and the epoch artifact on the last revision of
/// every epoch. Hashes and certificates are pseudo-random so that they
/// compress like real ones.
pub(super) fn heartbeat(
    height: u64,
    parent: &Block,
    info: &crate::GenesisEpochInfo,
    epoch_length: u64,
) -> (Block, FinalizationArtifacts) {
    let noise =
        |salt: u8| alloy_primitives::keccak256([&height.to_be_bytes()[..], &[salt]].concat());
    let mut next = block(height, parent.id());
    next.state_root = StateRoot(noise(0));
    next.module_state_root = noise(1);
    next.native_targets = Some([vera_domain::DbTarget::default(); 4]);
    next.receipt_commitment = Some(vera_executor::receipt_commitment(100, &[]));
    if (height + 1).is_multiple_of(epoch_length) {
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
    (next, artifacts)
}

/// The signer's epoch artifact the idle fixtures carry.
pub(super) fn heartbeat_info() -> crate::GenesisEpochInfo {
    crate::trusted_setup(7, [ed25519::PrivateKey::from_seed(7).public_key()])
        .unwrap()
        .0
}

/// An idle deployment of [`heartbeat`] revisions, each stored through
/// `append_finalized`. Writes skip the WAL sync; reopening reads back what
/// they wrote.
pub(super) fn heartbeats(revisions: u64, epoch_length: u64) -> Heartbeats {
    let directory = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let history =
        FinalizedHistory::open_with(directory.path(), &genesis, Some(HistoryMemory::EMBEDDED))
            .unwrap();
    history.db.skip_sync_for_test();
    let info = heartbeat_info();
    let mut parent = genesis.clone();
    for height in 1..=revisions {
        let (next, artifacts) = heartbeat(height, &parent, &info, epoch_length);
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

pub(super) fn directory_bytes(path: &std::path::Path) -> u64 {
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

/// Seconds and store reads of one recovery after reopening the store.
async fn timed_recover(fixture: Heartbeats) -> (Heartbeats, f64, u64) {
    let fixture = fixture.reopen();
    let epochs = fixture.epochs();
    let reads = fixture.history.db.reads();
    let started = Instant::now();
    fixture.recover(&BlockIndex::new(), &epochs).await.unwrap();
    let seconds = started.elapsed().as_secs_f64();
    let reads = fixture.history.db.reads() - reads;
    (fixture, seconds, reads)
}

/// `HISTORY_START_REVISIONS` lists the history lengths, 10,000 and 100,000 by default.
/// Each length is recovered once without the validated head, which checks
/// every record, and then twice with it.
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
        fixture.history.db.delete(VALIDATED).unwrap();
        let bytes = directory_bytes(fixture.directory.path());
        let (fixture, full_seconds, full_reads) = timed_recover(fixture).await;
        let (fixture, validated_seconds, validated_reads) = timed_recover(fixture).await;
        let (_, again_seconds, _) = timed_recover(fixture).await;
        println!(
            "history_start_cost={}",
            serde_json::json!({
                "revisions": revisions,
                "history_bytes": bytes,
                "write_seconds": write_seconds,
                "full_seconds": full_seconds,
                "full_microseconds_per_revision": full_seconds * 1e6 / revisions as f64,
                "full_store_reads": full_reads,
                "validated_seconds": [validated_seconds, again_seconds],
                "validated_store_reads": validated_reads,
            })
        );
    }
}
