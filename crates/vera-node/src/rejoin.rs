//! Rejoin recovery for a restart stranded behind peer retention.
//!
//! A completed state sync permanently skips peer synchronization on later
//! boots. If the node was offline (or crashed) long enough that every peer
//! pruned its floor, that skip strands the node: consensus cannot advance
//! without newer epoch material, and backfill cannot fetch pruned blocks.
//! Recovery re-arms peer state sync by discarding the sync bookkeeping so the
//! node re-synchronizes from a current floor.

use std::path::Path;

use crate::node::PARTITION_PREFIX;

/// Partition holding the stateful syncer's completed-sync marker.
const STATE_SYNC_METADATA: &str = "state_sync_metadata";
/// Partition holding the DKG state-sync transcript.
const DKG_STATE_SYNC: &str = "_dkg_state_sync";

/// Epochs beyond which a restart cannot recover by advancing through
/// reshare ceremonies one epoch at a time.
///
/// A node a few epochs behind follows the gossiped reshare mailboxes forward;
/// a node farther behind can no longer verify any live traffic and must
/// re-engage peer state sync from a current floor.
pub(crate) const REJOIN_EPOCHS: u64 = 3;

/// Whether a restart must re-engage peer state sync: the network is farther
/// ahead than sequential reshare advancement can cover.
///
/// Smaller gaps must NOT resync: ceremonies run every epoch, and a resync
/// landing mid-ceremony costs the network that node's dealing — with another
/// peer down, quorum is lost entirely. Nodes close behind follow boundary
/// ceremonies forward; the progress watchdog covers the case where following
/// stalls instead of catching up.
pub(crate) const fn stranded(our_epoch: u64, network_epoch: u64) -> bool {
    network_epoch.saturating_sub(our_epoch) >= REJOIN_EPOCHS
}

/// Whether a backup's next blocks may already be pruned by the device it follows.
///
/// A backup in epoch `our_epoch` may sit on that epoch's first block while the
/// active device finalizes the last block of `network_epoch`, and the active
/// device keeps `retained` consensus revisions: the backup's own setting, which
/// the devices of one account share. Without a retention the active device
/// prunes nothing. A backup deals nothing, so re-synchronizing early costs the
/// deployment nothing.
pub(crate) const fn beyond_retention(
    our_epoch: u64,
    network_epoch: u64,
    blocks_per_epoch: std::num::NonZeroU64,
    retained: Option<usize>,
) -> bool {
    let Some(retained) = retained else {
        return false;
    };
    let behind = network_epoch
        .saturating_sub(our_epoch)
        .saturating_add(1)
        .saturating_mul(blocks_per_epoch.get());
    network_epoch > our_epoch && behind > (retained as u64).saturating_add(2)
}

/// Discard sync bookkeeping so the next plan initialization re-arms peer
/// state sync. Application databases, marshal archives and durable history
/// are untouched; the syncer supersedes them from a current floor. The DKG
/// transcript is discarded with it: the rejoin path only runs when the node
/// is epochs behind, outside any ceremony it could still participate in, and
/// a stale transcript left behind the reconciling state sync stalls recovery.
pub(crate) fn reset_sync_bookkeeping(data_dir: &Path) -> std::io::Result<()> {
    let storage = data_dir.join("commonware");
    // Keep the completed-sync marker until the stale DKG transcript is durably
    // removed, so an interrupted reset takes this recovery path again.
    for suffix in [DKG_STATE_SYNC, STATE_SYNC_METADATA] {
        let partition = storage.join(format!("{PARTITION_PREFIX}{suffix}"));
        match std::fs::remove_dir_all(&partition) {
            Ok(()) => {
                tracing::warn!(partition = %partition.display(), "reset state sync bookkeeping for rejoin")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("failed to reset {}: {error}", partition.display()),
                ));
            }
        }
        std::fs::File::open(&storage)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_distant_networks_require_rejoin() {
        assert!(!stranded(4, 5));
        assert!(!stranded(4, 6));
        assert!(stranded(4, 7));
        assert!(stranded(6, 378));
        assert!(!stranded(u64::MAX, 0));
        assert!(!stranded(u64::MAX - 2, u64::MAX));
        assert!(stranded(u64::MAX - 3, u64::MAX));
    }

    #[test]
    fn a_backup_resynchronizes_once_its_next_block_may_be_pruned() {
        let epoch = std::num::NonZeroU64::new(256).unwrap();
        assert!(!beyond_retention(4, 4, epoch, Some(512)));
        assert!(!beyond_retention(4, 5, epoch, Some(512)));
        assert!(beyond_retention(4, 6, epoch, Some(512)));
        assert!(!beyond_retention(4, 6, epoch, Some(1_024)));
        assert!(!beyond_retention(4, 400, epoch, None));
        assert!(!beyond_retention(6, 4, epoch, Some(512)));
    }

    #[test]
    fn reset_reports_unremovable_bookkeeping() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        std::fs::create_dir(&storage).unwrap();
        let metadata = storage.join(format!("{PARTITION_PREFIX}{STATE_SYNC_METADATA}"));
        std::fs::write(&metadata, b"not a partition directory").unwrap();
        assert!(reset_sync_bookkeeping(directory.path()).is_err());
        assert!(metadata.is_file());
    }

    #[test]
    fn failed_transcript_reset_keeps_the_completed_sync_marker() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        let metadata = storage.join(format!("{PARTITION_PREFIX}{STATE_SYNC_METADATA}"));
        let transcript = storage.join(format!("{PARTITION_PREFIX}{DKG_STATE_SYNC}"));
        std::fs::create_dir_all(&metadata).unwrap();
        std::fs::write(metadata.join("blob"), b"completed").unwrap();
        std::fs::write(&transcript, b"not a partition directory").unwrap();
        assert!(reset_sync_bookkeeping(directory.path()).is_err());
        assert_eq!(std::fs::read(metadata.join("blob")).unwrap(), b"completed");
    }

    #[test]
    fn reset_removes_only_sync_partitions() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        let metadata = storage.join(format!("{PARTITION_PREFIX}{STATE_SYNC_METADATA}"));
        let transcript = storage.join(format!("{PARTITION_PREFIX}{DKG_STATE_SYNC}"));
        let history = directory.path().join("history");
        for path in [&metadata, &transcript, &history] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("blob"), [0u8; 8]).unwrap();
        }
        reset_sync_bookkeeping(directory.path()).unwrap();
        assert!(!metadata.exists());
        assert!(!transcript.exists());
        assert!(history.exists());
    }
}
