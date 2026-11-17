//! A validator's vote journal across a change of role.

use std::path::Path;

use super::{TermRecord, TermRefusal};
use crate::node::PARTITION_PREFIX;

/// The partitions Simplex journals an epoch's votes and certificates in.
const JOURNAL: &str = "-orchestrator_consensus_";
/// Where a validator's journals wait while the device follows.
const PARKED: &str = "-orchestrator_parked_";

/// Put the right vote journal in place before consensus opens it.
///
/// A validator journals its own votes, and Commonware refuses to replay
/// votes cast under a key the node no longer signs with, so a device that
/// starts to follow sets its journal aside. Simplex has no other record of
/// where an epoch stands: a validator that starts on an empty journal begins
/// the epoch at view 1 on the epoch's first parent, and execution, which is
/// past that block, refuses every proposal. A device that validates again
/// while its newest block is still `head`, the block it had when it set the
/// journal aside, therefore takes that journal back. If it received blocks
/// meanwhile, the journal it kept as a backup holds their certificates and
/// is the one to continue from.
pub(crate) fn settle(directory: &Path, backup: bool, head: u64) -> Result<(), TermRefusal> {
    let mut record = TermRecord::load(directory)?;
    let storage = directory.join("commonware");
    let moved = |source| TermRefusal::Io {
        path: storage.clone(),
        source,
    };
    if backup {
        if !record.voted {
            return Ok(());
        }
        rename(&storage, JOURNAL, PARKED).map_err(moved)?;
        record.parked = Some(head);
        record.voted = false;
    } else {
        if let Some(parked) = record.parked.take() {
            if parked == head {
                rename(&storage, PARKED, JOURNAL).map_err(moved)?;
            } else {
                remove(&storage, PARKED).map_err(moved)?;
            }
        } else if record.voted {
            return Ok(());
        }
        record.voted = true;
    }
    record.store(directory)
}

fn partitions(storage: &Path, kind: &str) -> std::io::Result<Vec<(std::path::PathBuf, String)>> {
    let prefix = format!("{PARTITION_PREFIX}{kind}");
    let entries = match std::fs::read_dir(storage) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        if let Some(epoch) = entry.file_name().to_string_lossy().strip_prefix(&prefix) {
            found.push((entry.path(), epoch.to_owned()));
        }
    }
    Ok(found)
}

fn remove(storage: &Path, kind: &str) -> std::io::Result<()> {
    for (path, _) in partitions(storage, kind)? {
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

/// Replace the partitions of kind `to` with those of kind `from`. A call
/// interrupted halfway finds nothing left to move and keeps what was moved.
fn rename(storage: &Path, from: &str, to: &str) -> std::io::Result<()> {
    let moving = partitions(storage, from)?;
    if moving.is_empty() {
        return Ok(());
    }
    remove(storage, to)?;
    for (path, epoch) in moving {
        std::fs::rename(path, storage.join(format!("{PARTITION_PREFIX}{to}{epoch}")))?;
    }
    std::fs::File::open(storage)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal(storage: &Path, kind: &str, epoch: u64, content: &str) {
        let partition = storage.join(format!("{PARTITION_PREFIX}{kind}{epoch}"));
        std::fs::create_dir_all(&partition).unwrap();
        std::fs::write(partition.join("blob"), content).unwrap();
    }

    fn content(storage: &Path, kind: &str, epoch: u64) -> Option<String> {
        let partition = storage.join(format!("{PARTITION_PREFIX}{kind}{epoch}"));
        std::fs::read_to_string(partition.join("blob")).ok()
    }

    #[test]
    fn a_device_that_followed_nobody_takes_its_own_journal_back() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        settle(directory.path(), false, 0).unwrap();
        journal(&storage, JOURNAL, 3, "votes");

        settle(directory.path(), true, 99).unwrap();
        assert_eq!(content(&storage, JOURNAL, 3), None);
        assert_eq!(content(&storage, PARKED, 3).as_deref(), Some("votes"));
        // As a backup it journals what it observes, here nothing.
        journal(&storage, JOURNAL, 3, "observed");
        settle(directory.path(), true, 99).unwrap();
        assert_eq!(content(&storage, PARKED, 3).as_deref(), Some("votes"));

        settle(directory.path(), false, 99).unwrap();
        assert_eq!(content(&storage, JOURNAL, 3).as_deref(), Some("votes"));
        assert_eq!(content(&storage, PARKED, 3), None);
        let record = TermRecord::load(directory.path()).unwrap();
        assert!(record.voted && record.parked.is_none());
    }

    #[test]
    fn a_device_that_received_blocks_continues_from_the_journal_it_kept_as_a_backup() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        settle(directory.path(), false, 0).unwrap();
        journal(&storage, JOURNAL, 3, "votes");
        settle(directory.path(), true, 99).unwrap();
        journal(&storage, JOURNAL, 3, "observed");

        settle(directory.path(), false, 120).unwrap();
        assert_eq!(content(&storage, JOURNAL, 3).as_deref(), Some("observed"));
        assert_eq!(content(&storage, PARKED, 3), None);
    }

    #[test]
    fn a_backup_that_never_validated_keeps_its_journal() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        journal(&storage, JOURNAL, 1, "observed");
        settle(directory.path(), true, 5).unwrap();
        assert_eq!(content(&storage, JOURNAL, 1).as_deref(), Some("observed"));
        assert!(!directory.path().join("term.json").exists());
    }
}
