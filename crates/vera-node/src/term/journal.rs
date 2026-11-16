//! The consensus journal across a change of role.

use std::path::Path;

use super::{TermRecord, TermRefusal};
use crate::node::PARTITION_PREFIX;

/// Prepare `directory` for a start as a backup (`backup`) or as the validator.
///
/// A validator journals its own votes, and Commonware refuses to replay
/// votes cast under a key the node no longer signs with. A device that
/// validated and now follows therefore drops the journal of the epochs it
/// voted in. It loses nothing by that: a backup casts no vote, and finalized
/// blocks are kept elsewhere.
pub(crate) fn settle_role(directory: &Path, backup: bool) -> Result<(), TermRefusal> {
    let mut record = TermRecord::load(directory)?;
    if record.voted != backup {
        return Ok(());
    }
    if backup {
        let storage = directory.join("commonware");
        remove_votes(&storage).map_err(|source| TermRefusal::Io {
            path: storage,
            source,
        })?;
    }
    record.voted = !backup;
    record.store(directory)
}

fn remove_votes(storage: &Path) -> std::io::Result<()> {
    let prefix = format!("{PARTITION_PREFIX}-orchestrator_consensus_");
    let entries = match std::fs::read_dir(storage) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    std::fs::File::open(storage)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_that_validated_drops_its_votes_when_it_follows() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        let votes = storage.join("vera-orchestrator_consensus_3");
        let blocks = storage.join("vera-blocks-value");
        for partition in [&votes, &blocks] {
            std::fs::create_dir_all(partition).unwrap();
        }

        settle_role(directory.path(), true).unwrap();
        assert!(
            votes.exists(),
            "a backup's journal holds no vote of its own"
        );
        settle_role(directory.path(), false).unwrap();
        assert!(TermRecord::load(directory.path()).unwrap().voted);
        assert!(votes.exists());
        settle_role(directory.path(), true).unwrap();
        assert!(!votes.exists());
        assert!(blocks.exists());
        assert!(!TermRecord::load(directory.path()).unwrap().voted);
    }
}
