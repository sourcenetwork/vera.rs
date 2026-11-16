//! Bringing a directory back to the block a later term builds on.

use std::{io::Write as _, path::Path};

use super::{TermRecord, TermRefusal};
use crate::{DiscardedSubmission, FinalizedHistory, HistoryMemory, history::Standing};

const DISCARDED: &str = "discarded-submissions.json";
const PENDING: &str = "discarded-submissions.pending";

/// Prepare `directory` to follow the device that holds the stored term.
///
/// Blocks this device finalized above the term's cut are void. Their
/// submissions are added to the report the host reads, their records are
/// dropped from finalized history, and the consensus archives and state
/// journals are removed: those cannot be cut back, so the device takes the
/// state at a block of the new term from the device it follows, and imports
/// the history between the cut and that block.
pub(crate) fn rewind(directory: &Path, memory: HistoryMemory) -> Result<(), TermRefusal> {
    let mut record = TermRecord::load(directory)?;
    let history = directory.join("history");
    if let (Some(change), true) = (record.change().copied(), history.is_dir()) {
        let failed = |error: anyhow::Error| TermRefusal::History(format!("{error:#}"));
        let stored = FinalizedHistory::open_stored(&history, &change.genesis_id, Some(memory))
            .map_err(failed)?;
        match stored
            .standing(change.cut.height, &change.cut.block, change.term)
            .map_err(failed)?
        {
            Standing::Within => {}
            Standing::Diverged => {
                return Err(TermRefusal::Diverged {
                    height: change.cut.height,
                });
            }
            Standing::Above => {
                let voided = stored
                    .submissions_above(change.cut.height)
                    .map_err(failed)?;
                report(directory, voided)?;
                // The stores are ahead of history from here until they are removed.
                record.resync = true;
                record.store(directory)?;
                stored.rewind_to(change.cut.height).map_err(failed)?;
            }
        }
    }
    if record.resync {
        let storage = directory.join("commonware");
        remove(&storage).map_err(|source| TermRefusal::Io {
            path: storage,
            source,
        })?;
        record.resync = false;
        record.store(directory)?;
    }
    Ok(())
}

/// Mark `directory` after its node refused a block, and return the refusal
/// as the node's error.
///
/// The refused block stays in the consensus archive, which cannot be cut
/// back, so the next start as a backup takes the stores again.
pub(crate) fn resync_after(directory: &Path, refusal: TermRefusal) -> anyhow::Error {
    let marked = TermRecord::load(directory).and_then(|mut record| {
        record.resync = true;
        record.store(directory)
    });
    if let Err(error) = marked {
        tracing::error!(%error, "the directory could not be marked for a new copy of its stores");
    }
    refusal.into()
}

fn remove(storage: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(storage) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match storage.parent() {
        Some(parent) => std::fs::File::open(parent)?.sync_all(),
        None => Ok(()),
    }
}

/// The submissions voided by rewinds of `directory` that the host has not acknowledged.
pub(crate) fn discarded(directory: &Path) -> Result<Vec<DiscardedSubmission>, TermRefusal> {
    let path = directory.join(DISCARDED);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| TermRefusal::Record {
            path,
            reason: error.to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(source) => Err(TermRefusal::Io { path, source }),
    }
}

/// Forget the report once the host has it.
pub(crate) fn acknowledge(directory: &Path) -> Result<(), TermRefusal> {
    let path = directory.join(DISCARDED);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TermRefusal::Io { path, source }),
    }
}

/// Add `voided` to the report. A rewind interrupted after this point reports
/// the same submissions again, which are kept once.
fn report(directory: &Path, voided: Vec<DiscardedSubmission>) -> Result<(), TermRefusal> {
    let mut reported = discarded(directory)?;
    for submission in voided {
        if !reported.contains(&submission) {
            reported.push(submission);
        }
    }
    let path = directory.join(DISCARDED);
    let bytes = serde_json::to_vec(&reported).map_err(|error| TermRefusal::Record {
        path: path.clone(),
        reason: error.to_string(),
    })?;
    let write = || {
        let pending = directory.join(PENDING);
        let mut file = std::fs::File::create(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&pending, &path)?;
        std::fs::File::open(directory)?.sync_all()
    };
    write().map_err(|source| TermRefusal::Io { path, source })
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::*;

    fn submission(height: u64) -> DiscardedSubmission {
        DiscardedSubmission {
            submission: B256::repeat_byte(height as u8),
            height,
            success: true,
            request: vec![height as u8].into(),
        }
    }

    #[test]
    fn the_report_keeps_each_submission_once_until_it_is_acknowledged() {
        let directory = tempfile::tempdir().unwrap();
        assert!(discarded(directory.path()).unwrap().is_empty());
        report(directory.path(), vec![submission(4), submission(5)]).unwrap();
        report(directory.path(), vec![submission(5), submission(6)]).unwrap();
        assert_eq!(
            discarded(directory.path()).unwrap(),
            [4, 5, 6].map(submission)
        );
        acknowledge(directory.path()).unwrap();
        acknowledge(directory.path()).unwrap();
        assert!(discarded(directory.path()).unwrap().is_empty());
    }

    #[test]
    fn a_directory_marked_for_it_loses_its_consensus_and_state_stores_only() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        std::fs::create_dir_all(storage.join("vera-blocks-value")).unwrap();
        std::fs::write(directory.path().join("solo-genesis.json"), b"{}").unwrap();

        rewind(directory.path(), HistoryMemory::EMBEDDED).unwrap();
        assert!(storage.exists());
        let record = TermRecord {
            resync: true,
            ..TermRecord::default()
        };
        record.store(directory.path()).unwrap();
        rewind(directory.path(), HistoryMemory::EMBEDDED).unwrap();
        assert!(!storage.exists());
        assert!(directory.path().join("solo-genesis.json").exists());
        assert!(!TermRecord::load(directory.path()).unwrap().resync);
    }
}
