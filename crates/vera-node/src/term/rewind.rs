//! Bringing a directory back to the block a later term builds on.

use std::{io::Write as _, path::Path};

use alloy_primitives::B256;

use super::{TermRecord, TermRefusal};
use crate::{DiscardedSubmission, FinalizedHistory, HistoryMemory, history::Standing};

const DISCARDED: &str = "discarded-submissions.json";
const PENDING: &str = "discarded-submissions.pending";

/// Prepare `directory` to follow the device that holds the stored term.
///
/// Nothing is voided or removed while the stored certificate names this
/// device (`this`): blocks above its cut are this device's own blocks of
/// that term, and a mark to take the stores again is refused with
/// [`TermRefusal::HolderResync`].
///
/// Otherwise blocks this device finalized above the term's cut are void, or
/// above the newest block it shares with the holder when its history left
/// the holder's below the cut (`TermRecord::common`). Their
/// submissions are added to the report the host reads, their records are
/// dropped from finalized history, and the consensus archives and state
/// journals are removed: those cannot be cut back, so the device takes the
/// state at a block of the new term from the device it follows, and imports
/// the history between the cut and that block.
pub(crate) fn rewind(
    directory: &Path,
    this: Option<B256>,
    memory: HistoryMemory,
) -> Result<(), TermRefusal> {
    let mut record = TermRecord::load(directory)?;
    if let Some(change) = record.change()
        && Some(change.holder) == this
    {
        return match record.resync {
            true => Err(TermRefusal::HolderResync(change.term)),
            false => Ok(()),
        };
    }
    let history = directory.join("history");
    if let (Some(change), true) = (record.change().copied(), history.is_dir()) {
        let failed = |error: anyhow::Error| TermRefusal::History(format!("{error:#}"));
        let stored = FinalizedHistory::open_stored(&history, &change.genesis_id, Some(memory))
            .map_err(failed)?;
        // A history that left the holder's below the cut is cut back to the
        // newest block the two share, whatever the term of the blocks above it.
        let (point, term) = record
            .common
            .map_or((change.cut, change.term), |common| (common, u64::MAX));
        match stored
            .standing(point.height, &point.block, term)
            .map_err(failed)?
        {
            Standing::Within => {}
            Standing::Diverged => {
                return Err(TermRefusal::Diverged {
                    height: change.cut.height,
                });
            }
            Standing::Above => {
                let voided = stored.submissions_above(point.height).map_err(failed)?;
                report(directory, voided)?;
                // The stores are ahead of history from here until they are removed.
                record.resync = true;
                record.store(directory)?;
                stored.rewind_to(point.height).map_err(failed)?;
            }
        }
        if record.common.take().is_some() {
            record.store(directory)?;
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

        rewind(directory.path(), None, HistoryMemory::EMBEDDED).unwrap();
        assert!(storage.exists());
        let record = TermRecord {
            resync: true,
            ..TermRecord::default()
        };
        record.store(directory.path()).unwrap();
        rewind(directory.path(), None, HistoryMemory::EMBEDDED).unwrap();
        assert!(!storage.exists());
        assert!(directory.path().join("solo-genesis.json").exists());
        assert!(!TermRecord::load(directory.path()).unwrap().resync);
    }

    #[test]
    fn the_holder_of_the_stored_term_keeps_its_stores() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        std::fs::create_dir_all(storage.join("vera-orchestrator_consensus_0")).unwrap();
        let this = B256::repeat_byte(2);
        let certificate = vera_domain::TermCertificate {
            change: vera_domain::TermChange {
                genesis_id: B256::repeat_byte(1),
                term: 3,
                holder: this,
                cut: vera_domain::TermCut {
                    height: 5,
                    block: B256::repeat_byte(3),
                },
            },
            approvals: Vec::new(),
        };
        let record = TermRecord {
            certificate: Some(certificate),
            resync: true,
            ..TermRecord::default()
        };
        record.store(directory.path()).unwrap();
        assert!(matches!(
            rewind(directory.path(), Some(this), HistoryMemory::EMBEDDED),
            Err(TermRefusal::HolderResync(3))
        ));
        assert!(storage.join("vera-orchestrator_consensus_0").exists());
        // Another device's copy of the same certificate takes the stores again.
        rewind(
            directory.path(),
            Some(B256::repeat_byte(4)),
            HistoryMemory::EMBEDDED,
        )
        .unwrap();
        assert!(!storage.exists());
    }
}
