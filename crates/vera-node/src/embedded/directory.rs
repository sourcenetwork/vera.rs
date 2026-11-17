//! Refusal of a node directory that is already in use.

use std::{
    fs::{File, OpenOptions, TryLockError},
    path::Path,
};

use super::EmbedError;

/// The file Commonware's storage locks for as long as anything can touch the directory.
const HOLD_NAME: &str = ".hold";
/// The file an embedded node locks in its data directory from before it
/// changes its term record or consensus storage until its runtime has stopped. It lies outside
/// `commonware/`, which a start may remove.
const CLAIM_NAME: &str = ".node-hold";

/// An embedded node's hold on its data directory. Released when dropped.
pub(super) struct Claim(#[expect(dead_code, reason = "held for its lock")] File);

/// Lock `directory` for one embedded node, or fail when another holds it.
pub(super) fn claim(directory: &Path) -> Result<Claim, EmbedError> {
    let io = |source| crate::SoloError::Io {
        path: directory.to_path_buf(),
        source,
    };
    std::fs::create_dir_all(directory).map_err(io)?;
    let hold = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(CLAIM_NAME))
        .map_err(io)?;
    match hold.try_lock() {
        Ok(()) => Ok(Claim(hold)),
        Err(TryLockError::WouldBlock) => Err(EmbedError::DirectoryInUse(directory.to_path_buf())),
        Err(TryLockError::Error(source)) => Err(io(source).into()),
    }
}

/// Fail when `storage` is held, where Commonware's runtime would wait without a deadline.
///
/// The probe releases the lock before the runtime takes it. Another embedded
/// node is kept out meanwhile by the [`Claim`] on the data directory; any
/// other holder that arrives in between is waited for by the runtime.
pub(super) fn refuse_held(storage: &Path) -> Result<(), EmbedError> {
    let io = |source| crate::SoloError::Io {
        path: storage.to_path_buf(),
        source,
    };
    let hold = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(storage.join(HOLD_NAME))
        .map_err(io)?;
    match hold.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(EmbedError::DirectoryInUse(storage.to_path_buf())),
        Err(TryLockError::Error(source)) => Err(io(source).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claimed_directory_is_refused_until_the_claim_is_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let held = claim(directory.path()).unwrap();
        assert!(matches!(
            claim(directory.path()),
            Err(EmbedError::DirectoryInUse(_))
        ));
        drop(held);
        claim(directory.path()).unwrap();
    }
}
