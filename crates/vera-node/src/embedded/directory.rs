//! Refusal of a node directory that is already in use.

use std::{
    fs::{OpenOptions, TryLockError},
    path::Path,
};

use super::EmbedError;

/// The file Commonware's storage locks for as long as anything can touch the directory.
const HOLD_NAME: &str = ".hold";

/// Fail when `storage` is held, where Commonware's runtime would wait without a deadline.
///
/// The probe releases the lock before the runtime takes it, so a holder that
/// arrives in between is waited for as before.
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
