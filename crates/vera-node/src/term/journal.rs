//! Whether a device last ran as a backup.

use std::path::Path;

use super::{TermRecord, TermRefusal};

/// Record a start as a backup in `directory`.
///
/// A device that followed the deployment validates again only under a
/// certificate that names it, which clears the mark when the device has
/// started on the certificate's cut.
pub(crate) fn settle_role(directory: &Path, backup: bool) -> Result<(), TermRefusal> {
    let mut record = TermRecord::load(directory)?;
    if !backup || record.followed {
        return Ok(());
    }
    record.followed = true;
    record.store(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_as_a_backup_is_remembered() {
        let directory = tempfile::tempdir().unwrap();
        settle_role(directory.path(), false).unwrap();
        assert!(!directory.path().join("term.json").exists());
        settle_role(directory.path(), true).unwrap();
        settle_role(directory.path(), false).unwrap();
        assert!(TermRecord::load(directory.path()).unwrap().followed);
    }
}
