//! Owner-only file writes for key material.

use std::io::Write;
use std::path::Path;

/// Create `path` with `bytes`, readable only by its owner. Existing paths are rejected.
///
/// Permissions are set at creation, not corrected afterwards, so the key
/// material is never briefly world-readable. The file and, on Unix, its parent
/// directory are synced before success. A failed write may leave an incomplete
/// file; callers must inspect it rather than replace an existing identity.
pub fn write_private(path: impl AsRef<Path>, bytes: &[u8]) -> std::io::Result<()> {
    #[allow(unused_mut)]
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path.as_ref())?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        let parent = path
            .as_ref()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn created_files_are_owner_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validator.key");
        write_private(&path, &[7; 32]).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = path.metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), vec![7; 32]);
    }

    #[test]
    fn existing_files_and_directories_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validator.key");
        std::fs::write(&path, [3; 32]).unwrap();
        let original_permissions = path.metadata().unwrap().permissions();
        assert_eq!(
            write_private(&path, &[7; 32]).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), [3; 32]);
        assert_eq!(path.metadata().unwrap().permissions(), original_permissions);

        let existing_directory = directory.path().join("existing");
        std::fs::create_dir(&existing_directory).unwrap();
        let marker = existing_directory.join("retained");
        std::fs::write(&marker, [9]).unwrap();
        assert!(write_private(&existing_directory, &[7; 32]).is_err());
        assert_eq!(std::fs::read(marker).unwrap(), [9]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_never_redirect_key_creation() {
        let directory = tempfile::tempdir().unwrap();
        for exists in [false, true] {
            let target = directory.path().join(format!("target-{exists}"));
            let link = directory.path().join(format!("link-{exists}"));
            if exists {
                std::fs::write(&target, [3; 32]).unwrap();
            }
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert_eq!(
                write_private(&link, &[7; 32]).unwrap_err().kind(),
                std::io::ErrorKind::AlreadyExists
            );
            assert_eq!(std::fs::read_link(link).unwrap(), target);
            if exists {
                assert_eq!(std::fs::read(target).unwrap(), [3; 32]);
            } else {
                assert!(!target.exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_keys_are_not_modified() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("retained.key");
        let path = directory.path().join("validator.key");
        std::fs::write(&original, [3; 32]).unwrap();
        std::fs::hard_link(&original, &path).unwrap();
        assert_eq!(
            write_private(&path, &[7; 32]).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(original).unwrap(), [3; 32]);
        assert_eq!(std::fs::read(path).unwrap(), [3; 32]);
    }

    #[test]
    fn concurrent_creators_cannot_replace_the_winning_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validator.key");
        let barrier = std::sync::Barrier::new(8);
        let winner = std::thread::scope(|scope| {
            let creators: Vec<_> = (0u8..8)
                .map(|value| {
                    let path = &path;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        (value, write_private(path, &[value; 32]))
                    })
                })
                .collect();
            let mut winners = Vec::new();
            for creator in creators {
                let (value, result) = creator.join().unwrap();
                match result {
                    Ok(()) => winners.push(value),
                    Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists),
                }
            }
            assert_eq!(winners.len(), 1);
            winners[0]
        });
        assert_eq!(std::fs::read(path).unwrap(), [winner; 32]);
    }
}
