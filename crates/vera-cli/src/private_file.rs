//! Owner-only file writes for key material.

use std::io::Write;
use std::path::Path;

/// Open existing private material and validate its metadata before reading.
///
/// Unix reads reject symlinks and require a regular, single-link file with no
/// group or other access.
/// The opened descriptor is checked before reading; permissions are not repaired.
/// Parent directories must be protected by the operator.
pub fn open_private(path: impl AsRef<Path>) -> std::io::Result<std::fs::File> {
    let path = path.as_ref();
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private material cannot be a symlink",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_NONBLOCK lets metadata reject a FIFO without waiting for a writer.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private material must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private material requires owner-only access and a single link",
            ));
        }
    }
    Ok(file)
}

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

    #[test]
    fn private_reads_preserve_created_material_and_missing_paths() {
        use std::io::Read as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validator.key");
        assert_eq!(
            open_private(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(!path.exists());
        write_private(&path, &[7; 32]).unwrap();
        let mut contents = Vec::new();
        open_private(&path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, [7; 32]);
        assert!(open_private(directory.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_reads_reject_exposed_permissions_without_repairing_them() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validator.key");
        write_private(&path, &[7; 32]).unwrap();
        for mode in [0o640, 0o604, 0o620, 0o602, 0o610, 0o601, 0o644, 0o666] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                open_private(&path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, mode);
            assert_eq!(std::fs::read(&path).unwrap(), [7; 32]);
        }
        for mode in [0o400, 0o600] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(open_private(&path).is_ok());
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_reads_reject_existing_and_dangling_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        for exists in [false, true] {
            let target = directory.path().join(format!("target-{exists}"));
            let link = directory.path().join(format!("link-{exists}"));
            if exists {
                write_private(&target, &[7; 32]).unwrap();
            }
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(open_private(&link).is_err());
            assert_eq!(std::fs::read_link(&link).unwrap(), target);
            if exists {
                assert_eq!(std::fs::read(&target).unwrap(), [7; 32]);
            } else {
                assert!(!target.exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_reads_reject_hard_links_and_non_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validator.key");
        write_private(&path, &[7; 32]).unwrap();
        let alias = directory.path().join("retained.key");
        std::fs::hard_link(&path, &alias).unwrap();
        assert_eq!(
            open_private(&path).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            open_private(&alias).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(std::fs::read(&path).unwrap(), [7; 32]);
        let socket_path = directory.path().join("socket");
        let _socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        assert!(open_private(&socket_path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_reads_reject_fifos_without_waiting_for_a_writer() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt as _};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pipe");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: The path is NUL-terminated and remains valid throughout mkfifo.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert_eq!(
            open_private(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert!(!path.metadata().unwrap().is_file());
    }

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
