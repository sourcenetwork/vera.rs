//! Whole-file replacement that survives a crash.

use std::{
    ffi::OsString,
    io::Write as _,
    path::{Path, PathBuf},
};

/// Replace `path` with `bytes` so that a reader sees the old or the new contents, never a part.
///
/// The bytes are written and synced under a temporary name beside `path`,
/// renamed over it, and the parent directory is synced. An interrupted write
/// can leave the temporary file behind; the next write replaces it.
pub fn write_durable(path: impl AsRef<Path>, bytes: &[u8]) -> std::io::Result<()> {
    let path = path.as_ref();
    let temporary = temporary_path(path)?;
    let mut file = std::fs::File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    sync_parent(path)
}

/// Sync the directory holding `path`, making a rename or removal inside it durable.
pub fn sync_parent(path: impl AsRef<Path>) -> std::io::Result<()> {
    let parent = path
        .as_ref()
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::File::open(parent)?.sync_all()
}

fn temporary_path(path: &Path) -> std::io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let mut temporary = OsString::from(name);
    temporary.push(".tmp");
    Ok(path.with_file_name(temporary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_contents_and_leaves_no_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("genesis.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::write(directory.path().join("genesis.json.tmp"), b"interrupted").unwrap();

        write_durable(&path, b"new").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["genesis.json"]);
    }

    #[test]
    fn a_failed_write_keeps_the_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("genesis.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::create_dir(directory.path().join("genesis.json.tmp")).unwrap();

        assert!(write_durable(&path, b"new").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
    }

    #[test]
    fn a_path_without_a_file_name_is_rejected() {
        assert_eq!(
            write_durable("/", b"new").unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}
