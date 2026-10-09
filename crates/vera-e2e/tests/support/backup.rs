//! Copy a stopped fixture directory without following links or replacing existing paths.

use std::{fs, io, path::Path};

pub(super) fn copy_directory(source: &Path, destination: &Path) -> io::Result<()> {
    if !fs::symlink_metadata(source)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup source must be a directory",
        ));
    }
    fs::create_dir(destination)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_directory(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)?;
            fs::File::open(target)?.sync_all()?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backup contains a link or special file",
            ));
        }
    }
    #[cfg(unix)]
    fs::File::open(destination)?.sync_all()?;
    Ok(())
}
