//! A private Linux tmpfs that exhausts one fixture's storage without filling the host.

use std::{
    fs::{self, File},
    io::{self, Write as _},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

#[path = "backup.rs"]
mod backup;

pub(super) struct Quota {
    mounts: Mutex<Vec<PathBuf>>,
    volume: PathBuf,
    root: tempfile::TempDir,
    log_destination: Mutex<Option<PathBuf>>,
}

impl Quota {
    pub(super) fn new() -> io::Result<Self> {
        let root = tempfile::tempdir()?;
        let owner = root.path().metadata()?;
        let volume = root.path().join("volume");
        fs::create_dir(&volume)?;
        privileged(&[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            &format!(
                "size=256m,nosuid,nodev,noexec,mode=0700,uid={},gid={}",
                owner.uid(),
                owner.gid()
            ),
            "vera-e2e-quota",
            path_arg(&volume)?,
        ])?;
        Ok(Self {
            mounts: Mutex::new(vec![volume.clone()]),
            volume,
            root,
            log_destination: Mutex::new(None),
        })
    }

    pub(super) fn bind_node(&self, directory: &Path) -> io::Result<()> {
        let state = self.volume.join("node");
        backup::copy_directory(directory, &state)?;
        privileged(&["mount", "--bind", path_arg(&state)?, path_arg(directory)?])?;
        self.mounts.lock().unwrap().push(directory.to_path_buf());
        // Preserve failure evidence when the validator's storage cannot accept a log write.
        let logs = self.root.path().join("logs");
        fs::create_dir(&logs)?;
        let destination = directory.join("logs");
        fs::create_dir_all(&destination)?;
        privileged(&["mount", "--bind", path_arg(&logs)?, path_arg(&destination)?])?;
        self.mounts.lock().unwrap().push(destination.clone());
        *self.log_destination.lock().unwrap() = Some(destination);
        Ok(())
    }

    pub(super) fn fill(&self) -> io::Result<u64> {
        let mut filler = File::options()
            .write(true)
            .create_new(true)
            .open(self.volume.join("filler"))?;
        let chunk = [0_u8; 64 * 1024];
        loop {
            match filler.write_all(&chunk) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(28) => {
                    return Ok(filler.metadata()?.len());
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(super) fn confirm_full(&self) -> io::Result<()> {
        let path = self.volume.join("enospc-probe");
        let result = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| file.write_all(&[0; 4096]));
        if path.try_exists()? {
            fs::remove_file(path)?;
        }
        match result {
            Err(error) if error.raw_os_error() == Some(28) => Ok(()),
            Err(error) => Err(error),
            Ok(()) => Err(io::Error::other(
                "validator volume no longer reports ENOSPC",
            )),
        }
    }

    pub(super) fn release_space(&self) -> io::Result<()> {
        fs::remove_file(self.volume.join("filler"))
    }

    pub(super) fn close(&self) -> io::Result<()> {
        let mut mounts = self.mounts.lock().unwrap();
        while let Some(path) = mounts.last() {
            privileged(&["umount", path_arg(path)?])?;
            mounts.pop();
        }
        // Restore process logs to the cluster directory after removing the private mounts.
        if let Some(destination) = self.log_destination.lock().unwrap().as_ref() {
            fs::create_dir_all(destination)?;
            for name in ["stdout.log", "stderr.log"] {
                let source = self.root.path().join("logs").join(name);
                if source.try_exists()? {
                    fs::copy(source, destination.join(name))?;
                }
            }
        }
        Ok(())
    }
}

impl Drop for Quota {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn path_arg(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 fixture path"))
}

fn privileged(args: &[&str]) -> io::Result<()> {
    let status = Command::new("sudo")
        .args(["--non-interactive", "--"])
        .args(args)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("fixture mount operation failed"))
    }
}
