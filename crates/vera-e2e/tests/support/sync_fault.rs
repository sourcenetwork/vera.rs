use std::{
    collections::BTreeSet,
    fs::{self, File},
    io,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

pub(super) struct SyncFault {
    process: Child,
    state: PathBuf,
    directory: tempfile::TempDir,
}

impl SyncFault {
    pub(super) fn attach(pid: u32, state: &Path) -> io::Result<Self> {
        let state = state.join("history").canonicalize()?;
        let mut paths = BTreeSet::new();
        for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
            let path = match fs::read_link(entry?.path()) {
                Ok(path) => path,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if path.starts_with(&state) && path.is_file() {
                paths.insert(path);
            }
        }
        if paths.is_empty() {
            return Err(io::Error::other("no open finalized-history files to fault"));
        }
        let directory = tempfile::tempdir()?;
        let trace = directory.path().join("sync.log");
        let mut command = Command::new("sudo");
        command
            .args(["--non-interactive", "--", "strace"])
            .args([
                "--follow-forks",
                "--output-separately",
                "--decode-fds=path",
                "--trace=fsync,fdatasync",
                "--inject=fsync,fdatasync:error=EIO:when=1",
                "--output",
            ])
            .arg(&trace)
            .arg(format!("--attach={pid}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(directory.path().join("attach.log"))?)
            .process_group(0);
        for path in paths {
            command.arg("--trace-path").arg(path);
        }
        let process = command.spawn()?;
        Ok(Self {
            process,
            state,
            directory,
        })
    }

    fn injected_calls(&self) -> io::Result<usize> {
        let prefix = format!("<{}/", self.state.display());
        let mut count = 0;
        for entry in fs::read_dir(self.directory.path())? {
            let entry = entry?;
            let name = entry.file_name();
            if !name.to_str().is_some_and(|name| {
                name.strip_prefix("sync.log.")
                    .is_some_and(|tid| tid.parse::<u32>().is_ok())
            }) {
                continue;
            }
            let text = fs::read_to_string(entry.path())?;
            for line in text.lines().filter(|line| line.contains("(INJECTED)")) {
                if !line.contains(&prefix)
                    || !line.contains("= -1 EIO ")
                    || !(line.starts_with("fsync(") || line.starts_with("fdatasync("))
                {
                    return Err(io::Error::other(
                        "sync fault did not target finalized history",
                    ));
                }
                count += 1;
            }
        }
        Ok(count)
    }

    pub(super) async fn finish(mut self) -> io::Result<usize> {
        let status = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(status) = self.process.try_wait()? {
                    return Ok::<_, io::Error>(status);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "sync tracer exit deadline"))??;
        if !status.success() {
            return Err(io::Error::other("sync tracer did not exit successfully"));
        }
        let calls = self.injected_calls()?;
        if calls == 0 {
            return Err(io::Error::other("no synchronization fault was observed"));
        }
        Ok(calls)
    }
}

impl Drop for SyncFault {
    fn drop(&mut self) {
        if let Ok(None) = self.process.try_wait() {
            // The isolated group includes sudo and its privileged tracer, never the validator.
            let _ = Command::new("sudo")
                .args(["--non-interactive", "--", "kill", "-TERM", "--"])
                .arg(format!("-{}", self.process.id()))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }
}
