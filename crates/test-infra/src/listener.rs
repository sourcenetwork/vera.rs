//! A TCP reservation inherited by one managed child and retained across restarts.

use std::{
    io,
    net::{SocketAddr, TcpListener},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::Command,
};

/// Keeps a bound TCP listener until the owning managed process is dropped.
#[derive(Debug)]
pub struct ReservedTcpListener {
    listener: TcpListener,
}

impl ReservedTcpListener {
    /// Bind a listener, using port zero for an OS-assigned port.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        let listener = if listener.as_raw_fd() < 3 {
            let duplicated = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if duplicated == -1 {
                return Err(io::Error::last_os_error());
            }
            TcpListener::from(unsafe { OwnedFd::from_raw_fd(duplicated) })
        } else {
            listener
        };
        let fd = listener.as_raw_fd();
        // Keep every reservation closed in other children, including concurrent spawns.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { listener })
    }

    /// Address kept reserved by this listener.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Descriptor number to pass explicitly to the child's listener option.
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        self.listener.as_raw_fd()
    }

    pub(super) fn configure_child(&self, command: &mut Command) {
        let fd = self.raw_fd();
        // The parent keeps ownership until spawn returns and across respawns.
        // Only async-signal-safe fcntl calls run between fork and exec.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}
