//! Explicit inherited TCP listener validation.

use std::{
    io,
    net::{SocketAddr, TcpListener},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

/// Duplicate and validate an explicitly inherited listening TCP socket.
///
/// Rejected descriptors remain untouched. On success the original stays open
/// until process exit and becomes close-on-exec; the returned duplicate is owned
/// by the RPC server. Both refer to the same socket, which becomes nonblocking.
pub fn inherited_tcp_listener(fd: RawFd, expected: SocketAddr) -> io::Result<TcpListener> {
    if fd < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "listener descriptor must be greater than two",
        ));
    }
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated == -1 {
        return Err(io::Error::last_os_error());
    }
    // Only the freshly duplicated descriptor is transferred to Rust ownership.
    let owned = unsafe { OwnedFd::from_raw_fd(duplicated) };
    if socket_option(&owned, libc::SOL_SOCKET, libc::SO_TYPE)? != libc::SOCK_STREAM
        || !is_listening(&owned)?
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inherited descriptor is not a listening TCP socket",
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if socket_option(&owned, libc::SOL_SOCKET, libc::SO_PROTOCOL)? != libc::IPPROTO_TCP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inherited descriptor does not use TCP",
        ));
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
    socket_option(&owned, libc::IPPROTO_TCP, libc::TCP_NODELAY)?;
    let listener = TcpListener::from(owned);
    // SocketAddr conversion rejects address families other than IPv4 and IPv6.
    let actual = listener.local_addr()?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("inherited listener address {actual} does not match configured {expected}"),
        ));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(not(target_vendor = "apple"))]
fn is_listening(fd: &OwnedFd) -> io::Result<bool> {
    socket_option(fd, libc::SOL_SOCKET, libc::SO_ACCEPTCONN).map(|value| value != 0)
}

#[cfg(target_vendor = "apple")]
fn is_listening(fd: &OwnedFd) -> io::Result<bool> {
    // Darwin does not expose SO_ACCEPTCONN through getsockopt. TCP_CONNECTION_INFO
    // starts with the u8 tcpi_state; TCPS_LISTEN is 1 in netinet/tcp_fsm.h.
    let mut state = 0_u8;
    let mut length = std::mem::size_of_val(&state) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            std::ptr::from_mut(&mut state).cast(),
            &mut length,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&state) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TCP connection state length",
        ));
    }
    Ok(state == 1)
}

fn socket_option(fd: &OwnedFd, level: libc::c_int, name: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            name,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&value) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socket option length",
        ));
    }
    Ok(value)
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod tests;
