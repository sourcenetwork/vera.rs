use super::*;
use std::{
    io::{Read as _, Seek as _, Write as _},
    net::{TcpStream, UdpSocket},
    os::unix::net::{UnixListener, UnixStream},
};

#[test]
fn inherited_listener_accepts_exact_address_and_restores_descriptor_flags() {
    let original = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = original.local_addr().unwrap();
    let fd = original.as_raw_fd();
    assert_ne!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, -1);
    let listener = inherited_tcp_listener(fd, address).unwrap();
    assert_ne!(listener.as_raw_fd(), fd);
    assert_eq!(listener.local_addr().unwrap(), address);
    for fd in [fd, listener.as_raw_fd()] {
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
    }
    assert!(TcpListener::bind(address).is_err());
}

#[test]
fn inherited_listener_rejects_foreign_descriptors_without_closing_them() {
    let expected = "127.0.0.1:9000".parse().unwrap();
    for fd in [-1, 0, 1, 2, i32::MAX] {
        assert!(inherited_tcp_listener(fd, expected).is_err());
    }
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"file").unwrap();
    file.rewind().unwrap();
    assert!(inherited_tcp_listener(file.as_raw_fd(), expected).is_err());
    let mut contents = [0; 4];
    file.read_exact(&mut contents).unwrap();
    assert_eq!(&contents, b"file");
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = udp.local_addr().unwrap();
    assert!(inherited_tcp_listener(udp.as_raw_fd(), address).is_err());
    assert_eq!(udp.local_addr().unwrap(), address);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("listener.sock");
    let unix = UnixListener::bind(&path).unwrap();
    assert!(inherited_tcp_listener(unix.as_raw_fd(), expected).is_err());
    let _client = UnixStream::connect(&path).unwrap();
    let (_peer, _) = unix.accept().unwrap();
    let unconnected = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
    assert_ne!(unconnected, -1);
    let unconnected = unsafe { OwnedFd::from_raw_fd(unconnected) };
    assert!(inherited_tcp_listener(unconnected.as_raw_fd(), expected).is_err());
    assert_ne!(
        unsafe { libc::fcntl(unconnected.as_raw_fd(), libc::F_GETFD) },
        -1
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    assert!(inherited_tcp_listener(stream.as_raw_fd(), stream.local_addr().unwrap()).is_err());
    stream.write_all(b"live").unwrap();
    let mut data = [0; 4];
    peer.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"live");
}

#[test]
fn inherited_listener_rejects_address_mismatch_without_releasing_reservation() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let different = SocketAddr::new(address.ip(), address.port().wrapping_add(1));
    assert!(inherited_tcp_listener(listener.as_raw_fd(), different).is_err());
    assert_eq!(listener.local_addr().unwrap(), address);
    assert!(TcpListener::bind(address).is_err());
    drop(listener);
    assert!(TcpListener::bind(address).is_ok());
}
