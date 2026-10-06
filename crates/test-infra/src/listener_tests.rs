use std::{
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::FromRawFd,
    sync::Mutex,
    time::Duration,
};

use crate::{ManagedProcess, ReservedTcpListener, TestRunDir};

// Concurrent forks temporarily retain each other's close-on-exec listeners until exec.
static LISTENER_PROCESS_TEST: Mutex<()> = Mutex::new(());

#[test]
#[ignore = "subprocess fixture for listener inheritance"]
fn inherited_listener_child() {
    let fd = std::env::var("TEST_INFRA_LISTENER_FD")
        .unwrap()
        .parse()
        .unwrap();
    let other: i32 = std::env::var("TEST_INFRA_OTHER_FD")
        .unwrap()
        .parse()
        .unwrap();
    let other_port: u16 = std::env::var("TEST_INFRA_OTHER_PORT")
        .unwrap()
        .parse()
        .unwrap();
    // A descriptor number can be reused by test startup; it must not name the other reservation.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    let result =
        unsafe { libc::getsockname(other, std::ptr::from_mut(&mut address).cast(), &mut length) };
    assert!(
        result == -1
            || address.sin_family as libc::c_int != libc::AF_INET
            || u16::from_be(address.sin_port) != other_port,
        "unselected listener was inherited"
    );
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        stream.write_all(b"ready").unwrap();
        let mut end = [0];
        let _ = stream.read(&mut end);
    }
}

fn exchange(address: SocketAddr) {
    let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut response = [0; 5];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"ready");
}

#[test]
fn inherited_listener_reserves_port_across_child_exit_and_restart() {
    let _guard = LISTENER_PROCESS_TEST.lock().unwrap();
    let root = TestRunDir::new(
        &std::env::temp_dir().join("listener-inheritance"),
        "TEST_INFRA_KEEP",
    )
    .unwrap();
    let listener = ReservedTcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = listener.local_addr().unwrap();
    let selected_fd = listener.raw_fd();
    let fd = selected_fd.to_string();
    let other = ReservedTcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let other_fd = other.raw_fd().to_string();
    let other_port = other.local_addr().unwrap().port().to_string();
    assert!(TcpListener::bind(address).is_err());
    let mut child = ManagedProcess::spawn_with_listener(
        "listener",
        &std::env::current_exe().unwrap(),
        &[
            "--exact",
            "process::listener_tests::inherited_listener_child",
            "--ignored",
            "--nocapture",
        ],
        &[
            ("TEST_INFRA_LISTENER_FD", &fd),
            ("TEST_INFRA_OTHER_FD", &other_fd),
            ("TEST_INFRA_OTHER_PORT", &other_port),
        ],
        root.path(),
        listener,
    )
    .unwrap();
    exchange(address);
    child.kill();
    assert!(
        TcpListener::bind(address).is_err(),
        "parent must reserve the stopped child's port"
    );
    child.respawn().unwrap();
    exchange(address);
    child.kill();
    for fd in [selected_fd, other.raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(flags, -1, "parent listener must remain open");
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "spawn must not change parent descriptor flags"
        );
    }
    drop(child);
    drop(TcpListener::bind(address).expect("dropping the owner must release the reservation"));
}

#[test]
fn failed_spawn_releases_the_listener() {
    let _guard = LISTENER_PROCESS_TEST.lock().unwrap();
    let root = TestRunDir::new(
        &std::env::temp_dir().join("listener-spawn-failure"),
        "TEST_INFRA_KEEP",
    )
    .unwrap();
    let listener = ReservedTcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = listener.local_addr().unwrap();
    assert!(
        ManagedProcess::spawn_with_listener(
            "missing",
            &root.path().join("missing"),
            &[],
            &[],
            root.path(),
            listener
        )
        .is_err()
    );
    drop(TcpListener::bind(address).expect("failed spawn must release its listener"));
}
