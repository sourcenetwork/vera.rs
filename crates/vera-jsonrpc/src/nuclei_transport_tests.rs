use std::{sync::Arc, time::Duration};

use jsonrpsee_server::{RpcModule, ServerConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::Server;

#[tokio::test]
async fn serves_a_request_and_stops_with_a_prebound_listener() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = Server::bind(address, Some(listener), ServerConfig::default()).unwrap();
    let mut methods = RpcModule::new(());
    methods.register_method("probe", |_, _, _| 42u32).unwrap();
    let handle = server.start(methods);

    let mut stream = TcpStream::connect(address).await.unwrap();
    let body = r#"{"jsonrpc":"2.0","method":"probe","id":1}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.contains("200 OK"), "{response}");
    assert!(response.contains("\"result\":42"), "{response}");
    handle.stop().unwrap();
    timeout(Duration::from_secs(5), handle.stopped())
        .await
        .unwrap();
}

#[tokio::test]
async fn stopping_drains_an_inflight_request() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = Server::bind(address, Some(listener), ServerConfig::default()).unwrap();
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let mut methods = RpcModule::new(());
    let started_for_method = Arc::clone(&started);
    let release_for_method = Arc::clone(&release);
    methods
        .register_async_method("pending", move |_, _, _| {
            let started = Arc::clone(&started_for_method);
            let release = Arc::clone(&release_for_method);
            async move {
                started.notify_one();
                release.notified().await;
                42u32
            }
        })
        .unwrap();
    let handle = server.start(methods);
    let mut stream = TcpStream::connect(address).await.unwrap();
    let body = r#"{"jsonrpc":"2.0","method":"pending","id":1}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    handle.stop().unwrap();
    release.notify_one();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8(response)
            .unwrap()
            .contains("\"result\":42")
    );
    timeout(Duration::from_secs(5), handle.stopped())
        .await
        .unwrap();
}
#[tokio::test]
async fn websocket_upgrade_dispatches_a_request() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = Server::bind(address, Some(listener), ServerConfig::default()).unwrap();
    let mut methods = RpcModule::new(());
    methods.register_method("probe", |_, _, _| 42u32).unwrap();
    let handle = server.start(methods);
    let mut stream = TcpStream::connect(address).await.unwrap();
    let handshake = format!(
        "GET / HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(handshake.as_bytes()).await.unwrap();
    timeout(Duration::from_secs(5), async {
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            assert!(headers.len() < 4096);
            headers.push(stream.read_u8().await.unwrap());
        }
        assert!(headers.starts_with(b"HTTP/1.1 101"));
    })
    .await
    .unwrap();
    let request = br#"{"jsonrpc":"2.0","method":"probe","id":1}"#;
    let mask = [1, 2, 3, 4];
    let mut frame = vec![0x81, 0x80 | request.len() as u8];
    frame.extend(mask);
    frame.extend(
        request
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ mask[i % 4]),
    );
    stream.write_all(&frame).await.unwrap();
    let response = timeout(Duration::from_secs(5), async {
        assert_eq!(stream.read_u8().await.unwrap(), 0x81);
        let size = stream.read_u8().await.unwrap();
        assert!(size < 126);
        let mut payload = vec![0; size as usize];
        stream.read_exact(&mut payload).await.unwrap();
        String::from_utf8(payload).unwrap()
    })
    .await
    .unwrap();
    assert!(response.contains("\"result\":42"), "{response}");
    drop(stream);
    handle.stop().unwrap();
    timeout(Duration::from_secs(5), handle.stopped())
        .await
        .unwrap();
}
#[tokio::test]
async fn websocket_non_reader_does_not_prevent_shutdown() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config = ServerConfig::builder()
        .max_connections(1)
        .max_response_body_size(5 << 20)
        .set_message_buffer_capacity(8)
        .build();
    let server = Server::bind(address, Some(listener), config).unwrap();
    let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
    let mut methods = RpcModule::new(());
    methods
        .register_method("large", move |_, _, _| {
            entered.send(()).unwrap();
            "x".repeat(4 << 20)
        })
        .unwrap();
    let handle = server.start(methods);
    let mut stream = TcpStream::connect(address).await.unwrap();
    let handshake = format!(
        "GET / HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(handshake.as_bytes()).await.unwrap();
    timeout(Duration::from_secs(5), async {
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            assert!(headers.len() < 4096);
            headers.push(stream.read_u8().await.unwrap());
        }
        assert!(headers.starts_with(b"HTTP/1.1 101"));
    })
    .await
    .unwrap();
    for id in 0..32 {
        let request = format!(r#"{{"jsonrpc":"2.0","method":"large","id":{id}}}"#);
        let mask = [1, 2, 3, 4];
        let mut frame = vec![0x81, 0x80 | request.len() as u8];
        frame.extend(mask);
        frame.extend(
            request
                .bytes()
                .enumerate()
                .map(|(i, byte)| byte ^ mask[i % 4]),
        );
        stream.write_all(&frame).await.unwrap();
    }
    timeout(Duration::from_secs(5), async {
        for _ in 0..8 {
            entries.recv().await.unwrap();
        }
    })
    .await
    .unwrap();
    handle.stop().unwrap();
    timeout(Duration::from_secs(15), handle.stopped())
        .await
        .unwrap();
    drop(stream);
}
#[tokio::test]
async fn rejects_an_oversized_request_before_dispatch() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config = ServerConfig::builder().max_request_body_size(64).build();
    let server = Server::bind(address, Some(listener), config).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut methods = RpcModule::new(());
    methods
        .register_method("probe", move |_, _, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            42u32
        })
        .unwrap();
    let handle = server.start(methods);
    let mut stream = TcpStream::connect(address).await.unwrap();
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"probe","id":1,"params":["{}"]}}"#,
        "x".repeat(128)
    );
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 413")
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    handle.stop().unwrap();
    timeout(Duration::from_secs(5), handle.stopped())
        .await
        .unwrap();
}

#[tokio::test]
async fn websocket_connections_share_the_configured_limit() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config = ServerConfig::builder().max_connections(1).build();
    let server = Server::bind(address, Some(listener), config).unwrap();
    let handle = server.start(RpcModule::new(()));
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    async fn headers(stream: &mut TcpStream) -> Vec<u8> {
        timeout(Duration::from_secs(5), async {
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                assert!(bytes.len() < 4096);
                bytes.push(stream.read_u8().await.unwrap());
            }
            bytes
        })
        .await
        .unwrap()
    }
    let mut first = TcpStream::connect(address).await.unwrap();
    first.write_all(request.as_bytes()).await.unwrap();
    assert!(headers(&mut first).await.starts_with(b"HTTP/1.1 101"));
    let mut second = TcpStream::connect(address).await.unwrap();
    second.write_all(request.as_bytes()).await.unwrap();
    assert!(headers(&mut second).await.starts_with(b"HTTP/1.1 429"));
    drop(first);
    drop(second);
    handle.stop().unwrap();
    timeout(Duration::from_secs(5), handle.stopped())
        .await
        .unwrap();
}
