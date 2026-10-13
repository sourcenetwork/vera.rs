use std::{sync::Arc, time::Duration};

use jsonrpsee::core::client::ClientT;
use tokio::sync::{Semaphore, mpsc};

#[tokio::test]
async fn http_rejects_aggregate_body_before_dispatch() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, Copy)]
    enum Encoding {
        ContentLength,
        HeadersOnly,
        Chunked,
    }

    async fn post(
        addr: std::net::SocketAddr,
        body: &str,
        encoding: Encoding,
    ) -> (u16, serde_json::Value) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut reader, mut writer) = socket.into_split();
            let framing = match encoding {
                Encoding::ContentLength | Encoding::HeadersOnly => {
                    format!("Content-Length: {}", body.len())
                }
                Encoding::Chunked => "Transfer-Encoding: chunked".to_owned(),
            };
            let headers = format!(
                "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{framing}\r\nConnection: close\r\n\r\n"
            );
            let (sent, response) = tokio::join!(
                async {
                    writer.write_all(headers.as_bytes()).await?;
                    match encoding {
                        Encoding::ContentLength => writer.write_all(body.as_bytes()).await?,
                        Encoding::HeadersOnly => {}
                        Encoding::Chunked => {
                            writer.write_all(format!("{:x}\r\n", body.len()).as_bytes()).await?;
                            writer.write_all(body.as_bytes()).await?;
                            writer.write_all(b"\r\n0\r\n\r\n").await?;
                        }
                    }
                    Ok::<_, std::io::Error>(())
                },
                async {
                    let mut response = Vec::new();
                    loop {
                        let mut chunk = [0; 512];
                        let count = reader.read(&mut chunk).await.unwrap();
                        assert!(count > 0, "HTTP response must be complete");
                        response.extend_from_slice(&chunk[..count]);
                        assert!(response.len() <= 4096);
                        let Some(end) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
                            continue;
                        };
                        let headers = std::str::from_utf8(&response[..end]).unwrap();
                        let length: usize = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        }).unwrap();
                        assert!(length <= 4096 - end - 4);
                        let body = &response[end + 4..];
                        if body.len() < length {
                            continue;
                        }
                        assert_eq!(body.len(), length);
                        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
                        break (status, serde_json::from_slice(body).unwrap());
                    }
                }
            );
            if response.0 == 200 {
                sent.unwrap();
            }
            response
        })
        .await
        .expect("bounded HTTP request deadline")
    }

    fn request(id: u64, bytes: usize) -> String {
        serde_json::json!({"jsonrpc": "2.0", "method": "bounded", "id": id,
            "params": ["x".repeat(bytes)]})
        .to_string()
    }

    let dispatched = Arc::new(AtomicUsize::new(0));
    let observed = dispatched.clone();
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("bounded", move |_, _, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            true
        })
        .unwrap();
    let (handle, addr) = crate::JsonRpcServer::new("127.0.0.1:0".parse().unwrap(), 1)
        .with_extra_module(module)
        .start()
        .await
        .unwrap();
    let limit = vera_domain::SUBMISSION_REQUEST_BYTES as usize;
    let first = request(1, limit / 2);
    let second = request(2, limit / 2);
    for (body, encoding) in [
        (&first, Encoding::ContentLength),
        (&second, Encoding::ContentLength),
        (&first, Encoding::Chunked),
    ] {
        assert!(body.len() < limit);
        let (status, response) = post(addr, body, encoding).await;
        assert_eq!(status, 200);
        assert_eq!(response["result"], true);
    }
    assert_eq!(dispatched.load(Ordering::SeqCst), 3);

    let batch = format!("[{first},{second}]");
    assert!(batch.len() > limit);
    for encoding in [Encoding::HeadersOnly, Encoding::Chunked] {
        let (status, response) = post(addr, &batch, encoding).await;
        assert_eq!(status, 413);
        assert_eq!(
            response["error"]["code"],
            jsonrpsee::types::error::OVERSIZED_REQUEST_CODE
        );
        assert_eq!(dispatched.load(Ordering::SeqCst), 3);
    }

    let (status, response) = post(addr, &request(3, 0), Encoding::ContentLength).await;
    assert_eq!(status, 200);
    assert_eq!(response["result"], true);
    assert_eq!(dispatched.load(Ordering::SeqCst), 4);
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn websocket_dispatch_applies_backpressure() {
    let permits = Arc::new(Semaphore::new(0));
    let (entered, mut entries) = mpsc::unbounded_channel();
    let mut module = jsonrpsee::RpcModule::new(());
    let gate = permits.clone();
    module
        .register_async_method("wait", move |_, _, _| {
            let gate = gate.clone();
            let entered = entered.clone();
            async move {
                entered.send(()).unwrap();
                gate.acquire().await.unwrap().forget();
                "done"
            }
        })
        .unwrap();
    let (handle, addr) = crate::JsonRpcServer::new("127.0.0.1:0".parse().unwrap(), 1)
        .with_extra_module(module)
        .start()
        .await
        .unwrap();
    let client = Arc::new(
        jsonrpsee::ws_client::WsClientBuilder::default()
            .build(format!("ws://{addr}"))
            .await
            .unwrap(),
    );
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..9 {
        let client = client.clone();
        requests.spawn(async move {
            client
                .request::<String, _>("wait", jsonrpsee::rpc_params![])
                .await
                .unwrap()
        });
    }
    for _ in 0..8 {
        tokio::time::timeout(Duration::from_secs(5), entries.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), entries.recv())
            .await
            .is_err()
    );
    permits.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), entries.recv())
        .await
        .unwrap()
        .unwrap();
    permits.add_permits(8);
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(result) = requests.join_next().await {
            assert_eq!(result.unwrap(), "done");
        }
    })
    .await
    .unwrap();
    handle.stop().unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle.stopped())
        .await
        .unwrap();
}

#[tokio::test]
async fn websocket_non_reader_does_not_hold_shutdown_open() {
    non_reader(true).await;
}

#[tokio::test]
async fn websocket_non_reader_releases_connection_slot() {
    non_reader(false).await;
}

async fn non_reader(stop_before_timeout: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (entered, mut entries) = mpsc::unbounded_channel();
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("large", move |_, _, _| {
            entered.send(()).unwrap();
            "x".repeat(4 << 20)
        })
        .unwrap();
    let (handle, addr) = crate::JsonRpcServer::new("127.0.0.1:0".parse().unwrap(), 1)
        .with_max_connections(1)
        .with_extra_module(module)
        .start()
        .await
        .unwrap();
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket.write_all(format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut handshake = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !handshake.ends_with(b"\r\n\r\n") {
            assert!(handshake.len() < 4096);
            handshake.push(socket.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(handshake.starts_with(b"HTTP/1.1 101"));
    for id in 0..32 {
        let request = format!(r#"{{"jsonrpc":"2.0","method":"large","id":{id}}}"#);
        assert!(request.len() < 126);
        let mask = [1, 2, 3, 4];
        let mut frame = vec![0x81, 0x80 | request.len() as u8];
        frame.extend(mask);
        frame.extend(request.bytes().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        socket.write_all(&frame).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..16 {
            entries.recv().await.unwrap();
        }
    })
    .await
    .unwrap();
    if !stop_before_timeout {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Ok(client) = jsonrpsee::ws_client::WsClientBuilder::default()
                    .build(format!("ws://{addr}"))
                    .await
                {
                    drop(client);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the timed-out writer must release its connection slot");
    }
    handle.stop().unwrap();
    tokio::time::timeout(Duration::from_secs(15), handle.stopped())
        .await
        .expect("a non-reading socket must not prevent server shutdown");
    drop(socket);
}
