use super::*;
use std::io::{BufRead, Read, Write};
use std::time::Duration;

#[tokio::test]
async fn transport_capacity_is_released_on_cancellation() {
    for queued in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = VeraClient::new(format!("http://{}", listener.local_addr().unwrap()))
            .with_max_concurrent_requests(std::num::NonZeroU32::new(1).unwrap());
        let client = if queued {
            client.with_request_queue(
                std::num::NonZeroU32::new(1).unwrap(),
                Duration::from_millis(20),
            )
        } else {
            client
        };
        let client = std::sync::Arc::new(client);
        let pending = {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .rpc_call_typed::<u64>("test", serde_json::json!([]))
                    .await
            })
        };
        let (first, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let error = client
            .rpc_call_typed::<u64>("test", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(matches!(error, ClientError::ClientCapacityExhausted));
        assert!(error.is_throttled());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        drop(first);
        let pending = tokio::spawn(async move {
            client
                .rpc_call_typed::<u64>("test", serde_json::json!([]))
                .await
        });
        let (_second, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
    }
}

async fn call(response: String, maximum: usize) -> Result<u64, ClientError> {
    call_transport(response, Some(maximum)).await
}

async fn call_transport(response: String, maximum: Option<usize>) -> Result<u64, ClientError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut input = std::io::BufReader::new(&mut stream);
        let mut length = 0;
        loop {
            let mut line = String::new();
            assert_ne!(input.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap();
            }
        }
        input.read_exact(&mut vec![0; length]).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
    });
    let client = VeraClient::new(format!("http://{address}"));
    let result = match maximum {
        Some(maximum) => {
            client
                .rpc_call_bounded("test", serde_json::json!([]), maximum)
                .await
        }
        None => client.rpc_call_typed("test", serde_json::json!([])).await,
    };
    server.join().unwrap();
    result
}

#[tokio::test]
async fn permission_transport_bounds_declared_and_chunked_responses() {
    let declared = "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n";
    assert!(matches!(
        call(declared.into(), 128).await,
        Err(ClientError::ResponseTooLarge(128))
    ));
    let declared = "HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\nConnection: close\r\n\r\n";
    assert!(matches!(
        call_transport(declared.into(), None).await,
        Err(ClientError::ResponseTooLarge(_))
    ));
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n100\r\n{}\r\n0\r\n\r\n",
        "x".repeat(256)
    );
    assert!(matches!(
        call(chunked, 128).await,
        Err(ClientError::ResponseTooLarge(128))
    ));
}

#[tokio::test]
async fn permission_transport_binds_response_id_before_returning_data() {
    for maximum in [None, Some(1024)] {
        for (id, protocol, valid) in [(1, "2.0", true), (2, "2.0", false), (1, "1.0", false)] {
            let body = format!(r#"{{"jsonrpc":"{protocol}","id":{id},"result":42}}"#);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let result = call_transport(response, maximum).await;
            if valid {
                assert_eq!(result.unwrap(), 42);
            } else {
                assert!(matches!(result, Err(ClientError::InvalidResponse(_))));
            }
        }
    }
}

#[tokio::test]
async fn transport_preserves_http_rejection_status_before_json_decoding() {
    for maximum in [None, Some(1024)] {
        let response =
            "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbusy";
        let error = call_transport(response.into(), maximum).await.unwrap_err();
        match error {
            ClientError::Transport(error) => {
                assert_eq!(error.status(), Some(reqwest::StatusCode::TOO_MANY_REQUESTS))
            }
            error => panic!("HTTP status lost: {error}"),
        }
    }
}
