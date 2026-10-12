use super::*;

#[test]
fn readiness_requires_a_matching_successful_rpc_response() {
    for body in [
        r#"{"jsonrpc":"2.0","id":1,"result":"0x0"}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x7a69","error":null}"#,
    ] {
        assert!(valid_response(body.as_bytes()));
    }
    for body in [
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"private"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":"0x1"}"#,
        r#"{"jsonrpc":"1.0","id":1,"result":"0x1"}"#,
        r#"{"id":1,"result":"0x1"}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"not-a-deployment"}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x"}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x+1"}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x10000000000000000"}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":1}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":"0x1","error":{"code":-1}}"#,
        "[]",
        "private invalid response",
    ] {
        assert!(!valid_response(body.as_bytes()));
    }
}

#[tokio::test]
async fn readiness_timeout_reports_member_positions_without_endpoints() {
    let listeners = [
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let urls = listeners
        .iter()
        .map(|listener| format!("http://{}", listener.local_addr().unwrap()))
        .collect::<Vec<_>>();
    let config = HealthCheckConfig {
        timeout: Duration::from_millis(20),
        poll_interval: Duration::from_millis(50),
    };
    let error = wait_all_healthy(&urls, &config).await.unwrap_err();
    assert_eq!(error.unavailable_nodes(), Some([0, 1].as_slice()));
    let text = error.to_string();
    assert!(!text.contains("127.0.0.1"));
    assert!(!text.contains("http://"));
}
