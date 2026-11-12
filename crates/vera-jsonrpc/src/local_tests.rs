use jsonrpsee::core::client::ClientT;

use crate::{LocalRpcError, NodeState, NodeStatus, RpcServer};

#[tokio::test]
async fn local_and_network_callers_reach_the_same_methods() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let state = NodeState::new(7, 0, 1);
    let (handle, local) = RpcServer::new(state, address)
        .start_with_local(Some(listener))
        .unwrap();

    let in_process: NodeStatus = local.call_empty("vera_nodeStatus").await.unwrap();
    let client = jsonrpsee::ws_client::WsClientBuilder::default()
        .build(format!("ws://{address}"))
        .await
        .unwrap();
    let over_network: NodeStatus = client
        .request("vera_nodeStatus", jsonrpsee::rpc_params![])
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&in_process).unwrap(),
        serde_json::to_value(&over_network).unwrap()
    );
    handle.abort();
}

#[tokio::test]
async fn local_only_table_reports_method_errors_without_a_listener() {
    let local = RpcServer::new(NodeState::new(7, 0, 1), "127.0.0.1:0".parse().unwrap())
        .into_local()
        .unwrap();
    assert!(local.method_names().any(|name| name == "vera_sendNativeTx"));

    let rejected = local
        .request::<serde_json::Value>("vera_sendNativeTx", vec![serde_json::json!("0x")])
        .await
        .unwrap_err();
    assert!(matches!(rejected, LocalRpcError::Call { .. }));
    assert!(!rejected.is_retryable());

    let unknown = local
        .call_empty::<serde_json::Value>("vera_missing")
        .await
        .unwrap_err();
    assert!(matches!(unknown, LocalRpcError::Call { code: -32601, .. }));
}
