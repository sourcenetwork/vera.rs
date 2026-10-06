use super::*;
use jsonrpsee::core::client::ClientT as _;

#[tokio::test]
async fn inherited_listener_serves_rpc_without_rebinding() {
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let server = RpcServer::new(NodeState::new(1, 0, 1), address)
        .start_with_listener(reservation.try_clone().unwrap())
        .unwrap();
    assert!(TcpListener::bind(address).is_err());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(format!("ws://{address}"))
            .await
            .unwrap();
        let chain: String = client
            .request("eth_chainId", jsonrpsee::rpc_params![])
            .await
            .unwrap();
        assert_eq!(chain, "0x1");
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test]
async fn inherited_listener_rejects_configured_address_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let different = SocketAddr::new(address.ip(), address.port().wrapping_add(1));
    assert!(
        RpcServer::new(NodeState::new(1, 0, 1), different)
            .start_with_listener(listener)
            .is_err()
    );
    assert!(TcpListener::bind(address).is_ok());
}
