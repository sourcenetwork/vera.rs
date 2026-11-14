use super::*;
use jsonrpsee::core::client::ClientT as _;

#[tokio::test]
async fn inherited_listener_serves_rpc_without_rebinding() {
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let (server, _local) = RpcServer::new(NodeState::new(1, 0, 1), address)
        .start_with_local(Some(reservation.try_clone().unwrap()))
        .unwrap();
    assert_eq!(server.local_addr(), address);
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
    server.stop();
}

#[tokio::test]
async fn inherited_listener_rejects_configured_address_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let different = SocketAddr::new(address.ip(), address.port().wrapping_add(1));
    assert!(
        RpcServer::new(NodeState::new(1, 0, 1), different)
            .start_with_local(Some(listener))
            .is_err()
    );
    assert!(TcpListener::bind(address).is_ok());
}

#[tokio::test]
async fn an_occupied_address_fails_the_start() {
    let occupant = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupant.local_addr().unwrap();
    assert!(matches!(
        RpcServer::new(NodeState::new(1, 0, 1), address).start_with_local(None),
        Err(ServerError::Bind(_))
    ));
}

#[tokio::test]
async fn a_system_chosen_port_is_bound_before_the_start_returns() {
    let (server, _local) = RpcServer::new(NodeState::new(1, 0, 1), "127.0.0.1:0".parse().unwrap())
        .start_with_local(None)
        .unwrap();
    let address = server.local_addr();
    assert_ne!(address.port(), 0);
    assert!(TcpListener::bind(address).is_err());
    server.stop();
    tokio::time::timeout(std::time::Duration::from_secs(5), server.stopped())
        .await
        .unwrap();
}
