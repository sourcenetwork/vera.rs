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
    assert!(local.method_names().contains(&"vera_sendNativeTx"));

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

/// Drives a future on the calling thread without any async runtime.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::sync::Arc::new(Unpark(std::thread::current())).into();
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => return output,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}

fn timer_module() -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_async_method("test_timer", |_, _, _| async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            tokio::task::spawn_blocking(|| "ran on the node runtime")
                .await
                .expect("blocking task")
        })
        .unwrap();
    module
}

#[test]
fn calls_run_on_the_building_runtime_from_a_thread_without_one() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let local = runtime.block_on(async {
        RpcServer::new(NodeState::new(7, 0, 1), "127.0.0.1:0".parse().unwrap())
            .with_extra_module(timer_module())
            .into_local()
            .unwrap()
    });
    assert!(tokio::runtime::Handle::try_current().is_err());

    let answer: String = block_on(local.call_empty("test_timer")).unwrap();
    assert_eq!(answer, "ran on the node runtime");
    let raw = block_on(local.request_raw("test_timer", Vec::new())).unwrap();
    assert_eq!(raw, "\"ran on the node runtime\"");

    drop(runtime);
    assert!(matches!(
        block_on(local.call_empty::<String>("test_timer")),
        Err(LocalRpcError::Stopped)
    ));
    assert!(matches!(
        block_on(local.subscribe("vera_subscribeHeaders", Vec::new(), 4)),
        Err(LocalRpcError::Stopped)
    ));
}

#[tokio::test]
async fn a_closed_table_is_released_for_every_clone() {
    let held = std::sync::Arc::new(());
    let witness = std::sync::Arc::downgrade(&held);
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("test_held", move |_, _, _| {
            std::sync::Arc::strong_count(&held)
        })
        .unwrap();
    let local = RpcServer::new(NodeState::new(7, 0, 1), "127.0.0.1:0".parse().unwrap())
        .with_extra_module(module)
        .into_local()
        .unwrap();
    let clone = local.clone();
    assert_eq!(clone.call_empty::<usize>("test_held").await.unwrap(), 1);

    local.close();

    assert!(witness.upgrade().is_none());
    assert!(clone.method_names().is_empty());
    assert!(matches!(
        clone.call_empty::<usize>("test_held").await,
        Err(LocalRpcError::Stopped)
    ));
    assert!(matches!(
        clone
            .subscribe("vera_subscribeHeaders", Vec::new(), 4)
            .await,
        Err(LocalRpcError::Stopped)
    ));
}
