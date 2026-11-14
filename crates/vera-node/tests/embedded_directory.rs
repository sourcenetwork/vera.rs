//! The directory of an embedded node: free once the node stops, refused while one runs.

use std::{net::SocketAddr, path::Path, time::Duration};

use vera_jsonrpc::LocalRpcError;
use vera_modules::vera::administration::OperatorPolicy;
use vera_node::{EmbedError, EmbeddedConfig, EmbeddedNode, SoloGenesis};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn config(directory: &Path) -> EmbeddedConfig {
    let genesis = SoloGenesis {
        chain_id: 9_271,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec![ACCOUNT_KEY.into()],
        },
        timestamp: 1_800_000_000,
    };
    let listen: SocketAddr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    EmbeddedConfig::new(directory, genesis, listen)
}

async fn start(directory: &Path) -> Result<EmbeddedNode, EmbedError> {
    tokio::time::timeout(
        Duration::from_secs(60),
        EmbeddedNode::start(config(directory)),
    )
    .await
    .expect("start deadline")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surviving_rpc_handle_does_not_hold_a_stopped_nodes_directory() {
    let directory = tempfile::tempdir().unwrap();
    let node = start(directory.path()).await.unwrap();
    let survivor = node.rpc().clone();
    let headers = survivor
        .subscribe("vera_subscribeHeaders", Vec::new(), 4)
        .await
        .unwrap();
    node.stop().await.unwrap();

    assert!(matches!(
        survivor
            .call_empty::<serde_json::Value>("vera_nodeStatus")
            .await,
        Err(LocalRpcError::Stopped)
    ));
    let restarted = start(directory.path()).await.unwrap();
    restarted.stop().await.unwrap();
    drop(headers);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_directory_in_use_is_refused_instead_of_waited_for() {
    let directory = tempfile::tempdir().unwrap();
    let node = start(directory.path()).await.unwrap();

    let second = start(directory.path()).await;

    assert!(matches!(second, Err(EmbedError::DirectoryInUse(_))));
    node.stop().await.unwrap();
}
