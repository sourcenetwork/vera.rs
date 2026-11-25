//! Integration test for gossip header subscriptions.
//!
//! Verifies that `vera_subscribeHeaders` delivers signed `GossipHeader`
//! events when blocks finalize. Requires `cargo build -p verad` before running.

use std::time::Duration;

use jsonrpsee::core::client::SubscriptionClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};

#[tokio::test]
async fn gossip_headers_subscription() {
    let chain_id = 9002;
    let genesis = GenesisBuilder::devnet();

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
        .chain_id(chain_id)
        .genesis(genesis)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .expect("cluster should start");

    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .expect("cluster should become healthy");

    // Subscribe to gossip headers on node 0.
    let ws_client = WsClientBuilder::default()
        .build(&cluster.node(0).ws_url())
        .await
        .expect("WebSocket connection should succeed");

    let mut headers_sub = ws_client
        .subscribe::<serde_json::Value, _>(
            "vera_subscribeHeaders",
            rpc_params![],
            "vera_unsubscribeHeaders",
        )
        .await
        .expect("headers subscription should succeed");

    // Blocks finalize continuously — wait for a header.
    let header = tokio::time::timeout(Duration::from_secs(15), headers_sub.next())
        .await
        .expect("header should arrive within timeout")
        .expect("subscription should not be closed")
        .expect("header should deserialize");

    assert_eq!(
        header["chain_id"], chain_id,
        "chain_id should match cluster"
    );
    let height = header["height"].as_u64().expect("height should be u64");
    assert!(height > 0, "height should be positive");
    assert!(
        !header["block_hash"].is_null(),
        "block_hash should be present"
    );
    assert!(
        !header["parent_hash"].is_null(),
        "parent_hash should be present"
    );
    assert!(
        !header["module_state_root"].is_null(),
        "module_state_root should be present"
    );

    let sig = header["signature"]
        .as_array()
        .expect("signature should be an array");
    assert_eq!(sig.len(), 96, "BLS certificate should be 96 bytes");
    assert!(
        sig.iter().any(|b| b.as_u64() != Some(0)),
        "signature should not be all zeros"
    );

    let publisher_index = header["publisher_index"]
        .as_u64()
        .expect("publisher_index should be u64");
    assert!(publisher_index < 4, "publisher_index should be < 4 nodes");

    // Verify a second header arrives (blocks keep finalizing).
    let header2 = tokio::time::timeout(Duration::from_secs(15), headers_sub.next())
        .await
        .expect("second header should arrive")
        .expect("subscription should not be closed")
        .expect("second header should deserialize");

    let height2 = header2["height"].as_u64().expect("height2 should be u64");
    assert!(
        height2 >= height,
        "second header height ({height2}) should be >= first ({height})"
    );

    // Verify headers arrive on a different node too.
    let ws_client2 = WsClientBuilder::default()
        .build(&cluster.node(1).ws_url())
        .await
        .expect("WebSocket connection to node 1 should succeed");

    let mut headers_sub2 = ws_client2
        .subscribe::<serde_json::Value, _>(
            "vera_subscribeHeaders",
            rpc_params![],
            "vera_unsubscribeHeaders",
        )
        .await
        .expect("headers subscription on node 1 should succeed");

    let header_node1 = tokio::time::timeout(Duration::from_secs(15), headers_sub2.next())
        .await
        .expect("node 1 header should arrive")
        .expect("subscription should not be closed")
        .expect("header should deserialize");

    assert_eq!(
        header_node1["chain_id"], chain_id,
        "node 1 chain_id should match"
    );
    let height_node1 = header_node1["height"]
        .as_u64()
        .expect("node 1 height should be u64");
    assert!(height_node1 > 0, "node 1 height should be positive");
}
