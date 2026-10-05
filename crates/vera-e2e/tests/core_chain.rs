//! Core chain e2e tests — BFT consensus, observability, cluster state.
//!
//! All tests use 4-node BFT clusters. This is a distributed system —
//! single-node tests don't exercise the interesting failure modes.
//!
//! Requires `cargo build -p verad` before running.

use std::time::Duration;

use vera_client::{ClientError, NodeStatus, VeraClient};
use vera_domain::ConsensusPublicKey;
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_e2e::observe::ClusterAssertions;

/// Canonical integration test exercising all observability subsystems.
///
/// Starts a 4-node BFT cluster, attaches observability, waits for blocks,
/// and cross-validates data between LogTracker, RpcPoller, and ClusterState.
#[tokio::test]
async fn cluster_observability_canonical() {
    let n = 4;
    let chain_id = 7777;

    // 1. Build 4-node BFT cluster with random keys.
    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(n)
        .chain_id(chain_id)
        // The observability assertion requires these INFO events even under RUST_LOG=warn.
        .rust_log("warn,vera_app::app=info")
        .build()
        .await
        .expect("cluster should start");

    // 2. Wait for all 4 nodes to become healthy.
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .expect("cluster should become healthy");

    // 3. Attach observability — spawns LogTracker per node + RpcPoller.
    let state = cluster.observe(Duration::from_millis(200));

    // 4. RPC poller should detect all 4 nodes as healthy.
    state
        .wait_for_healthy(n, Duration::from_secs(15))
        .await
        .expect("observer should see all nodes healthy");

    // 5. Wait for BFT consensus to finalize blocks.
    //    Height 6 gives the block index + RPC poller time to converge,
    //    so we can assert latest_block_height >= 4 below.
    state
        .wait_for_height(6, Duration::from_secs(30))
        .await
        .expect("should reach height 6");

    // 6. Chain ID must be consistent across all nodes (RPC poller).
    state
        .assert_chain_id(chain_id)
        .expect("chain_id should match across all nodes");

    // 7. All node snapshots should show consistent state.
    for i in 0..n {
        let snap = state.node(i);
        assert!(snap.is_healthy, "node{} should be healthy", i);
        assert_eq!(snap.chain_id, chain_id, "node{} snapshot chain_id", i);
        assert!(
            snap.effective_height() >= 6,
            "node{} effective height should be >= 6 (finalized={}, block={})",
            i,
            snap.finalized_count,
            snap.latest_block_height,
        );
        assert!(
            snap.finalized_height.is_some_and(|height| height >= 6),
            "node{} should report observed finalized progress: {:?}",
            i,
            snap.finalized_height,
        );
        assert!(snap.finalized_epoch.zip(snap.finalized_view).is_some());
        assert_eq!(snap.current_view, None, "live view is not yet instrumented");
        assert_eq!(snap.is_leader, None, "live leader is not yet instrumented");
        assert_eq!(snap.peer_count, None, "peer count is not yet instrumented");
        assert_eq!(
            snap.nullified_count, None,
            "nullifications are not yet instrumented"
        );
        assert!(
            snap.latest_block_height >= 4,
            "node{} latest_block_height should be >= 4 via IndexedStateProvider (got {})",
            i,
            snap.latest_block_height,
        );
    }

    // 8. LogTracker must be working — this test validates the observability framework.
    //    Wait for actual parsed progress instead of assuming a fixed parser delay.
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut poll = tokio::time::interval(Duration::from_millis(50));
        loop {
            poll.tick().await;
            if (0..n).all(|i| state.node_logs(i).latest_height() >= 2) {
                break;
            }
        }
    })
    .await
    .expect("all log trackers should parse at least height 2");
    for i in 0..n {
        let log_height = state.node_logs(i).latest_height();
        assert!(
            log_height >= 2,
            "node{} log tracker should have seen at least 2 blocks (got {}). \
             Log parser regex may not match vera's output format.",
            i,
            log_height,
        );
    }

    // 9. Cross-validate: log tracker heights and RPC poller heights must agree.
    for i in 0..n {
        let log_height = state.node_logs(i).latest_height();
        let rpc_height = state.node(i).effective_height();
        let diff = rpc_height.abs_diff(log_height);
        assert!(
            diff <= 5,
            "node{} log height ({}) and RPC height ({}) diverged by {} blocks",
            i,
            log_height,
            rpc_height,
            diff,
        );
    }

    // 10. All healthy nodes should have converged block heights (BFT guarantee).
    state
        .assert_heights_converged(2)
        .expect("BFT nodes should have converged heights");

    // 11. Verify node metadata across all validators.
    for i in 0..n {
        let snap = state.node(i);
        assert!(
            snap.uptime_secs > 0 || snap.finalized_count >= 6,
            "node{} should show progress (uptime={}, finalized={})",
            i,
            snap.uptime_secs,
            snap.finalized_count,
        );
    }

    // 12. Verify test infrastructure: each node has log and data files.
    for i in 0..n {
        let node = cluster.node(i);
        assert!(
            node.log_dir.join("stderr.log").exists(),
            "node{} stderr.log should exist",
            i,
        );
        assert!(
            node.log_dir.join("stdout.log").exists(),
            "node{} stdout.log should exist",
            i,
        );
        assert!(
            node.data_dir.join("genesis.json").exists(),
            "node{} genesis.json should exist",
            i,
        );
        assert!(
            node.data_dir.join("validator.key").exists(),
            "node{} validator.key should exist",
            i,
        );
    }

    // 13. No errors should have been logged by any node.
    state
        .assert_no_errors()
        .expect("cluster should have no errors");
}

/// Durable finalized observations survive isolated restart, then advance with quorum.
#[tokio::test]
async fn pipelined_finalized_telemetry_survives_restart() {
    let deployment = 7778;
    let trusted = *KeySet::builder()
        .nodes(4)
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .rust_log("warn,vera_node::node=info")
        .genesis(
            GenesisBuilder::devnet()
                .blocks_per_epoch(192)
                .simplex(vera_domain::SimplexParameters::default()),
        )
        .build()
        .await
        .expect("start pipelined validators");
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(3).rpc_url());
    wait_finalized_status(&client, "initial finalized observation", |status| {
        status.finalized_height.is_some_and(|height| height >= 6)
            && status.finalized_epoch.zip(status.finalized_view).is_some()
    })
    .await;

    // Stop peers first: recovery must use this node's durable data, without
    // fetching a newer header or waiting for another quorum to finalize a block.
    for index in 0..3 {
        cluster.kill_node(index);
    }
    let before = client
        .node_status()
        .await
        .expect("last published status before restart");
    let height_before = before.finalized_height.unwrap();
    let round_before = before.finalized_epoch.zip(before.finalized_view).unwrap();
    assert!(height_before >= 6);
    let data_dir = cluster.node(3).data_dir.clone();
    cluster.restart_node(3).expect("restart from retained data");
    assert_eq!(cluster.node(3).data_dir, data_dir);

    // RPC accessibility is enough here; with every peer stopped, consensus
    // readiness is deliberately not a prerequisite for observing recovered state.
    let recovered = wait_finalized_status(&client, "isolated recovered observation", |status| {
        status
            .finalized_height
            .is_some_and(|height| height >= height_before)
            && status.finalized_epoch.zip(status.finalized_view).is_some()
    })
    .await;
    let recovered_height = recovered.finalized_height.unwrap();
    let recovered_round = recovered
        .finalized_epoch
        .zip(recovered.finalized_view)
        .unwrap();
    if recovered_height == height_before {
        assert_eq!(recovered_round, round_before);
    } else {
        // The last pre-stop RPC read may lag a final callback already in flight.
        assert!(recovered_round > round_before);
    }
    assert_eq!(recovered.current_view, None);
    assert_eq!(recovered.is_leader, None);

    for index in 0..3 {
        cluster.restart_node(index).expect("resume quorum");
    }
    // Retained-history startup can spend 30 seconds probing the network epoch
    // before opening RPC. Allow that bounded probe plus normal startup time.
    cluster
        .wait_ready(Duration::from_secs(30) + vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let advanced = wait_finalized_status(
        &client,
        "finalized progress after quorum resumes",
        |status| {
            status
                .finalized_height
                .is_some_and(|height| height > recovered_height)
                && status
                    .finalized_epoch
                    .zip(status.finalized_view)
                    .is_some_and(|round| round > recovered_round)
        },
    )
    .await;
    // Authenticate both captured observations once peers can supply finality
    // artifacts; a telemetry observation need not already have a served proof.
    assert_observed_revision(&client, &recovered, &trusted).await;
    assert_observed_revision(&client, &advanced, &trusted).await;
}

async fn wait_finalized_status(
    client: &VeraClient,
    phase: &str,
    ready: impl Fn(&NodeStatus) -> bool,
) -> NodeStatus {
    let mut last = String::from("no response");
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut poll = tokio::time::interval(Duration::from_millis(100));
        loop {
            poll.tick().await;
            match client.node_status().await {
                Ok(status) if ready(&status) => return status,
                Ok(status) => last = format!("{status:?}"),
                Err(error) => last = error.to_string(),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{phase} deadline: {last}"))
}

async fn assert_observed_revision(
    client: &VeraClient,
    status: &NodeStatus,
    trusted: &ConsensusPublicKey,
) {
    let height = status.finalized_height.expect("observed finalized height");
    let pending = format!(
        "finalization certificate not found for height {height} within retained proof limits"
    );
    let revision = tokio::time::timeout(Duration::from_secs(30), async {
        let mut poll = tokio::time::interval(Duration::from_millis(100));
        loop {
            poll.tick().await;
            match client.read_finalized_revision(height, trusted).await {
                Ok(revision) => break revision,
                Err(ClientError::Rpc { message, .. }) if message.ends_with(&pending) => {}
                Err(error) => panic!("verify indexed finalized revision: {error}"),
            }
        }
    })
    .await
    .expect("indexed finalized revision deadline");
    assert_eq!(Some(revision.height), status.finalized_height);
    assert_eq!(Some(revision.epoch), status.finalized_epoch);
    assert_eq!(Some(revision.view), status.finalized_view);
}
