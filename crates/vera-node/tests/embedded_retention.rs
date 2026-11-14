//! Retention of an embedded node's consensus archives and state journals.

#![recursion_limit = "256"]

mod support;

use std::time::{Duration, Instant};

use support::{await_certified_receipt, block_on, config, finalize_a_write};
use vera_client::BlsSigner;
use vera_config::PruningConfig;
use vera_jsonrpc::NodeStatus;
use vera_node::{EmbeddedConfig, EmbeddedNode};

fn height(node: &EmbeddedNode) -> u64 {
    let status: NodeStatus = block_on(node.rpc().call_empty("vera_nodeStatus")).unwrap();
    status.finalized_height.unwrap_or(0)
}

#[test]
fn the_default_retention_covers_two_epochs() {
    let directory = tempfile::tempdir().unwrap();
    let settings = config(directory.path(), 9417);
    assert_eq!(settings.pruning, Some(EmbeddedConfig::RETENTION));
    assert_eq!(EmbeddedConfig::RETENTION.retained_consensus_revisions, 512);
    assert_eq!(EmbeddedConfig::RETENTION.retained_state_revisions, 256);
}

#[test]
fn a_write_older_than_the_retained_window_survives_pruning_and_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9418;
    let mut settings = config(directory.path(), chain_id);
    // The daemon cadence reaches the pruning horizon in under two minutes.
    settings.pacing = None;
    // The smallest window an epoch allows, pruned at every revision.
    settings.pruning = Some(PruningConfig {
        maintenance_interval: 1.try_into().unwrap(),
        retained_consensus_revisions: 254,
        retained_state_revisions: 0,
    });

    let node = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    let early = finalize_a_write(&node, &BlsSigner::new(40u64.into(), chain_id).unwrap());
    let written_at = height(&node);
    // Archives are stored in sections of 256 revisions; the first ends up wholly behind the window.
    let first_section = directory
        .path()
        .join("commonware/vera-blocks-value/0000000000000000");
    assert!(first_section.exists());
    let deadline = Instant::now() + Duration::from_secs(600);
    while height(&node) < written_at + 600 {
        assert!(Instant::now() < deadline, "pruning horizon deadline");
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(
        !first_section.exists(),
        "the first archive section was kept"
    );
    await_certified_receipt(&node, early);
    block_on(node.stop()).unwrap();

    let node = block_on(EmbeddedNode::start(settings)).unwrap();
    await_certified_receipt(&node, early);
    finalize_a_write(&node, &BlsSigner::new(41u64.into(), chain_id).unwrap());
    block_on(node.stop()).unwrap();
}
