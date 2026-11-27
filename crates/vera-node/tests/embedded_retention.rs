//! Retention of an embedded node's consensus archives, state journals and finalized history.

mod support;

use std::time::{Duration, Instant};

use support::{await_certified_receipt, block_on, config, finalize_a_write};
use vera_client::BlsSigner;
use vera_config::PruningConfig;
use vera_domain::ReceiptResponse;
use vera_jsonrpc::{LocalRpcError, NodeStatus};
use vera_node::{EmbedError, EmbeddedConfig, EmbeddedNode, RetentionTooShort};

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

#[test]
fn a_history_retention_below_the_minimum_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = config(directory.path(), 9419);
    let epoch_length = std::num::NonZeroU64::new(vera_node::SOLO_BLOCKS_PER_EPOCH).unwrap();
    let minimum = vera_node::minimum_history_retention(epoch_length);
    settings.history_retention = Some(minimum - 1);
    let refused = block_on(EmbeddedNode::start(settings)).unwrap_err();
    assert!(
        matches!(
            refused,
            EmbedError::HistoryRetention(RetentionTooShort { retained, minimum: stated })
                if retained == minimum - 1 && stated == minimum
        ),
        "{refused}"
    );
}

#[test]
fn a_write_below_the_retained_history_is_pruned_and_a_restart_recovers_from_the_floor() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9420;
    let mut settings = config(directory.path(), chain_id);
    settings.pacing = None;
    settings.pruning = Some(PruningConfig {
        maintenance_interval: 1.try_into().unwrap(),
        retained_consensus_revisions: 254,
        retained_state_revisions: 0,
    });
    let epoch_length = std::num::NonZeroU64::new(vera_node::SOLO_BLOCKS_PER_EPOCH).unwrap();
    let retained = vera_node::minimum_history_retention(epoch_length);
    settings.history_retention = Some(retained);

    let node = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    let sent_at = height(&node);
    let early = finalize_a_write(&node, &BlsSigner::new(42u64.into(), chain_id).unwrap());
    let written_at = height(&node);
    let deadline = Instant::now() + Duration::from_secs(1_500);
    // The floor is the first block of an epoch: it passes the write once the
    // retained window starts in a later epoch than the write's.
    let length = epoch_length.get();
    let past = written_at - written_at % length + length + retained;
    while height(&node) < past + 1 {
        assert!(Instant::now() < deadline, "history retention deadline");
        std::thread::sleep(Duration::from_millis(500));
    }
    let pruned = |node: &EmbeddedNode| {
        let receipt: Option<ReceiptResponse> = block_on(
            node.rpc()
                .request("vera_getReceiptProof", vec![serde_json::json!(early)]),
        )
        .unwrap();
        assert!(receipt.is_none(), "a pruned receipt is not served");
        let known = block_on(node.rpc().request::<serde_json::Value>(
            "vera_getReceiptProof",
            vec![
                serde_json::json!(early),
                serde_json::json!(format!("{sent_at:#x}")),
            ],
        ))
        .unwrap_err();
        assert!(
            matches!(&known, LocalRpcError::Call { code: 4444, .. }),
            "{known}"
        );
        let refused = block_on(node.rpc().request::<serde_json::Value>(
            "vera_getLightBlock",
            vec![serde_json::json!(format!("{written_at:#x}"))],
        ))
        .unwrap_err();
        assert!(
            matches!(&refused, LocalRpcError::Call { code: 4444, .. }),
            "{refused}"
        );
    };
    // The pass that raises the floor runs after the revision is published.
    let settle = Instant::now() + Duration::from_secs(30);
    while block_on(node.rpc().request::<serde_json::Value>(
        "vera_getLightBlock",
        vec![serde_json::json!(format!("{written_at:#x}"))],
    ))
    .is_ok()
    {
        assert!(Instant::now() < settle, "the floor did not pass the write");
        std::thread::sleep(Duration::from_millis(100));
    }
    pruned(&node);
    block_on(node.stop()).unwrap();

    let node = block_on(EmbeddedNode::start(settings)).unwrap();
    pruned(&node);
    finalize_a_write(&node, &BlsSigner::new(43u64.into(), chain_id).unwrap());
    block_on(node.stop()).unwrap();
}
