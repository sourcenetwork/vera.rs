//! Disk use of an embedded node's finalized history as its retained window fills and moves.

mod support;

use std::{
    num::NonZeroU64,
    path::Path,
    time::{Duration, Instant},
};

use support::{block_on, config, finalize_a_write};
use vera_client::BlsSigner;
use vera_jsonrpc::NodeStatus;
use vera_node::{EmbeddedNode, SOLO_BLOCKS_PER_EPOCH, minimum_history_retention};

fn directory_bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .map(|entry| {
                    let entry = entry.unwrap();
                    if entry.file_type().unwrap().is_dir() {
                        directory_bytes(&entry.path())
                    } else {
                        entry.metadata().map_or(0, |metadata| metadata.len())
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

fn height(node: &EmbeddedNode) -> u64 {
    let status: NodeStatus = block_on(node.rpc().call_empty("vera_nodeStatus")).unwrap();
    status.finalized_height.unwrap_or(0)
}

/// Prints one sample of the history directory each second: idle revisions
/// until `HISTORY_DISK_IDLE` (1,500), `HISTORY_DISK_WRITES` policy writes
/// (100), then idle revisions until the floor has moved for
/// `HISTORY_DISK_AFTER` revisions (2,000), under the minimum retention.
#[test]
#[ignore = "disk use is measured on demand"]
fn history_disk_use_as_the_window_fills_and_moves() {
    let setting = |name: &str, default: u64| {
        std::env::var(name).map_or(default, |value| value.trim().parse().unwrap())
    };
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9_461;
    let mut settings = config(directory.path(), chain_id);
    settings.pacing = None;
    let retained = minimum_history_retention(NonZeroU64::new(SOLO_BLOCKS_PER_EPOCH).unwrap());
    settings.history_retention = Some(retained);
    let history = directory.path().join("history");
    let node = block_on(EmbeddedNode::start(settings)).unwrap();
    let started = Instant::now();
    let sample = |phase: &str| {
        println!(
            "history_disk={}",
            serde_json::json!({
                "phase": phase,
                "seconds": started.elapsed().as_secs_f64(),
                "height": height(&node),
                "bytes": directory_bytes(&history),
            })
        );
    };
    let idle_until = |phase: &str, target: u64| {
        let deadline = Instant::now() + Duration::from_secs(3_600);
        while height(&node) < target {
            assert!(Instant::now() < deadline, "{phase} deadline");
            sample(phase);
            std::thread::sleep(Duration::from_secs(1));
        }
    };
    idle_until("idle", setting("HISTORY_DISK_IDLE", 1_500));
    sample("writes-start");
    for seed in 0..setting("HISTORY_DISK_WRITES", 100) {
        finalize_a_write(
            &node,
            &BlsSigner::new((100 + seed).into(), chain_id).unwrap(),
        );
    }
    sample("writes-end");
    let after = setting("HISTORY_DISK_AFTER", 2_000);
    idle_until("moving", retained + SOLO_BLOCKS_PER_EPOCH + after);
    sample("end");
    block_on(node.stop()).unwrap();
}
