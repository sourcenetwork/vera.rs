//! What keeping a retained window costs: maintenance time and disk use as the floor moves.

use super::start_cost_tests::{directory_bytes, heartbeat, heartbeat_info};
use super::*;
use std::{num::NonZeroU64, time::Instant};

const EPOCH: u64 = 256;

/// `HISTORY_RETENTION_COST_REVISIONS` sets the revisions appended, 20,000 by
/// default, under the minimum retention for 256-block epochs (or
/// `HISTORY_RETENTION_COST_RETAINED`), with a
/// maintenance pass every 64 revisions as an embedded node runs them.
/// Writes skip the WAL sync unless `HISTORY_RETENTION_COST_SYNC` is set.
#[test]
#[ignore = "retention cost is measured on demand with a release build"]
fn retention_cost_against_a_moving_floor() {
    let revisions: u64 = std::env::var("HISTORY_RETENTION_COST_REVISIONS")
        .map_or(20_000, |value| value.trim().parse().unwrap());
    let epoch_length = NonZeroU64::new(EPOCH).unwrap();
    let retention = HistoryRetention {
        retained: std::env::var("HISTORY_RETENTION_COST_RETAINED")
            .map_or(minimum_history_retention(epoch_length), |value| {
                value.trim().parse().unwrap()
            }),
        interval: NonZeroU64::new(64).unwrap(),
        epoch_length,
    };
    let directory = tempfile::tempdir().unwrap();
    let genesis = tests::block(0, BlockId(B256::ZERO));
    let history =
        FinalizedHistory::open_with(directory.path(), &genesis, Some(HistoryMemory::EMBEDDED))
            .unwrap();
    let synced = std::env::var_os("HISTORY_RETENTION_COST_SYNC").is_some();
    if !synced {
        history.db.skip_sync_for_test();
    }
    let info = heartbeat_info();
    let mut parent = genesis;
    let (mut idle_passes, mut pruning_passes) = (Vec::new(), Vec::new());
    for height in 1..=revisions {
        let (next, artifacts) = heartbeat(height, &parent, &info, EPOCH);
        history
            .append_finalized(&next, &[], 100, Some(&artifacts))
            .unwrap();
        parent = next;
        if retention.due(height) {
            let floor = history.floor_height().unwrap();
            let started = Instant::now();
            let moved = history.maintain(&retention).unwrap() != floor;
            let seconds = started.elapsed().as_secs_f64();
            if moved {
                pruning_passes.push(seconds);
            } else {
                idle_passes.push(seconds);
            }
        }
        if height.is_multiple_of(1_000) {
            println!(
                "history_retention_size={}",
                serde_json::json!({
                    "height": height,
                    "floor": history.floor_height().unwrap(),
                    "bytes": directory_bytes(directory.path()),
                })
            );
        }
    }
    let mut settled = Vec::new();
    for wait in [0, 10, 30] {
        std::thread::sleep(std::time::Duration::from_secs(wait));
        settled.push(directory_bytes(directory.path()));
    }
    history.db.flush_for_test().unwrap();
    let flushed = directory_bytes(directory.path());
    history.db.compact_for_test().unwrap();
    let compacted = directory_bytes(directory.path());
    let mean = |passes: &[f64]| passes.iter().sum::<f64>() / passes.len().max(1) as f64;
    let max = |passes: &[f64]| passes.iter().copied().fold(0.0, f64::max);

    // A pass that removes four epochs at once, as the first pass after enabling retention does.
    let backlog_directory = tempfile::tempdir().unwrap();
    let genesis = tests::block(0, BlockId(B256::ZERO));
    let backlog = FinalizedHistory::open_with(
        backlog_directory.path(),
        &genesis,
        Some(HistoryMemory::EMBEDDED),
    )
    .unwrap();
    if !synced {
        backlog.db.skip_sync_for_test();
    }
    let mut parent = genesis;
    for height in 1..=4 * EPOCH + 600 {
        let (next, artifacts) = heartbeat(height, &parent, &info, EPOCH);
        backlog
            .append_finalized(&next, &[], 100, Some(&artifacts))
            .unwrap();
        parent = next;
    }
    let started = Instant::now();
    assert_eq!(
        backlog.prune_below(4 * EPOCH, epoch_length).unwrap(),
        4 * EPOCH
    );
    let backlog_seconds = started.elapsed().as_secs_f64();
    println!(
        "history_retention_cost={}",
        serde_json::json!({
            "revisions": revisions,
            "synced": synced,
            "retained": retention.retained,
            "floor": history.floor_height().unwrap(),
            "idle_passes": idle_passes.len(),
            "idle_pass_mean_seconds": mean(&idle_passes),
            "pruning_passes": pruning_passes.len(),
            "pruning_pass_mean_seconds": mean(&pruning_passes),
            "pruning_pass_max_seconds": max(&pruning_passes),
            "bytes_after_0_10_40_seconds": settled,
            "bytes_after_flush": flushed,
            "bytes_after_full_compaction": compacted,
            "four_epoch_pass_seconds": backlog_seconds,
        })
    );
}
