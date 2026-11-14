//! Authenticated peer connectivity, read from the network's own metrics.
//!
//! Commonware's discovery network reports its connections only as a metric
//! family with one sample per connected peer, so the count comes from the
//! encoded registry.

use commonware_runtime::{Metrics as _, tokio::Context};
use std::{sync::Arc, time::Duration};
use vera_jsonrpc::NodeState;

/// The tracker's per-peer connection gauge under the node's `network` context.
const CONNECTED: &str = "network_tracker_directory_connected";

const INTERVAL: Duration = Duration::from_secs(10);

/// Count the peers the network reports an authenticated connection to.
pub(crate) fn connected_peers(metrics: &str) -> u64 {
    metrics
        .lines()
        .filter(|line| {
            line.strip_prefix(CONNECTED)
                .is_some_and(|rest| rest.starts_with(['{', ' ']))
        })
        .count() as u64
}

/// Publish the connected-peer count to the node's status until the node stops.
pub(crate) async fn run(context: Context, state: NodeState) {
    let context = Arc::new(context);
    let mut interval = tokio::time::interval(INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let context = context.clone();
        match tokio::task::spawn_blocking(move || connected_peers(&context.encode())).await {
            Ok(count) => state.set_peer_count(count),
            Err(error) => tracing::warn!(%error, "peer connectivity sample failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_one_sample_per_connected_peer_and_ignores_other_families() {
        let metrics = "\
# HELP network_tracker_directory_connected Unix timestamp in milliseconds when each connected peer became active.
# TYPE network_tracker_directory_connected gauge
network_tracker_directory_connected{peer=\"aa\"} 1731500000000
network_tracker_directory_connected{peer=\"bb\"} 1731500000500
network_tracker_directory_connected_total{peer=\"cc\"} 1
network_tracker_directory_tracked 3
other_network_tracker_directory_connected{peer=\"dd\"} 1
";
        assert_eq!(connected_peers(metrics), 2);
        assert_eq!(connected_peers("network_tracker_directory_tracked 3\n"), 0);
    }
}
