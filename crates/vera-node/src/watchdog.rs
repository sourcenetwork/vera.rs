//! Finality-progress watchdog gated by observed peer connectivity.
//!
//! A stall counts only while this node is connected to enough peers to form a
//! voting quorum with them; fewer, or unknown connectivity, leaves the watchdog
//! unarmed. A lone validator is its own quorum and needs no peer. A stall is
//! evidence of missing progress, not a diagnosis of its cause or a guarantee
//! that restart helps.

use std::time::Duration;

use commonware_utils::{Faults as _, N3f1};
use vera_jsonrpc::NodeState;

/// Exit code reported when the watchdog trips.
pub(crate) const EXIT_CODE: i32 = 83;

/// Decide whether the process should fail from observed progress.
///
/// `finalized_ever` gates arming: a node that has never finalized — in this
/// run or any earlier one — is still joining, and initial synchronization may
/// legitimately take longer than the stall budget. A restarted node arms from
/// its durable history, so a restart that stops finalizing is covered.
pub(crate) fn tripped(
    finalized_ever: bool,
    stalled_for: Duration,
    quorum_connected: bool,
    budget: Duration,
) -> bool {
    finalized_ever && quorum_connected && stalled_for >= budget
}

/// Peers this node must be connected to before it and they form a voting quorum.
///
/// `validators` is the configured validator count, this node included.
pub(crate) fn peers_for_quorum(validators: usize) -> u64 {
    u64::from(N3f1::quorum(validators.max(1))).saturating_sub(1)
}

/// Run the watchdog until it trips.
///
/// `has_durable_history` arms the watchdog for a restart even before this
/// process observes its first finalization. `needed_peers` is the result of
/// [`peers_for_quorum`] for the deployment.
pub(crate) async fn run(
    state: NodeState,
    budget: Duration,
    has_durable_history: bool,
    needed_peers: u64,
    mode: crate::WatchdogMode,
) {
    let mut progress = Progress::new(state.finalized_count(), has_durable_history, needed_peers);
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let peers = state.status().peer_count;
        if progress.observe(
            state.finalized_count(),
            peers,
            tokio::time::Instant::now(),
            budget,
        ) {
            tracing::error!(
                stalled_seconds = progress.since.elapsed().as_secs(),
                peers,
                ?mode,
                "finality stalled"
            );
            match mode {
                crate::WatchdogMode::ExitProcess => std::process::exit(EXIT_CODE),
                // Returning completes this actor, which stops the node with an error.
                crate::WatchdogMode::Report => return,
            }
        }
    }
}

struct Progress {
    count: u64,
    finalized_ever: bool,
    connected: bool,
    needed_peers: u64,
    since: tokio::time::Instant,
}

impl Progress {
    fn new(count: u64, has_durable_history: bool, needed_peers: u64) -> Self {
        Self {
            count,
            finalized_ever: has_durable_history || count > 0,
            connected: false,
            needed_peers,
            since: tokio::time::Instant::now(),
        }
    }

    fn observe(
        &mut self,
        count: u64,
        peers: Option<u64>,
        now: tokio::time::Instant,
        budget: Duration,
    ) -> bool {
        let connected =
            self.needed_peers == 0 || peers.is_some_and(|count| count >= self.needed_peers);
        if count != self.count || !connected || !self.connected {
            self.since = now;
        }
        self.count = count;
        self.finalized_ever |= count > 0;
        self.connected = connected;
        tripped(
            self.finalized_ever,
            now.duration_since(self.since),
            connected,
            budget,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arms_only_after_first_finalization() {
        let budget = Duration::from_secs(600);
        assert!(!tripped(false, Duration::from_secs(9_999), true, budget));
        assert!(tripped(true, Duration::from_secs(600), true, budget));
    }

    #[test]
    fn peerless_stalls_do_not_trip() {
        assert!(!tripped(
            true,
            Duration::from_secs(9_999),
            false,
            Duration::from_secs(600),
        ));
    }

    #[test]
    fn progress_within_budget_does_not_trip() {
        assert!(!tripped(
            true,
            Duration::from_secs(599),
            true,
            Duration::from_secs(600),
        ));
    }

    #[test]
    fn unknown_or_disconnected_time_does_not_count_after_reconnection() {
        let budget = Duration::from_secs(600);
        for unavailable in [None, Some(0)] {
            let mut progress = Progress::new(0, true, 2);
            let start = tokio::time::Instant::now();
            assert!(!progress.observe(0, Some(3), start, budget));
            assert!(!progress.observe(0, unavailable, start + budget, budget));
            let reconnected = start + budget * 2;
            assert!(!progress.observe(0, Some(3), reconnected, budget));
            assert!(!progress.observe(
                0,
                Some(3),
                reconnected + budget - Duration::from_secs(1),
                budget
            ));
            assert!(progress.observe(0, Some(3), reconnected + budget, budget));
        }
    }

    #[test]
    fn a_lone_validator_trips_without_peers_once_it_has_finalized() {
        let budget = Duration::from_secs(600);
        let start = tokio::time::Instant::now();
        for peers in [None, Some(0)] {
            let mut joining = Progress::new(0, false, 0);
            assert!(!joining.observe(0, peers, start, budget));
            assert!(!joining.observe(0, peers, start + budget * 2, budget));

            let mut progress = Progress::new(5, true, 0);
            assert!(!progress.observe(5, peers, start, budget));
            assert!(!progress.observe(6, peers, start + budget, budget));
            assert!(!progress.observe(
                6,
                peers,
                start + budget * 2 - Duration::from_secs(1),
                budget
            ));
            assert!(progress.observe(6, peers, start + budget * 2, budget));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_lone_validator_is_reported_and_a_live_one_is_not() {
        let budget = Duration::from_secs(600);
        let report = crate::WatchdogMode::Report;

        let stalled = NodeState::new(7, 0, 1);
        let started = tokio::time::Instant::now();
        run(stalled, budget, true, 0, report).await;
        assert!(started.elapsed() >= budget);
        assert!(started.elapsed() < budget + Duration::from_secs(60));

        let live = NodeState::new(7, 0, 1);
        let heartbeat = live.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                heartbeat.inc_finalized();
            }
        });
        let outcome = tokio::time::timeout(budget * 10, run(live, budget, true, 0, report)).await;
        assert!(
            outcome.is_err(),
            "a finalizing node was reported as stalled"
        );

        let peerless = NodeState::new(7, 0, 4);
        let outcome =
            tokio::time::timeout(budget * 10, run(peerless, budget, true, 2, report)).await;
        assert!(outcome.is_err(), "unknown connectivity armed the watchdog");
    }

    #[test]
    fn a_quorum_needs_two_peers_of_four_validators_and_none_for_one() {
        for (validators, peers) in [(1, 0), (2, 1), (3, 2), (4, 2), (7, 4), (10, 6)] {
            assert_eq!(
                peers_for_quorum(validators),
                peers,
                "{validators} validators"
            );
        }
    }

    #[test]
    fn a_stall_without_a_connected_quorum_does_not_trip() {
        let budget = Duration::from_secs(600);
        let start = tokio::time::Instant::now();
        let mut progress = Progress::new(9, true, 2);
        assert!(!progress.observe(9, Some(1), start, budget));
        assert!(!progress.observe(9, Some(1), start + budget * 3, budget));
        assert!(!progress.observe(9, Some(2), start + budget * 4, budget));
        assert!(progress.observe(9, Some(2), start + budget * 5, budget));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_validator_with_a_connected_quorum_is_reported() {
        let budget = Duration::from_secs(600);
        let state = NodeState::new(7, 0, 4);
        state.set_peer_count(3);
        let started = tokio::time::Instant::now();
        run(state, budget, true, 2, crate::WatchdogMode::Report).await;
        assert!(started.elapsed() >= budget);
        assert!(started.elapsed() < budget + Duration::from_secs(90));
    }

    #[test]
    fn empty_history_stays_unarmed_and_new_finalization_resets_progress() {
        let budget = Duration::from_secs(600);
        let start = tokio::time::Instant::now();
        let mut progress = Progress::new(0, false, 2);
        assert!(!progress.observe(0, Some(3), start, budget));
        assert!(!progress.observe(0, Some(3), start + budget * 2, budget));
        assert!(!progress.observe(1, Some(3), start + budget * 3, budget));
        assert!(!progress.observe(2, Some(3), start + budget * 4, budget));
        assert!(progress.observe(2, Some(3), start + budget * 5, budget));
    }
}
