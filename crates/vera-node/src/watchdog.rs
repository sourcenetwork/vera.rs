//! Finality-progress watchdog gated by observed peer connectivity.
//!
//! Unknown connectivity leaves the watchdog unarmed, except for a lone validator:
//! it finalizes by itself, so its stall needs no peer to be meaningful. A stall is
//! evidence of missing progress, not a diagnosis of its cause or a guarantee that
//! restart helps.

use std::time::Duration;

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
    peers_connected: bool,
    budget: Duration,
) -> bool {
    finalized_ever && peers_connected && stalled_for >= budget
}

/// Run the watchdog until it trips.
///
/// `has_durable_history` arms the watchdog for a restart even before this
/// process observes its first finalization. `lone_validator` says the
/// deployment's only validator is this node.
pub(crate) async fn run(
    state: NodeState,
    budget: Duration,
    has_durable_history: bool,
    lone_validator: bool,
    mode: crate::WatchdogMode,
) {
    let mut progress = Progress::new(state.finalized_count(), has_durable_history);
    progress.lone_validator = lone_validator;
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
    lone_validator: bool,
    since: tokio::time::Instant,
}

impl Progress {
    fn new(count: u64, has_durable_history: bool) -> Self {
        Self {
            count,
            finalized_ever: has_durable_history || count > 0,
            connected: false,
            lone_validator: false,
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
        let connected = self.lone_validator || peers.is_some_and(|count| count > 0);
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
            let mut progress = Progress::new(0, true);
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
            let mut joining = Progress::new(0, false);
            joining.lone_validator = true;
            assert!(!joining.observe(0, peers, start, budget));
            assert!(!joining.observe(0, peers, start + budget * 2, budget));

            let mut progress = Progress::new(5, true);
            progress.lone_validator = true;
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
        run(stalled, budget, true, true, report).await;
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
        let outcome =
            tokio::time::timeout(budget * 10, run(live, budget, true, true, report)).await;
        assert!(
            outcome.is_err(),
            "a finalizing node was reported as stalled"
        );

        let peerless = NodeState::new(7, 0, 4);
        let outcome =
            tokio::time::timeout(budget * 10, run(peerless, budget, true, false, report)).await;
        assert!(outcome.is_err(), "unknown connectivity armed the watchdog");
    }

    #[test]
    fn empty_history_stays_unarmed_and_new_finalization_resets_progress() {
        let budget = Duration::from_secs(600);
        let start = tokio::time::Instant::now();
        let mut progress = Progress::new(0, false);
        assert!(!progress.observe(0, Some(3), start, budget));
        assert!(!progress.observe(0, Some(3), start + budget * 2, budget));
        assert!(!progress.observe(1, Some(3), start + budget * 3, budget));
        assert!(!progress.observe(2, Some(3), start + budget * 4, budget));
        assert!(progress.observe(2, Some(3), start + budget * 5, budget));
    }
}
