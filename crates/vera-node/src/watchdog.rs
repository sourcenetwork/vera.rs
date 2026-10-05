//! Finality-progress watchdog gated by observed peer connectivity.
//!
//! Unknown connectivity leaves the watchdog unarmed. A stall is evidence of
//! missing progress, not a diagnosis of its cause or a guarantee that restart helps.

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

/// Run the watchdog until the process ends.
///
/// `has_durable_history` arms the watchdog for a restart even before this
/// process observes its first finalization.
pub(crate) async fn run(state: NodeState, budget: Duration, has_durable_history: bool) {
    let mut progress = Progress::new(state.finalized_count(), has_durable_history);
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
                "finality stalled with peers connected; exiting for supervised rejoin"
            );
            std::process::exit(EXIT_CODE);
        }
    }
}

struct Progress {
    count: u64,
    finalized_ever: bool,
    connected: bool,
    since: tokio::time::Instant,
}

impl Progress {
    fn new(count: u64, has_durable_history: bool) -> Self {
        Self {
            count,
            finalized_ever: has_durable_history || count > 0,
            connected: false,
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
        let connected = peers.is_some_and(|count| count > 0);
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
