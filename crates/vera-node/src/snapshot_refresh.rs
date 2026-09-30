//! Re-anchor snapshot initialization when a stale floor strands the sync.
//!
//! State sync retargets from marshal's finalized dispatches: if the selected
//! floor ages out of peer retention, ancestry backfill cannot reach the
//! gossiped tip, dispatches stop, and the database sync keeps chasing its
//! original unservable target. Marshal still verifies and stores gossiped
//! finalizations for recent rounds in that state, so recovery re-floors
//! marshal from the newest stored finalization: dispatches resume from a
//! retained anchor and the database sync retargets to servable targets.

use std::time::Duration;

use commonware_consensus::{marshal::Identifier, types::Height};

use crate::marshal_floor::VeraMarshal;

/// Watches marshal progress while snapshot initialization waits for databases
/// and re-floors from the newest stored finalization once processing stalls.
pub(crate) struct FloorRefresh {
    stall: Duration,
    last_processed: Option<Height>,
    refreshed_to: Option<Height>,
}

/// Result of recording one processed-height observation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stall {
    /// Processing advanced since the previous observation.
    Progress,
    /// Processing is static; marshal should re-floor to this stored height.
    Refresh(Height),
    /// Processing is static but no fresher finalization is worth installing.
    Quiet,
}

impl FloorRefresh {
    /// `stall` is the quiet period that triggers a refresh; `Duration::ZERO`
    /// disables refreshing.
    pub(crate) const fn new(stall: Duration) -> Self {
        Self {
            stall,
            last_processed: None,
            refreshed_to: None,
        }
    }

    /// Whether floor refreshing is enabled.
    pub(crate) const fn enabled(&self) -> bool {
        !self.stall.is_zero()
    }

    /// Quiet period between progress observations.
    pub(crate) const fn stall(&self) -> Duration {
        self.stall
    }

    /// Observe marshal progress and re-floor once it stalls.
    ///
    /// A no-op while processed heights keep advancing (ordinary backfill).
    /// Stored finalizations were verified against the epoch's registered key
    /// when marshal accepted them, so re-floors stay certificate-authenticated.
    pub(crate) async fn observe(&mut self, marshal: &VeraMarshal) {
        let processed = marshal
            .get_processed()
            .await
            .map(|processed| processed.height());
        let latest = marshal
            .get_info(Identifier::Latest)
            .await
            .map(|(height, _)| height);
        tracing::debug!(
            processed = ?processed,
            latest = ?latest,
            "snapshot floor refresh observation"
        );
        let floor = match self.record(processed, latest) {
            Stall::Refresh(height) => height,
            Stall::Progress | Stall::Quiet => return,
        };
        let Some(finalization) = marshal.get_finalization(floor).await else {
            return;
        };
        tracing::warn!(
            floor_height = processed.map(Height::get).unwrap_or_default(),
            refresh_height = floor.get(),
            "snapshot initialization stalled; re-flooring marshal from the newest stored finalization"
        );
        marshal.set_floor(finalization);
    }

    /// Decide whether static processing warrants a re-floor to `latest`.
    fn record(&mut self, processed: Option<Height>, latest: Option<Height>) -> Stall {
        let Some(processed) = processed else {
            return Stall::Quiet;
        };
        let stalled = self.last_processed == Some(processed);
        self.last_processed = Some(processed);
        if !stalled {
            return Stall::Progress;
        }
        let Some(height) = latest else {
            return Stall::Quiet;
        };
        if height <= processed
            || self
                .refreshed_to
                .is_some_and(|refreshed| height <= refreshed)
        {
            return Stall::Quiet;
        }
        self.refreshed_to = Some(height);
        Stall::Refresh(height)
    }
}

#[cfg(test)]
mod tests {
    use super::{FloorRefresh, Stall};
    use commonware_consensus::types::Height;
    use std::time::Duration;

    fn info(height: u64) -> Option<Height> {
        Some(Height::new(height))
    }

    #[test]
    fn zero_stall_disables_refresh() {
        let refresh = FloorRefresh::new(Duration::ZERO);
        assert!(!refresh.enabled());
        assert!(FloorRefresh::new(Duration::from_secs(1)).enabled());
    }

    #[test]
    fn first_observation_is_progress_even_when_static() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1));
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(30)),
            Stall::Progress
        );
    }

    #[test]
    fn static_processing_refreshes_to_the_latest_height() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1));
        refresh.record(Some(Height::new(10)), info(30));
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(30)),
            Stall::Refresh(Height::new(30))
        );
    }

    #[test]
    fn repeated_stalls_do_not_reinstall_the_same_floor() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1));
        refresh.record(Some(Height::new(10)), info(30));
        refresh.record(Some(Height::new(10)), info(30));
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(30)),
            Stall::Quiet
        );
    }

    #[test]
    fn latest_at_or_below_processed_is_never_installed() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1));
        refresh.record(Some(Height::new(10)), info(10));
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(10)),
            Stall::Quiet
        );
        assert_eq!(refresh.record(Some(Height::new(10)), info(9)), Stall::Quiet);
    }

    #[test]
    fn missing_processed_height_stays_quiet() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1));
        assert_eq!(refresh.record(None, info(30)), Stall::Quiet);
        assert_eq!(refresh.record(None, None), Stall::Quiet);
    }
}
