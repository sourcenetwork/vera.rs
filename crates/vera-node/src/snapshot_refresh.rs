//! Re-anchor snapshot initialization when a stale floor strands the sync.
//!
//! State sync retargets from marshal's finalized dispatches: if the selected
//! floor ages out of peer retention, ancestry backfill cannot reach the
//! gossiped tip, dispatches stop, and the database sync keeps chasing its
//! original unservable target. Marshal still verifies and stores gossiped
//! finalizations for recent rounds in that state, so recovery re-floors
//! marshal from the newest stored finalization: dispatches resume from a
//! retained anchor and the database sync retargets to servable targets.
//!
//! Processing is also static while the application holds a block marshal
//! delivered: the database sync records a target or imports history before it
//! acknowledges. That is no stall. A floor above the held block would make
//! marshal deliver a block that skips heights the reshare actor has not
//! applied, and Commonware's reshare actor stops the node on such a block.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use commonware_consensus::{marshal::Identifier, types::Height};

use crate::marshal::VeraMarshal;

/// Watches marshal progress while snapshot initialization waits for databases
/// and re-floors from the newest stored finalization once processing stalls.
pub(crate) struct FloorRefresh {
    stall: Duration,
    handoff: HandingOff,
    last_processed: Option<Height>,
    last_frontier: Option<Height>,
    refreshed_to: Option<Height>,
}

/// Heights scanned below the newest stored finalization for blocks marshal holds.
const FRONTIER_SCAN: u64 = 1_024;

/// Result of recording one processed-height observation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stall {
    /// Processing advanced since the previous observation.
    Progress,
    /// Processing is static; marshal should re-floor to this stored height.
    Refresh(Height),
    /// Processing is static but no fresher finalization is worth installing.
    Quiet,
    /// Processing is static because the application has not acknowledged the
    /// block after the processed height, which marshal holds.
    Held,
}

impl FloorRefresh {
    /// `stall` is the quiet period that triggers a refresh; `Duration::ZERO`
    /// disables refreshing.
    pub(crate) const fn new(stall: Duration, handoff: HandingOff) -> Self {
        Self {
            stall,
            handoff,
            last_processed: None,
            last_frontier: None,
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
        // The handoff imports history while marshal waits at its anchor. A
        // floor above the anchor would skip heights the reshare actor has not applied.
        if self.handoff.active() {
            self.last_processed = None;
            return;
        }
        let processed = marshal
            .get_processed()
            .await
            .map(|processed| processed.height());
        let latest = marshal
            .get_info(Identifier::Latest)
            .await
            .map(|(height, _)| height);
        let frontier = match (processed, latest) {
            (Some(processed), Some(latest)) if latest > processed => {
                repair_frontier(marshal, processed, latest).await
            }
            _ => None,
        };
        let next_held = match processed {
            Some(processed) => marshal
                .get_block(Identifier::Height(processed.next()))
                .await
                .is_some(),
            None => false,
        };
        tracing::debug!(
            processed = ?processed,
            latest = ?latest,
            next_held,
            frontier = ?frontier,
            "snapshot floor refresh observation"
        );
        let floor = match self.record(processed, latest, next_held, frontier) {
            Stall::Refresh(height) => height,
            Stall::Progress | Stall::Quiet | Stall::Held => return,
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
    /// `next_held` says whether marshal holds the block after `processed`, and
    /// `frontier` is the lowest height of the run of blocks it holds below
    /// `latest`. Marshal repairs a gap from its top down, so a frontier that
    /// moves down is backfill at work, however long `processed` stays put.
    fn record(
        &mut self,
        processed: Option<Height>,
        latest: Option<Height>,
        next_held: bool,
        frontier: Option<Height>,
    ) -> Stall {
        let Some(processed) = processed else {
            return Stall::Quiet;
        };
        let stalled = self.last_processed == Some(processed);
        let repairing =
            frontier.is_some_and(|frontier| self.last_frontier.is_none_or(|last| frontier < last));
        self.last_processed = Some(processed);
        self.last_frontier = frontier;
        if !stalled || repairing {
            return Stall::Progress;
        }
        if next_held {
            return Stall::Held;
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

/// The lowest height of the run of blocks marshal holds that ends at `latest`,
/// scanning at most [`FRONTIER_SCAN`] heights above `processed`.
async fn repair_frontier(
    marshal: &VeraMarshal,
    processed: Height,
    latest: Height,
) -> Option<Height> {
    let lowest = latest
        .get()
        .saturating_sub(FRONTIER_SCAN)
        .max(processed.get() + 1);
    let mut frontier = None;
    let mut height = latest.get();
    while height >= lowest
        && marshal
            .get_block(Identifier::Height(Height::new(height)))
            .await
            .is_some()
    {
        frontier = Some(Height::new(height));
        height -= 1;
    }
    frontier
}

/// Whether the synchronization handoff is running, during which marshal's
/// processed height stays at the anchor however long the history import takes.
#[derive(Clone, Debug, Default)]
pub(crate) struct HandingOff(Arc<AtomicBool>);

/// Marks the handoff as running until dropped.
pub(crate) struct Running(Arc<AtomicBool>);

impl HandingOff {
    pub(crate) fn enter(&self) -> Running {
        self.0.store(true, Ordering::Release);
        Running(self.0.clone())
    }

    fn active(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::{FloorRefresh, HandingOff, Stall};
    use commonware_consensus::types::Height;
    use std::time::Duration;

    fn info(height: u64) -> Option<Height> {
        Some(Height::new(height))
    }

    #[test]
    fn the_handoff_is_running_until_its_mark_is_dropped() {
        let handing_off = HandingOff::default();
        let running = handing_off.enter();
        assert!(handing_off.active());
        drop(running);
        assert!(!handing_off.active());
    }

    #[test]
    fn a_gap_repaired_from_the_top_down_is_not_a_stall() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1), HandingOff::default());
        refresh.record(
            Some(Height::new(10)),
            info(30),
            false,
            Some(Height::new(25)),
        );
        assert_eq!(
            refresh.record(
                Some(Height::new(10)),
                info(30),
                false,
                Some(Height::new(20))
            ),
            Stall::Progress
        );
        assert_eq!(
            refresh.record(
                Some(Height::new(10)),
                info(30),
                false,
                Some(Height::new(20))
            ),
            Stall::Refresh(Height::new(30))
        );
    }

    #[test]
    fn zero_stall_disables_refresh() {
        let refresh = FloorRefresh::new(Duration::ZERO, HandingOff::default());
        assert!(!refresh.enabled());
        assert!(FloorRefresh::new(Duration::from_secs(1), HandingOff::default()).enabled());
    }

    #[test]
    fn first_observation_is_progress_even_when_static() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1), HandingOff::default());
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(30), false, None),
            Stall::Progress
        );
    }

    #[test]
    fn static_processing_refreshes_to_the_latest_height() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1), HandingOff::default());
        refresh.record(Some(Height::new(10)), info(30), false, None);
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(30), false, None),
            Stall::Refresh(Height::new(30))
        );
    }

    #[test]
    fn repeated_stalls_do_not_reinstall_the_same_floor() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1), HandingOff::default());
        refresh.record(Some(Height::new(10)), info(30), false, None);
        refresh.record(Some(Height::new(10)), info(30), false, None);
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(30), false, None),
            Stall::Quiet
        );
    }

    #[test]
    fn latest_at_or_below_processed_is_never_installed() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1), HandingOff::default());
        refresh.record(Some(Height::new(10)), info(10), false, None);
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(10), false, None),
            Stall::Quiet
        );
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(9), false, None),
            Stall::Quiet
        );
    }

    #[test]
    fn missing_processed_height_stays_quiet() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1), HandingOff::default());
        assert_eq!(refresh.record(None, info(30), false, None), Stall::Quiet);
        assert_eq!(refresh.record(None, None, false, None), Stall::Quiet);
    }

    #[test]
    fn a_held_next_block_is_not_a_stall() {
        let mut refresh = FloorRefresh::new(Duration::from_secs(1), HandingOff::default());
        refresh.record(Some(Height::new(10)), info(30), true, None);
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(30), true, None),
            Stall::Held
        );
        // Once marshal lacks the next block, the stall refreshes to the same height.
        assert_eq!(
            refresh.record(Some(Height::new(10)), info(30), false, None),
            Stall::Refresh(Height::new(30))
        );
    }
}
