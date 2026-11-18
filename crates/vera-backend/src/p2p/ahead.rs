//! Requests for a size the serving database is about to reach.
//!
//! A syncing peer learns that a block is finalized from its certificate,
//! which can arrive before the serving node has applied that block's state.
//! Its sync then asks for a size just past the server's tip. Refusing makes
//! the peer retry after its retry delay, by when a busy deployment has
//! finalized the next block, so its sync converges only where the deployment
//! pauses. Waiting a moment instead answers the request once the block is applied.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use commonware_glue::stateful::db::{ReadGuard, Shared};
use commonware_storage::merkle::{Location, mmr};

use super::Partition;

/// Longest a request waits for its size, within the requester's two-second fetch timeout.
pub(super) const WAIT: Duration = Duration::from_secs(1);
/// Interval between checks of the database's size while a request waits.
const POLL: Duration = Duration::from_millis(5);
/// Requests waiting at once for one database. Others are answered at once.
const WAITING: usize = 64;

/// Bounds the requests waiting for a database to reach their size.
#[derive(Debug, Default)]
pub(super) struct Ahead {
    waiting: Arc<AtomicUsize>,
}

impl Ahead {
    /// A read of `db` once it has reached `size`, or once the wait is over.
    /// The lock is released between checks, so the writer that applies the
    /// next block is never held up.
    pub(super) async fn reached<'a, DB: Partition>(
        &self,
        db: &'a Shared<DB>,
        size: Location<mmr::Family>,
    ) -> ReadGuard<'a, DB> {
        let guard = db.read().await;
        if guard.bounds().end >= size {
            return guard;
        }
        let Some(_waiting) = Waiting::enter(&self.waiting) else {
            return guard;
        };
        drop(guard);
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            tokio::time::sleep(POLL).await;
            let guard = db.read().await;
            if guard.bounds().end >= size || tokio::time::Instant::now() >= deadline {
                return guard;
            }
        }
    }
}

struct Waiting(Arc<AtomicUsize>);

impl Waiting {
    fn enter(waiting: &Arc<AtomicUsize>) -> Option<Self> {
        waiting
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < WAITING).then_some(count + 1)
            })
            .ok()
            .map(|_| Self(waiting.clone()))
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
