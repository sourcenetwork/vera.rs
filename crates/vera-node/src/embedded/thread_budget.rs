//! The threads an embedded node starts, for a host that accounts for them.

/// Thread counts of an embedded node, by group.
///
/// Every thread but the node thread is created by the node thread or by a thread it created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadBudget {
    /// The node thread, which drives the runtime's root task.
    pub node: usize,
    /// Async worker threads of the node's runtime.
    pub workers: usize,
    /// Upper bound on the runtime's blocking threads, which start on demand and exit when idle.
    pub max_blocking: usize,
    /// Threads of the verification pool.
    pub verification: usize,
    /// Background threads of the finalized-history store.
    pub history: usize,
}

impl ThreadBudget {
    /// Threads that live as long as the node does.
    #[must_use]
    pub const fn persistent(&self) -> usize {
        self.node
            .saturating_add(self.workers)
            .saturating_add(self.verification)
            .saturating_add(self.history)
    }

    /// The most threads the node has at any one time.
    #[must_use]
    pub const fn max(&self) -> usize {
        self.persistent().saturating_add(self.max_blocking)
    }
}
