//! Host code that prepares the node thread before the node starts any other thread.

use std::{fmt, io, sync::Arc};

/// Runs on the node thread before the node's runtime is built.
///
/// Every other thread of the node is created afterwards, by the node thread or
/// by a thread it created. Where the platform lets a new thread inherit its
/// creator's placement, as Linux does for CPU affinity, what this sets applies
/// to all of them. It runs once per [`crate::EmbeddedNode::start`]; an error
/// fails that start before any other thread exists.
#[derive(Clone)]
pub struct ThreadSetup(Arc<dyn Fn() -> io::Result<()> + Send + Sync>);

impl ThreadSetup {
    /// Wrap `setup` so a configuration can carry it.
    pub fn new(setup: impl Fn() -> io::Result<()> + Send + Sync + 'static) -> Self {
        Self(Arc::new(setup))
    }

    pub(super) fn run(&self) -> io::Result<()> {
        (self.0)()
    }
}

impl fmt::Debug for ThreadSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ThreadSetup")
    }
}
