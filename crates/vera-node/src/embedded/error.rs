//! Failures of a node hosted inside another program.

/// Why an embedded node could not start or stopped.
#[derive(Debug, thiserror::Error)]
pub enum EmbedError {
    /// The deployment could not be created or reopened.
    #[error(transparent)]
    Deployment(#[from] crate::SoloError),
    /// The configuration cannot run.
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    /// Another node, or one that has not finished stopping, holds the directory.
    #[error("node directory {} is in use", .0.display())]
    DirectoryInUse(std::path::PathBuf),
    /// The node thread could not be spawned.
    #[error("cannot start node thread: {0}")]
    Thread(std::io::Error),
    /// The host's thread setup failed; no other thread was started.
    #[error("node thread setup failed: {0}")]
    ThreadSetup(std::io::Error),
    /// A node actor stopped; the node no longer makes progress.
    #[error("node stopped: {0}")]
    Stopped(String),
    /// The node thread panicked.
    #[error("node thread panicked")]
    Panicked,
}
