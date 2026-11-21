//! Shared integration test primitives for Source Network components.
//!
//! Provides the foundational building blocks that all component harnesses use:
//! - [`ManagedProcess`] — child process lifecycle (SIGTERM → wait → SIGKILL)
//! - [`TestRunDir`] — isolated test artifact directories with RAII cleanup
//! - [`BinaryResolver`] — version-aware binary resolution (local build → PATH → source)
//! - Port allocation — ephemeral OS-assigned ports for parallel test execution

pub mod binary;
#[cfg(unix)]
mod listener;
#[cfg(unix)]
pub use listener::ReservedTcpListener;
/// Component version manifest (`backbone.toml`) parsing.
pub mod manifest;
/// Ephemeral OS-assigned port allocation.
pub mod ports;
/// Child process lifecycle management.
pub mod process;
/// Isolated test run directories with RAII cleanup.
pub mod run;

pub use binary::{BinaryResolver, BinarySource, ResolvedBinary};
pub use manifest::{ComponentPin, Manifest};
pub use ports::allocate_ports;
pub use process::ManagedProcess;
pub use run::TestRunDir;
