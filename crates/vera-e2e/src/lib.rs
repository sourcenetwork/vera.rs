//! End-to-end test harness for vera.
//!
//! Re-exports `vera-harness` (from backbone) and provides workspace-relative
//! binary resolution so tests can find the locally-built `verad`.

use std::time::Duration;

pub use vera_harness::{cluster, observe, resolve_binary};

/// Receipt polling tuned for CI clusters, where all-validator gossip can take
/// multiple block intervals before the receipt becomes visible.
pub const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(300);
/// Maximum number of receipt polls before an e2e test gives up on a transaction.
pub const RECEIPT_POLL_ATTEMPTS: u32 = 400;

/// Cluster-readiness deadline, scaled by `VERA_E2E_DEADLINE_SCALE`.
///
/// CI runners may need longer than a developer machine for a multi-node
/// cluster to form; the scale multiplies a 30-second base deadline.
#[must_use]
pub fn readiness_deadline() -> std::time::Duration {
    let scale = std::env::var("VERA_E2E_DEADLINE_SCALE")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    std::time::Duration::from_secs(30 * u64::from(scale))
}
