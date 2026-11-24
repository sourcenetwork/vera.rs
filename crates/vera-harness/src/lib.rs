//! Vera.rs node manager, cluster builder, and observability.
//!
//! Provides everything needed to start, configure, and observe Vera.rs
//! validator clusters in integration tests:
//! - `TestClusterBuilder` — BFT-aware cluster setup with key generation
//! - `KeySet` — deterministic ed25519 identities + trusted-dealer BLS shares
//! - `ClusterState` — unified observability (log tracking + RPC polling)
//! - `GenesisBuilder` — genesis configuration
//! - Consensus presets — Fast/Normal/Stress timing profiles

pub mod cluster;
pub mod observe;

pub use cluster::resolve_binary;
