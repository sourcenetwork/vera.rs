//! An account's active device and its backups, in one process on loopback.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use vera_node::{DeviceKey, EmbeddedConfig, EmbeddedNode, SoloDeployment};

use super::short_epochs;

/// The active device's settings, with its listener kept across restarts and
/// `backups` admitted as peers.
pub(crate) fn active(
    directory: &Path,
    deployment: &SoloDeployment,
    backups: &[&DeviceKey],
) -> EmbeddedConfig {
    let mut config = short_epochs::settings(directory, deployment, true);
    config.backups = backups.iter().map(|key| key.public_key()).collect();
    config
}

/// A backup's settings for the deployment `active` runs, under `key`.
pub(crate) fn backup(
    directory: &Path,
    deployment: &SoloDeployment,
    active: &EmbeddedConfig,
    key: &DeviceKey,
) -> EmbeddedConfig {
    let shared = super::support::config(directory, 0);
    let mut config = EmbeddedConfig::backup(
        directory,
        deployment.record(),
        shared.p2p_listen,
        active.p2p_listen,
    )
    .unwrap();
    let vera_node::DeviceRole::Backup(role) = &mut config.role else {
        unreachable!("a backup configuration has the backup role");
    };
    role.transport_key = Some(key.clone());
    config.worker_threads = shared.worker_threads;
    config.max_blocking_threads = shared.max_blocking_threads;
    config.verification_threads = shared.verification_threads;
    config.pacing = None;
    config
}

/// Wait until `node` has finalized `height`, and return the height it reports.
pub(crate) fn await_height(node: &EmbeddedNode, height: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let reached = short_epochs::height(node);
        if reached >= height {
            return reached;
        }
        assert!(
            Instant::now() < deadline,
            "stalled at height {reached} below {height}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
