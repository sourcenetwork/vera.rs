//! Measures a backup catching up with an active device that keeps finalizing
//! blocks under load. Run explicitly:
//! `cargo test --release -p vera-node --test embedded_backup_busy_profile -- --ignored --nocapture`
//!
//! Each phase prints one JSON line; `began` is the UTC second of the day, to
//! match the log lines `RUST_LOG` selects.

#[expect(dead_code, reason = "shared with tests that wait on a backup's height")]
#[path = "support/backup.rs"]
mod backup;
#[expect(dead_code, reason = "shared with tests that keep keys in files")]
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::json;
use short_epochs::{deployment, height, run_until};
use support::{block_on, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::{DeviceKey, EmbeddedConfig, EmbeddedNode};

fn count(variable: &str, default: u64) -> u64 {
    std::env::var(variable)
        .ok()
        .map_or(default, |value| value.parse().unwrap())
}

/// Starts `settings` and follows the active device until the backup reaches
/// the height the active device had when the start returned.
fn catch_up(phase: &str, active: &EmbeddedNode, settings: EmbeddedConfig) -> EmbeddedNode {
    let (active_before, starting) = (height(active), Instant::now());
    let began = std::time::SystemTime::now();
    let follower = block_on(EmbeddedNode::start(settings)).unwrap();
    let start = starting.elapsed();
    let (joined, target) = (height(&follower), height(active));
    let deadline = Instant::now() + Duration::from_secs(600);
    while height(&follower) < target {
        assert!(Instant::now() < deadline, "{phase}: stalled below {target}");
        std::thread::sleep(Duration::from_millis(10));
    }
    let caught_up = starting.elapsed();
    let active_after = height(active);
    let seconds = caught_up.as_secs_f64();
    println!(
        "{}",
        json!({
            "phase": phase,
            "began": second_of_day(began),
            "active_height_at_start": active_before,
            "start_ms": start.as_secs_f64() * 1e3,
            "backup_height_when_started": joined,
            "active_height_when_started": target,
            "caught_up_ms": seconds * 1e3,
            "active_blocks_per_second": (active_after - active_before) as f64 / seconds,
            "backup_blocks_per_second_after_start":
                (target - joined) as f64 / (caught_up - start).as_secs_f64().max(1e-3),
        })
    );
    follower
}

fn second_of_day(time: std::time::SystemTime) -> f64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        % 86_400.0
}

#[test]
#[ignore = "measurement; run explicitly in release mode"]
fn profile_backup_catch_up_from_a_busy_active_device() {
    if let Ok(filter) = tracing_subscriber::EnvFilter::try_from_default_env() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_thread_ids(true)
            .try_init();
    }
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let chain_id = 9_452;
    let dealt = deployment(chain_id, 87);
    let key = DeviceKey::generate().unwrap();
    let mut active_settings = backup::active(first.path(), &dealt, &[&key]);
    // `PROFILE_BURST` sets both devices' peer-channel burst.
    if let Ok(burst) = std::env::var("PROFILE_BURST") {
        active_settings.sizing.channel_burst = burst.parse().unwrap();
    }
    let active = Arc::new(block_on(EmbeddedNode::start(active_settings.clone())).unwrap());

    // `PROFILE_WRITERS` threads each finalize one write after another.
    let running = Arc::new(AtomicBool::new(true));
    let writers: Vec<_> = (0..count("PROFILE_WRITERS", 2))
        .map(|writer| {
            let (active, running) = (active.clone(), running.clone());
            std::thread::spawn(move || {
                let signer = BlsSigner::new((100 + writer).into(), chain_id).unwrap();
                while running.load(Ordering::Relaxed) {
                    finalize_a_write(&active, &signer);
                }
            })
        })
        .collect();

    let lead = count("PROFILE_LEAD", 300);
    run_until(&active, |reached| reached >= lead);
    let mut settings = backup::backup(second.path(), &dealt, &active_settings, &key);
    settings.sizing = active_settings.sizing;
    let mut follower = catch_up("first start", &active, settings.clone());

    // `PROFILE_BEHIND` lists the gaps a restarted backup closes, in blocks.
    let behind = std::env::var("PROFILE_BEHIND").unwrap_or_else(|_| "48,400".into());
    for gap in behind.split(',').map(|gap| gap.parse::<u64>().unwrap()) {
        let left_at = height(&follower);
        block_on(follower.stop()).unwrap();
        run_until(&active, |reached| reached >= left_at + gap);
        follower = catch_up(&format!("restart {gap} behind"), &active, settings.clone());
    }

    running.store(false, Ordering::Relaxed);
    for writer in writers {
        writer.join().unwrap();
    }
    block_on(follower.stop()).unwrap();
    let Ok(active) = Arc::try_unwrap(active) else {
        unreachable!("every writer has stopped");
    };
    block_on(active.stop()).unwrap();
}
