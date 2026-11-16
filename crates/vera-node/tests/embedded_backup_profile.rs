//! Measures a backup following an embedded single-validator node. Run explicitly:
//! `cargo test --release -p vera-node --test embedded_backup_profile -- --ignored --nocapture`

use std::{
    path::Path,
    time::{Duration, Instant},
};

use serde_json::json;
use vera_jsonrpc::NodeStatus;
use vera_modules::vera::administration::OperatorPolicy;
use vera_node::{DeviceKey, EmbeddedConfig, EmbeddedNode, SoloDeployment, SoloGenesis};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn directory_bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                directory_bytes(&entry.path())
            } else {
                metadata.len()
            }
        })
        .sum()
}

/// Resident set size of this process, which holds both nodes and the test harness.
fn resident_bytes() -> u64 {
    let kibibytes = String::from_utf8(
        std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    kibibytes.trim().parse::<u64>().unwrap() * 1024
}

fn seconds(variable: &str, default: u64) -> Duration {
    Duration::from_secs(
        std::env::var(variable)
            .ok()
            .map_or(default, |seconds| seconds.parse().unwrap()),
    )
}

fn listen() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn height(node: &EmbeddedNode) -> u64 {
    let status: NodeStatus = node.rpc().call_empty("vera_nodeStatus").await.unwrap();
    status.finalized_height.unwrap_or(0)
}

async fn await_height(node: &EmbeddedNode, target: u64) {
    while height(node).await < target {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run explicitly in release mode"]
async fn profile_backup_catch_up_and_idle_cost() {
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let genesis = SoloGenesis {
        policies: Vec::new(),
        chain_id: 9_451,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec![ACCOUNT_KEY.into()],
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let active_listen = listen();
    let deployment = SoloDeployment::create(&genesis, active_listen).unwrap();
    let key = DeviceKey::generate().unwrap();
    let mut idle_active =
        EmbeddedConfig::adopt(first.path(), deployment.clone(), active_listen).unwrap();
    idle_active.backups = vec![key.public_key()];
    // The daemon cadence builds the blocks to catch up on; `PROFILE_BLOCKS` sets how many.
    let blocks: u64 = std::env::var("PROFILE_BLOCKS")
        .ok()
        .map_or(400, |blocks| blocks.parse().unwrap());
    let mut busy_active = idle_active.clone();
    busy_active.pacing = None;
    let active = EmbeddedNode::start(busy_active).await.unwrap();
    await_height(&active, blocks).await;
    active.stop().await.unwrap();
    let active = EmbeddedNode::start(idle_active).await.unwrap();
    let resident_before = resident_bytes();

    let mut settings =
        EmbeddedConfig::backup(second.path(), deployment.record(), listen(), active_listen)
            .unwrap();
    let vera_node::DeviceRole::Backup(role) = &mut settings.role else {
        unreachable!("a backup configuration has the backup role");
    };
    role.transport_key = Some(key);
    let target = height(&active).await;
    let starting = Instant::now();
    let backup = EmbeddedNode::start(settings).await.unwrap();
    let start_ms = starting.elapsed().as_secs_f64() * 1e3;
    let joined_at = height(&backup).await;
    await_height(&backup, target).await;
    let caught_up_ms = starting.elapsed().as_secs_f64() * 1e3;
    let bytes_after_catch_up = directory_bytes(second.path());

    // `PROFILE_SETTLE_SECONDS` lets the store flush before the idle period that
    // `PROFILE_IDLE_SECONDS` sets.
    tokio::time::sleep(seconds("PROFILE_SETTLE_SECONDS", 30)).await;
    let idle = seconds("PROFILE_IDLE_SECONDS", 300);
    let (backup_before, active_before) = (height(&backup).await, height(&active).await);
    let (backup_bytes, active_bytes) = (
        directory_bytes(second.path()),
        directory_bytes(first.path()),
    );
    tokio::time::sleep(idle).await;
    let (backup_after, active_after) = (height(&backup).await, height(&active).await);
    let per_hour =
        |before: u64, after: u64| (after as f64 - before as f64) * 3600.0 / idle.as_secs_f64();

    println!(
        "{}",
        json!({
            "catch_up": {
                "active_height": target,
                "backup_joined_at_height": joined_at,
                "start_ms": start_ms,
                "caught_up_ms": caught_up_ms,
                "backup_directory_bytes": bytes_after_catch_up,
            },
            "idle_seconds": idle.as_secs(),
            "backup_blocks_per_minute":
                (backup_after - backup_before) as f64 * 60.0 / idle.as_secs_f64(),
            "active_blocks_per_minute":
                (active_after - active_before) as f64 * 60.0 / idle.as_secs_f64(),
            "backup_disk_bytes_per_hour": per_hour(backup_bytes, directory_bytes(second.path())),
            "active_disk_bytes_per_hour": per_hour(active_bytes, directory_bytes(first.path())),
            "resident_bytes": {
                "active_alone": resident_before,
                "active_and_backup_after_idle": resident_bytes(),
            },
        })
    );
    backup.stop().await.unwrap();
    active.stop().await.unwrap();
}
