//! Measures an embedded single-validator node. Run explicitly:
//! `cargo test --release -p vera-node --test embedded_solo_profile -- --ignored --nocapture`

#![recursion_limit = "256"]

use std::{
    path::Path,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use serde_json::json;
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::ReceiptResponse;
use vera_jsonrpc::NodeStatus;
use vera_modules::{acp::abi::IAcp, vera::administration::OperatorPolicy};
use vera_node::{EmbeddedConfig, EmbeddedNode, SoloGenesis, SoloPacing};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const WRITES: usize = 100;
const IDLE: Duration = Duration::from_secs(30);

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

/// Resident set size of this process, which also holds the test harness and its runtime.
/// The system can lower it at any time by compressing or paging out idle memory.
fn resident_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    let kibibytes = std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:").map(str::to_owned))
        .unwrap();
    #[cfg(not(target_os = "linux"))]
    let kibibytes = String::from_utf8(
        std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let kibibytes: u64 = kibibytes
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .unwrap();
    kibibytes * 1024
}

/// Largest resident set size this process has had, which idle-memory reclaim cannot lower.
#[cfg(unix)]
fn peak_resident_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: `usage` is writable storage for one `rusage`, which the call fills on success.
    let usage = unsafe {
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()), 0);
        usage.assume_init()
    };
    // Darwin reports bytes; other systems report kibibytes.
    let unit = if cfg!(target_vendor = "apple") {
        1
    } else {
        1024
    };
    Some(u64::try_from(usage.ru_maxrss).unwrap() * unit)
}

#[cfg(not(unix))]
fn peak_resident_bytes() -> Option<u64> {
    None
}

fn memory() -> serde_json::Value {
    json!({ "resident_bytes": resident_bytes(), "peak_resident_bytes": peak_resident_bytes() })
}

fn mebibytes(variable: &str) -> Option<usize> {
    std::env::var(variable)
        .ok()
        .map(|value| value.parse::<usize>().unwrap() << 20)
}

async fn status(node: &EmbeddedNode) -> NodeStatus {
    node.rpc().call_empty("vera_nodeStatus").await.unwrap()
}

async fn certified_write(node: &EmbeddedNode, signer: &BlsSigner, index: usize) -> Duration {
    let call = IAcp::createPolicyCall {
        policy: format!(
            "name: profile-{index}\nresources:\n  - name: document\n    relations:\n      - name: reader\n        types: [actor]\n    permissions:\n      - name: read\n        expr: reader\n"
        )
        .into_bytes()
        .into(),
        marshalType: 1,
    };
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let started = Instant::now();
    let submission: B256 = node
        .rpc()
        .request(
            "vera_sendNativeTx",
            vec![json!(format!("0x{}", hex::encode(wire)))],
        )
        .await
        .unwrap();
    loop {
        let proof: Option<ReceiptResponse> = node
            .rpc()
            .request("vera_getReceiptProof", vec![json!(submission)])
            .await
            .unwrap();
        if let Some(proof) = proof {
            assert!(
                proof
                    .verify(submission, node.consensus_key())
                    .unwrap()
                    .success()
            );
            return started.elapsed();
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run explicitly in release mode"]
async fn profile_solo_writes_and_idle_cost() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9411;
    let genesis = SoloGenesis {
        chain_id,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec![ACCOUNT_KEY.into()],
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let listen = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut config = EmbeddedConfig::new(directory.path(), genesis, listen);
    // `PROFILE_IDLE_MS=off` measures the daemon cadence; a number overrides the idle wait.
    match std::env::var("PROFILE_IDLE_MS").ok().as_deref() {
        Some("off") => config.pacing = None,
        Some(millis) => {
            config.pacing = Some(SoloPacing {
                idle: Duration::from_millis(millis.parse().unwrap()),
                batch: std::env::var("PROFILE_BATCH_MS")
                    .ok()
                    .map_or(SoloPacing::BATCH, |batch| {
                        Duration::from_millis(batch.parse().unwrap())
                    }),
            });
        }
        None => {}
    }
    // `PROFILE_HISTORY_CACHE_MIB=512 PROFILE_HISTORY_BUFFER_MIB=64` measures the daemon's store sizes.
    if let Some(bytes) = mebibytes("PROFILE_HISTORY_CACHE_MIB") {
        config.history_memory.block_cache_bytes = bytes;
    }
    if let Some(bytes) = mebibytes("PROFILE_HISTORY_BUFFER_MIB") {
        config.history_memory.write_buffer_bytes = bytes;
    }
    let (pacing, history) = (config.pacing, config.history_memory);
    let memory_before_start = memory();
    let node = EmbeddedNode::start(config).await.unwrap();
    let memory_after_start = memory();
    let signer = BlsSigner::new(3u64.into(), chain_id).unwrap();

    let mut latencies = Vec::with_capacity(WRITES);
    for index in 0..WRITES {
        latencies.push(certified_write(&node, &signer, index).await);
    }
    latencies.sort();
    let percentile = |p: usize| latencies[(WRITES * p / 100).min(WRITES - 1)].as_secs_f64() * 1e3;

    let before = status(&node).await;
    let bytes_before = directory_bytes(directory.path());
    let memory_after_writes = memory();
    tokio::time::sleep(IDLE).await;
    let memory_after_idle = memory();
    let after = status(&node).await;
    let bytes_after = directory_bytes(directory.path());
    let blocks = after.finalized_height.unwrap() - before.finalized_height.unwrap();
    let nullified = after.nullified_count.unwrap_or(0) - before.nullified_count.unwrap_or(0);

    println!(
        "{}",
        json!({
            "idle_wait_ms": pacing.map(|pacing| pacing.idle.as_millis() as u64),
            "batch_ms": pacing.map(|pacing| pacing.batch.as_millis() as u64),
            "writes": WRITES,
            "certified_receipt_ms": {
                "p50": percentile(50), "p95": percentile(95), "max": percentile(100)
            },
            "idle_seconds": IDLE.as_secs(),
            "idle_blocks": blocks,
            "idle_blocks_per_second": blocks as f64 / IDLE.as_secs_f64(),
            "idle_nullified_views": nullified,
            "idle_disk_bytes_per_hour": (bytes_after.saturating_sub(bytes_before)) as f64
                * 3600.0 / IDLE.as_secs_f64(),
            "history_disk_bytes": directory_bytes(&directory.path().join("history")),
            "history_block_cache_bytes": history.block_cache_bytes,
            "history_write_buffer_bytes": history.write_buffer_bytes,
            "memory": {
                "before_start": memory_before_start,
                "after_start": memory_after_start,
                "after_writes": memory_after_writes,
                "after_idle": memory_after_idle,
            },
        })
    );
    node.stop().await.unwrap();
}
