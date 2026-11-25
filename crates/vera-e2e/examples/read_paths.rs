//! Compares unauthenticated `vera_call` queries with certified reads verified by the client.
//!
//! `read_paths embedded` serves an embedded lone validator from a child process;
//! `read_paths cluster` starts a four-node cluster from `VERAD_BINARY`. Both seed
//! one policy with 100 reader relationships and one namespace with 50 posts, then
//! time each read path sequentially and with 16 and 64 readers against one node,
//! first idle and then beside a writer sending about five requests per second.
//! `READ_SECONDS` (default 8) sets each concurrent run, `READ_SEQUENTIAL`
//! (default 200) the sequential reads and `READ_MAX_LOAD` (default 8) the load
//! average a run waits for, at most `READ_LOAD_WAIT_S` (default 1,800) in all.
//! `READ_QUERIES` keeps the queries whose names contain one of its
//! comma-separated parts, and `READ_VERIFIED_REVISIONS` bounds the revisions the
//! reading client remembers as verified (0 verifies every certificate).

use std::{
    io::{BufRead as _, Write as _},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use alloy_primitives::{B256, FixedBytes};
use alloy_sol_types::SolCall;
use commonware_codec::{DecodeExt as _, Encode as _};
use vera_client::{
    ACP_ADDRESS, AccessRequest, Actor, BULLETIN_ADDRESS, BlsSigner, ClientError, ModuleId, Object,
    Operation, PERMISSION_LIMITS, PermissionResponse, RECORD_PROOF_BYTES, RecordResponse,
    VeraClient,
};
use vera_domain::ConsensusPublicKey;
use vera_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use vera_modules::{
    acp::{abi::IAcp, pages::RelationshipPageRequest},
    bulletin::abi::IBulletin,
    vera::administration::OperatorPolicy,
};

#[path = "read_paths/host.rs"]
mod host;
#[path = "read_paths/reader.rs"]
mod reader;
#[path = "read_paths/run.rs"]
mod run;
#[path = "read_paths/seed.rs"]
mod seed;

use host::*;
use reader::*;
use run::*;
use seed::*;

const CHAIN_ID: u64 = 9471;
const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RELATIONSHIPS: usize = 100;
const POSTS: usize = 50;
const NAMESPACE: &str = "bulletin/team";
const POLICY: &str = "\
name: read-paths
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
    permissions:
      - name: read
        expr: reader
";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve(&args[1]).await,
        Some("embedded") => embedded().await,
        Some("cluster") => cluster().await,
        _ => panic!("usage: read_paths embedded|cluster"),
    }
}

async fn serve(directory: &str) {
    let genesis = vera_node::SoloGenesis {
        policies: Vec::new(),
        chain_id: CHAIN_ID,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec![ACCOUNT_KEY.into()],
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let mut config =
        vera_node::EmbeddedConfig::new(directory, genesis, "127.0.0.1:0".parse().unwrap());
    config.rpc_listen = Some("127.0.0.1:0".parse().unwrap());
    let node = vera_node::EmbeddedNode::start(config).await.unwrap();
    println!(
        "READY {} {}",
        node.rpc_addr().unwrap(),
        hex::encode(node.consensus_key().encode())
    );
    std::io::stdout().flush().unwrap();
    let _ = tokio::task::spawn_blocking(|| std::io::stdin().lock().lines().count()).await;
    node.stop().await.unwrap();
}

async fn embedded() {
    let directory = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("serve")
        .arg(directory.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let mut fields = line.split_whitespace().skip(1);
    let url = format!("http://{}", fields.next().unwrap());
    let key = ConsensusPublicKey::decode(hex::decode(fields.next().unwrap()).unwrap()).unwrap();
    let target = Target {
        reader: url.clone(),
        writer: url,
        pid: child.id(),
        trusted: key,
    };
    measure("embedded", &target).await;
    drop(child.stdin.take());
    let _ = child.wait();
}

async fn cluster() {
    let seed = 9471;
    let trusted = *KeySet::builder()
        .seed(seed)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(seed)
        .chain_id(CHAIN_ID)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(60))
        .await
        .unwrap();
    let target = Target {
        reader: cluster.node(0).rpc_url(),
        writer: cluster.node(1).rpc_url(),
        pid: cluster.node(0).process.id().unwrap(),
        trusted,
    };
    measure("cluster", &target).await;
}

struct Target {
    reader: String,
    writer: String,
    pid: u32,
    trusted: ConsensusPublicKey,
}

async fn measure(setup: &str, target: &Target) {
    let client = VeraClient::new(&target.writer);
    let seeding = Instant::now();
    let seeded = seed(&client).await;
    eprintln!(
        "seeded at revision {} in {:.1}s",
        seeded.minimum,
        seeding.elapsed().as_secs_f64()
    );
    let request = AccessRequest {
        actor: Actor(seeded.actor.parse().unwrap()),
        operations: vec![Operation {
            object: Object {
                resource: "document".into(),
                id: "doc".into(),
            },
            permission: "read".into(),
        }],
    };
    let mut client = VeraClient::new(&target.reader);
    if let Ok(remembered) = std::env::var("READ_VERIFIED_REVISIONS") {
        client = client.with_verified_revisions(remembered.parse().unwrap());
    }
    let selected = std::env::var("READ_QUERIES").ok();
    let permission = client
        .current_permission_response(
            &hex::encode(seeded.policy),
            &request,
            seeded.minimum,
            PERMISSION_LIMITS,
        )
        .await
        .unwrap();
    let record = fetch_record(&client, seeded.policy, seeded.minimum)
        .await
        .unwrap();
    let reader = Arc::new(Reader {
        client,
        trusted: target.trusted,
        seeded,
        request,
        record,
        permission,
    });
    let sequential: usize = std::env::var("READ_SEQUENTIAL").map_or(200, |v| v.parse().unwrap());
    let seconds =
        Duration::from_secs(std::env::var("READ_SECONDS").map_or(8, |v| v.parse().unwrap()));
    let mut budget = Duration::from_secs(
        std::env::var("READ_LOAD_WAIT_S").map_or(30 * 60, |v| v.parse().unwrap()),
    );
    println!(
        "| setup | phase | query | readers | n | reads/s | p50 ms | p95 ms | p99 ms | busy -32002 | client busy | retries | pending | other | node CPU ms/read | load |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    for phase in ["idle", "writer"] {
        let writer = (phase == "writer").then(|| start_writer(&target.writer));
        tokio::time::sleep(Duration::from_secs(3)).await;
        quiet_host(&mut budget).await;
        let idle_began = cpu_seconds(target.pid);
        let idle_clock = Instant::now();
        tokio::time::sleep(Duration::from_secs(10)).await;
        let background =
            (cpu_seconds(target.pid) - idle_began) / idle_clock.elapsed().as_secs_f64();
        eprintln!("{setup} {phase}: node background CPU {:.3} s/s", background);
        for query in QUERIES {
            let name = format!("{query:?}");
            if selected
                .as_ref()
                .is_some_and(|parts| !parts.split(',').any(|part| name.contains(part)))
            {
                continue;
            }
            for _ in 0..20 {
                let _ = reader.read(query).await;
            }
            for concurrency in [1, 16, 64] {
                let load = quiet_host(&mut budget).await;
                let cpu_began = cpu_seconds(target.pid);
                let (outcome, elapsed) =
                    run(&reader, query, concurrency, sequential, seconds).await;
                let cpu = cpu_seconds(target.pid) - cpu_began - background * elapsed.as_secs_f64();
                let mut latencies = outcome.latencies;
                latencies.sort_by(f64::total_cmp);
                let reads = latencies.len();
                println!(
                    "| {setup} | {phase} | {query:?} | {concurrency} | {reads} | {:.0} | {:.2} | {:.2} | {:.2} | {} | {} | {} | {} | {} | {:.3} | {load:.1} |",
                    reads as f64 / elapsed.as_secs_f64(),
                    percentile(&latencies, 0.50),
                    percentile(&latencies, 0.95),
                    percentile(&latencies, 0.99),
                    outcome.busy,
                    outcome.client_busy,
                    outcome.retried,
                    outcome.pending,
                    outcome.other,
                    cpu * 1e3 / reads.max(1) as f64,
                );
                if let Some(error) = outcome.first_other {
                    eprintln!(
                        "{setup} {phase} {query:?} {concurrency}: first other error: {error}"
                    );
                }
            }
        }
        if let Some((stop, sent, handle)) = writer {
            stop.store(true, Ordering::Relaxed);
            let failures = handle.await.unwrap();
            eprintln!(
                "{setup} writer: {} admitted, {failures} refused",
                sent.load(Ordering::Relaxed)
            );
        }
    }
    eprintln!("remaining load budget {:?}", budget);
}
