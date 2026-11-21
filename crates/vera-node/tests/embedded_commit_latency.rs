//! Breaks down the latency of one native request on an embedded lone validator.
//! Run explicitly:
//! `cargo test --release -p vera-node --test embedded_commit_latency -- --ignored --nocapture`
//!
//! `LATENCY_WRITES` (default 200) sets the requests each writer sends one at a
//! time and `LATENCY_CONCURRENCY` (default 1) the writers. `LATENCY_BATCH_MS`,
//! `LATENCY_SETTLED_MS` and `LATENCY_IDLE_MS` set the pacing. `LATENCY_WAIT`
//! selects how a writer waits for its receipt: `poll1` (default) polls every
//! millisecond, `poll200` every 200 ms, and `headers` polls once per
//! finalized header. Stage timings are reported for one writer only.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use serde_json::json;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{EnvFilter, Layer, layer::Context, prelude::*};
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::ReceiptResponse;
use vera_modules::{acp::abi::IAcp, vera::administration::OperatorPolicy};
use vera_node::{EmbeddedConfig, EmbeddedNode, SoloGenesis, SoloPacing};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// Log messages that mark a stage, with the label each is reported under.
const STAGES: &[(&str, &str)] = &[
    ("built block", "built"),
    ("broadcasting notarize", "notarize_vote_durable"),
    ("broadcasting notarization", "notarized"),
    ("attempting certification", "certify_started"),
    ("broadcasting finalize", "finalize_vote_durable"),
    ("broadcasting finalization", "finalized"),
    ("marshal stateful delivery", "marshal_delivered"),
    ("finalized state apply", "state_applied"),
    ("finalized sink started", "sink_started"),
    (
        "finalized revision publication",
        "history_durable_index_published",
    ),
    (
        "finalized state synchronization started",
        "state_sync_started",
    ),
    ("finalized state durability completed", "state_durable"),
    ("finalized sink completed", "sink_completed"),
];

/// Stage events: when, which stage, and the event's other fields.
type Events = Arc<Mutex<Vec<(Instant, &'static str, String)>>>;
/// Resource snapshots: durable height and storage syncs so far.
type Snapshots = Arc<Mutex<Vec<(u64, u64)>>>;

#[derive(Default, Clone)]
struct Recorder(Events, Snapshots);

struct Message(Option<String>, Vec<String>);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = Some(format!("{value:?}"));
        } else {
            self.1.push(format!("{}={value:?}", field.name()));
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0 = Some(value.to_owned());
        } else {
            self.1.push(format!("{}={value}", field.name()));
        }
    }
}

impl<S: Subscriber> Layer<S> for Recorder {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let now = Instant::now();
        // Each diagnostic is logged under two targets; one is enough.
        if event.metadata().target() == "vera_publication_diagnostics" {
            return;
        }
        let mut message = Message(None, Vec::new());
        event.record(&mut message);
        let Some(text) = message.0 else { return };
        if text == "node resource snapshot" {
            let field = |name: &str| {
                message
                    .1
                    .iter()
                    .find_map(|field| field.strip_prefix(name))
                    .unwrap_or_default()
                    .to_owned()
            };
            let syncs = field("runtime_metrics=")
                .lines()
                .filter(|line| line.contains("storage_syncs") && !line.starts_with('#'))
                .filter_map(|line| line.rsplit(' ').next()?.parse::<u64>().ok())
                .sum();
            let height = field("durable_height=")
                .trim_start_matches("Some(")
                .trim_end_matches(')')
                .parse()
                .unwrap_or_default();
            self.1.lock().unwrap().push((height, syncs));
            return;
        }
        if let Some((_, label)) = STAGES.iter().find(|(stage, _)| text == *stage) {
            self.0
                .lock()
                .unwrap()
                .push((now, label, message.1.join(" ")));
        }
    }
}

fn percentile(sorted: &[f64], p: usize) -> f64 {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

fn millis(variable: &str) -> Option<Duration> {
    std::env::var(variable)
        .ok()
        .map(|value| Duration::from_millis(value.parse().unwrap()))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run explicitly in release mode"]
async fn commit_latency_breakdown() {
    let recorder = Recorder::default();
    tracing_subscriber::registry()
        .with(recorder.clone().with_filter(EnvFilter::new(
            "warn,vera_app=info,vera_diagnostics=debug,commonware_consensus::simplex::actors::voter=debug",
        )))
        .init();
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9412;
    let genesis = SoloGenesis {
        policies: Vec::new(),
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
    config.pacing = Some(SoloPacing {
        idle: millis("LATENCY_IDLE_MS").unwrap_or(EmbeddedConfig::HEARTBEAT),
        batch: millis("LATENCY_BATCH_MS").unwrap_or(SoloPacing::BATCH),
        settled: millis("LATENCY_SETTLED_MS").unwrap_or(SoloPacing::SETTLED),
    });
    let writes: usize = std::env::var("LATENCY_WRITES")
        .ok()
        .map_or(200, |value| value.parse().unwrap());
    let concurrency: u64 = std::env::var("LATENCY_CONCURRENCY")
        .ok()
        .map_or(1, |value| value.parse().unwrap());
    let wait = std::env::var("LATENCY_WAIT").unwrap_or_else(|_| "poll1".into());
    let node = Arc::new(EmbeddedNode::start(config).await.unwrap());
    tokio::time::sleep(Duration::from_millis(500)).await;

    let rows: Arc<Mutex<BTreeMap<&'static str, Vec<f64>>>> = Arc::default();
    let add = {
        let rows = rows.clone();
        move |label: &'static str, value: Duration| {
            rows.lock()
                .unwrap()
                .entry(label)
                .or_default()
                .push(value.as_secs_f64() * 1e3);
        }
    };
    let began = Instant::now();
    let mut writers = Vec::new();
    for writer in 0..concurrency {
        let (node, recorder, add, wait) =
            (node.clone(), recorder.clone(), add.clone(), wait.clone());
        writers.push(tokio::spawn(async move {
            let signer = BlsSigner::new((3 + writer).into(), chain_id).unwrap();
            let mut headers = if wait == "headers" {
                Some(
                    node.rpc()
                        .subscribe("vera_subscribeHeaders", Vec::new(), 64)
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            for index in 0..writes {
                let call = IAcp::createPolicyCall {
                    policy: format!(
                        "name: latency-{writer}-{index}\nresources:\n  - name: document\n    relations:\n      - name: reader\n        types: [actor]\n    permissions:\n      - name: read\n        expr: reader\n"
                    )
                    .into_bytes()
                    .into(),
                    marshalType: 1,
                    nonce: vera_client::random_policy_nonce().0.into(),
                };
                let wire = signer
                    .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
                    .unwrap();
                if concurrency == 1 {
                    recorder.0.lock().unwrap().clear();
                }
                let started = Instant::now();
                let submission: B256 = node
                    .rpc()
                    .request(
                        "vera_sendNativeTx",
                        vec![json!(format!("0x{}", hex::encode(wire)))],
                    )
                    .await
                    .unwrap();
                add("a_submit_accepted", started.elapsed());
                let proof = loop {
                    match (&mut headers, wait.as_str()) {
                        (Some(headers), _) => {
                            headers.next::<serde_json::Value>().await.unwrap().unwrap();
                        }
                        (None, "poll200") => tokio::time::sleep(Duration::from_millis(200)).await,
                        _ => tokio::time::sleep(Duration::from_millis(1)).await,
                    }
                    let polled = Instant::now();
                    let proof: Option<ReceiptResponse> = node
                        .rpc()
                        .request("vera_getReceiptProof", vec![json!(submission)])
                        .await
                        .unwrap();
                    if let Some(proof) = proof {
                        add("y_receipt_proof_call", polled.elapsed());
                        break proof;
                    }
                };
                add("y_receipt_proof_returned", started.elapsed());
                let verifying = Instant::now();
                assert!(
                    proof
                        .verify(submission, node.consensus_key())
                        .unwrap()
                        .success()
                );
                add("z_verify", verifying.elapsed());
                add("z_total", started.elapsed());
                if concurrency > 1 {
                    continue;
                }
                let events = recorder.0.lock().unwrap().clone();
                let mut seen = std::collections::BTreeSet::new();
                for (at, label, fields) in events {
                    if label == "marshal_delivered" && !fields.contains("stage=block") {
                        continue;
                    }
                    if seen.insert(label) {
                        add(label, at.saturating_duration_since(started));
                        for field in fields.split(' ') {
                            if let Some((name, value)) = field.split_once('=')
                                && name.ends_with("_us")
                                && let Ok(micros) = value.parse::<u64>()
                            {
                                let name: &'static str =
                                    Box::leak(format!("{label}.{name}").into_boxed_str());
                                add(name, Duration::from_micros(micros));
                            }
                        }
                    }
                }
            }
        }));
    }
    for writer in writers {
        writer.await.unwrap();
    }
    let elapsed = began.elapsed();
    println!(
        "wait={wait} concurrency={concurrency} writes={} throughput={:.1}/s",
        writes as u64 * concurrency,
        (writes as u64 * concurrency) as f64 / elapsed.as_secs_f64()
    );
    let rows = std::mem::take(&mut *rows.lock().unwrap());
    let snapshots = recorder.1.clone();
    let first = snapshots.lock().unwrap().len();
    let waiting = Instant::now();
    while snapshots.lock().unwrap().len() == first && waiting.elapsed() < Duration::from_secs(40) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let snapshots = snapshots.lock().unwrap().clone();
    if let (Some(start), Some(end)) = (snapshots.first(), snapshots.last())
        && end.0 > start.0
    {
        println!(
            "storage syncs per block: {:.1} over {} blocks ({} snapshots)",
            (end.1 - start.1) as f64 / (end.0 - start.0) as f64,
            end.0 - start.0,
            snapshots.len()
        );
    }
    let mut table: Vec<_> = rows
        .into_iter()
        .map(|(label, mut values)| {
            values.sort_by(f64::total_cmp);
            (percentile(&values, 50), label, values)
        })
        .collect();
    table.sort_by(|a, b| a.0.total_cmp(&b.0));
    println!("| stage (ms from submit) | n | p50 | p95 |");
    println!("| --- | --- | --- | --- |");
    for (_, label, values) in table {
        println!(
            "| {label} | {} | {:.1} | {:.1} |",
            values.len(),
            percentile(&values, 50),
            percentile(&values, 95)
        );
    }
    Arc::into_inner(node).unwrap().stop().await.unwrap();
}
