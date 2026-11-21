//! Compares unverified `eth_call` queries with certified reads verified by the client.
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

struct Seeded {
    policy: B256,
    actor: String,
    minimum: u64,
}

async fn submit(
    client: &VeraClient,
    signer: &BlsSigner,
    to: alloy_primitives::Address,
    call: impl SolCall,
) -> u64 {
    let wire = signer.sign_native_tx(to, call.abi_encode().into()).unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    let receipt = client
        .wait_for_receipt(id, Duration::from_millis(20), 3_000)
        .await
        .unwrap();
    assert_eq!(receipt.status, 1, "seeding request failed");
    receipt.block_number
}

async fn seed(client: &VeraClient) -> Seeded {
    let owner = BlsSigner::new(7u64.into(), CHAIN_ID).unwrap();
    submit(
        client,
        &owner,
        ACP_ADDRESS,
        IAcp::createPolicyCall {
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
            nonce: vera_client::random_policy_nonce().0.into(),
        },
    )
    .await;
    let policy: B256 = client.get_policy_ids().await.unwrap()[0].parse().unwrap();
    let actors: Vec<String> = (0..RELATIONSHIPS)
        .map(|index| {
            BlsSigner::new((1_000 + index as u64).into(), CHAIN_ID)
                .unwrap()
                .did()
                .to_owned()
        })
        .collect();
    let mut minimum = 0;
    for (batch, chunk) in actors.chunks(20).enumerate() {
        let mut calls = Vec::new();
        if batch == 0 {
            calls.push(
                IAcp::registerObjectCall {
                    policyId: policy,
                    resource: "document".into(),
                    objectId: "doc".into(),
                }
                .abi_encode()
                .into(),
            );
        }
        for actor in chunk {
            calls.push(
                IAcp::setRelationshipCall {
                    policyId: policy,
                    resource: "document".into(),
                    objectId: "doc".into(),
                    relation: "reader".into(),
                    actor: actor.clone(),
                }
                .abi_encode()
                .into(),
            );
        }
        minimum = submit(client, &owner, ACP_ADDRESS, IAcp::batchCallsCall { calls }).await;
    }
    submit(
        client,
        &owner,
        BULLETIN_ADDRESS,
        IBulletin::registerNamespaceCall {
            namespace: "team".into(),
        },
    )
    .await;
    for index in 0..POSTS {
        minimum = submit(
            client,
            &owner,
            BULLETIN_ADDRESS,
            IBulletin::createPostCall {
                namespace: NAMESPACE.into(),
                payload: format!("post {index} {}", "x".repeat(200))
                    .into_bytes()
                    .into(),
                proof: vec![1, 2, 3].into(),
                artifact: "bulletin/read-paths".into(),
            },
        )
        .await;
    }
    Seeded {
        policy,
        actor: actors[RELATIONSHIPS / 2].clone(),
        minimum,
    }
}

#[derive(Clone, Copy, Debug)]
enum Query {
    PolicyCall,
    PolicyVerified,
    RelationshipsCall,
    RelationshipsVerified50,
    RelationshipsVerified128,
    AccessCall,
    AccessVerified,
    PostsCall,
    PostsVerified,
    PolicyFetchOnly,
    PolicyVerifyOnly,
    AccessFetchOnly,
    AccessVerifyOnly,
    CertificateVerifyOnly,
}

const QUERIES: [Query; 14] = [
    Query::PolicyCall,
    Query::PolicyVerified,
    Query::RelationshipsCall,
    Query::RelationshipsVerified50,
    Query::RelationshipsVerified128,
    Query::AccessCall,
    Query::AccessVerified,
    Query::PostsCall,
    Query::PostsVerified,
    Query::PolicyFetchOnly,
    Query::PolicyVerifyOnly,
    Query::AccessFetchOnly,
    Query::AccessVerifyOnly,
    Query::CertificateVerifyOnly,
];

struct Reader {
    client: VeraClient,
    trusted: ConsensusPublicKey,
    seeded: Seeded,
    request: AccessRequest,
    record: RecordResponse,
    permission: PermissionResponse,
}

impl Reader {
    /// Runs one read and returns how many records it produced, as a correctness check.
    async fn read(&self, query: Query) -> Result<usize, ClientError> {
        let policy = self.seeded.policy;
        let minimum = self.seeded.minimum;
        let trusted = &self.trusted;
        Ok(match query {
            Query::PolicyCall => usize::from(
                !self
                    .client
                    .get_policy(FixedBytes(policy.0))
                    .await?
                    .is_empty(),
            ),
            Query::PolicyVerified => usize::from(
                self.client
                    .read_policy(policy, minimum, trusted)
                    .await?
                    .value
                    .is_some(),
            ),
            Query::RelationshipsCall => self
                .client
                .get_relationships_page(
                    FixedBytes(policy.0),
                    &RelationshipPageRequest {
                        selector: Default::default(),
                        after: None,
                    },
                )
                .await?
                .records
                .len(),
            Query::RelationshipsVerified50 | Query::RelationshipsVerified128 => {
                let limit = if matches!(query, Query::RelationshipsVerified50) {
                    50
                } else {
                    128
                };
                self.client
                    .read_relationship_page(policy, None, limit, minimum, trusted)
                    .await?
                    .records
                    .len()
            }
            Query::AccessCall => usize::from(
                self.client
                    .verify_access_request(
                        FixedBytes(policy.0),
                        vec!["document".into()],
                        vec!["doc".into()],
                        vec!["read".into()],
                        &self.seeded.actor,
                    )
                    .await?,
            ),
            Query::AccessVerified => usize::from(
                self.client
                    .verify_current_access(
                        &hex::encode(policy),
                        &self.request,
                        minimum,
                        trusted,
                        PERMISSION_LIMITS,
                    )
                    .await?
                    .1,
            ),
            Query::PostsCall => {
                let bytes = self.client.get_namespace_posts(NAMESPACE).await?;
                serde_json::from_slice::<Vec<serde_json::Value>>(&bytes)
                    .map(|posts| posts.len())
                    .unwrap_or(usize::MAX)
            }
            Query::PostsVerified => self
                .client
                .list_bulletin_posts(NAMESPACE, None, 50, minimum, trusted)
                .await?
                .records
                .len(),
            Query::PolicyFetchOnly => usize::from(
                fetch_record(&self.client, policy, minimum)
                    .await?
                    .record
                    .value
                    .is_some(),
            ),
            Query::PolicyVerifyOnly => {
                self.record.verify(
                    ModuleId::Acp,
                    &policy_key(policy),
                    minimum,
                    trusted,
                    RECORD_PROOF_BYTES,
                )?;
                1
            }
            Query::AccessFetchOnly => {
                self.client
                    .current_permission_response(
                        &hex::encode(policy),
                        &self.request,
                        minimum,
                        PERMISSION_LIMITS,
                    )
                    .await?;
                1
            }
            Query::CertificateVerifyOnly => {
                vera_domain::verify_light_block(&self.record.revision, trusted)?;
                1
            }
            Query::AccessVerifyOnly => usize::from(self.permission.verify(
                &hex::encode(policy),
                &self.request,
                minimum,
                trusted,
                PERMISSION_LIMITS,
            )?),
        })
    }
}

/// The record request `read_policy` sends, without verifying the response.
async fn fetch_record(
    client: &VeraClient,
    policy: B256,
    minimum: u64,
) -> Result<RecordResponse, ClientError> {
    client
        .rpc_call_typed(
            "vera_getCurrentRecordProof",
            serde_json::json!([
                ModuleId::Acp,
                alloy_primitives::Bytes::from(policy_key(policy)),
                minimum
            ]),
        )
        .await
}

fn policy_key(policy: B256) -> Vec<u8> {
    vera_modules::acp::keys::policy_key(&hex::encode(policy))
}

fn load_average() -> f64 {
    let output = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

/// Waits for the host's one-minute load to fall under the limit within the shared budget.
async fn quiet_host(budget: &mut Duration) -> f64 {
    let limit: f64 = std::env::var("READ_MAX_LOAD").map_or(8.0, |value| value.parse().unwrap());
    loop {
        let load = load_average();
        if load < limit || budget.is_zero() {
            return load;
        }
        let pause = Duration::from_secs(5).min(*budget);
        tokio::time::sleep(pause).await;
        *budget -= pause;
    }
}

/// Process CPU time in seconds, user plus system, as `ps` reports it.
fn cpu_seconds(pid: u32) -> f64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    text.trim().split(':').fold(0.0, |total, part| {
        total * 60.0 + part.parse::<f64>().unwrap()
    })
}

#[derive(Default)]
struct Outcome {
    latencies: Vec<f64>,
    busy: u64,
    client_busy: u64,
    retried: u64,
    pending: u64,
    other: u64,
    first_other: Option<String>,
}

impl Outcome {
    fn record(&mut self, started: Instant, result: Result<usize, ClientError>, expected: usize) {
        match result {
            Ok(count) if count == expected => {
                self.latencies.push(started.elapsed().as_secs_f64() * 1e3)
            }
            Ok(count) => {
                self.other += 1;
                self.first_other
                    .get_or_insert(format!("unexpected count {count}, wanted {expected}"));
            }
            Err(ClientError::ClientCapacityExhausted) => self.client_busy += 1,
            Err(error) if error.is_throttled() => self.busy += 1,
            Err(ClientError::FinalityPending(_)) => self.pending += 1,
            Err(error) => {
                self.other += 1;
                self.first_other.get_or_insert(error.to_string());
            }
        }
    }

    fn merge(&mut self, other: Self) {
        self.latencies.extend(other.latencies);
        self.busy += other.busy;
        self.client_busy += other.client_busy;
        self.retried += other.retried;
        self.pending += other.pending;
        self.other += other.other;
        if self.first_other.is_none() {
            self.first_other = other.first_other;
        }
    }
}

fn expected(query: Query) -> usize {
    match query {
        Query::PolicyCall | Query::PolicyVerified | Query::AccessCall | Query::AccessVerified => 1,
        Query::RelationshipsCall | Query::RelationshipsVerified128 => RELATIONSHIPS + 1,
        Query::RelationshipsVerified50 => 50,
        Query::PostsCall | Query::PostsVerified => POSTS,
        Query::PolicyFetchOnly
        | Query::PolicyVerifyOnly
        | Query::AccessFetchOnly
        | Query::AccessVerifyOnly
        | Query::CertificateVerifyOnly => 1,
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

/// Background writer: one policy creation about every 200 ms, receipts not awaited.
fn start_writer(
    url: &str,
) -> (
    Arc<AtomicBool>,
    Arc<AtomicU64>,
    tokio::task::JoinHandle<u64>,
) {
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let client = VeraClient::new(url);
    let (stopping, counting) = (stop.clone(), sent.clone());
    let handle = tokio::spawn(async move {
        let signer = BlsSigner::new(99u64.into(), CHAIN_ID).unwrap();
        let mut failures = 0;
        let mut ticker = tokio::time::interval(Duration::from_millis(200));
        let mut index = 0u64;
        while !stopping.load(Ordering::Relaxed) {
            ticker.tick().await;
            index += 1;
            let call = IAcp::createPolicyCall {
                policy: format!("name: writer-{index}\nresources:\n  - name: document\n")
                    .into_bytes()
                    .into(),
                marshalType: 1,
                nonce: vera_client::random_policy_nonce().0.into(),
            };
            let wire = signer
                .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
                .unwrap();
            match client.send_native_tx(&wire).await {
                Ok(_) => {
                    counting.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    failures += 1;
                    if let Ok(next) = client.get_native_nonce(signer.did()).await {
                        signer.set_next_sequence(next);
                    }
                }
            }
        }
        failures
    });
    (stop, sent, handle)
}

/// One read as a consumer sees it: with `READ_RETRY_MS` set, a throttled read
/// waits that long and tries again, and its latency spans every attempt.
async fn attempt(reader: &Reader, query: Query, outcome: &mut Outcome, retry: Option<Duration>) {
    let started = Instant::now();
    loop {
        let result = reader.read(query).await;
        if let (Some(pause), Err(error)) = (retry, &result)
            && error.is_throttled()
            && started.elapsed() < Duration::from_secs(10)
        {
            outcome.retried += 1;
            tokio::time::sleep(pause).await;
            continue;
        }
        outcome.record(started, result, expected(query));
        return;
    }
}

async fn run(
    reader: &Arc<Reader>,
    query: Query,
    concurrency: usize,
    sequential: usize,
    seconds: Duration,
) -> (Outcome, Duration) {
    let retry = std::env::var("READ_RETRY_MS")
        .ok()
        .map(|value| Duration::from_millis(value.parse().unwrap()));
    let began = Instant::now();
    if concurrency == 1 {
        let mut outcome = Outcome::default();
        for _ in 0..sequential {
            attempt(reader, query, &mut outcome, retry).await;
        }
        return (outcome, began.elapsed());
    }
    let deadline = began + seconds;
    let mut tasks = Vec::new();
    for _ in 0..concurrency {
        let reader = reader.clone();
        tasks.push(tokio::spawn(async move {
            let mut outcome = Outcome::default();
            while Instant::now() < deadline {
                attempt(&reader, query, &mut outcome, retry).await;
            }
            outcome
        }));
    }
    let mut outcome = Outcome::default();
    for task in tasks {
        outcome.merge(task.await.unwrap());
    }
    (outcome, began.elapsed())
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
