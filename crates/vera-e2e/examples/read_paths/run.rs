//! Sequential and concurrent runs of one read path, beside an optional writer.

use super::*;

#[derive(Default)]
pub(super) struct Outcome {
    pub(super) latencies: Vec<f64>,
    pub(super) busy: u64,
    pub(super) client_busy: u64,
    pub(super) retried: u64,
    pub(super) pending: u64,
    pub(super) other: u64,
    pub(super) first_other: Option<String>,
}

impl Outcome {
    pub(super) fn record(
        &mut self,
        started: Instant,
        result: Result<usize, ClientError>,
        expected: usize,
    ) {
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

    pub(super) fn merge(&mut self, other: Self) {
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

pub(super) fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

/// Background writer: one policy creation about every 200 ms, receipts not awaited.
pub(super) fn start_writer(
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
pub(super) async fn attempt(
    reader: &Reader,
    query: Query,
    outcome: &mut Outcome,
    retry: Option<Duration>,
) {
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

pub(super) async fn run(
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
