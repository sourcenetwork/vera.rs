use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy_primitives::Bytes;
use serde_json::{Value, json};
use tokio::time::{Instant, timeout_at};
use vera_client::{
    ACP_ADDRESS, AccessRequest, Actor, BlsSigner, ClientError, Object, Operation,
    PERMISSION_LIMITS, RECORD_PROOF_BYTES, VeraClient,
};
use vera_domain::{ConsensusPublicKey, NativeTx};

pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub(super) struct Failure {
    pub(super) kind: &'static str,
    pub(super) message: String,
}
impl Failure {
    pub(super) fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}
pub(super) type Result<T> = std::result::Result<T, Failure>;

#[derive(Default)]
pub(super) struct Counts {
    issued: AtomicU64,
    mutations: AtomicU64,
    attempts: AtomicU64,
    confirmed: AtomicU64,
    confirmed_mutations: AtomicU64,
    permissions: AtomicU64,
    owners: AtomicU64,
    throttles: AtomicU64,
}
impl Counts {
    pub(super) fn json(&self) -> Value {
        json!({
            "issued_native_submissions": self.issued.load(Ordering::Relaxed),
            "issued_embedded_mutations": self.mutations.load(Ordering::Relaxed),
            "certified_embedded_mutations": self.confirmed_mutations.load(Ordering::Relaxed),
            "submission_attempts": self.attempts.load(Ordering::Relaxed),
            "certified_successes": self.confirmed.load(Ordering::Relaxed),
            "verified_permission_checks": self.permissions.load(Ordering::Relaxed),
            "verified_owners": self.owners.load(Ordering::Relaxed),
            "throttled_requests": self.throttles.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone)]
pub(super) struct Evidence {
    pub(super) trusted: ConsensusPublicKey,
    pub(super) counts: Arc<Counts>,
}

impl Evidence {
    async fn retry<T, F, Fut>(&self, deadline: Instant, mut request: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = std::result::Result<T, ClientError>>,
    {
        loop {
            if Instant::now() >= deadline {
                return Err(Failure::new("deadline", "fixed request deadline elapsed"));
            }
            let result = timeout_at(deadline, request())
                .await
                .map_err(|_| Failure::new("deadline", "fixed request deadline elapsed"))?;
            match result {
                Ok(value) => return Ok(value),
                Err(error) if error.is_throttled() => {
                    self.counts.throttles.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep_until(deadline.min(Instant::now() + POLL)).await;
                }
                Err(error) => {
                    return Err(Failure::new(
                        if matches!(
                            error,
                            ClientError::Finalization(_)
                                | ClientError::Receipt(_)
                                | ClientError::Permission(_)
                        ) {
                            "verification"
                        } else if matches!(error, ClientError::Rpc { .. }) {
                            "rpc_rejection"
                        } else {
                            "transport"
                        },
                        format!("{error:?}"),
                    ));
                }
            }
        }
    }

    pub(super) async fn submit(
        &self,
        client: &VeraClient,
        signer: &BlsSigner,
        calldata: Bytes,
        mutations: usize,
        phase: &str,
        workflow: Option<usize>,
    ) -> Result<u64> {
        let started = Instant::now();
        let raw = signer
            .sign_native_tx(ACP_ADDRESS, calldata)
            .map_err(|e| Failure::new("signing", e.to_string()))?;
        let hash = NativeTx::decode_wire(&raw)
            .map_err(|e| Failure::new("encoding", e.to_string()))?
            .tx_id()
            .0;
        self.counts.issued.fetch_add(1, Ordering::Relaxed);
        self.counts
            .mutations
            .fetch_add(mutations as u64, Ordering::Relaxed);
        println!(
            "{}",
            json!({"kind":"submission_started", "phase":phase, "workflow":workflow, "id":hash, "embedded_mutations":mutations})
        );
        let deadline = started + REQUEST_TIMEOUT;
        let result = async {
            let accepted = self
                .retry(deadline, || {
                    self.counts.attempts.fetch_add(1, Ordering::Relaxed);
                    client.send_native_tx(&raw)
                })
                .await?;
            if accepted != hash {
                return Err(Failure::new(
                    "verification",
                    "submission identifier differs",
                ));
            }
            let accepted_ms = started.elapsed().as_secs_f64() * 1000.0;
            loop {
                if let Some(response) = self
                    .retry(deadline, || client.read_receipt(hash, &self.trusted))
                    .await?
                {
                    let receipt = response
                        .receipts
                        .iter()
                        .find(|r| r.tx_hash == hash)
                        .ok_or_else(|| {
                            Failure::new("verification", "certified receipt selection missing")
                        })?;
                    if !receipt.success() {
                        return Err(Failure::new(
                            "reverted",
                            format!("certified failed receipt for {hash}"),
                        ));
                    }
                    self.counts.confirmed.fetch_add(1, Ordering::Relaxed);
                    self.counts
                        .confirmed_mutations
                        .fetch_add(mutations as u64, Ordering::Relaxed);
                    return Ok((response.revision.height, accepted_ms));
                }
                tokio::time::sleep_until(deadline.min(Instant::now() + POLL)).await;
            }
        }
        .await;
        println!(
            "{}",
            json!({"kind":"submission", "phase":phase, "workflow":workflow,
            "id":hash, "embedded_mutations":mutations, "elapsed_ms":started.elapsed().as_secs_f64()*1000.0,
            "revision":result.as_ref().ok().map(|r|r.0), "accepted_ms":result.as_ref().ok().map(|r|r.1),
            "failure_kind":result.as_ref().err().map(|e|e.kind), "error":result.as_ref().err().map(|e|&e.message)})
        );
        result.map(|r| r.0)
    }

    pub(super) async fn permission(
        &self,
        client: &VeraClient,
        policy: &str,
        object: &Object,
        actor: &str,
        expected: bool,
        minimum: u64,
    ) -> Result<u64> {
        let request = AccessRequest {
            actor: Actor(
                actor
                    .parse()
                    .map_err(|e| Failure::new("fixture", format!("{e}")))?,
            ),
            operations: vec![Operation {
                object: object.clone(),
                permission: "read".into(),
            }],
        };
        let (revision, allowed) = self
            .retry(Instant::now() + REQUEST_TIMEOUT, || {
                client.verify_current_access(
                    policy,
                    &request,
                    minimum,
                    &self.trusted,
                    PERMISSION_LIMITS,
                )
            })
            .await?;
        if revision.height < minimum || allowed != expected {
            return Err(Failure::new(
                "verification",
                format!(
                    "{}:{} actor {actor}: expected {expected} at >= {minimum}, got {allowed} at {}",
                    object.resource, object.id, revision.height
                ),
            ));
        }
        self.counts.permissions.fetch_add(1, Ordering::Relaxed);
        Ok(revision.height)
    }

    pub(super) async fn owner(
        &self,
        client: &VeraClient,
        policy: &str,
        object: &Object,
        owner: &str,
        minimum: u64,
    ) -> Result<()> {
        let prefix = vera_client::object_owner_prefix(policy, object)
            .map_err(|e| Failure::new("fixture", e.to_string()))?;
        let proof = self
            .retry(Instant::now() + REQUEST_TIMEOUT, || {
                client.read_current_policy_prefix(
                    policy,
                    &prefix,
                    minimum,
                    &self.trusted,
                    RECORD_PROOF_BYTES,
                )
            })
            .await?;
        let actual = proof
            .verify_object_owner(policy, object, minimum, &self.trusted)
            .map_err(|e| Failure::new("verification", e.to_string()))?;
        if actual.as_ref().map(|v| v.0.as_str()) != Some(owner) {
            return Err(Failure::new(
                "verification",
                format!("owner differs for {}:{}", object.resource, object.id),
            ));
        }
        self.counts.owners.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
