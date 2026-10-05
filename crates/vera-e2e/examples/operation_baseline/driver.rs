use std::{sync::Arc, time::Duration};

use alloy_primitives::{B256, FixedBytes};
use serde_json::{Value, json};
use tokio::{sync::OwnedSemaphorePermit, time::Instant};
use vera_client::{
    AccessRequest, Actor, ClientError, Object, Operation, PERMISSION_LIMITS, VeraClient,
};
use vera_domain::{ConsensusPublicKey, LightBlock, ReceiptResponse};

pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(50);
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub(super) struct Request {
    pub(super) index: usize,
    pub(super) object_id: String,
    pub(super) expected_access: bool,
    pub(super) final_registered: Option<bool>,
    pub(super) hash: B256,
    pub(super) owner: String,
    pub(super) raw: Vec<u8>,
}

pub(super) struct ReadContext {
    pub(super) trusted: ConsensusPublicKey,
    pub(super) policy: String,
    pub(super) permissions: bool,
}

#[derive(Debug)]
struct MeasuredReceipt {
    block_hash: B256,
    block_number: u64,
    status: u64,
}

#[derive(Debug)]
pub(super) struct Observation {
    pub(super) request: Request,
    outcome: &'static str,
    schedule_lag_ms: f64,
    submit_ms: Option<f64>,
    receipt_ms: Option<f64>,
    receipt_rpc_ms: Option<f64>,
    receipt: Option<MeasuredReceipt>,
    permission_ms: Option<f64>,
    workflow_ms: Option<f64>,
    error: Option<String>,
    failure_stage: Option<&'static str>,
    failed_request_ms: Option<f64>,
    verification_failure: bool,
    client_throttles: u64,
    submit_throttles: u64,
    receipt_throttles: u64,
    permission_throttles: u64,
    diagnostic_revision: Option<LightBlock>,
    diagnostic_error: Option<String>,
}

impl Observation {
    pub(super) fn measured_anchor(&self) -> Option<super::replica_barrier::Anchor> {
        self.receipt
            .as_ref()
            .map(|receipt| super::replica_barrier::Anchor {
                transaction_hash: self.request.hash,
                block_hash: receipt.block_hash,
                height: receipt.block_number,
                status: receipt.status,
            })
    }

    pub(super) fn completed(&self) -> bool {
        self.outcome == "confirmed" && self.workflow_ms.is_some()
    }

    pub(super) fn assert_completed(&self) {
        assert!(self.completed(), "update workflow failed: {}", self.json());
    }

    pub(super) fn json(&self) -> Value {
        json!({
            "kind": "observation", "index": self.request.index, "hash": self.request.hash,
            "object_id": self.request.object_id, "expected_access": self.request.expected_access,
            "outcome": self.outcome, "schedule_lag_ms": self.schedule_lag_ms,
            "submit_rpc_ms": self.submit_ms, "scheduled_to_certified_receipt_ms": self.receipt_ms,
            "permission_read_ms": self.permission_ms, "scheduled_to_workflow_ms": self.workflow_ms,
            "height": self.receipt.as_ref().map(|r| r.block_number), "error": self.error,
            "failure_stage": self.failure_stage, "failed_request_ms": self.failed_request_ms,
            "verification_failure": self.verification_failure,
            "client_throttles": self.client_throttles,
            "server_throttles": self.submit_throttles + self.receipt_throttles + self.permission_throttles - self.client_throttles,
            "submit_throttles": self.submit_throttles,
            "read_throttles": self.receipt_throttles + self.permission_throttles,
            "receipt_throttles": self.receipt_throttles,
            "receipt_rpc_ms": self.receipt_rpc_ms,
            "permission_throttles": self.permission_throttles,
            "diagnostic_refetched_revision": self.diagnostic_revision,
            "diagnostic_refetch_error": self.diagnostic_error,
        })
    }
}

pub(super) async fn observe(
    client: Arc<VeraClient>,
    request: Request,
    scheduled: Instant,
    permit: Option<OwnedSemaphorePermit>,
    reads: Arc<ReadContext>,
) -> Observation {
    let mut observation = Observation {
        request,
        outcome: "not_sent",
        schedule_lag_ms: scheduled.elapsed().as_secs_f64() * 1000.0,
        submit_ms: None,
        receipt_ms: None,
        receipt_rpc_ms: None,
        receipt: None,
        permission_ms: None,
        workflow_ms: None,
        error: None,
        failure_stage: None,
        failed_request_ms: None,
        verification_failure: false,
        client_throttles: 0,
        submit_throttles: 0,
        receipt_throttles: 0,
        permission_throttles: 0,
        diagnostic_revision: None,
        diagnostic_error: None,
    };
    let Some(_permit) = permit else {
        return observation;
    };
    observation.outcome = "unknown";
    let mut stage = "submit";
    let mut request_started = Instant::now();
    let completed = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let submit_start = Instant::now();
        let result = loop {
            request_started = Instant::now();
            let result = client.send_native_tx(&observation.request.raw).await;
            if let Err(error) = &result
                && is_throttled(error)
            {
                observation.client_throttles +=
                    u64::from(matches!(error, ClientError::ClientCapacityExhausted));
                observation.submit_throttles += 1;
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
            break result;
        };
        observation.submit_ms = Some(submit_start.elapsed().as_secs_f64() * 1000.0);
        match result {
            Ok(hash) => assert_eq!(hash, observation.request.hash, "submission hash mismatch"),
            Err(error) => {
                if matches!(error, ClientError::Rpc { .. }) || is_throttled(&error) {
                    observation.outcome = "rejected";
                }
                observation.error = Some(format!("{error:?}"));
                return;
            }
        }
        loop {
            stage = "receipt";
            request_started = Instant::now();
            match client
                .read_receipt(observation.request.hash, &reads.trusted)
                .await
            {
                Ok(Some(response)) => {
                    observation.receipt_rpc_ms =
                        Some(request_started.elapsed().as_secs_f64() * 1000.0);
                    let receipt = response
                        .receipts
                        .iter()
                        .find(|receipt| receipt.tx_hash == observation.request.hash)
                        .expect("verified receipt selection");
                    let success = receipt.success();
                    observation.receipt_ms = Some(scheduled.elapsed().as_secs_f64() * 1000.0);
                    observation.outcome = if success { "confirmed" } else { "reverted" };
                    observation.receipt = Some(MeasuredReceipt {
                        block_hash: response.revision.block_hash.parse().unwrap(),
                        block_number: response.revision.height,
                        status: u64::from(success),
                    });
                    if success && reads.permissions {
                        let request = AccessRequest {
                            actor: Actor(observation.request.owner.parse().unwrap()),
                            operations: vec![Operation {
                                object: Object {
                                    resource: "file".into(),
                                    id: observation.request.object_id.clone(),
                                },
                                permission: "read".into(),
                            }],
                        };
                        let started = Instant::now();
                        let permission = loop {
                            stage = "permission";
                            request_started = Instant::now();
                            let result = client
                                .verify_current_access(
                                    &reads.policy,
                                    &request,
                                    response.revision.height,
                                    &reads.trusted,
                                    PERMISSION_LIMITS,
                                )
                                .await;
                            if let Err(error) = &result
                                && is_throttled(error)
                            {
                                observation.client_throttles += u64::from(matches!(
                                    error,
                                    ClientError::ClientCapacityExhausted
                                ));
                                observation.permission_throttles += 1;
                                tokio::time::sleep(Duration::from_millis(250)).await;
                                continue;
                            }
                            break result;
                        };
                        observation.permission_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                        match permission {
                            Ok((_, allowed)) => {
                                assert_eq!(
                                    allowed, observation.request.expected_access,
                                    "certified permission differs"
                                )
                            }
                            Err(error) => {
                                observation.verification_failure = matches!(
                                    &error,
                                    ClientError::Finalization(_)
                                        | ClientError::Receipt(_)
                                        | ClientError::Permission(_)
                                );
                                observation.error = Some(format!("{error:?}"));
                                return;
                            }
                        }
                    }
                    if success {
                        observation.workflow_ms = Some(scheduled.elapsed().as_secs_f64() * 1000.0);
                    }
                    return;
                }
                Ok(None) => {}
                Err(error) if is_throttled(&error) => {
                    observation.client_throttles +=
                        u64::from(matches!(error, ClientError::ClientCapacityExhausted));
                    observation.receipt_throttles += 1;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                Err(error) => {
                    observation.verification_failure = matches!(
                        &error,
                        ClientError::Finalization(_)
                            | ClientError::Receipt(_)
                            | ClientError::Permission(_)
                    );
                    observation.error = Some(format!("{error:?}"));
                    observation.failed_request_ms =
                        Some(request_started.elapsed().as_secs_f64() * 1000.0);
                    if observation.verification_failure
                        && let Ok(Some(response)) = client
                            .rpc_call_typed::<Option<ReceiptResponse>>(
                                "vera_getReceiptProof",
                                json!([observation.request.hash]),
                            )
                            .await
                    {
                        observation.diagnostic_error = response
                            .verify(observation.request.hash, &reads.trusted)
                            .err()
                            .map(|error| error.to_string());
                        observation.diagnostic_revision = Some(response.revision);
                    }
                    return;
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await;
    if completed.is_err() && observation.error.is_none() {
        observation.error = Some("request deadline elapsed; submission was not retried".into());
    }
    if observation.error.is_some() {
        observation.failure_stage = Some(stage);
        if completed.is_ok() {
            observation
                .failed_request_ms
                .get_or_insert_with(|| request_started.elapsed().as_secs_f64() * 1000.0);
        }
    }
    observation
}

fn distribution(mut samples: Vec<f64>) -> Value {
    if samples.is_empty() {
        return Value::Null;
    }
    samples.sort_unstable_by(f64::total_cmp);
    let percentile = |p: usize| samples[(samples.len() * p).div_ceil(100) - 1];
    json!({"count": samples.len(), "p50": percentile(50), "p95": percentile(95), "p99": percentile(99)})
}

pub(super) fn summary(observations: &[Observation], elapsed: Duration) -> Value {
    let count = |status| observations.iter().filter(|o| o.outcome == status).count();
    json!({
        "kind": "summary", "elapsed_seconds": elapsed.as_secs_f64(),
        "offered": observations.len(), "confirmed": count("confirmed"),
        "reverted": count("reverted"), "rejected": count("rejected"),
        "unknown": count("unknown"), "not_sent": count("not_sent"),
        "client_throttles": observations.iter().map(|o| o.client_throttles).sum::<u64>(),
        "server_throttles": observations.iter().map(|o| o.submit_throttles + o.receipt_throttles + o.permission_throttles - o.client_throttles).sum::<u64>(),
        "submit_throttles": observations.iter().map(|o| o.submit_throttles).sum::<u64>(),
        "read_throttles": observations.iter().map(|o| o.receipt_throttles + o.permission_throttles).sum::<u64>(),
        "receipt_throttles": observations.iter().map(|o| o.receipt_throttles).sum::<u64>(),
        "permission_throttles": observations.iter().map(|o| o.permission_throttles).sum::<u64>(),
        "verification_failures": observations.iter().filter(|o| o.verification_failure).count(),
        "confirmed_per_second": count("confirmed") as f64 / elapsed.as_secs_f64(),
        "completed_workflows": observations.iter().filter(|o| o.workflow_ms.is_some()).count(),
        "completed_workflows_per_second": observations.iter().filter(|o| o.workflow_ms.is_some()).count() as f64 / elapsed.as_secs_f64(),
        "confirmed_incomplete_workflows": observations.iter().filter(|o| o.outcome == "confirmed" && o.workflow_ms.is_none()).count(),
        "permission_read_ms": distribution(observations.iter().filter_map(|o| o.permission_ms).collect()),
        "scheduled_to_workflow_ms": distribution(observations.iter().filter_map(|o| o.workflow_ms).collect()),
        "schedule_lag_ms": distribution(observations.iter().map(|o| o.schedule_lag_ms).collect()),
        "receipt_rpc_ms": distribution(observations.iter().filter_map(|o| o.receipt_rpc_ms).collect()),
        "submit_rpc_ms": distribution(observations.iter().filter_map(|o| o.submit_ms).collect()),
        "scheduled_to_certified_receipt_ms": distribution(observations.iter().filter_map(|o| o.receipt_ms).collect()),
    })
}

#[derive(Debug)]
pub(super) enum Resolution {
    Verified,
    Unresolved,
}

pub(super) async fn check_recovered(
    origin: &VeraClient,
    recovered: &VeraClient,
    policy_id: FixedBytes<32>,
    observation: &Observation,
) -> (bool, bool) {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let expected = origin
            .get_transaction_receipt(observation.request.hash)
            .await
            .unwrap();
        let actual = recovered
            .get_transaction_receipt(observation.request.hash)
            .await
            .unwrap();
        let receipt_matches = match (&expected, &actual) {
            (None, None) => true,
            (Some(expected), Some(actual)) => {
                expected.block_hash == actual.block_hash
                    && expected.status == actual.status
                    && expected.transaction_hash == actual.transaction_hash
            }
            _ => false,
        };
        let (registered, record) = recovered
            .get_object_owner(policy_id, "file", &observation.request.object_id.clone())
            .await
            .unwrap();
        let expected_registration = observation
            .request
            .final_registered
            .unwrap_or_else(|| expected.as_ref().is_some_and(|r| r.status == 1));
        let owner_matches = !registered || {
            let record: Value = serde_json::from_slice(&record).unwrap();
            record["metadata"]["owner_did"] == observation.request.owner
        };
        (
            receipt_matches,
            registered == expected_registration && owner_matches,
        )
    })
    .await
    .expect("recovered state inspection timed out")
}

pub(super) async fn verify(
    clients: &[VeraClient],
    policy_id: FixedBytes<32>,
    observation: &Observation,
) -> Resolution {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let origin = &clients[0];
        let receipt = origin
            .get_transaction_receipt(observation.request.hash)
            .await
            .unwrap();
        if observation.outcome == "unknown" && receipt.is_none() {
            return Resolution::Unresolved;
        }
        if matches!(observation.outcome, "not_sent" | "rejected") {
            assert!(receipt.is_none(), "rejected operation has a receipt");
        }
        if let Some(measured) = &observation.receipt {
            let current = receipt.as_ref().expect("measured receipt disappeared");
            assert_eq!(current.block_hash, measured.block_hash);
            assert_eq!(current.status, measured.status);
        }
        for (index, client) in clients.iter().enumerate() {
            let replica_receipt = if let Some(expected) = &receipt {
                let actual = client
                    .wait_for_receipt(observation.request.hash, POLL_INTERVAL, 600)
                    .await
                    .unwrap();
                assert_eq!(
                    actual.block_hash, expected.block_hash,
                    "replica {index} receipt differs"
                );
                assert_eq!(
                    actual.status, expected.status,
                    "replica {index} status differs"
                );
                Some(actual)
            } else {
                client
                    .get_transaction_receipt(observation.request.hash)
                    .await
                    .unwrap()
            };
            let (registered, record) = client
                .get_object_owner(policy_id, "file", &observation.request.object_id.clone())
                .await
                .unwrap();
            let expected_registration = observation
                .request
                .final_registered
                .unwrap_or_else(|| receipt.as_ref().is_some_and(|r| r.status == 1));
            assert_eq!(
                registered, expected_registration,
                "replica {index} ownership differs"
            );
            assert_eq!(replica_receipt.is_some(), receipt.is_some());
            if registered {
                let record: Value = serde_json::from_slice(&record).unwrap();
                assert_eq!(record["metadata"]["owner_did"], observation.request.owner);
            }
        }
        Resolution::Verified
    })
    .await
    .expect("replica verification timed out")
}

pub(super) fn assert_no_verification_failures(observations: &[Observation]) {
    assert!(
        observations.iter().all(|o| !o.verification_failure),
        "invalid proof responses invalidate the workload run"
    );
}

fn is_throttled(error: &ClientError) -> bool {
    error.is_throttled()
}
