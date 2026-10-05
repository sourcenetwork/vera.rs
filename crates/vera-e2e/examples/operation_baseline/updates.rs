use std::sync::Arc;

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use futures::{StreamExt, stream};
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};
use vera_client::{ACP_ADDRESS, BlsSigner, VeraClient};
use vera_domain::NativeTx;
use vera_modules::acp::abi::IAcp;

use super::{CHAIN_ID, driver};

pub(super) async fn prepare(
    client: Arc<VeraClient>,
    reads: Arc<driver::ReadContext>,
    policy: FixedBytes<32>,
    count: usize,
    objects: usize,
    concurrency: usize,
) -> Vec<driver::Request> {
    let signers: Vec<_> = (1..=objects)
        .map(|key| BlsSigner::new((key as u64).into(), CHAIN_ID).unwrap())
        .collect();
    let permits = Arc::new(Semaphore::new(concurrency));
    stream::iter(signers.iter().enumerate())
        .for_each_concurrent(concurrency, |(index, signer)| {
            let client = client.clone();
            let reads = reads.clone();
            let permits = permits.clone();
            async move {
                let raw = signer
                    .sign_native_tx(
                        ACP_ADDRESS,
                        IAcp::registerObjectCall {
                            policyId: policy,
                            resource: "file".into(),
                            objectId: index.to_string(),
                        }
                        .abi_encode()
                        .into(),
                    )
                    .unwrap();
                let request = driver::Request {
                    index,
                    object_id: index.to_string(),
                    expected_access: true,
                    final_registered: None,
                    hash: NativeTx::decode_wire(&raw).unwrap().tx_id().0,
                    owner: signer.did().to_string(),
                    raw,
                };
                driver::observe(
                    client,
                    request,
                    Instant::now(),
                    Some(permits.acquire_owned().await.unwrap()),
                    reads,
                )
                .await
                .assert_completed();
            }
        })
        .await;
    (0..count)
        .map(|index| {
            let object = index % objects;
            let signer = &signers[object];
            let expected_access = (index / objects) % 2 == 1;
            let calldata = if expected_access {
                IAcp::unarchiveObjectCall {
                    policyId: policy,
                    resource: "file".into(),
                    objectId: object.to_string(),
                }
                .abi_encode()
            } else {
                IAcp::archiveObjectCall {
                    policyId: policy,
                    resource: "file".into(),
                    objectId: object.to_string(),
                }
                .abi_encode()
            };
            let raw = signer.sign_native_tx(ACP_ADDRESS, calldata.into()).unwrap();
            let updates = (count - 1 - object) / objects + 1;
            driver::Request {
                index,
                object_id: object.to_string(),
                expected_access,
                final_registered: Some(updates.is_multiple_of(2)),
                hash: NativeTx::decode_wire(&raw).unwrap().tx_id().0,
                owner: signer.did().to_string(),
                raw,
            }
        })
        .collect()
}

pub(super) async fn run(
    requests: Vec<driver::Request>,
    objects: usize,
    rate: usize,
    started: Instant,
    client: Arc<VeraClient>,
    reads: Arc<driver::ReadContext>,
) -> Vec<driver::Observation> {
    let mut groups: Vec<Vec<_>> = (0..objects).map(|_| Vec::new()).collect();
    for request in requests {
        groups[request.index % objects].push(request);
    }
    let permits = Arc::new(Semaphore::new(objects));
    let mut workers = JoinSet::new();
    for group in groups {
        let client = client.clone();
        let reads = reads.clone();
        let permits = permits.clone();
        workers.spawn(async move {
            let mut results = Vec::with_capacity(group.len());
            let mut blocked = false;
            for request in group {
                let scheduled = started
                    + std::time::Duration::from_secs_f64(request.index as f64 / rate as f64);
                tokio::time::sleep_until(scheduled).await;
                let permit = if blocked {
                    None
                } else {
                    Some(permits.clone().acquire_owned().await.unwrap())
                };
                let result =
                    driver::observe(client.clone(), request, scheduled, permit, reads.clone())
                        .await;
                blocked |= !result.completed();
                results.push(result);
            }
            results
        });
    }
    let mut results = Vec::new();
    while let Some(worker) = workers.join_next().await {
        results.extend(worker.expect("update worker failed"));
    }
    results
}

pub(super) async fn verify_state(
    client: &VeraClient,
    observations: &[driver::Observation],
    objects: usize,
    reads: &driver::ReadContext,
) {
    for observation in &observations[..objects] {
        let request = &observation.request;
        let relationship = acp::Relationship::with_entity(
            "file",
            &request.object_id,
            "owner",
            request.owner.parse().unwrap(),
        );
        let key = vera_modules::acp::keys::relationship_key(
            &reads.policy,
            &vera_modules::acp::keys::relationship_storage_key(&relationship, 0),
        );
        let response = client
            .read_current_record(
                vera_domain::ModuleId::Acp,
                &key,
                0,
                &reads.trusted,
                vera_permission::RECORD_PROOF_BYTES,
            )
            .await
            .unwrap();
        let record: vera_modules::acp::types::RelationshipRecord = serde_json::from_slice(
            response
                .record
                .value
                .as_ref()
                .expect("owner record missing"),
        )
        .unwrap();
        assert_eq!(record.policy_id, reads.policy);
        assert_eq!(record.relationship, relationship);
        assert_eq!(record.metadata.owner_did, request.owner);
        assert_eq!(record.archived, !request.final_registered.unwrap());
    }
}
