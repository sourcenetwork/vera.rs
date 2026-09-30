use super::*;
use std::{
    collections::BTreeMap,
    sync::{Mutex, RwLock, mpsc},
};

use vera_client::{
    AccessRequest, Actor, Object, Operation, PERMISSION_LIMITS, PermissionResponse, VeraClient,
};
use vera_indexer::{BlockIndex, IndexedBlock};
use vera_jsonrpc::{JsonRpcServer, NodeState};

pub(super) const POLICY: &str = "\
name: documents
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
      - name: blocked
        types: [actor]
    permissions:
      - name: read
        expr: reader - blocked
";

pub(super) fn signed(signer: &BlsSigner, call: impl SolCall) -> Tx {
    Tx::new(
        signer
            .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
            .unwrap()
            .into(),
    )
}

pub(super) async fn apply(set: &OrderedState, height: u64, tx: Tx) {
    let (sealed, outcome) = set
        .execute(set.new_batches().await, &block(height), &[tx])
        .await
        .unwrap();
    assert!(outcome.receipts[0].success());
    set.apply(sealed).await;
    assert!(set.finalize().await.durable().await);
}

pub(super) fn index_block(index: &BlockIndex, block: &vera_domain::Block) {
    index.insert_block(
        IndexedBlock {
            hash: block.id().0,
            number: block.height,
            parent_hash: block.parent.0,
            state_root: block.state_root.0,
            module_state_root: block.module_state_root,
            timestamp: block.timestamp,
            gas_limit: 30_000_000,
            gas_used: 0,
            base_fee_per_gas: None,
            prevrandao: block.prevrandao,
            transaction_hashes: vec![],
        },
        vec![],
        vec![],
    );
}

#[test]
fn synchronized_permission_rpc_verifies_native_evidence_and_subsequent_denial() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| {
            Box::pin(async move {
                ::tokio::time::timeout(Duration::from_secs(30), async {
                    let source = OrderedState::init(
                        context.child("source"),
                        config(&context, "source", VeraExecutor::new(DEPLOYMENT)),
                        None,
                    )
                    .await;
                    let owner = BlsSigner::new(1u64.into(), DEPLOYMENT).unwrap();
                    let actor = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
                    apply(
                        &source,
                        1,
                        signed(
                            &owner,
                            IAcp::createPolicyCall {
                                policy: POLICY.as_bytes().to_vec().into(),
                                marshalType: 1,
                            },
                        ),
                    )
                    .await;
                    let policy = source
                        .executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .remove(0);
                    apply(
                        &source,
                        2,
                        signed(
                            &owner,
                            IAcp::batchCallsCall {
                                calls: vec![
                                    IAcp::registerObjectCall {
                                        policyId: policy.parse().unwrap(),
                                        resource: "document".into(),
                                        objectId: "report".into(),
                                    }
                                    .abi_encode()
                                    .into(),
                                    IAcp::setRelationshipCall {
                                        policyId: policy.parse().unwrap(),
                                        resource: "document".into(),
                                        objectId: "report".into(),
                                        relation: "reader".into(),
                                        actor: actor.into(),
                                    }
                                    .abi_encode()
                                    .into(),
                                ],
                            },
                        ),
                    )
                    .await;
                    let block = checkpoint::block(&source, 2).await;
                    let db = &source.databases;
                    let proof = native::SyncProof::capture(
                        &(db.3.clone(), db.4.clone(), db.5.clone(), db.6.clone()),
                        block.module_state_root,
                    )
                    .await
                    .unwrap();
                    let (light, trusted) = checkpoint::certify(&block, 42);
                    let checkpoint = OrderedCheckpoint::verify(&light, &trusted, &proof).unwrap();
                    let (replica, reached) = OrderedState::sync_checkpoint(
                        context.child("replica"),
                        config(&context, "replica", VeraExecutor::new(DEPLOYMENT)),
                        sources(&source),
                        checkpoint.clone(),
                        SyncEngineConfig {
                            fetch_batch_size: NZU64!(64),
                            apply_batch_size: NZU64!(64),
                            max_outstanding_requests: 2,
                            update_channel_size: NZUsize!(2),
                            max_retained_roots: 2,
                        },
                    )
                    .await
                    .unwrap();
                    assert_eq!(reached, *checkpoint.anchor());

                    let history = Arc::new(RwLock::new(BTreeMap::from([(2, light.clone())])));
                    let lookup = history.clone();
                    let index = Arc::new(BlockIndex::new());
                    index_block(&index, &block);
                    type Gate = (::tokio::sync::oneshot::Sender<()>, mpsc::Receiver<()>);
                    let gate = Arc::new(Mutex::new(None::<Gate>));
                    let lookup_gate = gate.clone();
                    let db = &replica.databases;
                    let (server, address) =
                        JsonRpcServer::new("127.0.0.1:0".parse().unwrap(), DEPLOYMENT)
                            .with_node_state(Arc::new(NodeState::new(DEPLOYMENT, 0, 4)))
                            .with_vera_index_and_modules(
                                index.clone(),
                                replica.executor.modules().clone(),
                            )
                            .with_vera_native_modules(
                                (db.3.clone(), db.4.clone(), db.5.clone(), db.6.clone()),
                                replica.executor.modules().clone(),
                            )
                            .with_vera_light_block_lookup(Arc::new(move |height| {
                                if let Some((entered, release)) = lookup_gate.lock().unwrap().take()
                                {
                                    entered.send(()).unwrap();
                                    release
                                        .recv_timeout(Duration::from_secs(2))
                                        .map_err(|e| e.to_string())?;
                                }
                                lookup
                                    .read()
                                    .unwrap()
                                    .get(&height)
                                    .cloned()
                                    .ok_or_else(|| "revision unavailable".into())
                            }))
                            .start()
                            .await
                            .unwrap();
                    let client = VeraClient::new(format!("http://{address}"));
                    let request = AccessRequest {
                        actor: Actor(actor.parse().unwrap()),
                        operations: vec![Operation {
                            object: Object {
                                resource: "document".into(),
                                id: "report".into(),
                            },
                            permission: "read".into(),
                        }],
                    };
                    assert!(
                        client
                            .verify_access_at(
                                &policy,
                                &request,
                                &light,
                                &trusted,
                                PERMISSION_LIMITS
                            )
                            .await
                            .unwrap()
                    );
                    let mut other = request.clone();
                    other.operations[0].object.id = "ungranted".into();
                    assert!(
                        !client
                            .verify_access_at(&policy, &other, &light, &trusted, PERMISSION_LIMITS)
                            .await
                            .unwrap()
                    );
                    assert!(
                        !client
                            .verify_access_at(
                                "missing",
                                &request,
                                &light,
                                &trusted,
                                PERMISSION_LIMITS
                            )
                            .await
                            .unwrap()
                    );

                    let response: PermissionResponse = client
                        .rpc_call_typed(
                            "vera_getCurrentPermissionProof",
                            serde_json::json!([policy, request, 2]),
                        )
                        .await
                        .unwrap();
                    assert!(
                        response
                            .verify(&policy, &request, 2, &trusted, PERMISSION_LIMITS)
                            .unwrap()
                    );
                    assert!(
                        response
                            .verify(&policy, &request, 3, &trusted, PERMISSION_LIMITS)
                            .is_err()
                    );
                    assert!(
                        client
                            .verify_current_access(
                                &policy,
                                &request,
                                3,
                                &trusted,
                                PERMISSION_LIMITS
                            )
                            .await
                            .is_err()
                    );
                    let mut tampered = response.clone();
                    tampered.revision.height += 1;
                    assert!(
                        tampered
                            .verify(&policy, &request, 2, &trusted, PERMISSION_LIMITS)
                            .is_err()
                    );
                    let mut tampered = response.clone();
                    tampered.proof.roots.as_mut().unwrap()[0].0[0] ^= 1;
                    assert!(
                        tampered
                            .verify(&policy, &request, 2, &trusted, PERMISSION_LIMITS)
                            .is_err()
                    );
                    let mut limits = PERMISSION_LIMITS;
                    limits.proof_bytes = 1;
                    assert!(
                        response
                            .verify(&policy, &request, 2, &trusted, limits)
                            .is_err()
                    );

                    let (entered, captured) = ::tokio::sync::oneshot::channel();
                    let (release, held) = mpsc::channel();
                    *gate.lock().unwrap() = Some((entered, held));
                    let pending = {
                        let client = VeraClient::new(format!("http://{address}"));
                        let policy = policy.clone();
                        let request = request.clone();
                        ::tokio::spawn(async move {
                            client
                                .verify_current_access(
                                    &policy,
                                    &request,
                                    2,
                                    &trusted,
                                    PERMISSION_LIMITS,
                                )
                                .await
                                .unwrap()
                        })
                    };
                    ::tokio::time::timeout(Duration::from_secs(1), captured)
                        .await
                        .unwrap()
                        .unwrap();

                    ::tokio::time::timeout(
                        Duration::from_secs(1),
                        apply(
                            &replica,
                            3,
                            signed(
                                &owner,
                                IAcp::setRelationshipCall {
                                    policyId: policy.parse().unwrap(),
                                    resource: "document".into(),
                                    objectId: "report".into(),
                                    relation: "blocked".into(),
                                    actor: actor.into(),
                                },
                            ),
                        ),
                    )
                    .await
                    .expect("permission certificate lookup must release storage guards");
                    let next_block = checkpoint::block(&replica, 3).await;
                    index_block(&index, &next_block);
                    let (next, _) = checkpoint::certify(&next_block, 42);
                    history.write().unwrap().insert(3, next.clone());
                    release.send(()).unwrap();
                    let (captured_revision, allowed) = pending.await.unwrap();
                    assert_eq!(captured_revision.height, 2);
                    assert!(allowed);
                    let (revision, allowed) = client
                        .verify_current_access(&policy, &request, 3, &trusted, PERMISSION_LIMITS)
                        .await
                        .unwrap();
                    assert_eq!(revision.height, 3);
                    assert!(!allowed);
                    let mut mixed = response;
                    mixed.revision = revision;
                    assert!(
                        mixed
                            .verify(&policy, &request, 3, &trusted, PERMISSION_LIMITS)
                            .is_err()
                    );
                    assert!(
                        client
                            .verify_access_at(
                                &policy,
                                &request,
                                &light,
                                &trusted,
                                PERMISSION_LIMITS
                            )
                            .await
                            .is_err()
                    );
                    assert!(
                        !client
                            .verify_access_at(&policy, &request, &next, &trusted, PERMISSION_LIMITS)
                            .await
                            .unwrap()
                    );
                    let mut owner_request = request;
                    owner_request.actor = Actor(owner.did().parse().unwrap());
                    assert!(
                        client
                            .verify_access_at(
                                &policy,
                                &owner_request,
                                &next,
                                &trusted,
                                PERMISSION_LIMITS
                            )
                            .await
                            .unwrap()
                    );
                    server.stop().unwrap();
                    server.stopped().await;
                })
                .await
                .expect("permission synchronization and RPC deadline");
            })
        },
    );
}
