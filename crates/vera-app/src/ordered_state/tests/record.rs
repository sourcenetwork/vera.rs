use super::permission::{POLICY, apply, index_block, signed};
use super::*;
use std::{
    collections::BTreeMap,
    sync::{Mutex, RwLock, mpsc},
};
use vera_client::{ModuleId, RECORD_PROOF_BYTES, VeraClient};
use vera_indexer::BlockIndex;
use vera_jsonrpc::{JsonRpcServer, NodeState};

#[test]
fn native_record_rpc_keeps_the_captured_revision_across_finalization() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| {
            Box::pin(async move {
                ::tokio::time::timeout(Duration::from_secs(20), async {
                    let set = OrderedState::init(
                        context.child("records"),
                        config(&context, "records", VeraExecutor::new(DEPLOYMENT)),
                        None,
                    )
                    .await;
                    let owner = BlsSigner::new(1u64.into(), DEPLOYMENT).unwrap();
                    apply(
                        &set,
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
                    let policy = set
                        .executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .remove(0);
                    let key = vera_modules::acp::keys::policy_key(&policy);
                    let first = checkpoint::block(&set, 1).await;
                    let (light, trusted) = checkpoint::certify(&first, 42);
                    let history = Arc::new(RwLock::new(BTreeMap::from([(1, light)])));
                    let lookup = history.clone();
                    let index = Arc::new(BlockIndex::new());
                    index_block(&index, &first);
                    type Gate = (::tokio::sync::oneshot::Sender<()>, mpsc::Receiver<()>);
                    let gate = Arc::new(Mutex::new(None::<Gate>));
                    let lookup_gate = gate.clone();
                    let db = &set.databases;
                    let (server, address) =
                        JsonRpcServer::new("127.0.0.1:0".parse().unwrap(), DEPLOYMENT)
                            .with_node_state(Arc::new(NodeState::new(DEPLOYMENT, 0, 4)))
                            .with_vera_index_and_modules(
                                index.clone(),
                                set.executor.modules().clone(),
                            )
                            .with_vera_native_modules(
                                (db.3.clone(), db.4.clone(), db.5.clone(), db.6.clone()),
                                set.executor.modules().clone(),
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
                    let record = client
                        .read_current_record(ModuleId::Acp, &key, 1, &trusted, RECORD_PROOF_BYTES)
                        .await
                        .unwrap();
                    assert!(record.record.value.is_some());
                    assert_eq!(record.revision.height, 1);
                    let missing = client
                        .read_current_record(
                            ModuleId::Acp,
                            b"missing",
                            1,
                            &trusted,
                            RECORD_PROOF_BYTES,
                        )
                        .await
                        .unwrap();
                    assert!(missing.record.value.is_none());
                    assert!(
                        client
                            .read_current_record(
                                ModuleId::Acp,
                                &key,
                                2,
                                &trusted,
                                RECORD_PROOF_BYTES
                            )
                            .await
                            .is_err()
                    );
                    assert!(
                        record
                            .verify(ModuleId::Acp, &key, 2, &trusted, RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    assert!(record.verify(ModuleId::Acp, &key, 1, &trusted, 1).is_err());
                    let (_, untrusted) = checkpoint::certify(&first, 43);
                    assert!(
                        record
                            .verify(ModuleId::Acp, &key, 1, &untrusted, RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    let mut changed = record.clone();
                    changed.revision.height += 1;
                    assert!(
                        changed
                            .verify(ModuleId::Acp, &key, 1, &trusted, RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    let (entered, captured) = ::tokio::sync::oneshot::channel();
                    let (release, held) = mpsc::channel();
                    *gate.lock().unwrap() = Some((entered, held));
                    let pending = {
                        let client = VeraClient::new(format!("http://{address}"));
                        let key = key.clone();
                        ::tokio::spawn(async move {
                            client
                                .read_current_record(
                                    ModuleId::Acp,
                                    &key,
                                    1,
                                    &trusted,
                                    RECORD_PROOF_BYTES,
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
                            &set,
                            2,
                            signed(
                                &owner,
                                IAcp::registerObjectCall {
                                    policyId: policy.parse().unwrap(),
                                    resource: "document".into(),
                                    objectId: "report".into(),
                                },
                            ),
                        ),
                    )
                    .await
                    .expect("record certificate lookup must release storage guards");
                    let second = checkpoint::block(&set, 2).await;
                    index_block(&index, &second);
                    let (next, _) = checkpoint::certify(&second, 42);
                    history.write().unwrap().insert(2, next.clone());
                    release.send(()).unwrap();
                    let captured = pending.await.unwrap();
                    assert_eq!(captured.revision.height, 1);
                    captured
                        .verify(ModuleId::Acp, &key, 1, &trusted, RECORD_PROOF_BYTES)
                        .unwrap();
                    let mut mixed = captured;
                    mixed.revision = next;
                    assert!(
                        mixed
                            .verify(ModuleId::Acp, &key, 2, &trusted, RECORD_PROOF_BYTES)
                            .is_err()
                    );
                    let current = client
                        .read_current_record(ModuleId::Acp, &key, 2, &trusted, RECORD_PROOF_BYTES)
                        .await
                        .unwrap();
                    assert_eq!(current.revision.height, 2);
                    server.stop().unwrap();
                })
                .await
                .unwrap();
            })
        },
    );
}
