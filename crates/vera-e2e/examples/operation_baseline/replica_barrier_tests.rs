use super::*;
use alloy_primitives::{Bytes, FixedBytes};
use alloy_sol_types::SolCall;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee_server::{ServerBuilder, ServerHandle};
use std::sync::{Arc, Mutex};
use vera_client::TransactionReceipt;
use vera_modules::acp::abi::IAcp;

struct Replica {
    early: TransactionReceipt,
    final_receipt: TransactionReceipt,
    expected_hash: B256,
    available_after: Option<usize>,
    final_queries: usize,
    caught_up: bool,
}

fn anchors() -> (Anchor, Anchor) {
    (
        Anchor {
            transaction_hash: B256::repeat_byte(1),
            block_hash: B256::repeat_byte(2),
            height: 31,
            status: 1,
        },
        Anchor {
            transaction_hash: B256::repeat_byte(3),
            block_hash: B256::repeat_byte(4),
            height: 268,
            status: 1,
        },
    )
}

fn receipt(anchor: Anchor) -> TransactionReceipt {
    TransactionReceipt {
        transaction_hash: anchor.transaction_hash,
        block_hash: anchor.block_hash,
        block_number: anchor.height,
        status: anchor.status,
        ..Default::default()
    }
}

async fn replica(
    final_response: Anchor,
    available_after: Option<usize>,
) -> (VeraClient, Arc<Mutex<Replica>>, ServerHandle) {
    let (early, latest) = anchors();
    let state = Arc::new(Mutex::new(Replica {
        early: receipt(early),
        final_receipt: receipt(final_response),
        expected_hash: latest.transaction_hash,
        available_after,
        final_queries: 0,
        caught_up: false,
    }));
    let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let mut rpc = jsonrpsee::RpcModule::new(state.clone());
    rpc.register_method("eth_getTransactionReceipt", |params, state, _| {
        let (hash,): (B256,) = params.parse()?;
        let mut state = state.lock().unwrap();
        let response = if hash == state.early.transaction_hash {
            Some(state.early.clone())
        } else if hash == state.expected_hash {
            state.final_queries += 1;
            state.caught_up = state
                .available_after
                .is_some_and(|count| state.final_queries >= count);
            state.caught_up.then(|| state.final_receipt.clone())
        } else {
            None
        };
        Ok::<_, ErrorObjectOwned>(response)
    })
    .unwrap();
    rpc.register_method("eth_call", |_, state, _| {
        let registered = !state.lock().unwrap().caught_up;
        Ok::<_, ErrorObjectOwned>(format!(
            "0x{}",
            hex::encode(IAcp::getObjectOwnerCall::abi_encode_returns(
                &IAcp::getObjectOwnerReturn {
                    registered,
                    record: Bytes::new()
                }
            ))
        ))
    })
    .unwrap();
    let handle = server.start(rpc);
    (VeraClient::new(format!("http://{address}")), state, handle)
}

#[tokio::test]
async fn old_receipt_does_not_release_final_ownership_verification() {
    let (early, latest) = anchors();
    let (client, state, handle) = replica(latest, Some(2)).await;
    let (ready, ready_state, ready_handle) = replica(latest, Some(1)).await;
    let old = client
        .wait_for_receipt(early.transaction_hash, POLL_INTERVAL, 1)
        .await
        .unwrap();
    assert_eq!(old.block_number, early.height);
    assert!(
        client
            .get_object_owner(FixedBytes::ZERO, "file", "object")
            .await
            .unwrap()
            .0,
        "the old receipt is available while the final archive is unapplied"
    );
    let clients = [ready, client];
    let evidence = synchronize(&clients, [latest, early].into_iter())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evidence["height"], latest.height);
    assert_eq!(evidence["transaction_hash"], json!(latest.transaction_hash));
    assert_eq!(evidence["block_hash"], json!(latest.block_hash));
    assert_eq!(evidence["replicas"], 2);
    assert_eq!(ready_state.lock().unwrap().final_queries, 1);
    assert_eq!(state.lock().unwrap().final_queries, 2);
    for client in &clients {
        assert!(
            !client
                .get_object_owner(FixedBytes::ZERO, "file", "object")
                .await
                .unwrap()
                .0,
            "final ownership is checked after each replica applies the archive"
        );
    }
    for handle in [handle, ready_handle] {
        handle.stop().unwrap();
        handle.stopped().await;
    }
}

#[tokio::test]
async fn final_state_barrier_rejects_each_receipt_identity_mismatch() {
    let (_, latest) = anchors();
    for field in 0..4 {
        let mut invalid = latest;
        match field {
            0 => invalid.transaction_hash = B256::repeat_byte(5),
            1 => invalid.block_hash = B256::repeat_byte(6),
            2 => invalid.height -= 1,
            3 => invalid.status = 0,
            _ => unreachable!(),
        }
        let (client, _, handle) = replica(invalid, Some(1)).await;
        let error = synchronize(&[client], [latest].into_iter())
            .await
            .unwrap_err();
        assert!(error.contains("replica 0"), "{error}");
        assert!(error.contains("receipt differs"), "{error}");
        assert!(error.contains("height: 268"), "{error}");
        handle.stop().unwrap();
        handle.stopped().await;
    }
}

#[tokio::test]
async fn missing_final_receipt_cannot_pass_the_bounded_barrier() {
    let (early, latest) = anchors();
    let (client, _, handle) = replica(latest, None).await;
    assert!(
        client
            .get_transaction_receipt(early.transaction_hash)
            .await
            .unwrap()
            .is_some()
    );
    let error = wait_for_replica(&client, 2, latest, Duration::from_millis(50))
        .await
        .unwrap_err();
    assert!(error.contains("replica 2"), "{error}");
    assert!(error.contains("timed out"), "{error}");
    assert!(error.contains("height: 268"), "{error}");
    handle.stop().unwrap();
    handle.stopped().await;
}
