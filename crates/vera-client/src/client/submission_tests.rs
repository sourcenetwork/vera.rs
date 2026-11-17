use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes};
use serde_json::json;
use vera_domain::NativeTx;

use super::stub::{Reply, Stub, submitted};
use super::*;
use crate::{BlsSigner, TransactionReceipt};

const POLL: Duration = Duration::from_millis(5);

fn target() -> Address {
    Address::repeat_byte(0x08)
}

fn receipt(tx_hash: B256) -> serde_json::Value {
    serde_json::to_value(TransactionReceipt {
        transaction_hash: tx_hash,
        status: 1,
        ..TransactionReceipt::default()
    })
    .unwrap()
}

#[tokio::test]
async fn sequence_advances_only_when_the_node_admits_the_request() {
    let signer = BlsSigner::random(7).unwrap();
    let stub = Stub::serve(vec![
        Reply::Error(json!({"code": -32000, "message": "rejected"})),
        Reply::Error(json!({"code": -32002, "message": "busy", "data": {"retryable": true}})),
        Reply::Disconnect,
        Reply::Result(json!(format!("{:?}", B256::repeat_byte(1)))),
        Reply::Admit,
        Reply::Admit,
    ]);
    let client = VeraClient::new(stub.url.clone());
    let submit = |calldata: &'static [u8]| {
        client.submit_native(&signer, target(), Bytes::from_static(calldata))
    };

    assert!(matches!(
        submit(b"first").await,
        Err(ClientError::Rpc { code: -32000, .. })
    ));
    assert!(matches!(
        submit(b"first").await,
        Err(ClientError::ResourceBusy(_))
    ));
    assert!(matches!(
        submit(b"first").await,
        Err(ClientError::SubmissionUnknown { sequence: 0, .. })
    ));
    assert!(matches!(
        submit(b"first").await,
        Err(ClientError::InvalidResponse(_))
    ));
    assert_eq!(signer.nonce(), 0);

    let first = submit(b"first").await.unwrap();
    assert_eq!(signer.nonce(), 1);
    let second = submit(b"second").await.unwrap();
    assert_eq!(signer.nonce(), 2);

    let requests = stub.requests();
    let sequences: Vec<u64> = requests.iter().map(|r| submitted(r).nonce).collect();
    assert_eq!(sequences, [0, 0, 0, 0, 0, 1]);
    assert_eq!(first, submitted(&requests[4]).tx_id().0);
    assert_eq!(second, submitted(&requests[5]).tx_id().0);
}

#[tokio::test]
async fn unsent_request_leaves_the_sequence_reusable() {
    let signer = BlsSigner::random(7).unwrap();
    let client = VeraClient::new("http://127.0.0.1:1")
        .with_max_concurrent_requests(std::num::NonZeroU32::new(1).unwrap());
    let _occupied = client.request_permit().await.unwrap();
    assert!(matches!(
        client
            .submit_native(&signer, target(), Bytes::from_static(b"call"))
            .await,
        Err(ClientError::ClientCapacityExhausted)
    ));
    assert_eq!(signer.nonce(), 0);
}

#[tokio::test]
async fn refused_connection_is_not_an_unknown_admission() {
    let signer = BlsSigner::random(7).unwrap();
    let client = VeraClient::new("http://127.0.0.1:1");
    assert!(matches!(
        client
            .submit_native(&signer, target(), Bytes::from_static(b"call"))
            .await,
        Err(ClientError::Transport(_))
    ));
    assert_eq!(signer.nonce(), 0);
}

#[tokio::test]
async fn lost_reply_names_the_submission_and_its_receipt_settles_the_sequence() {
    let signer = BlsSigner::random(7).unwrap();
    signer.set_next_sequence(4);
    let lost = signer
        .sign_native_tx_with_sequence(target(), Bytes::from_static(b"lost"), 4)
        .unwrap();
    let lost = NativeTx::decode_wire(&lost).unwrap().tx_id().0;
    let stub = Stub::serve(vec![
        Reply::Disconnect,
        Reply::Result(serde_json::Value::Null),
        Reply::Result(receipt(lost)),
        Reply::Admit,
    ]);
    let client = VeraClient::new(stub.url.clone());

    let outcome = client
        .submit_native(&signer, target(), Bytes::from_static(b"lost"))
        .await;
    let Err(ClientError::SubmissionUnknown {
        tx_hash,
        sequence,
        source,
    }) = outcome
    else {
        panic!("unexpected outcome: {outcome:?}");
    };
    assert_eq!((tx_hash, sequence), (lost, 4));
    assert!(matches!(*source, ClientError::Transport(_)));
    assert_eq!(signer.nonce(), 4);

    let settled = client
        .confirm_submission(&signer, tx_hash, sequence, POLL, 1_000)
        .await
        .unwrap();
    assert_eq!(settled.transaction_hash, lost);
    assert_eq!(signer.nonce(), 5);

    client
        .submit_native(&signer, target(), Bytes::from_static(b"next"))
        .await
        .unwrap();
    let requests = stub.requests();
    assert_eq!(submitted(&requests[0]).tx_id().0, lost);
    assert_eq!(submitted(&requests[3]).nonce, 5);
    assert_eq!(signer.nonce(), 6);
}

#[tokio::test]
async fn unsettled_submission_keeps_its_sequence_and_a_late_receipt_cannot_rewind() {
    let signer = BlsSigner::random(7).unwrap();
    let stub = Stub::serve(vec![
        Reply::Disconnect,
        Reply::Result(serde_json::Value::Null),
        Reply::Admit,
        Reply::Admit,
        Reply::Admit,
        Reply::Result(receipt(B256::repeat_byte(9))),
    ]);
    let client = VeraClient::new(stub.url.clone());
    let submit = |calldata: &'static [u8]| {
        client.submit_native(&signer, target(), Bytes::from_static(calldata))
    };

    let Err(ClientError::SubmissionUnknown {
        tx_hash, sequence, ..
    }) = submit(b"lost").await
    else {
        panic!("a lost reply must leave admission unknown");
    };
    assert!(matches!(
        client
            .confirm_submission(&signer, tx_hash, sequence, POLL, 1)
            .await,
        Err(ClientError::ReceiptTimeout { tx_hash: named, .. }) if named == tx_hash
    ));
    assert_eq!(signer.nonce(), 0);

    assert_eq!(submit(b"lost").await.unwrap(), tx_hash);
    submit(b"second").await.unwrap();
    submit(b"third").await.unwrap();
    assert_eq!(signer.nonce(), 3);

    client
        .confirm_submission(&signer, tx_hash, sequence, POLL, 1)
        .await
        .unwrap();
    assert_eq!(signer.nonce(), 3);
    stub.requests();
}

#[tokio::test]
async fn resynchronized_sequence_is_used_for_the_next_submission() {
    let signer = BlsSigner::random(7).unwrap();
    let stub = Stub::serve(vec![Reply::Admit]);
    let client = VeraClient::new(stub.url.clone());
    signer.set_next_sequence(9);
    client
        .submit_native(&signer, target(), Bytes::from_static(b"call"))
        .await
        .unwrap();
    assert_eq!(signer.nonce(), 10);
    assert_eq!(submitted(&stub.requests()[0]).nonce, 9);
}

#[tokio::test]
async fn receipt_polling_survives_a_dropped_connection() {
    let tx_hash = B256::repeat_byte(3);
    let stub = Stub::serve(vec![
        Reply::Result(serde_json::Value::Null),
        Reply::Disconnect,
        Reply::Result(receipt(tx_hash)),
    ]);
    let client = VeraClient::new(stub.url.clone());
    let found = client.wait_for_receipt(tx_hash, POLL, 1_000).await.unwrap();
    assert_eq!(found.transaction_hash, tx_hash);
    assert_eq!(stub.requests().len(), 3);
}

#[tokio::test]
async fn receipt_failures_name_the_submission() {
    let tx_hash = B256::repeat_byte(4);
    let stub = Stub::serve(vec![
        Reply::Result(serde_json::Value::Null),
        Reply::Error(json!({"code": -32603, "message": "internal"})),
    ]);
    let client = VeraClient::new(stub.url.clone());
    match client.wait_for_receipt(tx_hash, POLL, 1).await {
        Err(ClientError::ReceiptTimeout {
            tx_hash: named,
            attempts: 1,
        }) => assert_eq!(named, tx_hash),
        other => panic!("unexpected outcome: {other:?}"),
    }
    match client.wait_for_receipt(tx_hash, POLL, 1_000).await {
        Err(ClientError::ReceiptUnavailable {
            tx_hash: named,
            source,
        }) => {
            assert_eq!(named, tx_hash);
            assert!(matches!(*source, ClientError::Rpc { code: -32603, .. }));
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    stub.requests();
}

#[tokio::test]
async fn receipt_polling_stops_once_an_outage_outlasts_its_budget() {
    let tx_hash = B256::repeat_byte(5);
    let client = VeraClient::new("http://127.0.0.1:1");
    let outcome = client
        .wait_for_receipt(tx_hash, Duration::ZERO, 1_000)
        .await;
    assert!(matches!(
        outcome,
        Err(ClientError::ReceiptUnavailable { source, .. })
            if matches!(*source, ClientError::Transport(_))
    ));
}

#[tokio::test]
async fn a_refused_native_request_names_its_refusal_and_an_evm_revert_does_not() {
    let refusal = vera_domain::Refusal::new(
        vera_domain::RefusingModule::Acp,
        vera_domain::RefusalKind::InvalidPolicy,
        "invalid policy: unknown relation",
    );
    let failed = |refusal: Option<vera_domain::Refusal>| {
        serde_json::to_value(TransactionReceipt {
            transaction_hash: B256::repeat_byte(3),
            status: 0,
            gas_used: 5_000,
            refusal,
            ..TransactionReceipt::default()
        })
        .unwrap()
    };
    let stub = Stub::serve(vec![
        Reply::Result(failed(Some(refusal.clone()))),
        Reply::Result(failed(None)),
    ]);
    let client = VeraClient::new(stub.url.clone());
    match client.executed(B256::repeat_byte(3)).await {
        Err(ClientError::Refused {
            refusal: reported,
            receipt,
        }) => {
            assert_eq!(reported, refusal);
            assert_eq!(receipt.gas_used, 5_000);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(matches!(
        client.executed(B256::repeat_byte(3)).await,
        Err(ClientError::TxReverted { status: 0, .. })
    ));
}
