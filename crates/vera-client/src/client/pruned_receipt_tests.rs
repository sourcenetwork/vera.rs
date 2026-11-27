//! Receipt polling against a node that pruned the revisions a receipt may be in.

use std::time::Duration;

use alloy_primitives::B256;
use serde_json::json;

use super::stub::{Reply, Stub};
use super::*;

const POLL: Duration = Duration::from_millis(5);

fn pruned() -> Reply {
    Reply::Error(json!({
        "code": 4444,
        "message": "history pruned: revision 10 is below the retained floor 48",
        "data": {"retryable": false, "floor": 48},
    }))
}

#[tokio::test]
async fn polling_after_a_known_revision_stops_at_the_first_pruned_answer() {
    let tx_hash = B256::repeat_byte(6);
    let stub = Stub::serve(vec![Reply::Result(serde_json::Value::Null), pruned()]);
    let client = VeraClient::new(stub.url.clone());
    let outcome = client.wait_for_receipt_after(tx_hash, 9, POLL, 1_000).await;
    assert!(
        matches!(
            outcome,
            Err(ClientError::ReceiptPruned { tx_hash: named, floor: 48 }) if named == tx_hash
        ),
        "{outcome:?}"
    );
    let requests = stub.requests();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request["method"], "vera_getTransactionReceipt");
        assert_eq!(request["params"], json!([format!("{tx_hash:?}"), "0x9"]));
    }
}

#[tokio::test]
async fn polling_without_a_known_revision_sends_none_and_runs_out_its_attempts() {
    let tx_hash = B256::repeat_byte(7);
    let stub = Stub::serve(vec![
        Reply::Result(serde_json::Value::Null),
        Reply::Result(serde_json::Value::Null),
    ]);
    let client = VeraClient::new(stub.url.clone());
    assert!(matches!(
        client.wait_for_receipt(tx_hash, POLL, 2).await,
        Err(ClientError::ReceiptTimeout { attempts: 2, .. })
    ));
    for request in stub.requests() {
        assert_eq!(request["params"], json!([format!("{tx_hash:?}")]));
    }
}

#[tokio::test]
async fn a_pruned_read_names_the_floor() {
    let tx_hash = B256::repeat_byte(8);
    let stub = Stub::serve(vec![pruned()]);
    let client = VeraClient::new(stub.url.clone());
    assert!(matches!(
        client.get_transaction_receipt_after(tx_hash, 9).await,
        Err(ClientError::HistoryPruned { floor: 48, .. })
    ));
    stub.requests();
}
