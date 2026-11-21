use alloy_primitives::{Address, Bytes};
use vera_client::{BlsSigner, TransactionReceipt, VeraClient};
use vera_e2e::cluster::TestCluster;

/// Sign a native request, submit it to every node and wait for its receipt.
///
/// Each node gossips admitted requests to all validators, so one submission
/// reaches every validator; submitting to every node keeps the test robust
/// against a node that is briefly unavailable.
pub(super) async fn native(
    cluster: &TestCluster,
    client: &VeraClient,
    signer: &BlsSigner,
    target: Address,
    calldata: Vec<u8>,
) -> TransactionReceipt {
    let wire = signer
        .sign_native_tx(target, Bytes::from(calldata))
        .expect("BLS signing should succeed");
    let submissions: Vec<_> = (0..cluster.node_count())
        .map(|index| {
            let wire = wire.clone();
            let url = cluster.node(index).rpc_url();
            tokio::spawn(async move { VeraClient::new(url).send_native_tx(&wire).await })
        })
        .collect();
    let mut submission = None;
    for handle in submissions {
        if let Ok(Ok(hash)) = handle.await {
            submission = Some(hash);
        }
    }
    let submission = submission.expect("at least one node should admit the native request");
    super::native_receipt::wait(client, submission).await
}
