//! A refused native request says why in its receipt, its receipt proof and the client error.

use std::time::Duration;

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use vera_client::{BlsSigner, ClientError, VeraClient};
use vera_domain::{ConsensusPublicKey, NativeTx, Refusal, RefusalKind, RefusingModule};
use vera_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use vera_modules::validator_registry::abi::IValidatorRegistry;

const SEED: u64 = 9131;
const CHAIN: u64 = 9001;
const NATIVE_LIMIT: u64 = 1_000_000;

async fn verified_refusal(
    client: &VeraClient,
    trusted: &ConsensusPublicKey,
    submission: B256,
) -> Refusal {
    for _ in 0..200 {
        if let Some(proof) = client.read_receipt(submission, trusted).await.unwrap() {
            let receipt = proof.verify(submission, trusted).unwrap();
            assert!(!receipt.success());
            assert!(receipt.gas_used < NATIVE_LIMIT, "{receipt:?}");
            return receipt
                .refusal
                .clone()
                .expect("the proof names the refusal");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no receipt proof for {submission}");
}

async fn check(
    client: &VeraClient,
    trusted: &ConsensusPublicKey,
    result: Result<vera_client::TransactionReceipt, ClientError>,
    module: RefusingModule,
    kind: RefusalKind,
    message: &str,
) {
    let (refusal, receipt) = match result {
        Err(ClientError::Refused {
            refusal,
            receipt: Some(receipt),
        }) => (refusal, receipt),
        other => panic!("expected a refusal by {module:?}, got {other:?}"),
    };
    assert_eq!((refusal.module, refusal.kind), (module, kind), "{refusal}");
    assert!(refusal.message().contains(message), "{refusal}");
    assert!(receipt.gas_used < NATIVE_LIMIT);

    let proven = verified_refusal(client, trusted, receipt.transaction_hash).await;
    assert_eq!(proven, refusal);
    let native = client
        .get_transaction_receipt(receipt.transaction_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(native.refusal, Some(refusal));
    assert_eq!(native.gas_used, receipt.gas_used);
}

#[tokio::test]
async fn each_module_names_its_refusal_through_the_receipt_proof() {
    let trusted = *KeySet::builder()
        .seed(SEED)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(SEED)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let signer = BlsSigner::new(77u64.into(), CHAIN).unwrap();

    // The current parser accepts a permission with no expression; an
    // expression naming a relation the resource lacks is the nearest refusal.
    let accepted = client
        .native_create_policy(
            &signer,
            br#"{"name":"registrations","resources":[{"name":"file","permissions":[{"name":"read"}]}]}"#,
            2, Default::default(),
        )
        .await
        .unwrap();
    assert!(accepted.success);
    assert_eq!(accepted.refusal, None);
    check(
        &client,
        &trusted,
        client
            .native_create_policy(
                &signer,
                br#"{"name":"registrations","resources":[{"name":"file","permissions":[{"name":"read","expr":"reader"}]}]}"#,
                2, Default::default(),
            )
            .await,
        RefusingModule::Acp,
        RefusalKind::InvalidPolicy,
        "invalid policy",
    )
    .await;
    check(
        &client,
        &trusted,
        client.native_register_namespace(&signer, "").await,
        RefusingModule::Bulletin,
        RefusalKind::InvalidArgument,
        "namespace must be nonempty",
    )
    .await;
    check(
        &client,
        &trusted,
        client.native_invalidate_jws(&signer, "missing").await,
        RefusingModule::Vera,
        RefusalKind::NotFound,
        "JWS token not found: missing",
    )
    .await;

    let wire = signer
        .sign_native_tx(
            vera_client::VALIDATOR_REGISTRY_ADDRESS,
            IValidatorRegistry::setPolicyCall {
                policyId: B256::repeat_byte(1),
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let submission = NativeTx::decode_wire(&wire).unwrap().tx_id().0;
    assert_eq!(client.send_native_tx(&wire).await.unwrap(), submission);
    let receipt = client
        .wait_for_receipt(submission, Duration::from_millis(100), 300)
        .await
        .unwrap();
    assert!(!receipt.success);
    let refusal = receipt.refusal.clone().unwrap();
    assert_eq!(
        (refusal.module, refusal.kind),
        (RefusingModule::ValidatorRegistry, RefusalKind::Unauthorized)
    );
    assert_eq!(
        verified_refusal(&client, &trusted, submission).await,
        refusal
    );
}
