//! A solo deployment administered by an account key and a device key of other key types.

use std::{net::SocketAddr, time::Duration};

use alloy_sol_types::SolCall as _;
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use serde_json::json;
use vera_client::{
    BlsSigner, ReceiptResponse, VERA_ADDRESS,
    administration::{
        AdministrativeCommand, AdministrativeRequest, OperatorApproval, OperatorPolicy,
        SignedAdministrativeRequest, external_approval, external_der_approval,
    },
};
use vera_domain::LightBlock;
use vera_modules::vera::abi::IVera;
use vera_node::{EmbeddedConfig, EmbeddedNode, SoloGenesis};

async fn apply(
    node: &EmbeddedNode,
    submitter: &BlsSigner,
    signed: &SignedAdministrativeRequest,
) -> bool {
    let call = IVera::applyAdministrationCall {
        request: serde_json::to_vec(signed).unwrap().into(),
    };
    let wire = submitter
        .sign_native_tx(VERA_ADDRESS, call.abi_encode().into())
        .unwrap();
    let submission: alloy_primitives::B256 = node
        .rpc()
        .request(
            "vera_sendNativeTx",
            vec![json!(format!("0x{}", hex::encode(wire)))],
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let proof: Option<ReceiptResponse> = node
                .rpc()
                .request("vera_getReceiptProof", vec![json!(submission)])
                .await
                .unwrap();
            if let Some(proof) = proof {
                return proof
                    .verify(submission, node.consensus_key())
                    .unwrap()
                    .success();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("certified receipt deadline")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_account_key_and_a_device_key_together_administer_a_solo_node() {
    let account = p256::ecdsa::SigningKey::from_slice(&[11; 32]).unwrap();
    let device = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
    let mut keys = vec![
        vera_crypto::actor::p256_did(account.verifying_key().to_encoded_point(true).as_bytes())
            .unwrap(),
        vera_crypto::actor::ed25519_did(&device.verifying_key().to_bytes()).unwrap(),
    ];
    keys.sort();
    let account_index = keys
        .iter()
        .position(|key| key.starts_with("did:key:zDn"))
        .unwrap() as u16;
    let device_index = 1 - account_index;
    let policy = OperatorPolicy { threshold: 2, keys };

    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9407;
    let listen: SocketAddr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let genesis = SoloGenesis {
        policies: Vec::new(),
        chain_id,
        operators: policy.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let node = EmbeddedNode::start(EmbeddedConfig::new(directory.path(), genesis, listen))
        .await
        .unwrap();

    let first: LightBlock = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let block: Option<LightBlock> = node
                .rpc()
                .request("vera_getLightBlock", vec![json!("0x1")])
                .await
                .unwrap_or(None);
            match block {
                Some(block) => return block,
                None => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .expect("first finalized revision");
    vera_domain::verify_light_block(&first, node.consensus_key()).unwrap();
    let genesis_id = first
        .parent_hash
        .parse::<alloy_primitives::B256>()
        .unwrap()
        .0;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = |sequence| AdministrativeRequest {
        genesis_id,
        sequence,
        expires_at: now + 300,
        command: AdministrativeCommand::SetOperationBudget(32 << 20),
    };
    // The account key signs as a platform key store does: DER, over the digest.
    let account_approval = |request: &AdministrativeRequest| {
        let signature: p256::ecdsa::Signature = account
            .sign_prehash(&request.signing_digest().unwrap())
            .unwrap();
        external_der_approval(
            request,
            &policy,
            account_index,
            signature.to_der().as_bytes(),
        )
        .unwrap()
    };
    let device_approval = |request: &AdministrativeRequest| {
        let signature = device.sign(&request.signing_digest().unwrap()).to_bytes();
        external_approval(request, &policy, device_index, &signature).unwrap()
    };
    let ordered = |mut approvals: Vec<OperatorApproval>| {
        approvals.sort_by_key(|approval| approval.signer);
        approvals
    };
    let submitter = BlsSigner::new(5u64.into(), chain_id).unwrap();

    let alone = SignedAdministrativeRequest {
        approvals: vec![device_approval(&request(0))],
        request: request(0),
    };
    assert!(
        !apply(&node, &submitter, &alone).await,
        "one device alone must not change the deployment"
    );

    let together = SignedAdministrativeRequest {
        approvals: ordered(vec![
            account_approval(&request(0)),
            device_approval(&request(0)),
        ]),
        request: request(0),
    };
    assert!(apply(&node, &submitter, &together).await);
    assert!(
        !apply(&node, &submitter, &together).await,
        "an applied request must not replay"
    );

    // An approval made for one operator cannot be presented as another's.
    let signature = device
        .sign(&request(1).signing_digest().unwrap())
        .to_bytes();
    assert!(external_approval(&request(1), &policy, account_index, &signature).is_err());
    node.stop().await.unwrap();
}
