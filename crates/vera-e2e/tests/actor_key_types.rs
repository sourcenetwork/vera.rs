//! Ed25519 and P-256 actors own policies and objects through native workers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_sol_types::SolCall;
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::Signer as _;
use vera_client::{
    ACP_ADDRESS, BlsSigner, ClientError, RECORD_PROOF_BYTES, UnsignedToken, VeraClient,
};
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use vera_domain::ConsensusPublicKey;
use vera_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use vera_modules::acp::{
    abi::IAcp,
    delegated_operation::DelegatedOperation,
    types::{Object, PolicyCmd},
};

enum Actor {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl Actor {
    fn did(&self) -> String {
        match self {
            Self::Ed25519(key) => vera_crypto::actor::ed25519_did(&key.verifying_key().to_bytes()),
            Self::P256(key) => {
                vera_crypto::actor::p256_did(key.verifying_key().to_encoded_point(true).as_bytes())
            }
        }
        .unwrap()
    }

    /// Sign as an external key store would: P-256 returns DER with either `s`.
    fn sign(&self, unsigned: UnsignedToken) -> String {
        match self {
            Self::Ed25519(key) => {
                let signature = key.sign(unsigned.signing_input()).to_bytes();
                unsigned.finish(&signature)
            }
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(unsigned.signing_input());
                unsigned.finish_der(signature.to_der().as_bytes())
            }
        }
        .unwrap()
    }
}

async fn submit(
    client: &VeraClient,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: impl SolCall,
    success: bool,
) -> u64 {
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(response) = client.read_receipt(id, trusted).await.unwrap() {
                assert_eq!(response.verify(id, trusted).unwrap().success(), success);
                return response.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn ed25519_and_p256_actors_own_policies_and_objects() {
    let deployment = 9089;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let replica = VeraClient::new(cluster.node(1).rpc_url());
    let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
    let genesis = client
        .read_finalized_revision(1, &trusted)
        .await
        .unwrap()
        .parent_hash
        .parse::<alloy_primitives::B256>()
        .unwrap()
        .0;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let actors = [
        Actor::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[42; 32])),
        Actor::P256(p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap()),
    ];
    for (index, actor) in actors.iter().enumerate() {
        let did = actor.did();
        let delegation = UnsignedToken::delegation(
            &did,
            worker.did(),
            deployment,
            now,
            now + 120,
            DelegationScope::CreatePolicy,
        )
        .unwrap();
        let policy_source = format!("name: actor_{index}\nresources:\n  - name: file\n");
        let create = |token: String| IAcp::bearerCreatePolicyCall {
            bearerToken: token,
            policy: policy_source.clone().into_bytes().into(),
            marshalType: 1,
        };

        let mut wrong_algorithm = actor.sign(delegation.clone());
        wrong_algorithm.replace_range(
            ..wrong_algorithm.find('.').unwrap(),
            "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJ2ZXJhLWRlbGVnYXRpb24tdjErand0In0",
        );
        submit(&client, &worker, &trusted, create(wrong_algorithm), false).await;

        let created = submit(
            &client,
            &worker,
            &trusted,
            create(actor.sign(delegation)),
            true,
        )
        .await;
        let policy = client
            .read_policy_page(None, 2, created, &trusted)
            .await
            .unwrap()
            .records
            .into_iter()
            .find(|record| record.metadata.owner_did == did)
            .expect("the actor owns its policy");
        assert_eq!(policy.metadata.tx_signer, worker.did());

        let object = Object {
            resource: "file".into(),
            id: "report".into(),
        };
        let command = PolicyCmd::RegisterObject(object.clone());
        let mut id = [index as u8 + 1; 32];
        id[..8].copy_from_slice(&(now + 120).to_be_bytes());
        let claims = JwtClaims {
            iss: did.clone(),
            sub: worker.did().into(),
            exp: now + 120,
            aud: format!("vera:{deployment}"),
            scope: DelegationScope::PolicyCommands,
            iat: now,
            nbf: now,
            relay: None,
            request: Some(OperationClaim {
                id: OperationId(id),
                digest: DelegatedOperation::PolicyCommand(&policy.policy.id, &command)
                    .digest()
                    .unwrap(),
                genesis_id: genesis,
            }),
        };
        let registered = submit(
            &client,
            &worker,
            &trusted,
            IAcp::bearerPolicyCmdCall {
                policyId: policy.policy.id.parse().unwrap(),
                bearerToken: actor.sign(UnsignedToken::operation(&claims).unwrap()),
                cmd: serde_json::to_vec(&command).unwrap().into(),
            },
            true,
        )
        .await;

        let prefix = vera_client::object_owner_prefix(&policy.policy.id, &object).unwrap();
        let owner = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match replica
                    .read_current_policy_prefix(
                        &policy.policy.id,
                        &prefix,
                        registered,
                        &trusted,
                        RECORD_PROOF_BYTES,
                    )
                    .await
                {
                    Ok(owner) => return owner,
                    Err(error)
                        if error.is_throttled()
                            || matches!(error, ClientError::Rpc { code: -32002, .. }) =>
                    {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(error) => panic!("verified owner read failed: {error}"),
                }
            }
        })
        .await
        .expect("the replica reaches the registration revision");
        assert_eq!(
            owner
                .verify_object_owner(&policy.policy.id, &object, registered, &trusted)
                .unwrap()
                .unwrap()
                .0
                .as_str(),
            did
        );
    }
}
