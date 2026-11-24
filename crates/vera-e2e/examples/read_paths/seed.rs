//! Seeds the policy, relationships, namespace and posts the reads query.

use super::*;

pub(super) struct Seeded {
    pub(super) policy: B256,
    pub(super) actor: String,
    pub(super) minimum: u64,
}

pub(super) async fn submit(
    client: &VeraClient,
    signer: &BlsSigner,
    to: alloy_primitives::Address,
    call: impl SolCall,
) -> u64 {
    let wire = signer.sign_native_tx(to, call.abi_encode().into()).unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    let receipt = client
        .wait_for_receipt(id, Duration::from_millis(20), 3_000)
        .await
        .unwrap();
    assert!(receipt.success, "seeding request failed");
    receipt.block_number
}

pub(super) async fn seed(client: &VeraClient) -> Seeded {
    let owner = BlsSigner::new(7u64.into(), CHAIN_ID).unwrap();
    submit(
        client,
        &owner,
        ACP_ADDRESS,
        IAcp::createPolicyCall {
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
            nonce: vera_client::random_policy_nonce().0.into(),
        },
    )
    .await;
    let policy: B256 = client.get_policy_ids().await.unwrap()[0].parse().unwrap();
    let actors: Vec<String> = (0..RELATIONSHIPS)
        .map(|index| {
            BlsSigner::new((1_000 + index as u64).into(), CHAIN_ID)
                .unwrap()
                .did()
                .to_owned()
        })
        .collect();
    let mut minimum = 0;
    for (batch, chunk) in actors.chunks(20).enumerate() {
        let mut calls = Vec::new();
        if batch == 0 {
            calls.push(
                IAcp::registerObjectCall {
                    policyId: policy,
                    resource: "document".into(),
                    objectId: "doc".into(),
                }
                .abi_encode()
                .into(),
            );
        }
        for actor in chunk {
            calls.push(
                IAcp::setRelationshipCall {
                    policyId: policy,
                    resource: "document".into(),
                    objectId: "doc".into(),
                    relation: "reader".into(),
                    actor: actor.clone(),
                }
                .abi_encode()
                .into(),
            );
        }
        minimum = submit(client, &owner, ACP_ADDRESS, IAcp::batchCallsCall { calls }).await;
    }
    submit(
        client,
        &owner,
        BULLETIN_ADDRESS,
        IBulletin::registerNamespaceCall {
            namespace: "team".into(),
        },
    )
    .await;
    for index in 0..POSTS {
        minimum = submit(
            client,
            &owner,
            BULLETIN_ADDRESS,
            IBulletin::createPostCall {
                namespace: NAMESPACE.into(),
                payload: format!("post {index} {}", "x".repeat(200))
                    .into_bytes()
                    .into(),
                proof: vec![1, 2, 3].into(),
                artifact: "bulletin/read-paths".into(),
            },
        )
        .await;
    }
    Seeded {
        policy,
        actor: actors[RELATIONSHIPS / 2].clone(),
        minimum,
    }
}
