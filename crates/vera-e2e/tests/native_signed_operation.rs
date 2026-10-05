//! Direct actor signatures bind native commands and preserve identity across workers.

use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vera_client::{ACP_ADDRESS, BlsSigner, RECORD_PROOF_BYTES, VeraClient};
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
    receipt(client, trusted, id, success).await
}

async fn receipt(
    client: &VeraClient,
    trusted: &ConsensusPublicKey,
    id: alloy_primitives::B256,
    success: bool,
) -> u64 {
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
async fn actor_signed_command_rejects_substitution_and_deduplicates_across_workers() {
    let deployment = 9085;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let mut cluster = TestCluster::builder()
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
    let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
    let other = BlsSigner::new(8u64.into(), deployment).unwrap();
    let key = SigningKey::from_bytes((&[42u8; 32]).into()).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = vera_client::create_scoped_bearer_token(
        &key,
        worker.did(),
        deployment,
        now,
        now + 120,
        DelegationScope::CreatePolicy,
    )
    .unwrap();
    let created = submit(
        &client,
        &worker,
        &trusted,
        IAcp::bearerCreatePolicyCall {
            bearerToken: token.clone(),
            policy: b"name: signed_operation\nresources:\n  - name: file\n"
                .to_vec()
                .into(),
            marshalType: 1,
        },
        true,
    )
    .await;
    let policy = client
        .read_policy_page(None, 1, created, &trusted)
        .await
        .unwrap()
        .records
        .remove(0);
    let actor = vera_crypto::jwt::verify_bearer_token(&token).unwrap().iss;
    let genesis = client
        .read_finalized_revision(1, &trusted)
        .await
        .unwrap()
        .parent_hash
        .parse::<alloy_primitives::B256>()
        .unwrap()
        .0;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let command = PolicyCmd::RegisterObject(object.clone());
    let digest = DelegatedOperation::PolicyCommand(&policy.policy.id, &command)
        .digest()
        .unwrap();
    let mut id = [1; 32];
    id[..8].copy_from_slice(&(now + 120).to_be_bytes());
    let mut claims = JwtClaims {
        iss: actor.clone(),
        sub: worker.did().into(),
        exp: now + 120,
        aud: format!("vera:{deployment}"),
        scope: DelegationScope::PolicyCommands,
        iat: now,
        nbf: now,
        relay: None,
        request: Some(OperationClaim {
            id: OperationId(id),
            digest,
            genesis_id: genesis,
        }),
    };
    let signed = vera_client::create_operation_token(&key, &claims).unwrap();
    let call = |token: String, command: &PolicyCmd| IAcp::bearerPolicyCmdCall {
        policyId: policy.policy.id.parse().unwrap(),
        bearerToken: token,
        cmd: serde_json::to_vec(command).unwrap().into(),
    };
    let substituted = PolicyCmd::RegisterObject(Object {
        resource: "file".into(),
        id: "other".into(),
    });
    submit(
        &client,
        &worker,
        &trusted,
        call(signed.clone(), &substituted),
        false,
    )
    .await;
    submit(
        &client,
        &other,
        &trusted,
        call(signed.clone(), &command),
        false,
    )
    .await;
    let registered = submit(
        &client,
        &worker,
        &trusted,
        call(signed.clone(), &command),
        true,
    )
    .await;
    claims.sub = other.did().into();
    let retry = vera_client::create_operation_token(&key, &claims).unwrap();
    let retried = submit(&client, &other, &trusted, call(retry, &command), true).await;
    let prefix = vera_client::object_owner_prefix(&policy.policy.id, &object).unwrap();
    let owner = client
        .read_current_policy_prefix(
            &policy.policy.id,
            &prefix,
            retried,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert_eq!(
        owner
            .verify_object_owner(&policy.policy.id, &object, retried, &trusted)
            .unwrap()
            .unwrap()
            .0
            .as_str(),
        actor
    );
    let records = owner
        .verify(
            &policy.policy.id,
            &prefix,
            retried,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .unwrap();
    let records = records.expect("policy remains live");
    assert_eq!(records.entries.len(), 1);
    let record: vera_modules::acp::types::RelationshipRecord =
        serde_json::from_slice(&records.entries[0].value).unwrap();
    assert_eq!(record.metadata.creation_ts.block_height, registered);
    assert_eq!(record.metadata.tx_signer, worker.did());
    let hash = vera_modules::vera::keys::hash_jws_token(&signed)
        .parse()
        .unwrap();
    let active = client
        .read_token_record(hash, retried, &trusted)
        .await
        .unwrap()
        .value
        .unwrap();
    assert_eq!(
        active.status,
        vera_modules::vera::types::JWSTokenStatus::Valid
    );
    assert_eq!(active.authorized_account, worker.did());
    assert_eq!(active.issuer_did, actor);
    assert!(
        client
            .read_token_record(alloy_primitives::B256::ZERO, retried, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let invalidated = client
        .native_invalidate_jws(&worker, &hex::encode(hash))
        .await
        .unwrap();
    let invalidated_height = receipt(&client, &trusted, invalidated.transaction_hash, true).await;
    let revoked = client
        .read_token_record(hash, invalidated_height, &trusted)
        .await
        .unwrap()
        .value
        .unwrap();
    assert_eq!(
        revoked.status,
        vera_modules::vera::types::JWSTokenStatus::Invalid
    );
    assert_eq!(revoked.invalidated_by, worker.did());
    assert_eq!(
        revoked.invalidated_at.unwrap().block_height,
        invalidated_height
    );
    submit(&client, &worker, &trusted, call(signed, &command), false).await;
    let unused_object = Object {
        resource: "file".into(),
        id: "unused".into(),
    };
    let unused_command = PolicyCmd::RegisterObject(unused_object.clone());
    claims.sub = worker.did().into();
    let request = claims.request.as_mut().unwrap();
    request.id.0[8..].fill(2);
    request.digest = DelegatedOperation::PolicyCommand(&policy.policy.id, &unused_command)
        .digest()
        .unwrap();
    let unused = vera_client::create_operation_token(&key, &claims).unwrap();
    let unused_hash = vera_modules::vera::keys::hash_jws_token(&unused)
        .parse()
        .unwrap();
    assert!(matches!(
        client
            .native_revoke_delegation(&other, &unused)
            .await
            .unwrap_err(),
        vera_client::ClientError::TxReverted { .. }
    ));
    assert!(
        client
            .read_token_record(unused_hash, invalidated_height, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let revoked = client
        .native_revoke_delegation(&worker, &unused)
        .await
        .unwrap();
    let revoked_height = receipt(&client, &trusted, revoked.transaction_hash, true).await;
    cluster.restart_node(0).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let record = client
        .read_token_record(unused_hash, revoked_height, &trusted)
        .await
        .unwrap()
        .value
        .unwrap();
    assert_eq!(
        record.status,
        vera_modules::vera::types::JWSTokenStatus::Invalid
    );
    assert!(record.first_used_at.is_none());
    assert!(record.last_used_at.is_none());
    assert_eq!(record.invalidated_at.unwrap().block_height, revoked_height);
    assert_eq!(record.invalidated_by, worker.did());
    let rejected = submit(
        &client,
        &worker,
        &trusted,
        call(unused, &unused_command),
        false,
    )
    .await;
    let prefix = vera_client::object_owner_prefix(&policy.policy.id, &unused_object).unwrap();
    let absent = client
        .read_current_policy_prefix(
            &policy.policy.id,
            &prefix,
            rejected,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert!(
        absent
            .verify_object_owner(&policy.policy.id, &unused_object, rejected, &trusted)
            .unwrap()
            .is_none()
    );
}
