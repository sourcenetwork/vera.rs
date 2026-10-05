#[path = "decision_tests.rs"]
mod decisions;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use vera_crypto::{jwt::JwtClaims, operation::OperationClaim};

use super::*;
use crate::{
    acp::{
        delegated_operation::DelegatedOperation,
        types::{Object, PolicyCmd, PolicyMarshalingType},
    },
    kv_store::InMemoryKvStore,
    types::{BlockExecCtx, TxExecCtx},
    vera::VeraModule,
};

const POLICY: &str = "name: files\nresources:\n  - name: file\n";
const FORMAT: PolicyMarshalingType = PolicyMarshalingType::ShortYaml;

fn issuer() -> String {
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    vera_crypto::secp256k1::did_from_secp256k1_pubkey(key.verifying_key().to_sec1_bytes().as_ref())
        .unwrap()
}

fn id(entropy: u8, expiry: u64) -> OperationId {
    let mut bytes = [entropy; 32];
    bytes[..8].copy_from_slice(&expiry.to_be_bytes());
    OperationId(bytes)
}

fn submission(worker: u8) -> TxExecCtx {
    let key = SigningKey::from_slice(&[worker; 32]).unwrap();
    TxExecCtx {
        signer: vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            key.verifying_key().to_sec1_bytes().as_ref(),
        )
        .unwrap(),
        tx_hash: vec![worker; 32],
        sequence: 0,
    }
}

const fn context(now: u64) -> BlockExecCtx {
    BlockExecCtx {
        genesis_id: [7; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: now,
            block_height: now,
        },
    }
}

fn token(worker: &TxExecCtx, id: OperationId, operation: &DelegatedOperation<'_>) -> String {
    sign(&JwtClaims {
        iss: issuer(),
        sub: worker.signer.clone(),
        exp: id.expires_at(),
        aud: "vera:9001".into(),
        scope: operation.scope(),
        iat: 90,
        nbf: 90,
        relay: None,
        request: Some(OperationClaim {
            id,
            digest: operation.digest().unwrap(),
            genesis_id: [7; 32],
        }),
    })
}

fn sign(claims: &JwtClaims) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#);
    let input = format!(
        "{header}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    let signature: Signature = SigningKey::from_slice(&[42; 32])
        .unwrap()
        .sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[test]
fn workers_recover_the_original_outcome_after_edit_and_reopen() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let first = submission(7);
    let second = submission(8);
    let operation_id = id(1, 200);
    let create = DelegatedOperation::CreatePolicy(POLICY, &FORMAT);
    let first_token = token(&first, operation_id, &create);
    let created = acp
        .bearer_create_policy(
            &mut vera,
            &context(100),
            &first,
            &first_token,
            POLICY,
            FORMAT,
        )
        .unwrap();
    let original = acp.operation(&issuer(), operation_id).unwrap().unwrap();
    assert_eq!(original.submission, [7; 32]);
    assert_eq!(original.revision.seconds, 100);
    let edited = "name: changed\nresources:\n  - name: file\n";
    acp.edit_policy(
        &identity::Did::new(issuer()).unwrap(),
        &created.policy.id,
        edited,
        FORMAT,
    )
    .unwrap();
    let mut reopened =
        AcpModule::from_store(InMemoryKvStore::deserialize(&acp.store().serialize()).unwrap());
    let before = reopened.store().serialize();
    let retry_token = token(&second, operation_id, &create);
    let retry = reopened
        .bearer_create_policy(
            &mut vera,
            &context(101),
            &second,
            &retry_token,
            POLICY,
            FORMAT,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(retry).unwrap(),
        serde_json::to_value(&created).unwrap()
    );
    assert_eq!(reopened.store().serialize(), before);
    let mut alternate = vera_crypto::jwt::verify_bearer_token(&retry_token).unwrap();
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let mut raw_key = vec![0xe7, 0x01];
    raw_key.extend_from_slice(key.verifying_key().to_encoded_point(false).as_bytes());
    alternate.iss = format!("did:key:u{}", URL_SAFE_NO_PAD.encode(raw_key));
    assert_eq!(
        operation_key(&alternate.iss, operation_id).unwrap(),
        operation_key(&issuer(), operation_id).unwrap()
    );
    let alias_result = reopened
        .bearer_create_policy(
            &mut vera,
            &context(101),
            &second,
            &sign(&alternate),
            POLICY,
            FORMAT,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(alias_result).unwrap(),
        serde_json::to_value(&created).unwrap()
    );
    assert_eq!(reopened.store().serialize(), before);
    let conflict = token(
        &second,
        operation_id,
        &DelegatedOperation::CreatePolicy(edited, &FORMAT),
    );
    assert!(
        reopened
            .bearer_create_policy(&mut vera, &context(101), &second, &conflict, edited, FORMAT)
            .is_err()
    );
    assert_eq!(reopened.store().serialize(), before);
    vera.revoke_delegation(
        &context(101),
        &identity::Did::new(&second.signer).unwrap(),
        &retry_token,
    )
    .unwrap();
    assert!(
        reopened
            .bearer_create_policy(
                &mut vera,
                &context(101),
                &second,
                &retry_token,
                POLICY,
                FORMAT
            )
            .is_err()
    );
    assert_eq!(reopened.store().serialize(), before);

    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let command = PolicyCmd::RegisterObject(object.clone());
    let command_id = id(2, 200);
    let call = DelegatedOperation::PolicyCommand(&created.policy.id, &command);
    let a = token(&first, command_id, &call);
    let b = token(&second, command_id, &call);
    let result = reopened
        .bearer_policy_cmd(
            &mut vera,
            &context(102),
            &first,
            &a,
            &created.policy.id,
            command.clone(),
        )
        .unwrap();
    reopened
        .direct_policy_cmd(
            &identity::Did::new(issuer()).unwrap(),
            &created.policy.id,
            PolicyCmd::ArchiveObject(object),
        )
        .unwrap();
    let before = reopened.store().serialize();
    let replayed = reopened
        .bearer_policy_cmd(
            &mut vera,
            &context(103),
            &second,
            &b,
            &created.policy.id,
            command,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::to_value(replayed).unwrap()
    );
    assert_eq!(reopened.store().serialize(), before);
}

#[test]
fn request_binding_and_expiry_precede_effects_and_survive_pruning() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let worker = submission(7);
    let operation = DelegatedOperation::CreatePolicy(POLICY, &FORMAT);
    let identity = id(1, 200);
    let signed = token(&worker, identity, &operation);
    let valid = vera_crypto::jwt::verify_bearer_token(&signed).unwrap();
    for mutation in 0..5 {
        let mut claims = valid.clone();
        match mutation {
            0 => claims.request.as_mut().unwrap().digest = [0; 32],
            1 => claims.request.as_mut().unwrap().genesis_id = [0; 32],
            2 => claims.exp += 1,
            3 => claims.request.as_mut().unwrap().id = id(0, 200),
            4 => claims.request.as_mut().unwrap().id = id(1, 701),
            _ => unreachable!(),
        }
        let before = (acp.store().serialize(), vera.store().serialize());
        assert!(
            acp.bearer_create_policy(
                &mut vera,
                &context(100),
                &worker,
                &sign(&claims),
                POLICY,
                FORMAT
            )
            .is_err()
        );
        assert_eq!(before, (acp.store().serialize(), vera.store().serialize()));
        if mutation == 1 {
            assert!(
                vera.revoke_delegation(
                    &context(100),
                    &identity::Did::new(issuer()).unwrap(),
                    &sign(&claims)
                )
                .is_err()
            );
            assert_eq!(before, (acp.store().serialize(), vera.store().serialize()));
        }
    }
    acp.bearer_create_policy(&mut vera, &context(100), &worker, &signed, POLICY, FORMAT)
        .unwrap();
    assert!(
        acp.bearer_create_policy(&mut vera, &context(200), &worker, &signed, POLICY, FORMAT)
            .is_err()
    );
    acp.end_blocker(&context(200)).unwrap();
    assert!(acp.operation(&issuer(), identity).unwrap().is_none());
    assert_eq!(acp.operation_bytes().unwrap(), 0);
    let before = acp.store().serialize();
    assert!(
        acp.bearer_create_policy(&mut vera, &context(200), &worker, &signed, POLICY, FORMAT)
            .is_err()
    );
    assert_eq!(acp.store().serialize(), before);
}

#[test]
fn an_operation_identity_cannot_be_reused_for_different_arguments() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let worker = submission(7);
    let operation_id = id(1, 200);
    let original = token(
        &worker,
        operation_id,
        &DelegatedOperation::CreatePolicy(POLICY, &FORMAT),
    );
    let created = acp
        .bearer_create_policy(&mut vera, &context(100), &worker, &original, POLICY, FORMAT)
        .unwrap();
    let retained = acp.operation(&issuer(), operation_id).unwrap().unwrap();
    let conflicting = "name: other\nresources:\n  - name: file\n";
    let reused = token(
        &worker,
        operation_id,
        &DelegatedOperation::CreatePolicy(conflicting, &FORMAT),
    );
    let before = (acp.store().serialize(), vera.store().serialize());
    let error = acp
        .bearer_create_policy(
            &mut vera,
            &context(101),
            &worker,
            &reused,
            conflicting,
            FORMAT,
        )
        .unwrap_err();
    assert!(
        matches!(&error, AcpError::InvalidBearerToken { reason } if reason.contains("different arguments")),
        "{error}"
    );
    assert_eq!(before, (acp.store().serialize(), vera.store().serialize()));
    assert_eq!(
        serde_json::to_value(acp.operation(&issuer(), operation_id).unwrap().unwrap()).unwrap(),
        serde_json::to_value(&retained).unwrap()
    );
    assert_eq!(acp.query_policy_ids().unwrap(), vec![created.policy.id]);
}

#[test]
fn repeated_edit_returns_its_original_count_without_removing_new_relationships() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let owner = identity::Did::new(issuer()).unwrap();
    let original =
        "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n";
    let policy = acp
        .create_policy(&owner, original, FORMAT)
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "file".into(),
        id: "first".into(),
    };
    acp.direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    let relationship = acp::Relationship::with_entity("file", "first", "reader", owner.clone());
    acp.direct_policy_cmd(
        &owner,
        &policy,
        PolicyCmd::SetRelationship(relationship.clone()),
    )
    .unwrap();
    let replacement = POLICY;
    let first = submission(7);
    let second = submission(8);
    let operation_id = id(1, 200);
    let operation = DelegatedOperation::EditPolicy(&policy, replacement, &FORMAT);
    let a = token(&first, operation_id, &operation);
    let b = token(&second, operation_id, &operation);
    let result = acp
        .bearer_edit_policy(
            &mut vera,
            &context(100),
            &first,
            &a,
            &policy,
            replacement,
            FORMAT,
        )
        .unwrap();
    assert_eq!(result.0, 1);
    acp.edit_policy(&owner, &policy, original, FORMAT).unwrap();
    acp.direct_policy_cmd(&owner, &policy, PolicyCmd::SetRelationship(relationship))
        .unwrap();
    let before = acp.store().serialize();
    let replay = acp
        .bearer_edit_policy(
            &mut vera,
            &context(101),
            &second,
            &b,
            &policy,
            replacement,
            FORMAT,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::to_value(replay).unwrap()
    );
    assert_eq!(acp.store().serialize(), before);
    assert!(acp.query_object_owner(&policy, &object).unwrap().0);
}

#[test]
fn failed_or_over_budget_execution_does_not_reserve_an_operation() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let worker = submission(7);
    let operation_id = id(1, 200);
    for (policy, full) in [("invalid: [", false), (POLICY, true)] {
        if full {
            acp.store
                .put(BYTES_KEY, DEFAULT_OPERATION_BYTES.to_be_bytes().to_vec());
            let before = acp.store().serialize();
            assert!(
                acp.set_operation_budget(DEFAULT_OPERATION_BYTES - 1)
                    .is_err()
            );
            assert_eq!(acp.store().serialize(), before);
        }
        let signed = token(
            &worker,
            operation_id,
            &DelegatedOperation::CreatePolicy(policy, &FORMAT),
        );
        let before = (acp.store().serialize(), vera.store().serialize());
        assert!(
            acp.bearer_create_policy(&mut vera, &context(100), &worker, &signed, policy, FORMAT)
                .is_err()
        );
        assert_eq!(before, (acp.store().serialize(), vera.store().serialize()));
        assert!(acp.operation(&issuer(), operation_id).unwrap().is_none());
    }
}

#[test]
fn cleanup_is_bounded_and_record_limits_leave_storage_unchanged() {
    let mut acp = AcpModule::new();
    let actor = issuer();
    let mut record = OperationRecord {
        id: id(1, 200),
        digest: [1; 32],
        actor: actor.clone(),
        submission: [7; 32],
        worker: submission(7).signer,
        revision: context(100).timestamp,
        result: serde_json::json!({"ok":true}),
    };
    for entropy in 1..=OPERATION_PRUNE_LIMIT + 1 {
        record.id = id(u8::try_from(entropy).unwrap(), 200);
        acp.complete_operation(&actor, &record, None).unwrap();
    }
    let retained = acp.operation_bytes().unwrap();
    let key = operation_key(&actor, record.id).unwrap();
    let mut premature = expiry_key(record.id, &key);
    premature[EXPIRY_PREFIX.len()..EXPIRY_PREFIX.len() + 8].copy_from_slice(&100u64.to_be_bytes());
    acp.store.put(&premature, key);
    let before = acp.store().serialize();
    assert!(acp.prune_operations(100).is_err());
    assert_eq!(acp.store().serialize(), before);
    acp.store.delete(&premature);
    acp.prune_operations(199).unwrap();
    assert_eq!(acp.operation_bytes().unwrap(), retained);
    acp.prune_operations(200).unwrap();
    assert_eq!(acp.store.prefix_iter(EXPIRY_PREFIX).count(), 1);
    assert!(acp.operation_bytes().unwrap() > 0);
    acp.prune_operations(200).unwrap();
    assert_eq!(acp.operation_bytes().unwrap(), 0);
    let before = acp.store().serialize();
    record.result = serde_json::Value::String("x".repeat(MAX_OPERATION_RECORD_BYTES));
    assert!(acp.complete_operation(&actor, &record, None).is_err());
    assert_eq!(acp.store().serialize(), before);
}
