//! Relay authority, actor attribution and revocation across serialized state.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{
    Signature, SigningKey,
    signature::{Signer as _, hazmat::PrehashSigner as _},
};
use vera_crypto::jwt::{DelegationScope, JwtClaims, RelayAssertion};
use vera_identity::Did;
use vera_modules::{
    acp::{
        AcpModule,
        delegated_operation::DelegatedOperation,
        types::{Object, PolicyCmd, PolicyMarshalingType},
    },
    kv_store::InMemoryKvStore,
    types::{BlockExecCtx, Timestamp, TxExecCtx},
    vera::{VeraModule, administration::*, relay::RelayGrant},
};

const GENESIS: [u8; 32] = [7; 32];
const POLICY: &str = "name: files\nresources:\n  - name: file\n";
const FORMAT: PolicyMarshalingType = PolicyMarshalingType::ShortYaml;

fn key() -> SigningKey {
    SigningKey::from_slice(&[42; 32]).unwrap()
}
fn issuer() -> String {
    vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key().verifying_key().to_sec1_bytes().as_ref(),
    )
    .unwrap()
}
fn actor() -> String {
    format!("did:opk:{}", "ab".repeat(32))
}
const fn context() -> BlockExecCtx {
    BlockExecCtx {
        genesis_id: GENESIS,
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 100,
            block_height: 2,
        },
    }
}
fn submission() -> TxExecCtx {
    TxExecCtx {
        signer: "did:key:worker".into(),
        tx_hash: vec![9; 32],
        sequence: 0,
    }
}
fn grant() -> RelayGrant {
    RelayGrant {
        issuer: issuer(),
        scopes: vec![
            DelegationScope::PolicyCommands,
            DelegationScope::CreatePolicy,
            DelegationScope::EditPolicy,
        ],
        expires_at: 800,
    }
}
fn claims(operation: &DelegatedOperation<'_>) -> JwtClaims {
    JwtClaims {
        request: None,
        iss: issuer(),
        sub: submission().signer,
        exp: 200,
        aud: "vera:9001".into(),
        scope: operation.scope(),
        iat: 100,
        nbf: 100,
        relay: Some(RelayAssertion {
            actor: actor(),
            genesis_id: GENESIS,
            grant_sequence: 0,
            operation: operation.digest().unwrap(),
        }),
    }
}
fn sign(claims: &JwtClaims) -> String {
    sign_json("vera-relay-v1+jwt", &serde_json::to_string(claims).unwrap())
}
fn sign_json(typ: &str, payload: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256K","typ":"{typ}"}}"#));
    let message = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload));
    let signature: Signature = key().sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}
fn admin(
    vera: &mut VeraModule,
    acp: &mut AcpModule,
    command: AdministrativeCommand,
) -> Result<(), vera_modules::vera::error::VeraError> {
    let request = AdministrativeRequest {
        genesis_id: GENESIS,
        sequence: vera.administration()?.unwrap().sequence,
        expires_at: 500,
        command,
    };
    let signature: Signature = key().sign_prehash(&request.signing_digest()?).unwrap();
    vera.apply_administrative_request(
        acp,
        GENESIS,
        100,
        &SignedAdministrativeRequest {
            request,
            approvals: vec![OperatorApproval {
                signer: 0,
                signature: hex::encode(signature.to_bytes()),
            }],
        },
    )
}
fn modules() -> (VeraModule, AcpModule) {
    let mut vera = VeraModule::new();
    vera.initialize_administration(OperatorPolicy {
        threshold: 1,
        keys: vec![hex::encode(key().verifying_key().to_sec1_bytes())],
    })
    .unwrap();
    let mut acp = AcpModule::new();
    admin(
        &mut vera,
        &mut acp,
        AdministrativeCommand::SetRelay(grant()),
    )
    .unwrap();
    (vera, acp)
}
fn create(
    vera: &mut VeraModule,
    acp: &mut AcpModule,
    token: &str,
) -> Result<vera_modules::acp::types::PolicyRecord, vera_modules::acp::error::AcpError> {
    acp.bearer_create_policy(vera, &context(), &submission(), token, POLICY, FORMAT)
}

#[test]
fn relay_preserves_actor_in_create_edit_and_registration() {
    let (mut vera, mut acp) = modules();
    let token = sign(&claims(&DelegatedOperation::CreatePolicy(POLICY, &FORMAT)));
    let created = create(&mut vera, &mut acp, &token).unwrap();
    assert_eq!(created.metadata.owner_did, actor());
    assert_eq!(created.metadata.tx_signer, submission().signer);
    assert_eq!(created.metadata.tx_hash, submission().tx_hash);
    let record = vera
        .get_jws_token(&vera_modules::vera::keys::hash_jws_token(&token))
        .unwrap()
        .unwrap();
    assert_eq!(record.issuer_did, issuer());
    assert_eq!(record.authorized_account, submission().signer);
    let policy = created.policy.id;
    let mut edit = claims(&DelegatedOperation::EditPolicy(&policy, POLICY, &FORMAT));
    let worker = Did::new(&submission().signer).unwrap();
    edit.relay.as_mut().unwrap().actor = format!("did:opk:{}", "cd".repeat(32));
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(
        acp.bearer_edit_policy(
            &mut vera,
            &context(),
            &transaction(&worker),
            &sign(&edit),
            &policy,
            POLICY,
            FORMAT
        )
        .is_err()
    );
    assert_eq!(before, (vera.store().serialize(), acp.store().serialize()));
    edit.relay.as_mut().unwrap().actor = actor();
    acp.bearer_edit_policy(
        &mut vera,
        &context(),
        &transaction(&worker),
        &sign(&edit),
        &policy,
        POLICY,
        FORMAT,
    )
    .unwrap();
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let cmd = PolicyCmd::RegisterObject(object.clone());
    let token = sign(&claims(&DelegatedOperation::PolicyCommand(&policy, &cmd)));
    acp.bearer_policy_cmd(
        &mut vera,
        &context(),
        &transaction(&worker),
        &token,
        &policy,
        cmd,
    )
    .unwrap();
    assert_eq!(
        acp.query_object_owner(&policy, &object)
            .unwrap()
            .1
            .unwrap()
            .metadata
            .owner_did,
        actor()
    );
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(
        acp.bearer_policy_cmd(
            &mut vera,
            &context(),
            &transaction(&worker),
            &token,
            &policy,
            PolicyCmd::ArchiveObject(object)
        )
        .is_err()
    );
    assert_eq!(before, (vera.store().serialize(), acp.store().serialize()));
}

#[test]
fn relay_assertions_fail_closed_without_mutations() {
    let base = claims(&DelegatedOperation::CreatePolicy(POLICY, &FORMAT));
    let (vera, acp) = modules();
    let mut cases = Vec::new();
    for field in ["sub", "aud", "iss"] {
        let mut value = serde_json::to_value(&base).unwrap();
        value[field] = "wrong".into();
        cases.push(value);
    }
    for (field, value) in [
        ("exp", 100),
        ("exp", 801),
        ("exp", 701),
        ("nbf", 99),
        ("iat", 101),
    ] {
        let mut claims = serde_json::to_value(&base).unwrap();
        claims[field] = value.into();
        cases.push(claims);
    }
    for (field, value) in [
        ("grant_sequence", serde_json::json!(1)),
        ("genesis_id", serde_json::json!([0; 32].to_vec())),
        ("operation", serde_json::json!([0; 32].to_vec())),
        ("actor", serde_json::json!(issuer())),
        ("actor", serde_json::json!("did:opk:invalid")),
    ] {
        let mut claims = serde_json::to_value(&base).unwrap();
        claims["relay"][field] = value;
        cases.push(claims);
    }
    for value in cases {
        let mut vera = vera.clone();
        let mut acp = acp.clone();
        let before = (vera.store().serialize(), acp.store().serialize());
        let token = sign_json("vera-relay-v1+jwt", &value.to_string());
        assert!(create(&mut vera, &mut acp, &token).is_err(), "{value}");
        assert_eq!(before, (vera.store().serialize(), acp.store().serialize()));
    }
    for typ in ["vera-delegation-v1+jwt", "JWT"] {
        assert!(
            vera_crypto::jwt::verify_bearer_token(&sign_json(
                typ,
                &serde_json::to_string(&base).unwrap()
            ))
            .is_err()
        );
    }
    let mut no_assertion = base.clone();
    no_assertion.relay = None;
    assert!(vera_crypto::jwt::verify_bearer_token(&sign(&no_assertion)).is_err());
    let duplicate = serde_json::to_string(&base).unwrap().replace(
        "\"grant_sequence\":0",
        "\"grant_sequence\":0,\"grant_sequence\":0",
    );
    assert!(
        vera_crypto::jwt::verify_bearer_token(&sign_json("vera-relay-v1+jwt", &duplicate)).is_err()
    );
    let token = sign(&base);
    assert!(create(&mut VeraModule::new(), &mut AcpModule::new(), &token).is_err());
    let (mut vera, mut acp) = modules();
    let mut restricted = grant();
    restricted.scopes = vec![DelegationScope::PolicyCommands];
    admin(
        &mut vera,
        &mut acp,
        AdministrativeCommand::SetRelay(restricted),
    )
    .unwrap();
    let mut claims = base;
    claims.relay.as_mut().unwrap().grant_sequence = 1;
    assert!(create(&mut vera, &mut acp, &sign(&claims)).is_err());
}

#[test]
fn relay_and_assertion_revocations_survive_reopen_and_regrant() {
    let (mut vera, mut acp) = modules();
    let mut claims = claims(&DelegatedOperation::CreatePolicy(POLICY, &FORMAT));
    let token = sign(&claims);
    let worker = Did::new(&claims.sub).unwrap();
    assert!(
        vera.revoke_delegation(&context(), &Did::new("did:key:stranger").unwrap(), &token)
            .is_err()
    );
    let mut foreign = context();
    foreign.genesis_id = [8; 32];
    assert!(vera.revoke_delegation(&foreign, &worker, &token).is_err());
    vera.revoke_delegation(&context(), &worker, &token).unwrap();
    assert!(create(&mut vera, &mut acp, &token).is_err());
    claims.exp += 1;
    let unused = sign(&claims);
    create(&mut vera, &mut acp, &unused).unwrap();
    admin(
        &mut vera,
        &mut acp,
        AdministrativeCommand::RevokeRelay(issuer()),
    )
    .unwrap();
    let bytes = vera.store().serialize();
    vera = VeraModule::from_store(InMemoryKvStore::deserialize(&bytes).unwrap());
    assert!(create(&mut vera, &mut acp, &unused).is_err());
    admin(
        &mut vera,
        &mut acp,
        AdministrativeCommand::SetRelay(grant()),
    )
    .unwrap();
    assert!(create(&mut vera, &mut acp, &unused).is_err());
    claims.relay.as_mut().unwrap().grant_sequence = 2;
    create(&mut vera, &mut acp, &sign(&claims)).unwrap();
    assert!(create(&mut vera, &mut acp, &token).is_err());
}

#[test]
fn invalid_grants_do_not_consume_operator_sequence() {
    let (vera, acp) = modules();
    let mut cases = Vec::new();
    let mut invalid = grant();
    invalid.scopes.clear();
    cases.push(invalid);
    let mut invalid = grant();
    invalid.scopes.reverse();
    cases.push(invalid);
    let mut invalid = grant();
    invalid.scopes.push(DelegationScope::EditPolicy);
    cases.push(invalid);
    let mut invalid = grant();
    invalid.expires_at = 100;
    cases.push(invalid);
    let mut invalid = grant();
    invalid.issuer = "did:key:invalid".into();
    cases.push(invalid);
    for invalid in cases {
        let mut vera = vera.clone();
        let mut acp = acp.clone();
        let before = vera.store().serialize();
        assert!(
            admin(
                &mut vera,
                &mut acp,
                AdministrativeCommand::SetRelay(invalid)
            )
            .is_err()
        );
        assert_eq!(vera.store().serialize(), before);
    }
}

#[test]
fn operation_commitments_match_independent_json_vectors() {
    let command = PolicyCmd::RegisterObject(Object {
        resource: "file".into(),
        id: "report".into(),
    });
    let operations = [
        DelegatedOperation::CreatePolicy(POLICY, &FORMAT),
        DelegatedOperation::EditPolicy("policy-id", POLICY, &FORMAT),
        DelegatedOperation::PolicyCommand("policy-id", &command),
    ];
    let expected = [
        "d1539d909f3395fb921de0d7c5ac64e85c92b7e9147f0f714e76f45087161ac0",
        "7413ed3d879aebce3ab6f2c4ba0ae03ce8313afb89007c9b97404e6f42a96ee9",
        "43300ea9818bece4ed37a2f9b9e0fdbd8852e547f9b714000aa174d96d9f76f5",
    ];
    for (operation, expected) in operations.iter().zip(expected) {
        assert_eq!(hex::encode(operation.digest().unwrap()), expected);
    }
}

fn transaction(caller: &Did) -> vera_modules::types::TxExecCtx {
    vera_modules::types::TxExecCtx {
        sequence: 0,
        tx_hash: vec![1; 32],
        signer: caller.to_string(),
    }
}

#[test]
fn recording_decisions_requires_its_own_relay_grant_even_for_retries() {
    use vera_crypto::operation::{OperationClaim, OperationId};
    use vera_modules::acp::types::{AccessRequest, Actor, Operation};
    let (mut vera, mut acp) = modules();
    let owner = Did::new(actor()).unwrap();
    let policy = acp
        .create_policy(
            &owner,
            "name: decisions\nresources:\n  - name: file\n    permissions:\n      - name: read\n",
            FORMAT,
        )
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    acp.direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    let request = AccessRequest {
        actor: Actor(owner),
        operations: vec![Operation {
            object,
            permission: "read".into(),
        }],
    };
    let operation = DelegatedOperation::CheckAccess(&policy, &request);
    let mut id = [1; 32];
    id[..8].copy_from_slice(&200u64.to_be_bytes());
    let mut claims = claims(&operation);
    claims.request = Some(OperationClaim {
        id: OperationId(id),
        digest: operation.digest().unwrap(),
        genesis_id: GENESIS,
    });
    assert!(
        acp.bearer_check_access(
            &mut vera,
            &context(),
            &submission(),
            &sign(&claims),
            &policy,
            &request
        )
        .is_err()
    );
    let mut authority = grant();
    authority.scopes.push(DelegationScope::RecordAccessDecision);
    admin(
        &mut vera,
        &mut acp,
        AdministrativeCommand::SetRelay(authority),
    )
    .unwrap();
    claims.relay.as_mut().unwrap().grant_sequence = 1;
    let original = acp
        .bearer_check_access(
            &mut vera,
            &context(),
            &submission(),
            &sign(&claims),
            &policy,
            &request,
        )
        .unwrap();
    assert_eq!(original.creator, submission().signer);
    assert_eq!(original.actor, actor());
    assert!(acp.operation(&actor(), OperationId(id)).unwrap().is_some());
    admin(
        &mut vera,
        &mut acp,
        AdministrativeCommand::RevokeRelay(issuer()),
    )
    .unwrap();
    assert!(
        acp.bearer_check_access(
            &mut vera,
            &context(),
            &submission(),
            &sign(&claims),
            &policy,
            &request
        )
        .is_err()
    );
}
