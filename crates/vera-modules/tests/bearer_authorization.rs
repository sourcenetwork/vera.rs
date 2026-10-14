//! Expiration semantics from Vera 205df1ad, x/acp/bearer_token/spec.go.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use vera_identity::Did;
use vera_modules::{
    acp::{
        AcpModule,
        error::AcpError,
        types::{Object, PolicyCmd, PolicyMarshalingType},
    },
    types::{BlockExecCtx, Timestamp},
};

fn signed_token(key: &SigningKey, claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let message = format!("{header}.{payload}");
    let signature: Signature = key.sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[test]
fn bearer_expiration_uses_execution_time_before_mutating_state() {
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let actor = Did::new(&issuer).unwrap();
    let mut base = AcpModule::new();
    let policy_id = base
        .create_policy(
            &actor,
            "name: files\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;

    for (expiration, now, allowed) in [
        (Some(100), 99, true),
        (Some(100), 100, true),
        (Some(100), 101, false),
        (Some(0), 0, false),
        (None, 0, false),
    ] {
        let mut claims = serde_json::json!({"iss": issuer, "sub": issuer, "aud": "vera:9001", "scope": "acp:policy", "iat": 0, "nbf": 0});
        if let Some(expiration) = expiration {
            claims["exp"] = expiration.into();
        }
        let token = signed_token(&key, claims);
        let context = BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: now,
                block_height: 1,
            },
        };
        let object = Object {
            resource: "file".into(),
            id: "report".into(),
        };
        let mut module = base.clone();
        let before = module.store().serialize();
        let result = module.bearer_policy_cmd(
            &mut vera_modules::vera::VeraModule::new(),
            &context,
            &transaction(&actor),
            &token,
            &policy_id,
            PolicyCmd::RegisterObject(object.clone()),
        );

        if allowed {
            result.unwrap();
            let (registered, record) = module.query_object_owner(&policy_id, &object).unwrap();
            assert!(registered);
            assert_eq!(record.unwrap().metadata.owner_did, issuer);
        } else {
            assert!(
                matches!(result, Err(AcpError::InvalidBearerToken { .. })),
                "{result:?}"
            );
            assert_eq!(module.store().serialize(), before);
        }
    }
}

#[test]
fn delegated_scopes_authorize_only_their_operations() {
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let actor = Did::new(&issuer).unwrap();
    let mut module = AcpModule::new();
    let policy_id = module
        .create_policy(
            &actor,
            "name: files\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let context = BlockExecCtx {
        genesis_id: [0; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 10,
            block_height: 1,
        },
    };
    let claims = |scope: &str| {
        signed_token(
            &key,
            serde_json::json!({"iss": issuer, "sub": issuer, "aud": "vera:9001",
                "scope": scope, "iat": 0, "nbf": 0, "exp": 100}),
        )
    };
    let mut vera = vera_modules::vera::VeraModule::new();
    let before = module.store().serialize();
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let mismatches: [(&str, Result<(), AcpError>); 5] = [
        (
            "acp:policy:create",
            module
                .bearer_policy_cmd(
                    &mut vera,
                    &context,
                    &transaction(&actor),
                    &claims("acp:policy:create"),
                    &policy_id,
                    PolicyCmd::RegisterObject(object.clone()),
                )
                .map(|_| ()),
        ),
        (
            "acp:policy:edit",
            module
                .bearer_policy_cmd(
                    &mut vera,
                    &context,
                    &transaction(&actor),
                    &claims("acp:policy:edit"),
                    &policy_id,
                    PolicyCmd::RegisterObject(object.clone()),
                )
                .map(|_| ()),
        ),
        (
            "acp:policy",
            module
                .bearer_create_policy(
                    &mut vera,
                    &context,
                    &transaction(&actor),
                    &claims("acp:policy"),
                    "name: forged\nresources:\n  - name: file\n",
                    PolicyMarshalingType::ShortYaml,
                )
                .map(|_| ()),
        ),
        (
            "acp:policy",
            module
                .bearer_edit_policy(
                    &mut vera,
                    &context,
                    &transaction(&actor),
                    &claims("acp:policy"),
                    &policy_id,
                    "name: forged\nresources:\n  - name: file\n",
                    PolicyMarshalingType::ShortYaml,
                )
                .map(|_| ()),
        ),
        (
            "acp:policy",
            module
                .bearer_check_access(
                    &mut vera,
                    &context,
                    &transaction(&actor),
                    &claims("acp:policy"),
                    &policy_id,
                    &vera_modules::acp::types::AccessRequest {
                        actor: vera_modules::acp::types::Actor(actor.clone()),
                        operations: vec![vera_modules::acp::types::Operation {
                            object: object.clone(),
                            permission: "read".into(),
                        }],
                    },
                )
                .map(|_| ()),
        ),
    ];
    for (scope, result) in mismatches {
        let error = result.expect_err(scope);
        assert!(
            matches!(&error, AcpError::InvalidBearerToken { reason } if reason.contains("does not authorize this operation")),
            "{scope}: {error}"
        );
        assert_eq!(module.store().serialize(), before);
    }
    assert!(
        module
            .bearer_policy_cmd(
                &mut vera,
                &context,
                &transaction(&actor),
                &claims("acp:policy"),
                &policy_id,
                PolicyCmd::RegisterObject(object),
            )
            .is_ok()
    );
}

#[test]
fn delegation_binds_caller_deployment_and_revocation() {
    use vera_modules::kv_store::InMemoryKvStore;
    use vera_modules::vera::{VeraModule, types::JWSTokenStatus};

    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let owner = Did::new(&issuer).unwrap();
    let caller = Did::new("did:key:caller").unwrap();
    let stranger = Did::new("did:key:stranger").unwrap();
    let token = signed_token(
        &key,
        serde_json::json!({
            "iss": issuer, "sub": caller.to_string(), "aud": "vera:9001",
            "scope": "acp:policy", "iat": 10, "nbf": 5, "exp": 100,
        }),
    );
    let mut context = BlockExecCtx {
        genesis_id: [0; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 20,
            block_height: 1,
        },
    };
    let mut base = AcpModule::new();
    let policy = base
        .create_policy(
            &owner,
            "name: files\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let command = || PolicyCmd::RegisterObject(object.clone());
    let mut vera = VeraModule::new();
    let before = base.store().serialize();
    assert!(
        base.bearer_policy_cmd(
            &mut vera,
            &context,
            &transaction(&stranger),
            &token,
            &policy,
            command()
        )
        .is_err()
    );
    context.deployment_id = 9002;
    assert!(
        base.bearer_policy_cmd(
            &mut vera,
            &context,
            &transaction(&caller),
            &token,
            &policy,
            command()
        )
        .is_err()
    );
    context.deployment_id = 9001;
    context.timestamp.seconds = 4;
    assert!(
        base.bearer_policy_cmd(
            &mut vera,
            &context,
            &transaction(&caller),
            &token,
            &policy,
            command()
        )
        .is_err()
    );
    assert_eq!(base.store().serialize(), before);
    assert!(vera.store().is_empty());
    context.timestamp.seconds = 20;

    // Both the issuer and bound submitter can revoke before any use.
    for revoker in [&owner, &caller] {
        let mut revoked = vera.clone();
        let denied = revoked.store().serialize();
        assert!(
            revoked
                .revoke_delegation(&context, &stranger, &token)
                .is_err()
        );
        assert_eq!(revoked.store().serialize(), denied);
        let record = revoked
            .revoke_delegation(&context, revoker, &token)
            .unwrap();
        assert_eq!(record.status, JWSTokenStatus::Invalid);
        assert!(record.first_used_at.is_none());
        let mut reopened = VeraModule::from_store(
            InMemoryKvStore::deserialize(&revoked.store().serialize()).unwrap(),
        );
        assert!(
            base.bearer_policy_cmd(
                &mut reopened,
                &context,
                &transaction(&caller),
                &token,
                &policy,
                command()
            )
            .is_err()
        );
        assert_eq!(base.store().serialize(), before);
        assert_eq!(
            reopened.get_jws_token(&record.token_hash).unwrap(),
            Some(record)
        );
    }

    // A rejected command cannot register token usage.
    let invalid = PolicyCmd::RegisterObject(Object {
        resource: "missing".into(),
        id: "report".into(),
    });
    assert!(
        base.bearer_policy_cmd(
            &mut vera,
            &context,
            &transaction(&caller),
            &token,
            &policy,
            invalid
        )
        .is_err()
    );
    assert!(vera.store().is_empty());
    base.bearer_policy_cmd(
        &mut vera,
        &context,
        &transaction(&caller),
        &token,
        &policy,
        command(),
    )
    .unwrap();
    let (_, record) = base.query_object_owner(&policy, &object).unwrap();
    assert_eq!(record.unwrap().metadata.owner_did, issuer);
    let hash = vera_modules::vera::keys::hash_jws_token(&token);
    let used = vera.get_jws_token(&hash).unwrap().unwrap();
    assert_eq!(used.authorized_account, caller.to_string());
    assert_eq!(used.first_used_at, Some(context.timestamp.clone()));
    vera.revoke_delegation(&context, &owner, &token).unwrap();
    let before = base.store().serialize();
    assert!(
        base.bearer_policy_cmd(
            &mut vera,
            &context,
            &transaction(&caller),
            &token,
            &policy,
            command()
        )
        .is_err()
    );
    assert_eq!(base.store().serialize(), before);
    assert_eq!(
        vera.get_jws_token(&hash).unwrap().unwrap().status,
        JWSTokenStatus::Invalid
    );
}

#[test]
fn delegated_policy_lifecycle_preserves_ownership_and_revocation() {
    use vera_modules::vera::VeraModule;

    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let owner = Did::new(&issuer).unwrap();
    let worker = Did::new("did:key:worker").unwrap();
    let submission = vera_modules::types::TxExecCtx {
        sequence: 0,
        tx_hash: vec![7; 32],
        signer: worker.to_string(),
    };
    let other_worker = Did::new("did:key:other-worker").unwrap();
    let context = BlockExecCtx {
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 20,
            block_height: 1,
        },
        ..Default::default()
    };
    let claims = serde_json::json!({
        "iss": issuer, "sub": worker.to_string(), "aud": "vera:9001",
        "scope": "acp:policy:create", "iat": 10, "nbf": 5, "exp": 100,
    });
    let token = signed_token(&key, claims.clone());
    let mut edit_claims = claims.clone();
    edit_claims["scope"] = serde_json::json!("acp:policy:edit");
    let edit_token = signed_token(&key, edit_claims);
    let policy = "name: files\nresources:\n  - name: file\n";
    let mut module = AcpModule::new();
    let mut vera = VeraModule::new();
    for (field, value) in [
        ("sub", serde_json::json!(other_worker.to_string())),
        ("aud", serde_json::json!("vera:9002")),
        ("scope", serde_json::json!("bulletin")),
        ("scope", serde_json::json!("acp:policy")),
        ("scope", serde_json::json!("acp:policy:edit")),
        ("exp", serde_json::json!(19)),
    ] {
        let mut invalid_claims = claims.clone();
        invalid_claims[field] = value;
        let invalid_token = signed_token(&key, invalid_claims);
        let before = module.store().serialize();
        assert!(
            module
                .bearer_create_policy(
                    &mut vera,
                    &context,
                    &submission,
                    &invalid_token,
                    policy,
                    PolicyMarshalingType::ShortYaml,
                )
                .is_err()
        );
        assert_eq!(module.store().serialize(), before);
        assert!(vera.store().is_empty());
    }
    let created = module
        .bearer_create_policy(
            &mut vera,
            &context,
            &submission,
            &token,
            policy,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    assert_eq!(created.metadata.owner_did, issuer);
    assert_eq!(created.metadata.tx_hash, submission.tx_hash);
    assert_eq!(created.metadata.tx_signer, submission.signer);
    assert_eq!(created.metadata.creation_ts, context.timestamp);
    let before = module.store().serialize();
    let vera_before = vera.store().serialize();
    for lifecycle_token in [&token, &edit_token] {
        assert!(
            module
                .bearer_policy_cmd(
                    &mut vera,
                    &context,
                    &transaction(&worker),
                    lifecycle_token,
                    &created.policy.id,
                    PolicyCmd::RegisterObject(Object {
                        resource: "file".into(),
                        id: "report".into()
                    }),
                )
                .is_err()
        );
    }
    assert_eq!(module.store().serialize(), before);
    assert_eq!(vera.store().serialize(), vera_before);
    let edited = "name: updated\nresources:\n  - name: file\n";
    let before = module.store().serialize();
    let intruder_key = SigningKey::from_slice(&[43; 32]).unwrap();
    let intruder = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        intruder_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .unwrap();
    let mut intruder_claims = claims.clone();
    intruder_claims["iss"] = serde_json::json!(intruder);
    intruder_claims["scope"] = serde_json::json!("acp:policy:edit");
    let intruder_token = signed_token(&intruder_key, intruder_claims);
    let vera_before = vera.store().serialize();
    assert!(matches!(
        module.bearer_edit_policy(
            &mut vera,
            &context,
            &transaction(&worker),
            &intruder_token,
            &created.policy.id,
            edited,
            PolicyMarshalingType::ShortYaml,
        ),
        Err(AcpError::Unauthorized { .. })
    ));
    assert_eq!(module.store().serialize(), before);
    assert_eq!(vera.store().serialize(), vera_before);
    assert!(
        module
            .edit_policy(
                &worker,
                &created.policy.id,
                edited,
                PolicyMarshalingType::ShortYaml
            )
            .is_err()
    );
    assert_eq!(module.store().serialize(), before);
    let mut other_claims = claims;
    other_claims["sub"] = serde_json::json!(other_worker.to_string());
    other_claims["scope"] = serde_json::json!("acp:policy:edit");
    let other_token = signed_token(&key, other_claims);
    let (_, updated) = module
        .bearer_edit_policy(
            &mut vera,
            &context,
            &transaction(&other_worker),
            &other_token,
            &created.policy.id,
            edited,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    assert_eq!(updated.metadata.owner_did, issuer);
    assert_eq!(updated.raw_policy, edited);
    let before = module.store().serialize();
    let vera_before = vera.store().serialize();
    assert!(
        module
            .bearer_edit_policy(
                &mut vera,
                &context,
                &transaction(&worker),
                &edit_token,
                &created.policy.id,
                "name: removes-resource\nresources: []\n",
                PolicyMarshalingType::ShortYaml,
            )
            .is_err()
    );
    assert_eq!(module.store().serialize(), before);
    assert_eq!(vera.store().serialize(), vera_before);
    vera.revoke_delegation(&context, &owner, &token).unwrap();
    vera.revoke_delegation(&context, &owner, &edit_token)
        .unwrap();
    let vera_before = vera.store().serialize();
    assert!(
        module
            .bearer_create_policy(
                &mut vera,
                &context,
                &submission,
                &token,
                policy,
                PolicyMarshalingType::ShortYaml,
            )
            .is_err()
    );
    assert!(
        module
            .bearer_edit_policy(
                &mut vera,
                &context,
                &transaction(&worker),
                &edit_token,
                &created.policy.id,
                policy,
                PolicyMarshalingType::ShortYaml,
            )
            .is_err()
    );
    assert_eq!(module.store().serialize(), before);
    assert_eq!(vera.store().serialize(), vera_before);
}

#[test]
fn delegated_policy_creation_rolls_back_when_usage_cannot_be_recorded() {
    use vera_modules::{
        kv_store::{InMemoryKvStore, ModuleKvStore},
        vera::VeraModule,
    };

    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let worker = Did::new("did:key:worker").unwrap();
    let submission = vera_modules::types::TxExecCtx {
        sequence: 0,
        tx_hash: vec![7; 32],
        signer: worker.to_string(),
    };
    let policy = "name: files\nresources:\n  - name: file\n";
    let mut operation_id = [1; 32];
    operation_id[..8].copy_from_slice(&100u64.to_be_bytes());
    let request = vera_crypto::operation::OperationClaim {
        id: vera_crypto::operation::OperationId(operation_id),
        digest: vera_modules::acp::delegated_operation::DelegatedOperation::CreatePolicy(
            policy,
            &PolicyMarshalingType::ShortYaml,
        )
        .digest()
        .unwrap(),
        genesis_id: [7; 32],
    };
    let token = signed_token(
        &key,
        serde_json::json!({
            "iss": issuer, "sub": worker.to_string(), "aud": "vera:9001",
            "scope": "acp:policy:create", "iat": 10, "nbf": 5, "exp": 100, "request": request,
        }),
    );
    let context = BlockExecCtx {
        genesis_id: [7; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 20,
            block_height: 1,
        },
    };
    let mut store = InMemoryKvStore::default();
    store.put(vera_modules::vera::keys::CHAIN_CONFIG_KEY, vec![0xff]);
    let mut vera = VeraModule::from_store(store);
    let mut module = AcpModule::new();
    let before = module.store().serialize();
    let vera_before = vera.store().serialize();
    assert!(
        module
            .bearer_create_policy(
                &mut vera,
                &context,
                &submission,
                &token,
                "name: files\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .is_err()
    );
    assert_eq!(module.store().serialize(), before);
    assert_eq!(vera.store().serialize(), vera_before);
    assert!(module.query_policy_ids().unwrap().is_empty());
}

fn transaction(caller: &Did) -> vera_modules::types::TxExecCtx {
    vera_modules::types::TxExecCtx {
        sequence: 0,
        tx_hash: vec![1; 32],
        signer: caller.to_string(),
    }
}
