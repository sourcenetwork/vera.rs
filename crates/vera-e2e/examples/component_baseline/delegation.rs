use identity::Did;
use k256::ecdsa::SigningKey;
use std::hint::black_box;
use vera_client::{BlsSigner, create_operation_token};
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use vera_modules::{
    acp::{
        AcpModule,
        delegated_operation::DelegatedOperation,
        types::{Object, PolicyCmd, PolicyMarshalingType},
    },
    types::{BlockExecCtx, Timestamp, TxExecCtx},
    vera::VeraModule,
};

pub(super) fn run() {
    let key = SigningKey::from_bytes((&[42; 32]).into()).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let actor: Did = issuer.parse().unwrap();
    let worker: Did = BlsSigner::new(43_u64.into(), 9001)
        .unwrap()
        .did()
        .parse()
        .unwrap();
    let other_worker: Did = BlsSigner::new(44_u64.into(), 9001)
        .unwrap()
        .did()
        .parse()
        .unwrap();
    let context = BlockExecCtx {
        genesis_id: [42; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 10,
            block_height: 1,
        },
    };
    let submission = TxExecCtx {
        signer: worker.to_string(),
        tx_hash: vec![43; 32],
        sequence: 1,
    };
    let retry_submission = TxExecCtx {
        signer: other_worker.to_string(),
        tx_hash: vec![44; 32],
        sequence: 1,
    };
    let mut base = AcpModule::new();
    let policy = base
        .create_policy(
            &actor,
            "name: delegated-component\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let command = PolicyCmd::RegisterObject(object.clone());
    let digest = DelegatedOperation::PolicyCommand(&policy, &command)
        .digest()
        .unwrap();
    let mut id = [42; 32];
    id[..8].copy_from_slice(&100_u64.to_be_bytes());
    let id = OperationId(id);
    let claims = JwtClaims {
        iss: issuer,
        sub: worker.to_string(),
        exp: 100,
        aud: "vera:9001".into(),
        scope: DelegationScope::PolicyCommands,
        iat: 10,
        nbf: 10,
        relay: None,
        request: Some(OperationClaim {
            id,
            digest,
            genesis_id: context.genesis_id,
        }),
    };
    let token = create_operation_token(&key, &claims).unwrap();
    let retry_claims = JwtClaims {
        sub: other_worker.to_string(),
        ..claims.clone()
    };
    let retry_token = create_operation_token(&key, &retry_claims).unwrap();
    let base_bytes = base.store().serialize();
    let mut executed = base.clone();
    let unused = VeraModule::new();
    let mut vera = unused.clone();
    let result = executed
        .bearer_policy_cmd(
            &mut vera,
            &context,
            &submission,
            &token,
            &policy,
            command.clone(),
        )
        .unwrap();
    let (registered, owner) = executed.query_object_owner(&policy, &object).unwrap();
    assert!(registered);
    assert_eq!(owner.unwrap().metadata.owner_did, actor.as_str());
    let outcome = executed.operation(actor.as_str(), id).unwrap().unwrap();
    assert_eq!(outcome.worker, submission.signer);
    assert_eq!(outcome.submission.as_slice(), submission.tx_hash);
    assert_eq!(outcome.digest, digest);
    assert_eq!(outcome.result, serde_json::to_value(&result).unwrap());

    let before_retry = (executed.store().serialize(), vera.store().serialize());
    let recovered = executed
        .bearer_policy_cmd(
            &mut vera,
            &context,
            &retry_submission,
            &retry_token,
            &policy,
            command.clone(),
        )
        .unwrap();
    assert_eq!(serde_json::to_value(recovered).unwrap(), outcome.result);
    assert_eq!(executed.store().serialize(), before_retry.0);
    assert_eq!(vera.store().serialize(), before_retry.1);
    assert_eq!(base.store().serialize(), base_bytes);
    let scope = DelegationScope::PolicyCommands;
    let authorized = vera
        .authorize_delegation(&context, &worker, &token, scope, digest)
        .unwrap();
    assert_eq!(authorized.iss, actor.as_str());
    assert!(
        vera.authorize_delegation(&context, &other_worker, &token, scope, digest)
            .is_err()
    );
    assert!(
        vera.authorize_delegation(&context, &worker, &token, scope, [0; 32])
            .is_err()
    );
    let mut revoked = vera.clone();
    revoked
        .revoke_delegation(&context, &actor, &retry_token)
        .unwrap();
    let mut rejected = executed.clone();
    assert!(
        rejected
            .bearer_policy_cmd(
                &mut revoked,
                &context,
                &retry_submission,
                &retry_token,
                &policy,
                command.clone(),
            )
            .is_err()
    );
    assert_eq!(rejected.store().serialize(), before_retry.0);

    super::measure_prepared(
        "native_operation_token_sign",
        || (),
        |_| create_operation_token(black_box(&key), black_box(&claims)).unwrap(),
    );
    super::measure_prepared(
        "native_delegation_authorize",
        || (),
        |_| {
            vera.authorize_delegation(
                black_box(&context),
                black_box(&worker),
                black_box(&token),
                scope,
                digest,
            )
            .unwrap()
        },
    );
    for (name, state, tokens, submission, token) in [
        (
            "acp_delegated_register",
            &base,
            &unused,
            &submission,
            &token,
        ),
        (
            "acp_delegated_retry",
            &executed,
            &vera,
            &retry_submission,
            &retry_token,
        ),
    ] {
        super::measure_prepared(
            name,
            || (state.clone(), tokens.clone(), Some(command.clone())),
            |(acp, vera, command)| {
                acp.bearer_policy_cmd(
                    vera,
                    &context,
                    submission,
                    token,
                    &policy,
                    command.take().unwrap(),
                )
                .unwrap()
            },
        );
    }
}
