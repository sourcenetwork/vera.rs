use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use vera_modules::acp::{
    delegated_operation::DelegatedOperation,
    types::{PolicyCommandRequest, SuppliedMetadata},
};
use vera_modules::types::Timestamp;

#[derive(Clone)]
struct Fixture {
    acp: AcpModule,
    vera: VeraModule,
    block: BlockExecCtx,
    tx: TxExecCtx,
    policy: B256,
}
impl Fixture {
    fn new() -> Self {
        let actor = Did::new(issuer()).unwrap();
        let mut acp = AcpModule::new();
        let policy = acp.create_policy(&actor, "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n", PolicyMarshalingType::ShortYaml).unwrap().policy.id;
        let block = BlockExecCtx {
            timestamp: Timestamp {
                seconds: 10,
                block_height: 1,
            },
            deployment_id: 9001,
            genesis_id: [7; 32],
        };
        let tx = TxExecCtx {
            signer: actor.to_string(),
            tx_hash: vec![1; 32],
            sequence: 0,
        };
        acp.execute_policy_cmd_with_metadata(
            &actor,
            &policy,
            PolicyCommandRequest {
                command: PolicyCmd::RegisterObject(Object {
                    resource: "file".into(),
                    id: "report".into(),
                }),
                metadata: SuppliedMetadata {
                    attributes: [("note".into(), "x".repeat(60 << 10))].into(),
                    ..Default::default()
                },
            },
            &block,
            &tx,
        )
        .unwrap();
        Self {
            acp,
            vera: VeraModule::new(),
            block,
            tx,
            policy: policy.parse().unwrap(),
        }
    }
    fn dispatch(&mut self, input: &[u8], gas: u64) -> DispatchReturn {
        dispatch(
            &mut self.acp,
            &mut self.vera,
            &self.block,
            &self.tx,
            input,
            gas,
        )
    }
    fn state(&self) -> (Vec<u8>, Vec<u8>) {
        (self.acp.store().serialize(), self.vera.store().serialize())
    }
    fn command(&self) -> PolicyCmd {
        PolicyCmd::SetRelationship(acp::Relationship::with_entity(
            "file",
            "report",
            "reader",
            Did::new("did:key:reader").unwrap(),
        ))
    }
    fn generic(&self) -> Vec<u8> {
        IAcp::executePolicyCommandCall {
            policyId: self.policy,
            request: serde_json::to_vec(&PolicyCommandRequest {
                command: self.command(),
                metadata: SuppliedMetadata {
                    attributes: [("label".into(), "grant".into())].into(),
                    ..Default::default()
                },
            })
            .unwrap()
            .into(),
        }
        .abi_encode()
    }
    fn bearer(&self) -> Vec<u8> {
        let command = self.command();
        let mut id = [17; 32];
        id[..8].copy_from_slice(&100u64.to_be_bytes());
        let claims = JwtClaims {
            iss: issuer(),
            sub: self.tx.signer.clone(),
            exp: 100,
            aud: "vera:9001".into(),
            scope: DelegationScope::PolicyCommands,
            iat: 0,
            nbf: 0,
            relay: None,
            request: Some(OperationClaim {
                id: OperationId(id),
                genesis_id: self.block.genesis_id,
                digest: DelegatedOperation::PolicyCommand(&hex::encode(self.policy), &command)
                    .digest()
                    .unwrap(),
            }),
        };
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#);
        let message = format!(
            "{header}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key().sign(message.as_bytes());
        IAcp::bearerPolicyCmdCall {
            bearerToken: format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())),
            policyId: self.policy,
            cmd: serde_json::to_vec(&command).unwrap().into(),
        }
        .abi_encode()
    }
    fn set(&self) -> Vec<u8> {
        IAcp::setRelationshipCall {
            policyId: self.policy,
            resource: "file".into(),
            objectId: "report".into(),
            relation: "reader".into(),
            actor: "did:key:reader".into(),
        }
        .abi_encode()
    }
    fn query(&self, actor: &str) -> Vec<u8> {
        IAcp::checkManagementAuthorityCall {
            policyId: self.policy,
            resource: "file".into(),
            objectId: "report".into(),
            relation: "reader".into(),
            actor: actor.into(),
        }
        .abi_encode()
    }
}
fn key() -> SigningKey {
    SigningKey::from_slice(&[42; 32]).unwrap()
}
fn issuer() -> String {
    vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key().verifying_key().to_sec1_bytes().as_ref(),
    )
    .unwrap()
}
fn batch(calls: Vec<Vec<u8>>) -> Vec<u8> {
    IAcp::batchCallsCall {
        calls: calls.into_iter().map(Into::into).collect(),
    }
    .abi_encode()
}
fn create() -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: b"name: transient\nresources:\n  - name: file\n"
            .to_vec()
            .into(),
        marshalType: 1,
    }
    .abi_encode()
}

#[test]
fn command_budget_all_management_routes_accept_exact_allowance_and_reject_one_less() {
    let fixture = Fixture::new();
    let inputs = vec![
        fixture.set(),
        fixture.generic(),
        fixture.bearer(),
        fixture.query(&issuer()),
        IAcp::deleteRelationshipCall {
            policyId: fixture.policy,
            resource: "file".into(),
            objectId: "report".into(),
            relation: "reader".into(),
            actor: "did:key:reader".into(),
        }
        .abi_encode(),
        IAcp::setRelationshipSubjectCall {
            policyId: fixture.policy,
            resource: "file".into(),
            objectId: "report".into(),
            relation: "reader".into(),
            subjectKind: 0,
            subjectResource: String::new(),
            subjectObjectId: "did:key:reader".into(),
            subjectRelation: String::new(),
        }
        .abi_encode(),
        IAcp::deleteRelationshipSubjectCall {
            policyId: fixture.policy,
            resource: "file".into(),
            objectId: "report".into(),
            relation: "reader".into(),
            subjectKind: 0,
            subjectResource: String::new(),
            subjectObjectId: "did:key:reader".into(),
            subjectRelation: String::new(),
        }
        .abi_encode(),
        IAcp::transferObjectCall {
            policyId: fixture.policy,
            resource: "file".into(),
            objectId: "report".into(),
            newOwner: "did:key:next".into(),
        }
        .abi_encode(),
        IAcp::archiveObjectCall {
            policyId: fixture.policy,
            resource: "file".into(),
            objectId: "report".into(),
        }
        .abi_encode(),
    ];
    for input in inputs {
        let mut measured = fixture.clone();
        let output = measured.dispatch(&input, 1_000_000).unwrap();
        assert!(!output.precompile.reverted, "{:?}", output.precompile.bytes);
        let required = output.precompile.gas_used;
        let mut exact = fixture.clone();
        let result = exact.dispatch(&input, required).unwrap();
        assert!(!result.precompile.reverted);
        assert_eq!(result.precompile.bytes, output.precompile.bytes);
        assert_eq!(result.precompile.gas_used, required);
        assert_eq!(exact.state(), measured.state());
        let mut low = fixture.clone();
        assert!(matches!(
            low.dispatch(&input, required - 1),
            Err(PrecompileError::OutOfGas)
        ));
        assert_eq!(low.state(), fixture.state());
    }
}

#[test]
fn management_denials_retain_dispatch_work_and_nested_batches_rollback() {
    let fixture = Fixture::new();
    let query = fixture.query("did:key:stranger");
    let denied = fixture.clone().dispatch(&query, 1_000_000).unwrap();
    assert!(
        !IAcp::checkManagementAuthorityCall::abi_decode_returns(&denied.precompile.bytes).unwrap()
    );
    assert!(denied.precompile.gas_used > READ_GAS + 60_000 / 16);
    let creation_gas = fixture
        .clone()
        .dispatch(&create(), 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    for input in [fixture.set(), fixture.generic()] {
        let mut stranger = fixture.clone();
        stranger.tx.signer = "did:key:stranger".into();
        let failure = stranger.dispatch(&input, 1_000_000).unwrap();
        assert!(failure.precompile.reverted);
        assert!(failure.precompile.gas_used > WRITE_GAS);
        let result = stranger
            .dispatch(&batch(vec![create(), batch(vec![input])]), 1_000_000)
            .unwrap();
        assert!(result.precompile.reverted);
        // Creation cost includes signer bytes; compare the same actor's measured leaf.
        let mut other = fixture.clone();
        other.tx.signer = stranger.tx.signer.clone();
        let same_actor_creation = other
            .dispatch(&create(), 1_000_000)
            .unwrap()
            .precompile
            .gas_used;
        assert_eq!(
            result.precompile.gas_used,
            same_actor_creation + 2 * READ_GAS + failure.precompile.gas_used
        );
        assert!(result.logs.is_empty());
        assert_eq!(stranger.state(), fixture.state());
    }
    assert!(creation_gas > WRITE_GAS);
    let owner_query = fixture.query(&issuer());
    let cost = fixture
        .clone()
        .dispatch(&owner_query, 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    let input = batch(vec![
        create(),
        batch(vec![owner_query.clone(), owner_query]),
    ]);
    let exact = creation_gas + 2 * READ_GAS + 2 * cost;
    assert!(
        !fixture
            .clone()
            .dispatch(&input, exact)
            .unwrap()
            .precompile
            .reverted
    );
    let mut low = fixture.clone();
    assert!(matches!(
        low.dispatch(&input, exact - 1),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(low.state(), fixture.state());
}

#[test]
fn command_input_is_reserved_before_json_and_aliased_abi_decoding() {
    let fixture = Fixture::new();
    let malformed = IAcp::executePolicyCommandCall {
        policyId: fixture.policy,
        request: vec![b' '; 128 << 10].into(),
    }
    .abi_encode();
    let failure = fixture.clone().dispatch(&malformed, 1_000_000).unwrap();
    assert!(failure.precompile.reverted);
    assert!(failure.precompile.gas_used > WRITE_GAS + (128 << 10) / 2);
    assert!(matches!(
        fixture.clone().dispatch(&malformed, WRITE_GAS + 1_000),
        Err(PrecompileError::OutOfGas)
    ));
    let mut alias = fixture.set();
    // Give each dynamic string the same invalid UTF-8 tail. Low allowance must
    // exhaust while reserving these copies, before Alloy's owned decoder runs.
    alias.truncate(4 + 5 * 32);
    for field in 1..=4 {
        alias[4 + field * 32..4 + (field + 1) * 32]
            .copy_from_slice(&alloy_primitives::U256::from(5 * 32).to_be_bytes::<32>());
    }
    alias.extend_from_slice(&alloy_primitives::U256::from(32 << 10).to_be_bytes::<32>());
    alias.extend(vec![255; 32 << 10]);
    let raw_cost = (alias.len() as u64).div_ceil(16) * 8;
    let invalid_actor = fixture.clone().dispatch(&alias, 1_000_000).unwrap();
    assert!(invalid_actor.precompile.reverted);
    assert_eq!(
        invalid_actor.precompile.gas_used,
        WRITE_GAS + raw_cost + 4 * 3 * (32 << 10) / 2
    );
    let mut low = fixture.clone();
    assert!(matches!(
        low.dispatch(&alias, WRITE_GAS + raw_cost + (32 << 10)),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(low.state(), fixture.state());
}

#[test]
fn bearer_command_outcome_is_atomic_metered_and_survives_policy_retirement() {
    let mut fixture = Fixture::new();
    let call = fixture.bearer();
    let mut measured = fixture.clone();
    let first = measured.dispatch(&call, 1_000_000).unwrap();
    assert!(!first.precompile.reverted);
    let required = first.precompile.gas_used;
    assert!(matches!(
        fixture.dispatch(&call, required - 1),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(
        fixture.vera.store().serialize(),
        VeraModule::new().store().serialize()
    );
    let success = fixture.dispatch(&call, required).unwrap();
    assert_eq!(success.precompile.bytes, first.precompile.bytes);
    assert_eq!(fixture.state(), measured.state());
    fixture
        .acp
        .delete_policy(&Did::new(issuer()).unwrap(), &hex::encode(fixture.policy))
        .unwrap();
    let before = fixture.state();
    let retry = fixture.dispatch(&call, 1_000_000).unwrap();
    assert!(!retry.precompile.reverted);
    assert_eq!(retry.precompile.bytes, first.precompile.bytes);
    assert!(retry.precompile.gas_used > WRITE_GAS);
    assert_eq!(fixture.state(), before);
    assert!(matches!(
        fixture.dispatch(&call, retry.precompile.gas_used - 1),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(fixture.state(), before);
    // A retained outcome does not authorize a different worker to use the token.
    fixture.tx.signer = "did:key:other-worker".into();
    assert!(
        fixture
            .dispatch(&call, 1_000_000)
            .unwrap()
            .precompile
            .reverted
    );
    assert_eq!(fixture.state(), before);
}
