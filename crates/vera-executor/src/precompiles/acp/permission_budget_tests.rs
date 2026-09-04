use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use revm::precompile::{PrecompileHalt, PrecompileStatus};
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
        let policy = acp
            .create_policy(
                &actor,
                "name: files\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
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

    fn request(&self, actor: &str) -> AccessRequest {
        AccessRequest {
            actor: Actor(Did::new(actor).unwrap()),
            operations: vec![Operation {
                object: Object {
                    resource: "file".into(),
                    id: "report".into(),
                },
                permission: "owner".into(),
            }],
        }
    }

    fn query(&self, actor: &str) -> Vec<u8> {
        IAcp::verifyAccessRequestCall {
            policyId: self.policy,
            resources: vec!["file".into()],
            objectIds: vec!["report".into()],
            permissions: vec!["owner".into()],
            actor: actor.into(),
        }
        .abi_encode()
    }

    fn decision(&self, bearer: bool, actor: &str) -> Vec<u8> {
        if !bearer {
            return IAcp::checkAccessCall {
                policyId: self.policy,
                resources: vec!["file".into()],
                objectIds: vec!["report".into()],
                permissions: vec!["owner".into()],
                actor: actor.into(),
            }
            .abi_encode();
        }
        let request = self.request(actor);
        let mut id = [17; 32];
        id[..8].copy_from_slice(&100u64.to_be_bytes());
        let claims = JwtClaims {
            iss: issuer(),
            sub: self.tx.signer.clone(),
            exp: 100,
            aud: "vera:9001".into(),
            scope: DelegationScope::RecordAccessDecision,
            iat: 0,
            nbf: 0,
            relay: None,
            request: Some(OperationClaim {
                id: OperationId(id),
                genesis_id: self.block.genesis_id,
                digest: DelegatedOperation::CheckAccess(&hex::encode(self.policy), &request)
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
        IAcp::bearerCheckAccessCall {
            bearerToken: format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())),
            policyId: self.policy,
            request: serde_json::to_vec(&request).unwrap().into(),
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
fn permission_budget_all_routes_accept_exact_allowance_and_reject_one_less() {
    let fixture = Fixture::new();
    for (input, base) in [
        (fixture.query(&issuer()), READ_GAS),
        (fixture.decision(false, &issuer()), WRITE_GAS),
        (fixture.decision(true, &issuer()), WRITE_GAS),
    ] {
        let mut measured = fixture.clone();
        let output = measured.dispatch(&input, 1_000_000).unwrap();
        assert!(
            !output.precompile.status.is_revert(),
            "{:?}",
            output.precompile.bytes
        );
        let required = output.precompile.gas_used;
        assert!(required > base + 60_000 / 16);
        let mut exact = fixture.clone();
        let result = exact.dispatch(&input, required).unwrap();
        assert!(!result.precompile.status.is_revert());
        assert_eq!(result.precompile.bytes, output.precompile.bytes);
        assert_eq!(result.precompile.gas_used, required);
        assert_eq!(exact.state(), measured.state());
        for gas in [base, required - 1] {
            let mut low = fixture.clone();
            assert!(matches!(
                low.dispatch(&input, gas),
                Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
            ));
            assert_eq!(low.state(), fixture.state());
        }
    }
}

#[test]
fn permission_budget_nested_checks_share_remaining_allowance_and_restore_prior_writes() {
    let fixture = Fixture::new();
    let query = fixture.query(&issuer());
    let cost = fixture
        .clone()
        .dispatch(&query, 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    let creation_gas = fixture
        .clone()
        .dispatch(&create(), 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    let input = batch(vec![create(), batch(vec![query.clone(), query.clone()])]);
    let required = creation_gas + 2 * READ_GAS + 2 * cost;
    let result = fixture.clone().dispatch(&input, required).unwrap();
    assert!(!result.precompile.status.is_revert());
    assert_eq!(result.precompile.gas_used, required);
    let mut low = fixture.clone();
    assert!(matches!(
        low.dispatch(&input, required - 1),
        Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
    ));
    assert_eq!(low.state(), fixture.state());
    let repeated = batch(vec![query; batch::MAX_CALLS - 1]);
    batch::validate(&repeated).unwrap();
    assert!(matches!(
        low.dispatch(&repeated, 1_000_000),
        Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
    ));
    assert_eq!(low.state(), fixture.state());
}

#[test]
fn permission_budget_denial_retains_work_and_does_not_mask_exhaustion() {
    let fixture = Fixture::new();
    let query = fixture.query("did:key:stranger");
    let output = fixture.clone().dispatch(&query, 1_000_000).unwrap();
    assert!(!output.precompile.status.is_revert());
    assert!(!IAcp::verifyAccessRequestCall::abi_decode_returns(&output.precompile.bytes).unwrap());
    assert!(output.precompile.gas_used > READ_GAS);
    assert!(matches!(
        fixture
            .clone()
            .dispatch(&query, output.precompile.gas_used - 1),
        Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
    ));
    let creation_gas = fixture
        .clone()
        .dispatch(&create(), 1_000_000)
        .unwrap()
        .precompile
        .gas_used;
    for bearer in [false, true] {
        let call = fixture.decision(bearer, "did:key:stranger");
        let failure = fixture.clone().dispatch(&call, 1_000_000).unwrap();
        assert!(failure.precompile.status.is_revert());
        assert!(failure.precompile.gas_used > WRITE_GAS);
        let mut nested = fixture.clone();
        let result = nested
            .dispatch(&batch(vec![create(), batch(vec![call])]), 1_000_000)
            .unwrap();
        assert!(result.precompile.status.is_revert());
        assert_eq!(
            result.precompile.gas_used,
            creation_gas + 2 * READ_GAS + failure.precompile.gas_used
        );
        assert!(result.logs.is_empty());
        assert_eq!(nested.state(), fixture.state());
    }
}

#[test]
fn permission_budget_cached_bearer_decision_survives_retirement_and_remains_metered() {
    let mut fixture = Fixture::new();
    let call = fixture.decision(true, &issuer());
    let first = fixture.dispatch(&call, 1_000_000).unwrap();
    assert!(
        !first.precompile.status.is_revert(),
        "{:?}",
        first.precompile.bytes
    );
    let delete = IAcp::deletePolicyCall {
        policyId: fixture.policy,
    }
    .abi_encode();
    assert!(
        !fixture
            .dispatch(&delete, 1_000_000)
            .unwrap()
            .precompile
            .status
            .is_revert()
    );
    let before = fixture.state();
    let retry = fixture.dispatch(&call, 1_000_000).unwrap();
    assert!(!retry.precompile.status.is_revert());
    assert_eq!(retry.precompile.bytes, first.precompile.bytes);
    assert!(retry.precompile.gas_used > WRITE_GAS);
    assert_eq!(fixture.state(), before);
    let exact = fixture.dispatch(&call, retry.precompile.gas_used).unwrap();
    assert_eq!(exact.precompile.bytes, first.precompile.bytes);
    assert!(matches!(
        fixture.dispatch(&call, retry.precompile.gas_used - 1),
        Ok(outcome) if matches!(outcome.precompile.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas))
    ));
    assert_eq!(fixture.state(), before);
}

#[test]
fn permission_budget_bearer_bounds_apply_before_owned_decode() {
    for (request, token) in [
        (vec![b' '; (64 << 10) + 1], String::new()),
        (vec![], "x".repeat((16 << 10) + 1)),
    ] {
        let input = IAcp::bearerCheckAccessCall {
            bearerToken: token,
            policyId: B256::ZERO,
            request: request.into(),
        }
        .abi_encode();
        let mut remaining = vera_domain::MAX_TX_BYTES;
        assert!(leaf::validate(&input, &mut remaining).is_err());
        assert_eq!(leaf::required_gas(&input), Some(WRITE_GAS));
    }
}
