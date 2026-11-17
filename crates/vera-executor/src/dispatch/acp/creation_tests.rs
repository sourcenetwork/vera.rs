use super::*;
use crate::dispatch::{ModuleError, ModuleStatus};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use vera_modules::acp::{
    delegated_operation::DelegatedOperation,
    types::{PolicyCreation, PolicyRecord, SuppliedMetadata},
};
use vera_modules::types::Timestamp;

const POLICY: &str = "name: creation\nresources:\n  - name: file\n";
#[derive(Clone)]
struct Fixture {
    acp: AcpModule,
    vera: VeraModule,
    block: BlockExecCtx,
    tx: TxExecCtx,
}
impl Fixture {
    fn new() -> Self {
        Self {
            acp: AcpModule::new(),
            vera: VeraModule::new(),
            block: BlockExecCtx {
                timestamp: Timestamp {
                    seconds: 10,
                    block_height: 1,
                },
                deployment_id: 9001,
                genesis_id: [7; 32],
            },
            tx: TxExecCtx {
                signer: issuer(),
                tx_hash: vec![1; 32],
                sequence: 0,
            },
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
    fn bearer(&self) -> Vec<u8> {
        let mut id = [17; 32];
        id[..8].copy_from_slice(&100u64.to_be_bytes());
        let claims = JwtClaims {
            iss: issuer(),
            sub: self.tx.signer.clone(),
            exp: 100,
            aud: "vera:9001".into(),
            scope: DelegationScope::CreatePolicy,
            iat: 0,
            nbf: 0,
            relay: None,
            request: Some(OperationClaim {
                id: OperationId(id),
                genesis_id: self.block.genesis_id,
                digest: DelegatedOperation::CreatePolicy(
                    POLICY,
                    &PolicyMarshalingType::ShortYaml,
                    &Default::default(),
                )
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
        IAcp::bearerCreatePolicyCall {
            bearerToken: format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())),
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
            nonce: Default::default(),
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
fn direct(policy: &str) -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: policy.as_bytes().to_vec().into(),
        marshalType: 1,
        nonce: Default::default(),
    }
    .abi_encode()
}
fn options() -> Vec<u8> {
    IAcp::createPolicyWithOptionsCall {
        request: serde_json::to_vec(&PolicyCreation {
            policy: POLICY.into(),
            marshal_type: PolicyMarshalingType::ShortYaml,
            required_specification: None,
            metadata: SuppliedMetadata {
                attributes: [("note".into(), "x".repeat(60 << 10))].into(),
                ..Default::default()
            },
            nonce: vera_modules::acp::types::PolicyNonce([1; 32]),
        })
        .unwrap()
        .into(),
    }
    .abi_encode()
}
fn batch(calls: Vec<Vec<u8>>) -> Vec<u8> {
    IAcp::batchCallsCall {
        calls: calls.into_iter().map(Into::into).collect(),
    }
    .abi_encode()
}

#[test]
fn all_creation_routes_charge_exact_work_and_preserve_state_one_unit_short() {
    let fixture = Fixture::new();
    for input in [direct(POLICY), options(), fixture.bearer()] {
        let mut measured = fixture.clone();
        let output = measured.dispatch(&input, 1_000_000).unwrap();
        assert!(
            !output.output.status.is_revert(),
            "{:?}",
            output.output.bytes
        );
        let required = output.output.gas_used;
        assert!(required > WRITE_GAS);
        let mut exact = fixture.clone();
        let result = exact.dispatch(&input, required).unwrap();
        assert_eq!(result.output.bytes, output.output.bytes);
        assert_eq!(result.output.gas_used, required);
        assert_eq!(exact.state(), measured.state());
        for gas in [WRITE_GAS, required - 1] {
            let mut short = fixture.clone();
            assert!(matches!(
                short.dispatch(&input, gas),
                Ok(outcome) if matches!(outcome.output.status, ModuleStatus::OutOfGas)
            ));
            assert_eq!(short.state(), fixture.state());
        }
    }
}

#[test]
fn options_decode_charges_whitespace_and_malformed_json_before_allocation() {
    let mut fixture = Fixture::new();
    let before = fixture.state();
    let request = serde_json::to_vec(&PolicyCreation {
        policy: POLICY.into(),
        marshal_type: PolicyMarshalingType::ShortYaml,
        required_specification: None,
        metadata: Default::default(),
        nonce: Default::default(),
    })
    .unwrap();
    let mut padded = vec![b' '; 128 << 10];
    padded.extend_from_slice(&request);
    let input = IAcp::createPolicyWithOptionsCall {
        request: padded.into(),
    }
    .abi_encode();
    assert!(matches!(
        fixture.dispatch(&input, WRITE_GAS + 1_000),
        Ok(outcome) if matches!(outcome.output.status, ModuleStatus::OutOfGas)
    ));
    assert_eq!(fixture.state(), before);
    let result = fixture.dispatch(&input, 1_000_000).unwrap();
    assert!(!result.output.status.is_revert());
    assert!(result.output.gas_used > WRITE_GAS + (128 << 10) / 2);
    for input in [
        IAcp::createPolicyWithOptionsCall {
            request: vec![b'!'; 128 << 10].into(),
        }
        .abi_encode(),
        direct("resources: ["),
    ] {
        let before = fixture.state();
        let failure = fixture.dispatch(&input, 1_000_000).unwrap();
        assert!(failure.output.status.is_revert());
        assert!(failure.output.gas_used > WRITE_GAS);
        assert_eq!(fixture.state(), before);
        assert!(matches!(
            fixture.dispatch(&input, failure.output.gas_used - 1),
            Ok(outcome) if matches!(outcome.output.status, ModuleStatus::OutOfGas)
        ));
    }
}

#[test]
fn nested_and_repeated_creation_share_remaining_work_and_roll_back_allocations() {
    let fixture = Fixture::new();
    let input = batch(vec![direct(POLICY), batch(vec![options()])]);
    let mut measured = fixture.clone();
    let output = measured.dispatch(&input, 1_000_000).unwrap();
    assert!(!output.output.status.is_revert());
    let mut exact = fixture.clone();
    assert!(
        !exact
            .dispatch(&input, output.output.gas_used)
            .unwrap()
            .output
            .status
            .is_revert()
    );
    assert_eq!(exact.state(), measured.state());
    let mut short = fixture.clone();
    assert!(matches!(
        short.dispatch(&input, output.output.gas_used - 1),
        Ok(outcome) if matches!(outcome.output.status, ModuleStatus::OutOfGas)
    ));
    assert_eq!(short.state(), fixture.state());
    let large = format!("{POLICY}# {}", "x".repeat(60 << 10));
    let repeated = batch(
        (0..32u8)
            .map(|index| {
                IAcp::createPolicyCall {
                    policy: large.as_bytes().to_vec().into(),
                    marshalType: 1,
                    nonce: [index; 32].into(),
                }
                .abi_encode()
            })
            .collect(),
    );
    batch::validate(&repeated).unwrap();
    assert!(matches!(
        short.dispatch(&repeated, 1_000_000),
        Ok(outcome) if matches!(outcome.output.status, ModuleStatus::OutOfGas)
    ));
    assert_eq!(short.state(), fixture.state());
    let malformed = IAcp::createPolicyWithOptionsCall {
        request: b"!".to_vec().into(),
    }
    .abi_encode();
    let failure = short
        .dispatch(
            &batch(vec![direct(POLICY), batch(vec![malformed])]),
            1_000_000,
        )
        .unwrap();
    assert!(failure.output.status.is_revert());
    assert!(failure.output.gas_used > WRITE_GAS + 2 * READ_GAS);
    assert!(failure.logs.is_empty());
    assert_eq!(short.state(), fixture.state());
}

#[test]
fn authenticated_creation_retry_after_retirement_is_metered_and_does_not_reallocate() {
    let mut fixture = Fixture::new();
    let input = fixture.bearer();
    let original = fixture.dispatch(&input, 1_000_000).unwrap();
    assert!(!original.output.status.is_revert());
    let bytes = IAcp::bearerCreatePolicyCall::abi_decode_returns(&original.output.bytes).unwrap();
    let policy: PolicyRecord = serde_json::from_slice(&bytes).unwrap();
    fixture
        .acp
        .delete_policy(&Did::new(issuer()).unwrap(), &policy.policy.id.to_string())
        .unwrap();
    let before = fixture.state();
    let retry = fixture.dispatch(&input, 1_000_000).unwrap();
    assert_eq!(retry.output.bytes, original.output.bytes);
    assert!(retry.output.gas_used > WRITE_GAS);
    assert_eq!(fixture.state(), before);
    assert_eq!(
        fixture
            .dispatch(&input, retry.output.gas_used)
            .unwrap()
            .output
            .bytes,
        original.output.bytes
    );
    assert!(matches!(
        fixture.dispatch(&input, retry.output.gas_used - 1),
        Ok(outcome) if matches!(outcome.output.status, ModuleStatus::OutOfGas)
    ));
    assert_eq!(fixture.state(), before);
}

#[test]
fn creation_preflight_preserves_definition_and_token_limits() {
    for input in [
        direct(&"x".repeat((64 << 10) + 1)),
        IAcp::bearerCreatePolicyCall {
            bearerToken: "x".repeat((16 << 10) + 1),
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
            nonce: Default::default(),
        }
        .abi_encode(),
    ] {
        let mut budget = vera_domain::MAX_TX_BYTES;
        assert!(leaf::validate(&input, &mut budget).is_err());
        assert_eq!(leaf::required_gas(&input), Some(WRITE_GAS));
    }
    let mut bytes = POLICY.as_bytes().to_vec();
    bytes.resize(64 << 10, b' ');
    let input = IAcp::createPolicyCall {
        policy: bytes.into(),
        marshalType: 1,
        nonce: Default::default(),
    }
    .abi_encode();
    let mut budget = vera_domain::MAX_TX_BYTES;
    leaf::validate(&input, &mut budget).unwrap();
}

#[test]
fn a_malformed_derived_signer_is_a_node_fault_on_every_creation_route() {
    let mut fixture = Fixture::new();
    fixture.tx.signer = "malformed".into();
    let before = fixture.state();
    for input in [
        direct(POLICY),
        options(),
        batch(vec![direct(POLICY)]),
        batch(vec![options()]),
    ] {
        let fault = fixture.dispatch(&input, 10_000_000).unwrap_err();
        assert!(matches!(fault, ModuleError::Fault(_)), "{fault}");
    }
    assert_eq!(fixture.state(), before);

    fixture.tx.signer = String::new();
    for input in [direct(POLICY), options()] {
        let refusal = fixture.dispatch(&input, 10_000_000).unwrap();
        assert!(refusal.output.status.is_revert());
        assert!(
            String::from_utf8_lossy(&refusal.output.bytes)
                .contains("requires an authenticated caller")
        );
    }
    assert_eq!(fixture.state(), before);
}
