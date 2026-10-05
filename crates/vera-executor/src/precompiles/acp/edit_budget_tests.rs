use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use vera_modules::acp::{delegated_operation::DelegatedOperation, types::PolicyRecord};
use vera_modules::types::Timestamp;

const POLICY: &str = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n";
const EDITED: &str = "name: files\nresources:\n  - name: file\n";
const FORMAT: PolicyMarshalingType = PolicyMarshalingType::ShortYaml;

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
        let actor = Did::new(&issuer()).unwrap();
        let mut acp = AcpModule::new();
        let policy = acp.create_policy(&actor, POLICY, FORMAT).unwrap().policy.id;
        for command in [
            PolicyCmd::RegisterObject(Object {
                resource: "file".into(),
                id: "report".into(),
            }),
            PolicyCmd::SetRelationship(acp::Relationship::new(
                "file",
                "report",
                "reader",
                acp::Subject::entity(actor.clone()),
            )),
        ] {
            acp.direct_policy_cmd(&actor, &policy, command).unwrap();
        }
        Self {
            acp,
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
                signer: actor.to_string(),
                tx_hash: vec![1; 32],
                sequence: 0,
            },
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

    fn edit(&self, policy: &str, bearer: bool, retryable: bool) -> Vec<u8> {
        if !bearer {
            return IAcp::editPolicyCall {
                policyId: self.policy,
                policy: policy.as_bytes().to_vec().into(),
                marshalType: 1,
            }
            .abi_encode();
        }
        let mut claims = JwtClaims {
            iss: issuer(),
            sub: self.tx.signer.clone(),
            exp: 100,
            aud: "vera:9001".into(),
            scope: DelegationScope::EditPolicy,
            iat: 0,
            nbf: 0,
            relay: None,
            request: None,
        };
        if retryable {
            let mut id = [17; 32];
            id[..8].copy_from_slice(&100u64.to_be_bytes());
            claims.request = Some(OperationClaim {
                id: OperationId(id),
                genesis_id: self.block.genesis_id,
                digest: DelegatedOperation::EditPolicy(&hex::encode(self.policy), policy, &FORMAT)
                    .digest()
                    .unwrap(),
            });
        }
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#);
        let message = format!(
            "{header}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key().sign(message.as_bytes());
        let token = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        IAcp::bearerEditPolicyCall {
            bearerToken: token,
            policyId: self.policy,
            policy: policy.as_bytes().to_vec().into(),
            marshalType: 1,
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

fn earlier_write() -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: Bytes::from_static(b"name: preceding\nresources:\n  - name: file\n"),
        marshalType: 1,
    }
    .abi_encode()
}

#[test]
fn direct_and_bearer_policy_edit_accept_exact_work_gas_and_reject_one_less() {
    for bearer in [false, true] {
        let fixture = Fixture::new();
        let input = fixture.edit(EDITED, bearer, false);
        let mut measured = fixture.clone();
        let output = measured.dispatch(&input, 1_000_000).unwrap();
        assert!(!output.precompile.reverted);
        assert!(output.precompile.gas_used > WRITE_GAS);
        assert_eq!(output.logs.len(), 1);
        // The direct and bearer methods have the same return ABI.
        let decoded = IAcp::editPolicyCall::abi_decode_returns(&output.precompile.bytes).unwrap();
        assert_eq!(decoded.relationshipsRemoved, 1);
        let record: PolicyRecord = serde_json::from_slice(&decoded.record).unwrap();
        assert_eq!(record.last_modified, Some(fixture.block.timestamp.clone()));
        let mut exact = fixture.clone();
        let result = exact.dispatch(&input, output.precompile.gas_used).unwrap();
        assert_eq!(result.precompile.gas_used, output.precompile.gas_used);
        assert_eq!(result.precompile.bytes, output.precompile.bytes);
        assert_eq!(exact.state(), measured.state());
        for gas in [WRITE_GAS, output.precompile.gas_used - 1] {
            let mut low = fixture.clone();
            assert!(matches!(
                low.dispatch(&input, gas),
                Err(PrecompileError::OutOfGas)
            ));
            assert_eq!(low.state(), fixture.state());
        }
    }
}

#[test]
fn ordinary_failed_edits_charge_completed_work_and_preserve_state() {
    for bearer in [false, true] {
        let fixture = Fixture::new();
        let input = fixture.edit("resources: [", bearer, false);
        let mut measured = fixture.clone();
        let failure = measured.dispatch(&input, 1_000_000).unwrap();
        assert!(failure.precompile.reverted);
        assert!(failure.precompile.gas_used > WRITE_GAS);
        assert!(failure.logs.is_empty());
        assert_eq!(measured.state(), fixture.state());
        let mut exact = fixture.clone();
        let result = exact.dispatch(&input, failure.precompile.gas_used).unwrap();
        assert!(result.precompile.reverted);
        assert_eq!(result.precompile.gas_used, failure.precompile.gas_used);
        assert_eq!(result.precompile.bytes, failure.precompile.bytes);
        let mut low = fixture.clone();
        assert!(matches!(
            low.dispatch(&input, failure.precompile.gas_used - 1),
            Err(PrecompileError::OutOfGas)
        ));
        assert_eq!(low.state(), fixture.state());
    }
}

#[test]
fn nested_policy_edit_work_uses_remaining_gas_and_rolls_back_preceding_writes() {
    let fixture = Fixture::new();
    let input = batch(vec![
        earlier_write(),
        batch(vec![fixture.edit(EDITED, false, false)]),
    ]);
    let mut measured = fixture.clone();
    let output = measured.dispatch(&input, 1_000_000).unwrap();
    assert!(!output.precompile.reverted);
    assert_eq!(output.logs.len(), 2);
    let mut edit_only = fixture.clone();
    let edit = edit_only
        .dispatch(&fixture.edit(EDITED, false, false), 1_000_000)
        .unwrap();
    assert_eq!(
        output.precompile.gas_used,
        2 * READ_GAS + WRITE_GAS + edit.precompile.gas_used
    );
    let mut exact = fixture.clone();
    let result = exact.dispatch(&input, output.precompile.gas_used).unwrap();
    assert!(!result.precompile.reverted);
    assert_eq!(exact.state(), measured.state());
    let mut low = fixture.clone();
    assert!(matches!(
        low.dispatch(&input, output.precompile.gas_used - 1),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(low.state(), fixture.state());
}

#[test]
fn nested_failed_edit_keeps_work_charges_but_no_writes_or_logs() {
    let fixture = Fixture::new();
    let edit = fixture.edit("resources: [", true, false);
    let mut single = fixture.clone();
    let failure = single.dispatch(&edit, 1_000_000).unwrap();
    let input = batch(vec![earlier_write(), batch(vec![edit])]);
    let mut nested = fixture.clone();
    let result = nested.dispatch(&input, 1_000_000).unwrap();
    assert!(result.precompile.reverted);
    assert_eq!(
        result.precompile.gas_used,
        2 * READ_GAS + WRITE_GAS + failure.precompile.gas_used
    );
    assert!(result.logs.is_empty());
    assert_eq!(nested.state(), fixture.state());
}

#[test]
fn bearer_retry_after_retirement_is_metered_without_reading_current_policy() {
    let mut fixture = Fixture::new();
    let input = fixture.edit(EDITED, true, true);
    let first = fixture.dispatch(&input, 1_000_000).unwrap();
    assert!(
        !first.precompile.reverted,
        "{}",
        String::from_utf8_lossy(&first.precompile.bytes)
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
            .reverted
    );
    let before = fixture.state();
    let mut measured = fixture.clone();
    let retry = measured.dispatch(&input, 1_000_000).unwrap();
    assert!(
        !retry.precompile.reverted,
        "{}",
        String::from_utf8_lossy(&retry.precompile.bytes)
    );
    assert!(retry.precompile.gas_used > WRITE_GAS);
    assert_eq!(retry.precompile.bytes, first.precompile.bytes);
    assert_eq!(measured.state(), before);
    let mut exact = fixture.clone();
    let output = exact.dispatch(&input, retry.precompile.gas_used).unwrap();
    assert!(!output.precompile.reverted);
    assert_eq!(output.precompile.bytes, first.precompile.bytes);
    assert_eq!(exact.state(), before);
    assert!(matches!(
        fixture.dispatch(&input, retry.precompile.gas_used - 1),
        Err(PrecompileError::OutOfGas)
    ));
    assert_eq!(fixture.state(), before);
}
