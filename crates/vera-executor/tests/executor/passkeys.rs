//! Native requests authorized by passkeys: an administrative change approved
//! by a passkey operator, and a policy created under a passkey delegation.

use super::native_call::{execute_native, member_did};
use alloy_sol_types::SolCall;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use vera_crypto::{
    jwt::WEBAUTHN_TOKEN_TYPE,
    webauthn::{join_token_signature, testing::Authenticator},
};
use vera_executor::{
    ModuleState, VeraExecutor,
    dispatch::{ACP_ADDRESS, VERA_ADDRESS},
};
use vera_modules::{
    acp::abi::IAcp,
    vera::{abi::IVera, administration::*},
};

const GENESIS: [u8; 32] = [7; 32];

fn passkey() -> Authenticator {
    Authenticator::new([21; 32])
}

fn executor(operators: OperatorPolicy) -> VeraExecutor {
    let mut modules = ModuleState::default();
    modules.vera.initialize_administration(operators).unwrap();
    let executor = VeraExecutor::new(9001).with_genesis_id(GENESIS);
    executor.set_base_modules(modules);
    executor
}

fn administration(passkey: &Authenticator, sequence: u64) -> Vec<u8> {
    let request = AdministrativeRequest {
        genesis_id: GENESIS,
        sequence,
        expires_at: 100,
        command: AdministrativeCommand::SetPolicyOperationLead(1200 + sequence),
    };
    let signed = passkey.assert(&request.signing_digest().unwrap());
    let signed = SignedAdministrativeRequest {
        request,
        approvals: vec![OperatorApproval {
            signer: 0,
            signature: hex::encode(signed.signature),
            webauthn: Some(PasskeyAssertion::new(
                &signed.authenticator_data,
                &signed.client_data_json,
            )),
        }],
    };
    IVera::applyAdministrationCall {
        request: serde_json::to_vec(&signed).unwrap().into(),
    }
    .abi_encode()
}

fn sequence(executor: &VeraExecutor) -> u64 {
    let modules = executor.modules();
    let modules = modules.read().unwrap();
    modules.vera.administration().unwrap().unwrap().sequence
}

#[test]
fn a_passkey_operator_approves_an_administrative_request() {
    let passkey = passkey();
    let executor = executor(OperatorPolicy {
        threshold: 1,
        keys: vec![passkey.did()],
    });
    let (outcome, _) = execute_native(VERA_ADDRESS, administration(&passkey, 0), executor.clone());
    assert!(
        outcome.receipts[0].success(),
        "{:?}",
        outcome.receipts[0].refusal
    );
    assert_eq!(sequence(&executor), 1);

    let mut unverified = passkey;
    unverified.flags = 0x01;
    let (outcome, _) = execute_native(
        VERA_ADDRESS,
        administration(&unverified, 1),
        executor.clone(),
    );
    assert!(!outcome.receipts[0].success());
    assert_eq!(sequence(&executor), 1);
}

fn create_policy(token: String) -> Vec<u8> {
    IAcp::bearerCreatePolicyCall {
        bearerToken: token,
        policy: b"name: passkey\nresources:\n  - name: file\n"
            .to_vec()
            .into(),
        marshalType: 1,
        nonce: Default::default(),
    }
    .abi_encode()
}

/// A creation delegation from `passkey` to the native member, signed by the
/// authenticator under the token type `typ`.
fn delegation(passkey: &Authenticator, typ: &str) -> String {
    let header = format!(r#"{{"alg":"ES256","typ":"{typ}"}}"#);
    let claims = serde_json::json!({
        "aud": "vera:9001", "exp": 100, "iat": 0, "iss": passkey.did(), "nbf": 0,
        "scope": "acp:policy:create", "sub": member_did().to_string(),
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signed = passkey.assert(&Sha256::digest(input.as_bytes()).into());
    let segment = join_token_signature(&signed.assertion(), &signed.signature);
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(segment))
}

#[test]
fn a_worker_creates_a_policy_owned_by_a_passkey_account() {
    let passkey = passkey();
    let executor = executor(OperatorPolicy {
        threshold: 1,
        keys: vec![passkey.did()],
    });
    let raw_type = delegation(&passkey, "vera-delegation-v1+jwt");
    let (outcome, modules) = execute_native(ACP_ADDRESS, create_policy(raw_type), executor.clone());
    assert!(!outcome.receipts[0].success());
    assert!(modules.acp.query_policy_ids().unwrap().is_empty());

    let token = delegation(&passkey, WEBAUTHN_TOKEN_TYPE);
    let (outcome, modules) = execute_native(ACP_ADDRESS, create_policy(token), executor);
    assert!(
        outcome.receipts[0].success(),
        "{:?}",
        outcome.receipts[0].refusal
    );
    let ids = modules.acp.query_policy_ids().unwrap();
    let record = modules.acp.query_policy(&ids[0]).unwrap();
    assert_eq!(record.metadata.owner_did, passkey.did());
    assert_eq!(record.metadata.tx_signer, member_did().to_string());
}
