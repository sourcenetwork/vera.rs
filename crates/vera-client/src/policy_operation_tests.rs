use ed25519_dalek::Signer as _;
use vera_crypto::{
    actor::ed25519_did,
    jwt::verify_bearer_token,
    operation::{DEFAULT_OPERATION_LEAD, MAX_OPERATION_LEAD},
};
use vera_modules::acp::types::Object;

use super::*;
use crate::{UnsignedToken, create_operation_token_with_lead};

const POLICY: &str = "0xABCDEF0000000000000000000000000000000000000000000000000000000001";
const ISSUED: u64 = 1_000;
const TWO_HOURS: u64 = 7_200;

fn register(name: &str) -> PolicyCmd {
    PolicyCmd::RegisterObject(Object {
        resource: "file".into(),
        id: name.into(),
    })
}

fn list() -> PolicyOperation {
    PolicyOperation::list(vec![
        (POLICY.into(), register("a")),
        (POLICY.into(), register("b")),
    ])
    .unwrap()
}

fn claims(operation: &PolicyOperation, issuer: &str, lead: u64) -> JwtClaims {
    operation
        .claims(
            issuer,
            "did:key:worker",
            9001,
            [7; 32],
            OperationId::new(ISSUED + lead, [3; 24]),
            ISSUED,
        )
        .unwrap()
}

#[test]
fn policy_identifiers_take_the_spelling_the_node_executes() {
    let normalized = POLICY[2..].to_lowercase();
    let PolicyOperation::List(commands) = list() else {
        panic!("expected a list");
    };
    assert!(
        commands
            .iter()
            .all(|(policy_id, _)| *policy_id == normalized)
    );
    let calldata = list().calldata("token").unwrap();
    let call = IAcp::bearerPolicyCmdsCall::abi_decode(&calldata).unwrap();
    let decoded: Vec<(String, PolicyCmd)> = serde_json::from_slice(&call.commands).unwrap();
    assert_eq!(
        DelegatedOperation::PolicyCommandList(&decoded)
            .digest()
            .unwrap(),
        list().digest().unwrap()
    );
    let single = PolicyOperation::command(POLICY, register("a")).unwrap();
    let call = IAcp::bearerPolicyCmdCall::abi_decode(&single.calldata("token").unwrap()).unwrap();
    let command: PolicyCmd = serde_json::from_slice(&call.cmd).unwrap();
    assert_eq!(
        DelegatedOperation::PolicyCommand(&hex::encode(call.policyId), &command)
            .digest()
            .unwrap(),
        single.digest().unwrap()
    );
    assert_ne!(single.digest().unwrap(), list().digest().unwrap());
}

#[test]
fn a_list_must_hold_valid_policies_and_between_one_and_the_maximum_commands() {
    let too_long = (0..=MAX_POLICY_COMMAND_LIST)
        .map(|index| (POLICY.to_owned(), register(&index.to_string())))
        .collect();
    for commands in [
        Vec::new(),
        too_long,
        vec![("0xabcd".to_owned(), register("a"))],
    ] {
        assert!(PolicyOperation::list(commands).is_err());
    }
}

#[test]
fn an_external_signer_signs_a_long_lived_list_within_the_lead_it_names() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let issuer = ed25519_did(&key.verifying_key().to_bytes()).unwrap();
    let claims = claims(&list(), &issuer, TWO_HOURS);
    assert!(UnsignedToken::operation(&claims).is_err());
    assert!(UnsignedToken::operation_with_lead(&claims, TWO_HOURS - 1).is_err());
    assert!(UnsignedToken::operation_with_lead(&claims, MAX_OPERATION_LEAD + 1).is_err());
    let unsigned = UnsignedToken::operation_with_lead(&claims, TWO_HOURS).unwrap();
    let signature = key.sign(unsigned.signing_input()).to_bytes();
    let decoded = verify_bearer_token(&unsigned.finish(&signature).unwrap()).unwrap();
    assert_eq!(decoded.exp, ISSUED + TWO_HOURS);
    assert_eq!(decoded.scope, DelegationScope::PolicyCommands);
    assert_eq!(decoded.request.unwrap().digest, list().digest().unwrap());
}

#[test]
fn a_lead_beyond_the_default_is_refused_outside_policy_commands() {
    let key = crate::Secp256k1SigningKey::from_bytes((&[42u8; 32]).into()).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_sec1_point(true).as_bytes(),
    )
    .unwrap();
    let mut long = claims(&list(), &issuer, TWO_HOURS);
    let token = create_operation_token_with_lead(&key, &long, TWO_HOURS).unwrap();
    assert_eq!(verify_bearer_token(&token).unwrap().iss, issuer);
    long.scope = DelegationScope::CreatePolicy;
    assert!(create_operation_token_with_lead(&key, &long, TWO_HOURS).is_err());
    let mut short = claims(&list(), &issuer, DEFAULT_OPERATION_LEAD);
    short.scope = DelegationScope::CreatePolicy;
    assert!(create_operation_token_with_lead(&key, &short, DEFAULT_OPERATION_LEAD).is_ok());
}

#[test]
fn a_stored_lead_must_be_eight_bytes_within_its_bounds() {
    assert_eq!(decode_lead(&TWO_HOURS.to_be_bytes()).unwrap(), TWO_HOURS);
    for invalid in [
        vec![0; 7],
        (DEFAULT_OPERATION_LEAD - 1).to_be_bytes().to_vec(),
        (MAX_OPERATION_LEAD + 1).to_be_bytes().to_vec(),
    ] {
        assert!(decode_lead(&invalid).is_err());
    }
}
