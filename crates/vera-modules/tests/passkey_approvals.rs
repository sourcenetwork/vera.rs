//! Administrative requests approved by passkey operators.

use k256::ecdsa::signature::hazmat::PrehashSigner as _;
use vera_crypto::webauthn::testing::{Authenticator, Signed};
use vera_modules::{
    acp::AcpModule,
    vera::{VeraModule, administration::*},
};

const GENESIS: [u8; 32] = [7; 32];

fn recovery() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap()
}

/// An account passkey and a secp256k1 recovery key; either approves alone.
fn policy(passkey: &Authenticator) -> OperatorPolicy {
    let mut keys = vec![
        passkey.did(),
        hex::encode(recovery().verifying_key().to_sec1_bytes()),
    ];
    keys.sort();
    OperatorPolicy { threshold: 1, keys }
}

fn signer(policy: &OperatorPolicy, passkey: &Authenticator) -> u16 {
    policy
        .keys
        .iter()
        .position(|key| *key == passkey.did())
        .unwrap() as u16
}

const fn request(sequence: u64) -> AdministrativeRequest {
    AdministrativeRequest {
        genesis_id: GENESIS,
        sequence,
        expires_at: 100,
        command: AdministrativeCommand::SetPolicyOperationLead(1200),
    }
}

fn approval(signer: u16, signed: &Signed) -> OperatorApproval {
    OperatorApproval {
        signer,
        signature: hex::encode(signed.signature),
        webauthn: Some(PasskeyAssertion::new(
            &signed.authenticator_data,
            &signed.client_data_json,
        )),
    }
}

fn deployment(policy: OperatorPolicy) -> (VeraModule, AcpModule) {
    let mut vera = VeraModule::new();
    vera.initialize_administration(policy).unwrap();
    (vera, AcpModule::new())
}

fn apply(
    vera: &mut VeraModule,
    acp: &mut AcpModule,
    request: AdministrativeRequest,
    approval: OperatorApproval,
) -> Result<(), vera_modules::vera::error::VeraError> {
    let signed = SignedAdministrativeRequest {
        request,
        approvals: vec![approval],
    };
    let decoded: SignedAdministrativeRequest =
        serde_json::from_slice(&serde_json::to_vec(&signed).unwrap()).unwrap();
    vera.apply_administrative_request(acp, GENESIS, 50, &decoded)
}

#[test]
fn a_passkey_operator_approves_a_change() {
    let passkey = Authenticator::new([3; 32]);
    let policy = policy(&passkey);
    let (mut vera, mut acp) = deployment(policy.clone());
    let signed = passkey.assert(&request(0).signing_digest().unwrap());
    apply(
        &mut vera,
        &mut acp,
        request(0),
        approval(signer(&policy, &passkey), &signed),
    )
    .unwrap();
    assert_eq!(vera.administration().unwrap().unwrap().sequence, 1);
}

#[test]
fn the_same_p256_key_still_approves_with_a_raw_signature() {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    let passkey = Authenticator::new([3; 32]);
    let key = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
    let policy = policy(&passkey);
    let (mut vera, mut acp) = deployment(policy.clone());
    let signature: p256::ecdsa::Signature = key
        .sign_prehash(&request(0).signing_digest().unwrap())
        .unwrap();
    let raw = OperatorApproval {
        signer: signer(&policy, &passkey),
        signature: hex::encode(signature.normalize_s().unwrap_or(signature).to_bytes()),
        webauthn: None,
    };
    apply(&mut vera, &mut acp, request(0), raw).unwrap();
}

#[test]
fn an_assertion_replayed_for_another_sequence_is_refused() {
    let passkey = Authenticator::new([3; 32]);
    let policy = policy(&passkey);
    let (mut vera, mut acp) = deployment(policy.clone());
    let index = signer(&policy, &passkey);
    let first = approval(
        index,
        &passkey.assert(&request(0).signing_digest().unwrap()),
    );
    apply(&mut vera, &mut acp, request(0), first.clone()).unwrap();
    let before = vera.store().serialize();
    assert!(apply(&mut vera, &mut acp, request(1), first).is_err());
    assert_eq!(vera.store().serialize(), before);
}

#[test]
fn an_assertion_on_a_secp256k1_entry_is_refused() {
    let passkey = Authenticator::new([3; 32]);
    let policy = policy(&passkey);
    let (mut vera, mut acp) = deployment(policy.clone());
    let digest = request(0).signing_digest().unwrap();
    let signature: k256::ecdsa::Signature = recovery().sign_prehash(&digest).unwrap();
    let signed = passkey.assert(&digest);
    let mut approval = approval(1 - signer(&policy, &passkey), &signed);
    approval.signature = hex::encode(signature.normalize_s().unwrap_or(signature).to_bytes());
    let error = apply(&mut vera, &mut acp, request(0), approval).unwrap_err();
    assert!(error.to_string().contains("P-256"), "{error}");
}

#[test]
fn assertion_fields_are_lowercase_hex_within_bounds() {
    let passkey = Authenticator::new([3; 32]);
    let policy = policy(&passkey);
    let index = signer(&policy, &passkey);
    let digest = request(0).signing_digest().unwrap();
    let valid = approval(index, &passkey.assert(&digest));
    policy.verify_approval(&digest, &valid).unwrap();
    let mut upper = valid.clone();
    upper.webauthn.as_mut().unwrap().client_data_json = valid
        .webauthn
        .as_ref()
        .unwrap()
        .client_data_json
        .to_uppercase();
    let mut prefixed = valid.clone();
    prefixed.webauthn.as_mut().unwrap().authenticator_data = format!(
        "0x{}",
        &valid.webauthn.as_ref().unwrap().authenticator_data[2..]
    );
    let mut short = valid.clone();
    short
        .webauthn
        .as_mut()
        .unwrap()
        .authenticator_data
        .truncate(72);
    let mut long = valid.clone();
    long.webauthn.as_mut().unwrap().client_data_json = "20".repeat(1025);
    for invalid in [upper, prefixed, short, long] {
        assert!(policy.verify_approval(&digest, &invalid).is_err());
    }
    let mut json = serde_json::to_value(&valid).unwrap();
    let mut null = json.clone();
    json["webauthn"]["credential_id"] = "00".into();
    assert!(serde_json::from_value::<OperatorApproval>(json).is_err());
    null["webauthn"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<OperatorApproval>(null.clone()).is_err());
    null.as_object_mut().unwrap().remove("webauthn");
    assert!(
        serde_json::from_value::<OperatorApproval>(null)
            .unwrap()
            .webauthn
            .is_none()
    );
}

#[test]
fn an_assertion_on_an_ed25519_entry_is_refused() {
    use ed25519_dalek::Signer as _;
    let passkey = Authenticator::new([3; 32]);
    let device = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
    let entry = vera_crypto::actor::ed25519_did(&device.verifying_key().to_bytes()).unwrap();
    let policy = OperatorPolicy {
        threshold: 1,
        keys: vec![entry],
    };
    let digest = request(0).signing_digest().unwrap();
    let mut approval = approval(0, &passkey.assert(&digest));
    for signature in [
        approval.signature.clone(),
        hex::encode(device.sign(&digest).to_bytes()),
    ] {
        approval.signature = signature;
        let error = policy.verify_approval(&digest, &approval).unwrap_err();
        assert!(error.to_string().contains("P-256"), "{error}");
    }
    approval.webauthn = None;
    policy.verify_approval(&digest, &approval).unwrap();
}

/// An assertion Chrome made of this request's digest approves it.
#[test]
fn a_chrome_assertion_approves_its_request() {
    let vector = vera_crypto::webauthn::testing::chrome_vector("administrative");
    let digest = request(0).signing_digest().unwrap();
    assert_eq!(hex::encode(digest), vector.digest);
    let policy = OperatorPolicy {
        threshold: 1,
        keys: vec![vector.did.clone()],
    };
    let chrome = OperatorApproval {
        signer: 0,
        signature: vector.signature.clone(),
        webauthn: Some(PasskeyAssertion::new(
            &hex::decode(&vector.authenticator_data).unwrap(),
            vector.client_data_json.as_bytes(),
        )),
    };
    policy.verify_approval(&digest, &chrome).unwrap();
    assert!(
        policy
            .verify_approval(&request(1).signing_digest().unwrap(), &chrome)
            .is_err()
    );
    let (mut vera, mut acp) = deployment(policy);
    apply(&mut vera, &mut acp, request(0), chrome).unwrap();
    assert_eq!(vera.administration().unwrap().unwrap().sequence, 1);
}
