use alloy_primitives::B256;
use vera_crypto::webauthn::testing::{Authenticator, Signed};
use vera_domain::{TermCertificate, TermCut};
use vera_modules::vera::administration::AdministrativeCommand;

use super::*;

/// A policy of a passkey and a secp256k1 key, either of which approves.
fn policy(passkey: &Authenticator) -> (OperatorPolicy, u16) {
    let secp256k1 = k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
    let mut keys = vec![
        passkey.did(),
        hex::encode(secp256k1.verifying_key().to_sec1_bytes()),
    ];
    keys.sort();
    let index = keys.iter().position(|key| *key == passkey.did()).unwrap() as u16;
    (OperatorPolicy { threshold: 1, keys }, index)
}

fn request() -> AdministrativeRequest {
    AdministrativeRequest {
        genesis_id: [1; 32],
        sequence: 3,
        expires_at: 100,
        command: AdministrativeCommand::SetOperationBudget(4096),
    }
}

fn change() -> TermChange {
    TermChange {
        genesis_id: B256::repeat_byte(1),
        term: 1,
        holder: B256::repeat_byte(2),
        cut: TermCut {
            height: 9,
            block: B256::repeat_byte(3),
        },
    }
}

fn parts(signed: &Signed) -> (&[u8], &[u8], &[u8]) {
    (
        &signed.authenticator_data,
        &signed.client_data_json,
        &signed.der,
    )
}

#[test]
fn a_platform_assertion_becomes_an_administrative_approval() {
    let passkey = Authenticator::new([5; 32]);
    let (policy, index) = policy(&passkey);
    let digest = request().signing_digest().unwrap();
    let signed = passkey.assert(&digest);
    let (data, client, der) = parts(&signed);
    let approval = webauthn_approval(&request(), &policy, index, data, client, der).unwrap();
    assert_eq!(approval.signature, hex::encode(signed.signature));
    assert_eq!(approval.webauthn, Some(PasskeyAssertion::new(data, client)));
    policy.verify_approval(&digest, &approval).unwrap();
    let json = serde_json::to_value(&approval).unwrap();
    assert_eq!(json["webauthn"]["authenticator_data"], hex::encode(data));

    let other = AdministrativeRequest {
        sequence: 4,
        ..request()
    };
    assert!(webauthn_approval(&other, &policy, index, data, client, der).is_err());
    assert!(webauthn_approval(&request(), &policy, 1 - index, data, client, der).is_err());
    assert!(
        webauthn_approval(&request(), &policy, index, data, client, &signed.signature).is_err()
    );
}

#[test]
fn a_platform_assertion_becomes_a_term_approval() {
    let passkey = Authenticator::new([5; 32]);
    let (policy, index) = policy(&passkey);
    let signed = passkey.assert(&change().signing_digest());
    let (data, client, der) = parts(&signed);
    let approval = webauthn_term_approval(&change(), &policy, index, data, client, der).unwrap();
    let certificate = TermCertificate {
        change: change(),
        approvals: vec![approval],
    };
    crate::term::verify_term_certificate(&certificate, &B256::repeat_byte(1), &policy).unwrap();
    let json = serde_json::to_value(&certificate).unwrap();
    assert_eq!(
        json["approvals"][0]["webauthn"]["client_data_json"],
        format!("0x{}", hex::encode(client))
    );

    let mut other = change();
    other.term = 2;
    assert!(webauthn_term_approval(&other, &policy, index, data, client, der).is_err());
    let mut unverified = passkey;
    unverified.flags = 0x01;
    let signed = unverified.assert(&change().signing_digest());
    let (data, client, der) = parts(&signed);
    assert!(webauthn_term_approval(&change(), &policy, index, data, client, der).is_err());
}
