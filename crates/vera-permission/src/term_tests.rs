use alloy_primitives::{Bytes, FixedBytes};
use k256::ecdsa::signature::hazmat::PrehashSigner as _;
use vera_crypto::webauthn::testing::{Authenticator, Signed};
use vera_domain::{TermApproval, TermChange, TermCut, TermPasskeyAssertion};

use super::*;

const GENESIS: B256 = B256::repeat_byte(4);

fn change() -> TermChange {
    TermChange {
        genesis_id: GENESIS,
        term: 3,
        holder: B256::repeat_byte(5),
        cut: TermCut {
            height: 70,
            block: B256::repeat_byte(6),
        },
    }
}

fn account() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap()
}

/// An account passkey and a secp256k1 recovery key, both required.
fn policy(passkey: &Authenticator) -> OperatorPolicy {
    let mut keys = vec![
        passkey.did(),
        hex::encode(account().verifying_key().to_sec1_bytes()),
    ];
    keys.sort();
    OperatorPolicy { threshold: 2, keys }
}

fn index(policy: &OperatorPolicy, entry: &str) -> u16 {
    policy.keys.iter().position(|key| key == entry).unwrap() as u16
}

fn passkey_approval(signer: u16, signed: &Signed) -> TermApproval {
    TermApproval {
        signer,
        signature: FixedBytes::from(signed.signature),
        webauthn: Some(TermPasskeyAssertion {
            authenticator_data: Bytes::copy_from_slice(&signed.authenticator_data),
            client_data_json: Bytes::copy_from_slice(&signed.client_data_json),
        }),
    }
}

fn certificate(passkey: &Authenticator, signed: &Signed) -> TermCertificate {
    let policy = policy(passkey);
    let account_entry = hex::encode(account().verifying_key().to_sec1_bytes());
    let signature: k256::ecdsa::Signature =
        account().sign_prehash(&change().signing_digest()).unwrap();
    let mut approvals = vec![
        passkey_approval(index(&policy, &passkey.did()), signed),
        TermApproval {
            signer: index(&policy, &account_entry),
            signature: FixedBytes::from_slice(
                &signature.normalize_s().unwrap_or(signature).to_bytes(),
            ),
            webauthn: None,
        },
    ];
    approvals.sort_by_key(|approval| approval.signer);
    TermCertificate {
        change: change(),
        approvals,
    }
}

#[test]
fn a_passkey_and_a_raw_key_approve_a_term_together() {
    let passkey = Authenticator::new([8; 32]);
    let signed = passkey.assert(&change().signing_digest());
    let certificate = certificate(&passkey, &signed);
    verify_term_certificate(&certificate, &GENESIS, &policy(&passkey)).unwrap();
    let decoded: TermCertificate =
        serde_json::from_slice(&serde_json::to_vec(&certificate).unwrap()).unwrap();
    verify_term_certificate(&decoded, &GENESIS, &policy(&passkey)).unwrap();
}

#[test]
fn a_passkey_approval_of_another_change_or_without_verification_fails() {
    let passkey = Authenticator::new([8; 32]);
    let signer = index(&policy(&passkey), &passkey.did());
    let mut other = change();
    other.term = 4;
    let mut unverified = passkey.clone();
    unverified.flags = 0x11;
    for signed in [
        passkey.assert(&other.signing_digest()),
        unverified.assert(&change().signing_digest()),
    ] {
        assert_eq!(
            verify_term_certificate(&certificate(&passkey, &signed), &GENESIS, &policy(&passkey)),
            Err(TermError::Signature(signer))
        );
    }
}

#[test]
fn an_assertion_without_its_member_or_on_another_key_fails() {
    let passkey = Authenticator::new([8; 32]);
    let policy = policy(&passkey);
    let signed = passkey.assert(&change().signing_digest());
    let mut certificate = certificate(&passkey, &signed);
    let passkey_index = usize::from(index(&policy, &passkey.did()));
    let mut stripped = certificate.clone();
    stripped.approvals[passkey_index].webauthn = None;
    assert_eq!(
        verify_term_certificate(&stripped, &GENESIS, &policy),
        Err(TermError::Signature(passkey_index as u16))
    );
    let account_index = 1 - passkey_index;
    certificate.approvals[account_index].webauthn =
        certificate.approvals[passkey_index].webauthn.clone();
    assert_eq!(
        verify_term_certificate(&certificate, &GENESIS, &policy),
        Err(TermError::Signature(account_index as u16))
    );
}
