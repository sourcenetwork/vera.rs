use super::testing::{self, Authenticator, Signed};
use super::*;

const DIGEST: [u8; 32] = [0x5a; 32];

fn authenticator() -> Authenticator {
    Authenticator::new([7; 32])
}

pub(super) fn client_data(members: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://app.example"{members}}}"#,
        challenge(&DIGEST)
    )
    .into_bytes()
}

fn check(signed: &Signed) -> Result<(), WebauthnError> {
    verify(
        &authenticator().did(),
        &DIGEST,
        &signed.assertion(),
        &signed.signature,
    )
}

/// Sign `client_data_json` with the default authenticator data, so that only
/// the client data can fail.
pub(super) fn with_client_data(client_data_json: &[u8]) -> Result<(), WebauthnError> {
    let authenticator = authenticator();
    check(&authenticator.sign(&authenticator.authenticator_data(), client_data_json))
}

/// Sign the default client data under authenticator data with `flags`.
fn with_flags(flags: u8) -> Result<(), WebauthnError> {
    let mut authenticator = authenticator();
    authenticator.flags = flags;
    check(&authenticator.assert(&DIGEST))
}

#[test]
fn an_assertion_of_the_digest_verifies() {
    let signed = authenticator().assert(&DIGEST);
    check(&signed).unwrap();
    assert_eq!(challenge(&DIGEST).len(), 43);
}

#[test]
fn the_signature_base_is_fixed() {
    let signed = authenticator().assert(&DIGEST);
    let message = signed.assertion().signed_hash(&DIGEST).unwrap();
    let mut expected = Sha256::new();
    expected.update(&signed.authenticator_data);
    expected.update(Sha256::digest(&signed.client_data_json));
    assert_eq!(message, <[u8; 32]>::from(expected.finalize()));
    assert_eq!(
        String::from_utf8(signed.client_data_json).unwrap(),
        r#"{"type":"webauthn.get","challenge":"WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo","origin":"https://app.example","crossOrigin":false}"#
    );
    assert_eq!(
        hex::encode(message),
        "b1ae41141feaeafd4f38ff9f46f33fd5c50f7ae896d4515a642518d78a0be9cf",
        "the signed message is SHA-256(authenticatorData || SHA-256(clientDataJSON))"
    );
}

#[test]
fn the_counter_relying_party_and_unsigned_flags_are_not_compared() {
    let authenticator = authenticator();
    let mut data = authenticator.authenticator_data();
    data[..32].copy_from_slice(&[0xee; 32]);
    data[33..].copy_from_slice(&[0xff; 4]);
    check(&authenticator.sign(&data, &authenticator.client_data(&DIGEST))).unwrap();
    // Device-bound (no backup flags), backup eligible only, and the reserved bits 1 and 5.
    for flags in [0x05, 0x0d, 0x1d, 0x07, 0x25, 0x3f] {
        with_flags(flags).unwrap_or_else(|e| panic!("{flags:#x}: {e}"));
    }
}

#[test]
fn presence_and_verification_are_required() {
    for flags in [0x1c, 0x19, 0x18, 0x00] {
        assert_eq!(
            with_flags(flags),
            Err(WebauthnError::UserNotVerified),
            "{flags:#x}"
        );
    }
}

#[test]
fn attested_credential_and_extension_data_are_refused() {
    for flags in [0x45, 0x85, 0xc5] {
        assert_eq!(
            with_flags(flags),
            Err(WebauthnError::AuthenticatorDataExtended),
            "{flags:#x}"
        );
    }
}

#[test]
fn a_backup_without_eligibility_is_refused() {
    assert_eq!(with_flags(0x15), Err(WebauthnError::BackupState));
}

#[test]
fn authenticator_data_is_exactly_37_bytes() {
    let authenticator = authenticator();
    let client = authenticator.client_data(&DIGEST);
    let data = authenticator.authenticator_data();
    for length in [0, 36, 38, 37 + 64] {
        let mut resized = data.clone();
        resized.resize(length, 0);
        assert_eq!(
            check(&authenticator.sign(&resized, &client)),
            Err(WebauthnError::AuthenticatorDataLength),
            "{length}"
        );
    }
}

#[test]
fn another_or_respelled_challenge_is_refused() {
    let other = challenge(&[0x5b; 32]);
    let padded = format!("{}=", challenge(&DIGEST));
    let mut trailing_bits = challenge(&DIGEST).into_bytes();
    // `o` and `p` decode to the same 32 bytes: only the last character's low bits differ.
    trailing_bits[42] = if trailing_bits[42] == b'o' {
        b'p'
    } else {
        b'o'
    };
    let trailing_bits = String::from_utf8(trailing_bits).unwrap();
    for spelling in [other, padded, trailing_bits, String::new()] {
        let data = format!(
            r#"{{"type":"webauthn.get","challenge":"{spelling}","origin":"https://app.example"}}"#
        );
        assert_eq!(
            with_client_data(data.as_bytes()),
            Err(WebauthnError::Challenge),
            "{spelling}"
        );
    }
    let digest = [0x41; 32];
    let signed = authenticator().assert(&digest);
    assert_eq!(check(&signed), Err(WebauthnError::Challenge));
}

#[test]
fn a_registration_or_other_ceremony_is_refused() {
    for kind in [
        "webauthn.create",
        "payment.get",
        "webauthn.get ",
        "WEBAUTHN.GET",
    ] {
        let data = format!(
            r#"{{"type":"{kind}","challenge":"{}","origin":"https://app.example"}}"#,
            challenge(&DIGEST)
        );
        assert_eq!(
            with_client_data(data.as_bytes()),
            Err(WebauthnError::CeremonyType),
            "{kind}"
        );
    }
}

#[test]
fn only_a_raw_low_s_signature_by_the_key_verifies() {
    let signed = authenticator().assert(&DIGEST);
    let signature = p256::ecdsa::Signature::from_slice(&signed.signature).unwrap();
    let high = p256::ecdsa::Signature::from_scalars(signature.r(), -*signature.s()).unwrap();
    let mut flipped = signed.signature;
    flipped[10] ^= 1;
    for bad in [
        high.to_vec(),
        signed.der.clone(),
        flipped.to_vec(),
        vec![0; 64],
        signed.signature[..63].to_vec(),
    ] {
        assert_eq!(
            verify(&authenticator().did(), &DIGEST, &signed.assertion(), &bad),
            Err(WebauthnError::Signature)
        );
    }
    let other = Authenticator::new([8; 32]);
    assert_eq!(
        verify(
            &other.did(),
            &DIGEST,
            &signed.assertion(),
            &signed.signature
        ),
        Err(WebauthnError::Signature)
    );
}

/// `r` or `s` equal to or above the P-256 group order `n` is refused.
#[test]
fn a_scalar_at_or_above_the_group_order_is_refused() {
    let order =
        hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
    let mut order_plus_one = order.clone();
    order_plus_one[31] += 1;
    let signed = authenticator().assert(&DIGEST);
    for scalar in [order, order_plus_one, vec![0xff; 32]] {
        for half in [0..32, 32..64] {
            let mut bad = signed.signature;
            bad[half].copy_from_slice(&scalar);
            assert_eq!(
                verify(&authenticator().did(), &DIGEST, &signed.assertion(), &bad),
                Err(WebauthnError::Signature),
                "{}",
                hex::encode(bad)
            );
        }
    }
}

#[test]
fn a_raw_signature_of_the_digest_is_not_an_assertion_and_back() {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let raw: p256::ecdsa::Signature = key.sign_prehash(&DIGEST).unwrap();
    let raw = raw.normalize_s().unwrap_or(raw);
    let signed = authenticator().assert(&DIGEST);
    assert_eq!(
        verify(
            &authenticator().did(),
            &DIGEST,
            &signed.assertion(),
            &raw.to_bytes()
        ),
        Err(WebauthnError::Signature)
    );
    assert!(
        crate::actor::verify_digest(&authenticator().did(), &DIGEST, &signed.signature).is_err()
    );
}

#[test]
fn only_p256_keys_sign_assertions() {
    let signed = authenticator().assert(&DIGEST);
    let ed25519 = crate::actor::ed25519_did(
        &ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let secp256k1 = crate::secp256k1::did_from_secp256k1_pubkey(
        &k256::ecdsa::SigningKey::from_slice(&[1; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_bytes(),
    )
    .unwrap();
    for did in [ed25519.as_str(), &secp256k1, "did:key:zNotAKey"] {
        assert!(matches!(
            verify(did, &DIGEST, &signed.assertion(), &signed.signature),
            Err(WebauthnError::KeyType(_))
        ));
    }
}

#[test]
fn token_signature_segments_split_and_join() {
    let signed = authenticator().assert(&DIGEST);
    let segment = join_token_signature(&signed.assertion(), &signed.signature);
    let (assertion, signature) = split_token_signature(&segment).unwrap();
    assert_eq!(assertion, signed.assertion());
    assert_eq!(signature, signed.signature);
    for length in [0, 101, 101 + MAX_CLIENT_DATA_BYTES + 1] {
        assert_eq!(
            split_token_signature(&vec![b'{'; length]).err(),
            Some(WebauthnError::TokenSignatureLength)
        );
    }
    assert!(split_token_signature(&vec![b'{'; 101 + MAX_CLIENT_DATA_BYTES]).is_ok());
}

/// Assertions captured from Chrome's virtual authenticator, with and without
/// the member Chrome inserts at random, and of a real administrative digest
/// and token challenge.
#[test]
fn chrome_assertions_verify() {
    let mut forms = Vec::new();
    for vector in testing::chrome_vectors() {
        let bytes = |text: &str| hex::decode(text).unwrap();
        let did = vector.did.as_str();
        assert_eq!(
            crate::actor::p256_did(&bytes(&vector.public_key)).unwrap(),
            did
        );
        assert_eq!(Authenticator::new([0x2a; 32]).did(), did);
        let digest: [u8; 32] = bytes(&vector.digest).try_into().unwrap();
        let authenticator_data = bytes(&vector.authenticator_data);
        let assertion = Assertion {
            authenticator_data: &authenticator_data,
            client_data_json: vector.client_data_json.as_bytes(),
        };
        let signature = bytes(&vector.signature);
        assert_eq!(
            crate::actor::canonical_der_signature(did, &bytes(&vector.der_signature)).unwrap(),
            signature
        );
        verify(did, &digest, &assertion, &signature).unwrap();
        assert_eq!(
            verify(did, &[0; 32], &assertion, &signature),
            Err(WebauthnError::Challenge)
        );
        if vector.purpose == "digest" {
            forms.push(vector.client_data_form);
        }
    }
    forms.sort();
    assert_eq!(forms, ["extra", "plain"]);
    for purpose in ["administrative", "token"] {
        assert_eq!(testing::chrome_vector(purpose).purpose, purpose);
    }
}

#[path = "client_data_tests.rs"]
mod client_data_tests;
