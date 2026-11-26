use super::testing::{Authenticator, Signed};
use super::*;

const DIGEST: [u8; 32] = [0x5a; 32];

fn authenticator() -> Authenticator {
    Authenticator::new([7; 32])
}

fn client_data(members: &str) -> Vec<u8> {
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
fn with_client_data(client_data_json: &[u8]) -> Result<(), WebauthnError> {
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
fn chrome_and_platform_client_data_verify() {
    for members in [
        r#","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex""#,
        "",
        r#","androidPackageName":"com.example.app","n":-1.5e+3,"t":true,"z":null"#,
    ] {
        with_client_data(&client_data(members)).unwrap_or_else(|e| panic!("{members}: {e}"));
    }
    let native = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"android:apk-key-hash:AbCdEf0123456789-_"}}"#,
        challenge(&DIGEST)
    );
    with_client_data(native.as_bytes()).unwrap();
}

#[test]
fn values_compare_after_unescaping_and_whitespace_surrounds_tokens() {
    let escaped = format!(
        " \r\n\t{{ \"typ\\u0065\" : \"webauthn\\u002eget\" , \"challenge\":\"{}\\u{}\", \"origin\":\"https:\\/\\/app.example\\ud83d\\ude00\"}} \n",
        &challenge(&DIGEST)[..42],
        format_args!("{:04X}", u32::from(challenge(&DIGEST).as_bytes()[42])),
    );
    with_client_data(escaped.as_bytes()).unwrap();
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
fn cross_origin_and_embedded_ceremonies_are_refused() {
    for members in [
        r#","crossOrigin":true"#,
        r#","crossOrigin":null"#,
        r#","crossOrigin":"false""#,
        r#","topOrigin":"https://other.example""#,
        r#","crossOrigin":false,"topOrigin":"https://app.example""#,
    ] {
        assert_eq!(
            with_client_data(&client_data(members)),
            Err(WebauthnError::CrossOrigin),
            "{members}"
        );
    }
}

#[test]
fn a_repeated_member_is_refused_known_or_unknown() {
    let refused = Err(WebauthnError::ClientData("repeats a member"));
    for members in [
        r#","type":"webauthn.get""#,
        r#","challenge":"x""#,
        r#","origin":"https://app.example""#,
        r#","crossOrigin":false,"crossOrigin":false"#,
        r#","extra":1,"extra":1"#,
        r#","extra":1,"ext\u0072a":2"#,
        r#","typ\u0065":"webauthn.get""#,
    ] {
        assert_eq!(
            with_client_data(&client_data(members)),
            refused,
            "{members}"
        );
    }
}

#[test]
fn member_values_are_scalars() {
    for members in [r#","extra":{}"#, r#","extra":{"a":1}"#, r#","extra":[]"#] {
        assert_eq!(
            with_client_data(&client_data(members)),
            Err(WebauthnError::ClientData("member values must be scalars")),
            "{members}"
        );
    }
    let c = challenge(&DIGEST);
    for data in [
        format!(r#"{{"type":1,"challenge":"{c}","origin":"o"}}"#),
        r#"{"type":"webauthn.get","challenge":null,"origin":"o"}"#.to_owned(),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":false}}"#),
    ] {
        assert_eq!(
            with_client_data(data.as_bytes()),
            Err(WebauthnError::ClientData(
                "type, challenge and origin must be strings"
            )),
            "{data}"
        );
    }
}

#[test]
fn required_members_must_appear() {
    let c = challenge(&DIGEST);
    for data in [
        format!(r#"{{"challenge":"{c}","origin":"o"}}"#),
        r#"{"type":"webauthn.get","origin":"o"}"#.to_owned(),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}"}}"#),
    ] {
        assert_eq!(
            with_client_data(data.as_bytes()),
            Err(WebauthnError::ClientData(
                "type, challenge and origin are required"
            )),
            "{data}"
        );
    }
}

#[test]
fn client_data_is_at_most_1024_bytes_with_an_origin_of_at_most_512() {
    let fill = |length: usize| {
        let base = client_data(r#","pad":"""#).len();
        client_data(&format!(r#","pad":"{}""#, "p".repeat(length - base)))
    };
    with_client_data(&fill(MAX_CLIENT_DATA_BYTES)).unwrap();
    assert_eq!(
        with_client_data(&fill(MAX_CLIENT_DATA_BYTES + 1)),
        Err(WebauthnError::ClientData("longer than 1,024 bytes"))
    );
    let origin = |length: usize| {
        format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
            challenge(&DIGEST),
            "o".repeat(length)
        )
    };
    with_client_data(origin(MAX_ORIGIN_BYTES).as_bytes()).unwrap();
    assert_eq!(
        with_client_data(origin(MAX_ORIGIN_BYTES + 1).as_bytes()),
        Err(WebauthnError::ClientData("origin is too long"))
    );
}

#[test]
fn encoding_and_framing_are_strict() {
    let valid = client_data("");
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (
            [b"\xef\xbb\xbf".as_slice(), &valid].concat(),
            "starts with a byte order mark",
        ),
        ([valid.as_slice(), b"x"].concat(), "data follows the object"),
        (
            [valid.as_slice(), b"{}"].concat(),
            "data follows the object",
        ),
        (
            [valid.as_slice(), b"\0"].concat(),
            "data follows the object",
        ),
        (
            client_data(",\"extra\":\"\u{0}\""),
            "unescaped control character",
        ),
        (client_data(",\"extra\":\"\\x\""), "invalid escape"),
        (client_data(r#","extra":"\u12""#), "invalid escape"),
        (client_data(r#","extra":"\ud800""#), "unpaired surrogate"),
        (
            client_data(r#","extra":"\ud800\u0041""#),
            "unpaired surrogate",
        ),
        (client_data(r#","extra":"\udc00""#), "unpaired surrogate"),
        (client_data(r#","extra":01"#), "not a JSON object"),
        (client_data(r#","extra":1."#), "not a JSON number"),
        (client_data(r#","extra":-"#), "not a JSON number"),
        (client_data(r#","extra":1e"#), "not a JSON number"),
        (client_data(r#","extra":+1"#), "not a JSON value"),
        (client_data(r#","extra":tru"#), "not a JSON value"),
        (client_data(r#","extra":'x'"#), "not a JSON value"),
        (client_data(","), "member names must be strings"),
        (client_data(r#",extra:1"#), "member names must be strings"),
        ([&valid[..valid.len() - 1], b"\xff}"].concat(), "not UTF-8"),
        (b"[]".to_vec(), "not a JSON object"),
        (b"".to_vec(), "not a JSON object"),
        (valid[..valid.len() - 1].to_vec(), "not a JSON object"),
        (b"{}".to_vec(), "type, challenge and origin are required"),
    ];
    for (data, reason) in cases {
        assert_eq!(
            with_client_data(&data),
            Err(WebauthnError::ClientData(reason)),
            "{}",
            String::from_utf8_lossy(&data)
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
