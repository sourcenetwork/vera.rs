use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::*;

fn b64(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).unwrap()
}

fn did(codec: u64, key: &[u8]) -> String {
    let mut buffer = [0u8; 10];
    let mut bytes = unsigned_varint::encode::u64(codec, &mut buffer).to_vec();
    bytes.extend_from_slice(key);
    format!("did:key:{}", crate::did_key::encode(&bytes))
}

// RFC 8037, appendix A.4.
const ED25519_KEY: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const ED25519_INPUT: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
const ED25519_SIGNATURE: &str =
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

// RFC 7515, appendix A.3.
const P256_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const P256_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
const P256_INPUT: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
const P256_SIGNATURE: &str =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

fn p256_point(compressed: bool) -> Vec<u8> {
    let mut uncompressed = vec![4];
    uncompressed.extend(b64(P256_X));
    uncompressed.extend(b64(P256_Y));
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed)
        .unwrap()
        .to_encoded_point(compressed)
        .as_bytes()
        .to_vec()
}

#[test]
fn ed25519_rfc8037_signature_verifies_and_alterations_do_not() {
    let actor = ActorKey::from_did(&did(ED25519_MULTICODEC, &b64(ED25519_KEY))).unwrap();
    assert_eq!(actor.algorithm(), "EdDSA");
    let signature = b64(ED25519_SIGNATURE);
    actor.verify(ED25519_INPUT.as_bytes(), &signature).unwrap();

    assert!(actor.verify(b"another input", &signature).is_err());
    let mut flipped = signature.clone();
    flipped[0] ^= 1;
    assert!(actor.verify(ED25519_INPUT.as_bytes(), &flipped).is_err());
    assert!(
        actor
            .verify(ED25519_INPUT.as_bytes(), &signature[..63])
            .is_err()
    );
}

#[test]
fn p256_rfc7515_signature_verifies_only_in_low_s_form() {
    let actor = ActorKey::from_did(&did(P256_MULTICODEC, &p256_point(true))).unwrap();
    assert_eq!(actor.algorithm(), "ES256");
    let published = p256::ecdsa::Signature::from_slice(&b64(P256_SIGNATURE)).unwrap();
    // The published example is high-S. Both forms are valid ECDSA; only one may be a token.
    let low = published.normalize_s().expect("published vector is high-S");
    actor
        .verify(P256_INPUT.as_bytes(), &low.to_bytes())
        .unwrap();
    assert!(
        actor
            .verify(P256_INPUT.as_bytes(), &published.to_bytes())
            .is_err()
    );
    assert!(actor.verify(b"another input", &low.to_bytes()).is_err());
}

#[test]
fn did_key_specification_vectors_decode_to_their_keys() {
    let ed25519 = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
    let ActorKey::Ed25519(key) = ActorKey::from_did(ed25519).unwrap() else {
        panic!("not an Ed25519 key");
    };
    assert_eq!(
        bs58::encode(key.to_bytes()).into_string(),
        "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS"
    );

    // The specification's P-256 example; it publishes no coordinates.
    let p256 = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";
    assert!(matches!(
        ActorKey::from_did(p256).unwrap(),
        ActorKey::P256(_)
    ));
    // RFC 7515's P-256 key under the same multicodec.
    assert!(did(P256_MULTICODEC, &p256_point(true)).starts_with("did:key:zDn"));
    for did in [ed25519, p256] {
        assert_eq!(ActorKey::from_did(did).unwrap().canonical_did(), did);
    }
}

#[test]
fn new_key_types_have_exactly_one_spelling() {
    let ed25519 = b64(ED25519_KEY);
    let base64url = |codec: u64, key: &[u8]| {
        let mut buffer = [0u8; 10];
        let mut bytes = unsigned_varint::encode::u64(codec, &mut buffer).to_vec();
        bytes.extend_from_slice(key);
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes))
    };
    let rejected = [
        // The same keys in a second multibase.
        base64url(ED25519_MULTICODEC, &ed25519),
        base64url(P256_MULTICODEC, &p256_point(true)),
        // An uncompressed P-256 point.
        did(P256_MULTICODEC, &p256_point(false)),
        // Wrong lengths.
        did(ED25519_MULTICODEC, &ed25519[..31]),
        did(P256_MULTICODEC, &p256_point(true)[..32]),
        // The identity point, a small-order Ed25519 key.
        did(ED25519_MULTICODEC, &{
            let mut identity = [0u8; 32];
            identity[0] = 1;
            identity
        }),
        // A key type Vera does not accept (X25519).
        did(0xec, &ed25519),
        "did:web:example.com".to_owned(),
    ];
    for did in rejected {
        assert!(ActorKey::from_did(&did).is_err(), "accepted {did}");
    }
}

#[test]
fn secp256k1_keeps_its_spellings_and_one_canonical_did() {
    let compressed =
        hex_point("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&compressed).unwrap();
    let uncompressed = key.to_encoded_point(false).as_bytes().to_vec();
    let canonical = did(SECP256K1_MULTICODEC, &compressed);
    for spelling in [canonical.clone(), did(SECP256K1_MULTICODEC, &uncompressed)] {
        let actor = ActorKey::from_did(&spelling).unwrap();
        assert_eq!(actor.algorithm(), "ES256K");
        assert_eq!(actor.canonical_did(), canonical);
    }
}

fn hex_point(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
