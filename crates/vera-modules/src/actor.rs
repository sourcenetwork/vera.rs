//! The one spelling under which an actor is recorded and compared.
//!
//! A request may name a secp256k1 key in any spelling the delegation verifier
//! accepts. State, results and comparisons use [`vera_crypto::actor::canonical_did`],
//! so one key is one actor. Request digests and operation identities still bind
//! the request as its caller wrote it.

use std::borrow::Cow;

use vera_identity::Did;

/// `did` in the spelling under which its actor is recorded.
pub fn canonical(did: &Did) -> Did {
    match vera_crypto::actor::canonical_did(did.as_str()) {
        Cow::Borrowed(_) => did.clone(),
        Cow::Owned(canonical) => Did::new_unchecked(canonical),
    }
}

/// An identity string in the spelling under which its actor is recorded.
pub fn canonical_str(identity: &str) -> Cow<'_, str> {
    vera_crypto::actor::canonical_did(identity)
}

/// Rewrite an identity string in place when it is not already canonical.
pub(crate) fn canonicalize(identity: &mut String) {
    if let Cow::Owned(canonical) = vera_crypto::actor::canonical_did(identity) {
        *identity = canonical;
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;

    fn spellings() -> [String; 4] {
        let key = k256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
        let bytes = |compressed| {
            let mut bytes = vec![0xe7, 0x01];
            bytes.extend_from_slice(key.verifying_key().to_encoded_point(compressed).as_bytes());
            bytes
        };
        [
            format!("did:key:z{}", bs58::encode(bytes(true)).into_string()),
            format!("did:key:z{}", bs58::encode(bytes(false)).into_string()),
            format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes(true))),
            format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes(false))),
        ]
    }

    #[test]
    fn every_spelling_of_a_key_is_one_did() {
        let [expected, ..] = spellings();
        for spelling in spellings() {
            let did = canonical(&Did::new(&spelling).unwrap());
            assert_eq!(did.as_str(), expected);
            assert_eq!(canonical(&did), did);
            assert_eq!(canonical_str(&spelling), expected);
            let mut identity = spelling;
            canonicalize(&mut identity);
            assert_eq!(identity, expected);
        }
    }

    #[test]
    fn other_identities_are_unchanged() {
        let mut identities = vec![Did::wildcard()];
        for written in [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
            format!("did:opk:{}", "ab".repeat(32)),
            "did:key:alice".to_owned(),
            "did:key:uAQID".to_owned(),
            "did:key:".to_owned(),
        ] {
            identities.push(Did::new(written).unwrap());
        }
        for did in identities {
            assert_eq!(canonical(&did), did);
            assert!(matches!(canonical_str(did.as_str()), Cow::Borrowed(_)));
            let mut identity = did.to_string();
            canonicalize(&mut identity);
            assert_eq!(identity, did.as_str());
        }
        for account in ["", "0xABCD", "worker"] {
            assert!(matches!(canonical_str(account), Cow::Borrowed(_)));
        }
    }
}
