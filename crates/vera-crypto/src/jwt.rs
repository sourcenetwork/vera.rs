//! JWT verification for bearer token authentication.
//!
//! Verifies delegation tokens signed with ES256K (secp256k1), EdDSA (Ed25519)
//! or ES256 (P-256). The issuer (`iss`) claim is a `did:key:` identifier; its
//! key verifies the signature and fixes the algorithm the header must name.
//! Relay tokens are ES256K only.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::actor_key::ActorKey;

/// Operations an actor authorizes a worker to submit.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub enum DelegationScope {
    /// Object registration, archival and relationship commands.
    #[serde(rename = "acp:policy")]
    PolicyCommands,
    /// Create policies owned by the actor.
    #[serde(rename = "acp:policy:create")]
    CreatePolicy,
    /// Edit policies owned by the actor.
    #[serde(rename = "acp:policy:edit")]
    EditPolicy,
    /// Record a successful access decision for the requested actor and operations.
    #[serde(rename = "acp:access:record")]
    RecordAccessDecision,
    /// Create and manage threshold-service rings under ACP authority.
    #[serde(rename = "orbis:ring")]
    ManageRings,
    /// Register encrypted documents and signing derivations.
    #[serde(rename = "orbis:object:store")]
    StoreThresholdObject,
}

/// Verified claims extracted from a JWT bearer token.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtClaims {
    /// Issuer: a secp256k1, Ed25519 or P-256 `did:key:` identifier.
    pub iss: String,
    /// Authenticated submitting identity.
    pub sub: String,
    /// Expiry in Unix seconds; the caller must check it against execution time.
    pub exp: u64,
    /// Deployment audience, formatted as `vera:<deployment_id>`.
    pub aud: String,
    /// Delegated operation scope.
    pub scope: DelegationScope,
    /// Issuance time in Unix seconds.
    pub iat: u64,
    /// Earliest execution time in Unix seconds.
    pub nbf: u64,
    /// Relay assertion, accepted only under an active operator-authorized grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayAssertion>,
    /// Optional caller operation identity; execution must verify its exact request binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<crate::operation::OperationClaim>,
}

/// Provider identity attested by an explicitly authorized relay.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAssertion {
    /// Stable identity authenticated by the relay.
    pub actor: String,
    /// Exact genesis identity of the deployment.
    pub genesis_id: [u8; 32],
    /// Administrative sequence that installed the current relay grant.
    pub grant_sequence: u64,
    /// Digest of the exact delegated operation, excluding its bearer token.
    pub operation: [u8; 32],
}

impl JwtClaims {
    /// Actor identity; relay claims still require committed grant verification.
    pub fn actor(&self) -> &str {
        self.relay.as_ref().map_or(&self.iss, |relay| &relay.actor)
    }

    /// Check the authenticated caller, deployment and agreed execution time.
    pub fn authorize(&self, submitter: &str, deployment_id: u64, now: u64) -> Result<(), JwtError> {
        if self.sub != submitter || self.aud != format!("vera:{deployment_id}") {
            return Err(JwtError::InvalidClaims(
                "caller or deployment mismatch".into(),
            ));
        }
        if now < self.nbf || now > self.exp {
            return Err(JwtError::InvalidClaims(
                "token is outside its validity interval".into(),
            ));
        }
        Ok(())
    }
}

/// Errors from JWT verification.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// Required delegation claims are invalid.
    #[error("invalid delegation claims: {0}")]
    InvalidClaims(String),
    /// Token does not have exactly three `.`-separated segments.
    #[error("malformed token: {0}")]
    MalformedToken(String),
    /// Header names an algorithm the issuer's key type does not sign with.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Signature verification failed, or the signature encoding is not canonical.
    #[error("invalid signature")]
    InvalidSignature,
    /// The `iss` claim is not a supported, canonically spelled `did:key:`.
    #[error("invalid issuer: {0}")]
    InvalidIssuer(String),
    /// Payload decoding or deserialization failed.
    #[error("payload decode: {0}")]
    PayloadDecode(String),
}

/// Verify a JWT bearer token against the key its `did:key:` issuer names.
///
/// Returns the verified claims on success. The header's `alg` must be the one
/// the issuer's key type signs with.
pub fn verify_bearer_token(token: &str) -> Result<JwtClaims, JwtError> {
    if token.len() > 16 * 1024 {
        return Err(JwtError::MalformedToken("token exceeds 16 KiB".into()));
    }
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::MalformedToken("expected three segments".into()));
    };
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Header {
        alg: String,
        typ: String,
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| JwtError::MalformedToken(format!("header base64: {e}")))?;
    let header: Header = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwtError::MalformedToken(format!("header JSON: {e}")))?;
    if !matches!(header.alg.as_str(), "ES256K" | "EdDSA" | "ES256") {
        return Err(JwtError::UnsupportedAlgorithm(header.alg));
    }
    if header.typ != "vera-delegation-v1+jwt" && header.typ != "vera-relay-v1+jwt" {
        return Err(JwtError::InvalidClaims("unsupported token type".into()));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| JwtError::PayloadDecode(format!("payload base64: {e}")))?;
    let raw: JwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwtError::PayloadDecode(format!("payload JSON: {e}")))?;
    if raw.relay.is_some() != (header.typ == "vera-relay-v1+jwt") {
        return Err(JwtError::InvalidClaims(
            "token type and relay claims differ".into(),
        ));
    }

    let issuer = ActorKey::from_did(&raw.iss)?;
    if issuer.algorithm() != header.alg
        || (raw.relay.is_some() && !matches!(issuer, ActorKey::Secp256k1(_)))
    {
        return Err(JwtError::UnsupportedAlgorithm(header.alg));
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| JwtError::MalformedToken(format!("signature base64: {e}")))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    issuer.verify(signing_input.as_bytes(), &sig_bytes)?;

    if raw.sub.is_empty() || raw.nbf > raw.iat || raw.iat >= raw.exp {
        return Err(JwtError::InvalidClaims(
            "invalid subject or validity interval".into(),
        ));
    }
    Ok(raw)
}

/// Canonical compressed key DID used to identify an authorized relay.
///
/// Relays are secp256k1 keys; any other issuer is rejected.
pub fn canonical_issuer(issuer: &str) -> Result<String, JwtError> {
    match ActorKey::from_did(issuer)? {
        key @ ActorKey::Secp256k1(_) => Ok(key.canonical_did()),
        _ => Err(JwtError::InvalidIssuer("not a secp256k1 did:key".into())),
    }
}

/// The single DID under which a delegation actor of any supported key type is recorded.
pub fn canonical_actor(actor: &str) -> Result<String, JwtError> {
    ActorKey::from_did(actor).map(|key| key.canonical_did())
}

/// Match an issuer for revocation, including compressed and uncompressed key DIDs.
/// This does not change the issuer identity recorded in policies or token indexes.
pub fn matches_issuer(issuer: &str, caller: &str) -> bool {
    issuer == caller
        || match (ActorKey::from_did(issuer), ActorKey::from_did(caller)) {
            (Ok(issuer), Ok(caller)) => issuer == caller,
            _ => false,
        }
}

#[cfg(test)]
#[path = "jwt_key_type_tests.rs"]
mod key_type_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{Signature, SigningKey};
    use sha2::{Digest as _, Sha256};

    #[test]
    fn issuer_revocation_matches_key_encodings() {
        let key = SigningKey::from_slice(&[42; 32]).unwrap();
        let did = |compressed| {
            let mut bytes = vec![0xe7, 0x01];
            bytes.extend_from_slice(key.verifying_key().to_encoded_point(compressed).as_bytes());
            format!("did:key:{}", crate::did_key::encode(&bytes))
        };
        assert!(matches_issuer(&did(true), &did(false)));
        assert!(matches_issuer(&did(false), &did(true)));
        let other = SigningKey::from_slice(&[43; 32]).unwrap();
        let other = crate::secp256k1::did_from_secp256k1_pubkey(
            other.verifying_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap();
        assert!(!matches_issuer(&did(false), &other));
        assert!(!matches_issuer("invalid", &did(true)));
    }

    #[test]
    fn issuer_matches_base58_and_base64url_key_forms() {
        let key = SigningKey::from_slice(&[42; 32]).unwrap();
        let mut bytes = vec![0xe7, 0x01];
        bytes.extend_from_slice(key.verifying_key().to_encoded_point(true).as_bytes());
        let base58 = format!("did:key:{}", crate::did_key::encode(&bytes));
        let base64 = format!("did:key:u{}", URL_SAFE_NO_PAD.encode(&bytes));
        assert!(matches_issuer(&base58, &base64));
        assert_eq!(
            canonical_issuer(&base58).unwrap(),
            canonical_issuer(&base64).unwrap()
        );
        assert_eq!(
            crate::secp256k1::evm_address_from_did(&base58).unwrap(),
            crate::secp256k1::evm_address_from_did(&base64).unwrap(),
        );
        assert!(canonical_issuer("did:key:z0").is_err());
        assert!(canonical_issuer("did:key:uAA=").is_err());
    }

    fn create_jwt(signing_key: &SigningKey, claims_json: &str) -> String {
        let mut claims: serde_json::Value = serde_json::from_str(claims_json).unwrap();
        claims["aud"] = "vera:9001".into();
        claims["scope"] = "acp:policy".into();
        claims["iat"] = 1.into();
        claims["nbf"] = 1.into();
        if claims.get("sub").is_none() {
            claims["sub"] = "caller".into();
        }
        let claims_json = serde_json::to_string(&claims).unwrap();
        let header = r#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let digest = Sha256::digest(signing_input.as_bytes());

        let (sig, _): (Signature, _) = signing_key
            .sign_prehash_recoverable(digest.as_ref())
            .expect("signing should succeed");
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    fn test_key_and_did() -> (SigningKey, String) {
        let secret = [42u8; 32];
        let signing_key = SigningKey::from_bytes((&secret).into()).unwrap();
        let compressed = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let did = crate::secp256k1::did_from_secp256k1_pubkey(&compressed).unwrap();
        (signing_key, did)
    }

    #[test]
    fn verify_valid_token() {
        let (sk, did) = test_key_and_did();
        let claims = format!(r#"{{"iss":"{did}","sub":"policy-ctx","exp":9999999999}}"#);
        let token = create_jwt(&sk, &claims);

        let result = verify_bearer_token(&token).unwrap();
        assert_eq!(result.iss, did);
        assert_eq!(result.sub, "policy-ctx");
        assert_eq!(result.exp, 9_999_999_999);
    }

    #[test]
    fn verify_base64url_issuer_with_compressed_and_uncompressed_keys() {
        let (sk, _) = test_key_and_did();
        for compressed in [true, false] {
            let mut key = vec![0xe7, 0x01];
            key.extend_from_slice(sk.verifying_key().to_encoded_point(compressed).as_bytes());
            let did = format!("did:key:u{}", URL_SAFE_NO_PAD.encode(key));
            let claims = format!(r#"{{"iss":"{did}","sub":"policy-ctx","exp":9999999999}}"#);
            let token = create_jwt(&sk, &claims);
            assert_eq!(verify_bearer_token(&token).unwrap().iss, did);
        }
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, did) = test_key_and_did();
        let claims = format!(r#"{{"iss":"{did}","sub":"original","exp":0}}"#);
        let token = create_jwt(&sk, &claims);

        let parts: Vec<&str> = token.split('.').collect();
        let mut tampered_claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        tampered_claims["sub"] = "tampered".into();
        let tampered_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered_claims).unwrap());
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        assert!(matches!(
            verify_bearer_token(&tampered_token),
            Err(JwtError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (_sk_a, did_a) = test_key_and_did();
        let sk_b = SigningKey::from_bytes((&[99u8; 32]).into()).unwrap();

        let claims = format!(r#"{{"iss":"{did_a}","sub":"test","exp":0}}"#);
        let token = create_jwt(&sk_b, &claims);

        assert!(matches!(
            verify_bearer_token(&token),
            Err(JwtError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_rejects_non_es256k() {
        let (sk, did) = test_key_and_did();
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let claims = format!(r#"{{"iss":"{did}","sub":"test","exp":0}}"#);

        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let digest = Sha256::digest(signing_input.as_bytes());
        let (sig, _): (Signature, _) = sk.sign_prehash_recoverable(digest.as_ref()).unwrap();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");

        assert!(matches!(
            verify_bearer_token(&token),
            Err(JwtError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn verify_rejects_malformed() {
        assert!(matches!(
            verify_bearer_token(""),
            Err(JwtError::MalformedToken(_))
        ));
        assert!(matches!(
            verify_bearer_token("a.b"),
            Err(JwtError::MalformedToken(_))
        ));
        assert!(matches!(
            verify_bearer_token("a.b.c.d"),
            Err(JwtError::MalformedToken(_))
        ));
    }

    #[test]
    fn verify_rejects_invalid_signature_lengths() {
        let (sk, did) = test_key_and_did();
        let token = create_jwt(&sk, &format!(r#"{{"iss":"{did}","exp":100}}"#));
        let (message, _) = token.rsplit_once('.').unwrap();
        for len in [0, 1, 63, 65, 128] {
            let signature = URL_SAFE_NO_PAD.encode(vec![0; len]);
            assert!(matches!(
                verify_bearer_token(&format!("{message}.{signature}")),
                Err(JwtError::InvalidSignature)
            ));
        }
    }
    fn sign_raw(key: &SigningKey, header: &str, payload: &str) -> String {
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let digest = Sha256::digest(message.as_bytes());
        let (signature, _) = key.sign_prehash_recoverable(&digest).unwrap();
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[test]
    fn delegation_rejects_missing_duplicate_and_unsupported_claims() {
        let (key, did) = test_key_and_did();
        let header = r#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#;
        let claims = serde_json::json!({"iss": did, "sub": "caller", "aud": "vera:9001", "scope": "acp:policy", "iat": 10, "nbf": 5, "exp": 100});
        for field in ["iss", "sub", "aud", "scope", "iat", "nbf", "exp"] {
            let mut missing = claims.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                verify_bearer_token(&sign_raw(&key, header, &missing.to_string())).is_err(),
                "missing {field}"
            );
        }
        for (field, value) in [
            ("scope", serde_json::json!("relay")),
            ("nbf", serde_json::json!(11)),
            ("exp", serde_json::json!(10)),
        ] {
            let mut invalid = claims.clone();
            invalid[field] = value;
            assert!(verify_bearer_token(&sign_raw(&key, header, &invalid.to_string())).is_err());
        }
        let duplicate = format!(r#"{{"sub":"attacker",{}"#, &claims.to_string()[1..]);
        assert!(verify_bearer_token(&sign_raw(&key, header, &duplicate)).is_err());
        let duplicate_header = r#"{"alg":"ES256K","alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#;
        assert!(
            verify_bearer_token(&sign_raw(&key, duplicate_header, &claims.to_string())).is_err()
        );
        assert!(
            verify_bearer_token(&sign_raw(
                &key,
                r#"{"alg":"ES256K","typ":"JWT"}"#,
                &claims.to_string()
            ))
            .is_err()
        );
        assert!(verify_bearer_token(&"x".repeat(16 * 1024 + 1)).is_err());
    }

    #[test]
    fn delegation_rejects_signature_aliases_and_checks_context() {
        let (key, did) = test_key_and_did();
        let token = create_jwt(
            &key,
            &serde_json::json!({"iss": did, "sub": "caller", "exp": 100}).to_string(),
        );
        let claims = verify_bearer_token(&token).unwrap();
        assert!(claims.authorize("caller", 9001, 1).is_ok());
        assert!(claims.authorize("caller", 9001, 100).is_ok());
        assert!(claims.authorize("caller", 9001, 0).is_err());
        assert!(claims.authorize("caller", 9001, 101).is_err());
        assert!(claims.authorize("other", 9001, 50).is_err());
        assert!(claims.authorize("caller", 9002, 50).is_err());
        let (message, encoded) = token.rsplit_once('.').unwrap();
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        let (r, s) = signature.split_scalars();
        let high = Signature::from_scalars(r.to_bytes(), (-s).to_bytes()).unwrap();
        assert!(matches!(
            verify_bearer_token(&format!(
                "{message}.{}",
                URL_SAFE_NO_PAD.encode(high.to_bytes())
            )),
            Err(JwtError::InvalidSignature)
        ));
        assert!(verify_bearer_token(&format!("{token}=")).is_err());
    }
}
