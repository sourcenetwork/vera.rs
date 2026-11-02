//! JWT ES256K bearer token creation for client-side signing.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use k256_native::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use vera_crypto::jwt::DelegationScope;

use crate::error::ClientError;

/// Create a JWT bearer token signed with ES256K.
///
/// The issuer (`iss`) is derived from the signing key's secp256k1 `did:key:`.
/// Bind the submitting DID and deployment. Times are Unix seconds.
pub fn create_bearer_token(
    signing_key: &SigningKey,
    subject: &str,
    deployment_id: u64,
    issued_at: u64,
    expires_at: u64,
) -> Result<String, ClientError> {
    create_scoped_bearer_token(
        signing_key,
        subject,
        deployment_id,
        issued_at,
        expires_at,
        DelegationScope::PolicyCommands,
    )
}

/// Sign a delegation limited to one operation scope, worker, deployment and lifetime.
pub fn create_scoped_bearer_token(
    signing_key: &SigningKey,
    subject: &str,
    deployment_id: u64,
    issued_at: u64,
    expires_at: u64,
    scope: DelegationScope,
) -> Result<String, ClientError> {
    if issued_at >= expires_at {
        return Err(ClientError::Signing("invalid delegation lifetime".into()));
    }
    let compressed = signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let iss = vera_crypto::secp256k1::did_from_secp256k1_pubkey(&compressed)
        .map_err(|e| ClientError::Signing(format!("DID derivation: {e}")))?;

    let header = r#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#;
    let payload = serde_json::json!({
        "iss": iss, "sub": subject, "aud": format!("vera:{deployment_id}"),
        "scope": scope, "iat": issued_at,
        "nbf": issued_at.saturating_sub(30), "exp": expires_at,
    })
    .to_string();

    sign_payload(signing_key, header, &payload)
}

/// Sign one exact caller operation without operator-managed relay authority.
/// The request binds its immutable ID, semantic digest and genesis identity.
pub fn create_operation_token(
    signing_key: &SigningKey,
    claims: &vera_crypto::jwt::JwtClaims,
) -> Result<String, ClientError> {
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        signing_key.verifying_key().to_sec1_point(true).as_bytes(),
    )
    .map_err(|e| ClientError::Signing(e.to_string()))?;
    let request = claims
        .request
        .as_ref()
        .ok_or_else(|| ClientError::Signing("operation claim required".into()))?;
    if claims.iss != issuer
        || claims.relay.is_some()
        || claims.nbf != claims.iat
        || claims.iat >= claims.exp
        || claims.exp > request.id.expires_at()
        || request.genesis_id == [0; 32]
    {
        return Err(ClientError::Signing(
            "invalid operation issuer, binding or lifetime".into(),
        ));
    }
    request
        .id
        .validate(claims.iat)
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    sign_payload(
        signing_key,
        r#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#,
        &serde_json::to_string(claims)?,
    )
}

/// Sign an operation-bound relay assertion. The issuer must match the signing key.
/// The node separately verifies the committed grant, actor authority and revocations.
pub fn create_relay_token(
    signing_key: &SigningKey,
    claims: &vera_crypto::jwt::JwtClaims,
) -> Result<String, ClientError> {
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        signing_key.verifying_key().to_sec1_point(true).as_bytes(),
    )
    .map_err(|error| ClientError::Signing(error.to_string()))?;
    if claims.iss != issuer
        || claims.relay.is_none()
        || claims.nbf != claims.iat
        || claims.iat >= claims.exp
        || claims.exp - claims.iat > vera_modules::vera::relay::MAX_RELAY_TOKEN_TTL
    {
        return Err(ClientError::Signing(
            "invalid relay issuer, assertion or lifetime".into(),
        ));
    }
    sign_payload(
        signing_key,
        r#"{"alg":"ES256K","typ":"vera-relay-v1+jwt"}"#,
        &serde_json::to_string(claims)?,
    )
}

fn sign_payload(
    signing_key: &SigningKey,
    header: &str,
    payload: &str,
) -> Result<String, ClientError> {
    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    let signing_input = format!("{header_b64}.{payload_b64}");
    let digest = Sha256::digest(signing_input.as_bytes());

    let (sig, _) = signing_key.sign_prehash_recoverable(digest.as_ref());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes((&[42u8; 32]).into()).unwrap()
    }

    #[test]
    fn create_and_verify_roundtrip() {
        let key = test_key();
        let subject = "did:key:zSubject\",\"scope\":\"other";
        let token = create_bearer_token(&key, subject, 9001, 50, 100).unwrap();

        let claims = vera_crypto::jwt::verify_bearer_token(&token).unwrap();
        assert_eq!(claims.sub, subject);
        assert_eq!(claims.scope, DelegationScope::PolicyCommands);
        assert_eq!(claims.exp, 100);
        claims.authorize(subject, 9001, 50).unwrap();
        assert!(claims.iss.starts_with("did:key:"));
    }

    #[test]
    fn invalid_lifetime_is_rejected() {
        let key = test_key();
        for expires_at in [0, 50] {
            assert!(create_bearer_token(&key, "s", 9001, 50, expires_at).is_err());
        }
    }

    #[test]
    fn operation_tokens_require_actor_binding_and_immutable_deadline() {
        use vera_crypto::operation::{OperationClaim, OperationId};
        let key = test_key();
        let token = create_bearer_token(&key, "did:key:worker", 9001, 50, 100).unwrap();
        let mut claims = vera_crypto::jwt::verify_bearer_token(&token).unwrap();
        claims.nbf = claims.iat;
        assert!(create_operation_token(&key, &claims).is_err());
        let mut id = [1; 32];
        id[..8].copy_from_slice(&100u64.to_be_bytes());
        claims.request = Some(OperationClaim {
            id: OperationId(id),
            digest: [3; 32],
            genesis_id: [4; 32],
        });
        let signed = create_operation_token(&key, &claims).unwrap();
        let decoded = vera_crypto::jwt::verify_bearer_token(&signed).unwrap();
        assert_eq!(decoded.request.unwrap().digest, [3; 32]);
        for case in 0..5 {
            let mut invalid = claims.clone();
            match case {
                0 => invalid.iss = "did:key:other".into(),
                1 => invalid.exp = 101,
                2 => invalid.request.as_mut().unwrap().genesis_id = [0; 32],
                3 => invalid.request.as_mut().unwrap().id.0[8..].fill(0),
                _ => invalid.nbf -= 1,
            }
            assert!(create_operation_token(&key, &invalid).is_err());
        }
    }
}
