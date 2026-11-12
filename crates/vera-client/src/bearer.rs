//! Bearer tokens signed with a secp256k1 key held by the caller.

use k256_native::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use vera_crypto::jwt::DelegationScope;

use crate::{error::ClientError, unsigned_token::UnsignedToken};

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
    let unsigned = UnsignedToken::delegation(
        &issuer(signing_key)?,
        subject,
        deployment_id,
        issued_at,
        expires_at,
        scope,
    )?;
    Ok(sign(signing_key, unsigned))
}

/// Sign one exact caller operation without operator-managed relay authority.
/// The request binds its immutable ID, semantic digest and genesis identity.
pub fn create_operation_token(
    signing_key: &SigningKey,
    claims: &vera_crypto::jwt::JwtClaims,
) -> Result<String, ClientError> {
    if claims.iss != issuer(signing_key)? {
        return Err(ClientError::Signing("invalid operation issuer".into()));
    }
    Ok(sign(signing_key, UnsignedToken::operation(claims)?))
}

/// Sign an operation-bound relay assertion. The issuer must match the signing key.
/// The node separately verifies the committed grant, actor authority and revocations.
pub fn create_relay_token(
    signing_key: &SigningKey,
    claims: &vera_crypto::jwt::JwtClaims,
) -> Result<String, ClientError> {
    if claims.iss != issuer(signing_key)?
        || claims.relay.is_none()
        || claims.nbf != claims.iat
        || claims.iat >= claims.exp
        || claims.exp - claims.iat > vera_modules::vera::relay::MAX_RELAY_TOKEN_TTL
    {
        return Err(ClientError::Signing(
            "invalid relay issuer, assertion or lifetime".into(),
        ));
    }
    let unsigned = UnsignedToken::new(
        &claims.iss,
        "vera-relay-v1+jwt",
        &serde_json::to_string(claims)?,
    )?;
    Ok(sign(signing_key, unsigned))
}

fn issuer(signing_key: &SigningKey) -> Result<String, ClientError> {
    vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        signing_key.verifying_key().to_sec1_point(true).as_bytes(),
    )
    .map_err(|e| ClientError::Signing(format!("DID derivation: {e}")))
}

fn sign(signing_key: &SigningKey, unsigned: UnsignedToken) -> String {
    let digest = Sha256::digest(unsigned.signing_input());
    let (signature, _) = signing_key.sign_prehash_recoverable(digest.as_ref());
    unsigned.assemble(&signature.to_bytes())
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
    fn secp256k1_tokens_keep_their_exact_bytes() {
        let token = create_scoped_bearer_token(
            &test_key(),
            "did:key:worker",
            9001,
            50,
            100,
            DelegationScope::CreatePolicy,
        )
        .unwrap();
        assert_eq!(
            token,
            "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJ2ZXJhLWRlbGVnYXRpb24tdjErand0In0.\
             eyJhdWQiOiJ2ZXJhOjkwMDEiLCJleHAiOjEwMCwiaWF0Ijo1MCwiaXNzIjoiZGlkOmtleTp6UTNzaGtwcVphUlI0UDhLc1RFMXZYSFJ0akFBaktQZkhGZXU1Qjh2bVBuVzc5QTUxIiwibmJmIjoyMCwic2NvcGUiOiJhY3A6cG9saWN5OmNyZWF0ZSIsInN1YiI6ImRpZDprZXk6d29ya2VyIn0.\
             K2C9cBB2Iu2XS0cRD9S_lXQ9hqFs8IjE8tQv8Y7MXQ0nRq_iziAQzVW2Z99xPJ4pyFxKJ1e19QoVmhn7C8tFuA"
        );
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
