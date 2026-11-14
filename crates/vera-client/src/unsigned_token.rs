//! Delegation tokens signed outside this library.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vera_crypto::jwt::{DelegationScope, JwtClaims};

use crate::error::ClientError;

/// A delegation token awaiting its issuer's signature.
///
/// For keys this library cannot hold, such as hardware-backed or platform
/// keys. The issuer is a secp256k1, Ed25519 or P-256 `did:key`; see
/// [`vera_crypto::actor`] for deriving one from a public key.
///
/// secp256k1 (ES256K) and P-256 (ES256) keys sign the SHA-256 digest of
/// [`signing_input`](Self::signing_input). Ed25519 keys sign the input itself.
#[derive(Clone, Debug)]
pub struct UnsignedToken {
    issuer: String,
    input: String,
}

/// Delegation claims in the order their bytes are signed.
///
/// A JSON map would order them by a `serde_json` feature that any crate in
/// the build can switch, and token records are keyed by the hash of these bytes.
#[derive(serde::Serialize)]
struct DelegationClaims<'a> {
    aud: String,
    exp: u64,
    iat: u64,
    iss: &'a str,
    nbf: u64,
    scope: DelegationScope,
    sub: &'a str,
}

impl UnsignedToken {
    /// A delegation limited to one scope, worker, deployment and lifetime.
    pub fn delegation(
        issuer: &str,
        subject: &str,
        deployment_id: u64,
        issued_at: u64,
        expires_at: u64,
        scope: DelegationScope,
    ) -> Result<Self, ClientError> {
        if issued_at >= expires_at {
            return Err(ClientError::Signing("invalid delegation lifetime".into()));
        }
        let payload = serde_json::to_string(&DelegationClaims {
            aud: format!("vera:{deployment_id}"),
            exp: expires_at,
            iat: issued_at,
            iss: issuer,
            nbf: issued_at.saturating_sub(30),
            scope,
            sub: subject,
        })?;
        Self::new(issuer, "vera-delegation-v1+jwt", &payload)
    }

    /// One exact caller operation, bound to its ID, digest and genesis identity.
    pub fn operation(claims: &JwtClaims) -> Result<Self, ClientError> {
        let request = claims
            .request
            .as_ref()
            .ok_or_else(|| ClientError::Signing("operation claim required".into()))?;
        if claims.relay.is_some()
            || claims.nbf != claims.iat
            || claims.iat >= claims.exp
            || claims.exp > request.id.expires_at()
            || request.genesis_id == [0; 32]
        {
            return Err(ClientError::Signing(
                "invalid operation binding or lifetime".into(),
            ));
        }
        request
            .id
            .validate(claims.iat)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        Self::new(
            &claims.iss,
            "vera-delegation-v1+jwt",
            &serde_json::to_string(claims)?,
        )
    }

    pub(crate) fn new(issuer: &str, token_type: &str, payload: &str) -> Result<Self, ClientError> {
        let algorithm = vera_crypto::actor::algorithm(issuer)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        let header = format!(r#"{{"alg":"{algorithm}","typ":"{token_type}"}}"#);
        Ok(Self {
            issuer: issuer.to_owned(),
            input: format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header),
                URL_SAFE_NO_PAD.encode(payload)
            ),
        })
    }

    /// The bytes the issuer's key signs.
    pub const fn signing_input(&self) -> &[u8] {
        self.input.as_bytes()
    }

    /// Complete the token with a raw signature: 64-byte `r || s` for ECDSA
    /// keys, or the 64-byte Ed25519 signature.
    ///
    /// Either ECDSA `s` is accepted. A signature that the issuer's key did
    /// not make over this token is an error.
    pub fn finish(self, signature: &[u8]) -> Result<String, ClientError> {
        let signature = vera_crypto::actor::canonical_signature(&self.issuer, signature)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        self.verified(&signature)
    }

    /// Complete the token with an ASN.1 DER ECDSA signature, as platform key
    /// stores return it.
    pub fn finish_der(self, signature: &[u8]) -> Result<String, ClientError> {
        let signature = vera_crypto::actor::canonical_der_signature(&self.issuer, signature)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        self.verified(&signature)
    }

    fn verified(self, signature: &[u8]) -> Result<String, ClientError> {
        let token = self.assemble(signature);
        vera_crypto::jwt::verify_bearer_token(&token)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        Ok(token)
    }

    pub(crate) fn assemble(self, signature: &[u8]) -> String {
        format!("{}.{}", self.input, URL_SAFE_NO_PAD.encode(signature))
    }
}

#[cfg(test)]
#[path = "unsigned_token_tests.rs"]
mod tests;
