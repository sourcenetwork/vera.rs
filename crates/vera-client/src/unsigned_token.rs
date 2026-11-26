//! Delegation tokens signed outside this library.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use vera_crypto::jwt::{DELEGATION_TOKEN_TYPE, DelegationScope, JwtClaims, WEBAUTHN_TOKEN_TYPE};
use vera_crypto::operation::{DEFAULT_OPERATION_LEAD, MAX_OPERATION_LEAD};
use vera_crypto::webauthn;

use crate::error::ClientError;

/// A delegation token awaiting its issuer's signature.
///
/// For keys this library cannot hold, such as hardware-backed or platform
/// keys. The issuer is a secp256k1, Ed25519 or P-256 `did:key`; see
/// [`vera_crypto::actor`] for deriving one from a public key.
///
/// secp256k1 (ES256K) and P-256 (ES256) keys sign the SHA-256 digest of
/// [`signing_input`](Self::signing_input). Ed25519 keys sign the input itself.
///
/// A P-256 issuer may sign a delegation with a passkey instead: it asserts
/// [`webauthn_challenge`](Self::webauthn_challenge), and
/// [`finish_webauthn`](Self::finish_webauthn) completes the token.
#[derive(Clone, Debug)]
pub struct UnsignedToken {
    issuer: String,
    token_type: String,
    payload: String,
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
        Self::new(issuer, DELEGATION_TOKEN_TYPE, &payload)
    }

    /// One exact caller operation, bound to its ID, digest and genesis identity.
    /// The ID's deadline lies at most the default 600 seconds after `iat`.
    pub fn operation(claims: &JwtClaims) -> Result<Self, ClientError> {
        Self::operation_with_lead(claims, DEFAULT_OPERATION_LEAD)
    }

    /// One exact caller operation whose deadline lies at most `max_lead` seconds
    /// after `iat`. A lead beyond the default is for policy commands only, and
    /// executes only where the deployment's operators allow at least that lead.
    pub fn operation_with_lead(claims: &JwtClaims, max_lead: u64) -> Result<Self, ClientError> {
        let request = claims
            .request
            .as_ref()
            .ok_or_else(|| ClientError::Signing("operation claim required".into()))?;
        if max_lead > MAX_OPERATION_LEAD
            || (max_lead > DEFAULT_OPERATION_LEAD
                && claims.scope != DelegationScope::PolicyCommands)
        {
            return Err(ClientError::Signing(
                "a lead beyond the default applies to policy commands within the ceiling".into(),
            ));
        }
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
            .validate(claims.iat, max_lead)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        Self::new(
            &claims.iss,
            DELEGATION_TOKEN_TYPE,
            &serde_json::to_string(claims)?,
        )
    }

    pub(crate) fn new(issuer: &str, token_type: &str, payload: &str) -> Result<Self, ClientError> {
        let payload = URL_SAFE_NO_PAD.encode(payload);
        Ok(Self {
            issuer: issuer.to_owned(),
            token_type: token_type.to_owned(),
            input: signing_input(issuer, token_type, &payload)?,
            payload,
        })
    }

    /// The challenge a passkey asserts to sign this delegation: the SHA-256
    /// digest of the signing input under the passkey token type.
    ///
    /// The issuer must be a P-256 `did:key`, and relay tokens cannot be
    /// signed with a passkey. Pass these bytes as the `challenge` of
    /// `navigator.credentials.get`, or its platform equivalent, with user
    /// verification required.
    pub fn webauthn_challenge(&self) -> Result<[u8; 32], ClientError> {
        Ok(Sha256::digest(self.webauthn_input()?.as_bytes()).into())
    }

    /// Complete the token with a passkey assertion of
    /// [`webauthn_challenge`](Self::webauthn_challenge): the authenticator
    /// data, the client data JSON exactly as returned, and the ASN.1 DER
    /// signature. An assertion that does not verify is an error.
    pub fn finish_webauthn(
        self,
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
    ) -> Result<String, ClientError> {
        let input = self.webauthn_input()?;
        let signature = vera_crypto::actor::canonical_der_signature(&self.issuer, signature)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        let segment = webauthn::join_token_signature(
            &webauthn::Assertion {
                authenticator_data,
                client_data_json,
            },
            &signature,
        );
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(segment));
        vera_crypto::jwt::verify_bearer_token(&token)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        Ok(token)
    }

    fn webauthn_input(&self) -> Result<String, ClientError> {
        let p256 = vera_crypto::actor::key_type(&self.issuer)
            .is_ok_and(|key| key == vera_crypto::actor::ActorKeyType::P256);
        if !p256 || self.token_type != DELEGATION_TOKEN_TYPE {
            return Err(ClientError::Signing(
                "only a P-256 issuer's delegation can be signed with a passkey".into(),
            ));
        }
        signing_input(&self.issuer, WEBAUTHN_TOKEN_TYPE, &self.payload)
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

fn signing_input(issuer: &str, token_type: &str, payload: &str) -> Result<String, ClientError> {
    let algorithm =
        vera_crypto::actor::algorithm(issuer).map_err(|e| ClientError::Signing(e.to_string()))?;
    let header = format!(r#"{{"alg":"{algorithm}","typ":"{token_type}"}}"#);
    Ok(format!("{}.{payload}", URL_SAFE_NO_PAD.encode(header)))
}

#[cfg(test)]
#[path = "unsigned_token_tests.rs"]
mod tests;
