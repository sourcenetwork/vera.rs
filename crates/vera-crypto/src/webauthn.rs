//! Passkey (WebAuthn) assertions over a 32-byte digest.
//!
//! An authenticator does not sign a caller's digest directly. It signs
//! `authenticatorData || SHA-256(clientDataJSON)`, where the client data
//! carries the digest as its base64url `challenge`. An assertion approves a
//! digest when its authenticator data and client data pass the rules below
//! and its P-256 signature verifies over that message.
//!
//! Every rule is fixed so that two verifiers cannot disagree:
//! authenticator data is exactly 37 bytes with no attested credential or
//! extension data, and user presence and verification asserted; client data
//! is parsed strictly by [`client_data`] and never re-serialized; the
//! challenge is compared as a string; the signature is the raw 64-byte low-S
//! `r || s`. The relying party, origin and signature counter are not checked.
//!
//! An assertion proves only that the holder of the key signed. It carries no
//! attestation, so a software key emitting assertions is indistinguishable
//! from a platform passkey.

mod client_data;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};

/// Length of the authenticator data an assertion carries.
pub const AUTHENTICATOR_DATA_BYTES: usize = 37;
/// Longest accepted client data.
pub const MAX_CLIENT_DATA_BYTES: usize = 1024;
/// Longest accepted `origin` member, after unescaping.
pub const MAX_ORIGIN_BYTES: usize = 512;
/// Length of the raw `r || s` signature.
pub const SIGNATURE_BYTES: usize = 64;

const USER_PRESENT: u8 = 1 << 0;
const USER_VERIFIED: u8 = 1 << 2;
const BACKUP_ELIGIBLE: u8 = 1 << 3;
const BACKED_UP: u8 = 1 << 4;
const ATTESTED_CREDENTIAL: u8 = 1 << 6;
const EXTENSIONS: u8 = 1 << 7;

/// The authenticator output that accompanies an assertion's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assertion<'a> {
    /// `rpIdHash (32) || flags (1) || signCount (4)`.
    pub authenticator_data: &'a [u8],
    /// The client data JSON exactly as the authenticator hashed it.
    pub client_data_json: &'a [u8],
}

/// Why an assertion does not approve a digest.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WebauthnError {
    /// The signer is not a P-256 `did:key`.
    #[error("passkey assertions are signed by P-256 keys: {0}")]
    KeyType(String),
    /// Authenticator data is not 37 bytes.
    #[error("authenticator data must contain {AUTHENTICATOR_DATA_BYTES} bytes")]
    AuthenticatorDataLength,
    /// Authenticator data announces attested credential or extension data.
    #[error("authenticator data carries attested credential or extension data")]
    AuthenticatorDataExtended,
    /// User presence or user verification is not asserted.
    #[error("the assertion does not assert user presence and verification")]
    UserNotVerified,
    /// The backed-up flag is set without the backup-eligible flag.
    #[error("the assertion claims a backup without backup eligibility")]
    BackupState,
    /// Client data is not one strict JSON object within the limits.
    #[error("invalid client data: {0}")]
    ClientData(&'static str),
    /// Client data names another ceremony than `webauthn.get`.
    #[error("client data is not an assertion")]
    CeremonyType,
    /// The challenge is not the digest's base64url encoding.
    #[error("client data challenges another digest")]
    Challenge,
    /// Client data claims a cross-origin or embedded ceremony.
    #[error("client data claims a cross-origin ceremony")]
    CrossOrigin,
    /// A composite token signature is shorter or longer than its parts allow.
    #[error("passkey token signature has an invalid length")]
    TokenSignatureLength,
    /// The signature is not a low-S P-256 signature of the assertion.
    #[error("invalid passkey signature")]
    Signature,
}

/// The `challenge` an assertion of `digest` carries: its unpadded base64url
/// encoding, 43 characters. A platform authenticator takes the digest bytes
/// themselves as its challenge and writes this encoding into client data.
#[must_use]
pub fn challenge(digest: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(digest)
}

impl Assertion<'_> {
    /// Check that this assertion is a get ceremony for `digest`, and return
    /// the message hash its signature covers.
    pub fn signed_hash(&self, digest: &[u8; 32]) -> Result<[u8; 32], WebauthnError> {
        let flags = match self.authenticator_data {
            data if data.len() == AUTHENTICATOR_DATA_BYTES => data[32],
            _ => return Err(WebauthnError::AuthenticatorDataLength),
        };
        if flags & (ATTESTED_CREDENTIAL | EXTENSIONS) != 0 {
            return Err(WebauthnError::AuthenticatorDataExtended);
        }
        if flags & (USER_PRESENT | USER_VERIFIED) != USER_PRESENT | USER_VERIFIED {
            return Err(WebauthnError::UserNotVerified);
        }
        if flags & BACKED_UP != 0 && flags & BACKUP_ELIGIBLE == 0 {
            return Err(WebauthnError::BackupState);
        }
        let client = client_data::parse(self.client_data_json)?;
        if client.ceremony != "webauthn.get" {
            return Err(WebauthnError::CeremonyType);
        }
        if client.challenge != challenge(digest) {
            return Err(WebauthnError::Challenge);
        }
        let mut message = Sha256::new();
        message.update(self.authenticator_data);
        message.update(Sha256::digest(self.client_data_json));
        Ok(message.finalize().into())
    }
}

/// Split a passkey token's signature segment, `authenticatorData (37) ||
/// r || s (64) || clientDataJSON`, into its assertion and signature.
pub const fn split_token_signature(
    segment: &[u8],
) -> Result<(Assertion<'_>, &[u8]), WebauthnError> {
    let fixed = AUTHENTICATOR_DATA_BYTES + SIGNATURE_BYTES;
    if segment.len() <= fixed || segment.len() > fixed + MAX_CLIENT_DATA_BYTES {
        return Err(WebauthnError::TokenSignatureLength);
    }
    let (authenticator_data, rest) = segment.split_at(AUTHENTICATOR_DATA_BYTES);
    let (signature, client_data_json) = rest.split_at(SIGNATURE_BYTES);
    Ok((
        Assertion {
            authenticator_data,
            client_data_json,
        },
        signature,
    ))
}

/// Join an assertion and its raw signature into a passkey token's signature segment.
#[must_use]
pub fn join_token_signature(assertion: &Assertion<'_>, signature: &[u8]) -> Vec<u8> {
    [
        assertion.authenticator_data,
        signature,
        assertion.client_data_json,
    ]
    .concat()
}

/// Verify that `actor`, a P-256 `did:key`, approved `digest` with this
/// assertion and its raw 64-byte low-S signature.
pub fn verify(
    actor: &str,
    digest: &[u8; 32],
    assertion: &Assertion<'_>,
    signature: &[u8],
) -> Result<(), WebauthnError> {
    crate::actor_key::ActorKey::from_did(actor)
        .map_err(|error| WebauthnError::KeyType(error.to_string()))?
        .verify_assertion(digest, assertion, signature)
}

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests;
