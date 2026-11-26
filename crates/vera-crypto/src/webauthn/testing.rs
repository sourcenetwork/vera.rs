//! A software authenticator that signs assertions as a platform passkey does.

use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};
use sha2::{Digest as _, Sha256};

use super::Assertion;

/// Assertions captured from Chrome's virtual authenticator by
/// `tools/webauthn-vectors/capture.mjs`, all by the key of
/// `Authenticator::new([0x2a; 32])`.
pub const CHROME_VECTORS: &str = include_str!("chrome_vectors.json");

/// One captured assertion, its bytes in hexadecimal.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct ChromeVector {
    /// What the digest approves: `digest` for an arbitrary one,
    /// `administrative` or `token` for the fixed request and delegation the
    /// capture script names.
    pub purpose: String,
    /// `extra` when Chrome added `other_keys_can_be_added_here`, else `plain`.
    pub client_data_form: String,
    /// The credential's `did:key`.
    pub did: String,
    /// The uncompressed SEC1 public key.
    pub public_key: String,
    /// The challenge's 32 bytes.
    pub digest: String,
    /// The 37 bytes of authenticator data.
    pub authenticator_data: String,
    /// The client data JSON, as text.
    pub client_data_json: String,
    /// The signature as Chrome returned it.
    pub der_signature: String,
    /// The raw low-S `r || s`.
    pub signature: String,
}

/// The captured assertion for `purpose`.
///
/// # Panics
///
/// When no vector has that purpose.
#[must_use]
pub fn chrome_vector(purpose: &str) -> ChromeVector {
    chrome_vectors()
        .into_iter()
        .find(|vector| vector.purpose == purpose)
        .expect("a captured vector for the purpose")
}

/// Every captured assertion.
///
/// # Panics
///
/// Never: the vectors are checked in.
#[must_use]
pub fn chrome_vectors() -> Vec<ChromeVector> {
    serde_json::from_str(CHROME_VECTORS).expect("valid vectors")
}

/// Flags of a synced passkey's assertion: user present and verified,
/// backup eligible and backed up.
pub const SYNCED_FLAGS: u8 = 0x1d;

/// A P-256 key that answers `navigator.credentials.get` for any challenge.
#[derive(Clone, Debug)]
pub struct Authenticator {
    key: SigningKey,
    /// The flags byte written into authenticator data.
    pub flags: u8,
    /// The origin written into client data.
    pub origin: String,
}

/// The output of one assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// The 37 bytes of authenticator data.
    pub authenticator_data: Vec<u8>,
    /// The client data JSON as the browser produced it.
    pub client_data_json: Vec<u8>,
    /// The raw low-S `r || s`.
    pub signature: [u8; 64],
    /// The same signature in ASN.1 DER, as an authenticator returns it.
    pub der: Vec<u8>,
}

impl Signed {
    /// The assertion without its signature.
    #[must_use]
    pub fn assertion(&self) -> Assertion<'_> {
        Assertion {
            authenticator_data: &self.authenticator_data,
            client_data_json: &self.client_data_json,
        }
    }
}

impl Authenticator {
    /// An authenticator holding the P-256 key with this secret scalar.
    ///
    /// # Panics
    ///
    /// When `secret` is not a valid P-256 scalar.
    #[must_use]
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_slice(&secret).expect("valid P-256 scalar"),
            flags: SYNCED_FLAGS,
            origin: "https://app.example".into(),
        }
    }

    /// The `did:key` of the credential's public key.
    ///
    /// # Panics
    ///
    /// Never: the key is a valid P-256 point.
    #[must_use]
    pub fn did(&self) -> String {
        crate::actor::p256_did(self.key.verifying_key().to_encoded_point(true).as_bytes())
            .expect("valid P-256 key")
    }

    /// Authenticator data for the relying party `example.com` with a zero counter.
    #[must_use]
    pub fn authenticator_data(&self) -> Vec<u8> {
        let mut data = Sha256::digest(b"example.com").to_vec();
        data.push(self.flags);
        data.extend_from_slice(&[0; 4]);
        data
    }

    /// Client data of a get ceremony for `digest`, as a browser writes it.
    #[must_use]
    pub fn client_data(&self, digest: &[u8; 32]) -> Vec<u8> {
        format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            super::challenge(digest),
            self.origin
        )
        .into_bytes()
    }

    /// Sign `authenticator_data || SHA-256(client_data_json)`, whatever they hold.
    ///
    /// # Panics
    ///
    /// Never: signing a 32-byte prehash with a valid key succeeds.
    #[must_use]
    pub fn sign(&self, authenticator_data: &[u8], client_data_json: &[u8]) -> Signed {
        let mut message = Sha256::new();
        message.update(authenticator_data);
        message.update(Sha256::digest(client_data_json));
        let signature: Signature = self
            .key
            .sign_prehash(&message.finalize())
            .expect("prehash signing succeeds");
        let signature = signature.normalize_s().unwrap_or(signature);
        Signed {
            authenticator_data: authenticator_data.to_vec(),
            client_data_json: client_data_json.to_vec(),
            signature: signature.to_bytes().into(),
            der: signature.to_der().as_bytes().to_vec(),
        }
    }

    /// Approve `digest` as a platform authenticator would.
    #[must_use]
    pub fn assert(&self, digest: &[u8; 32]) -> Signed {
        self.sign(&self.authenticator_data(), &self.client_data(digest))
    }
}
