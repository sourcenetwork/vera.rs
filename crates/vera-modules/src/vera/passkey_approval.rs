//! The authenticator output a passkey operator's approval carries.

use serde::{Deserialize, Serialize};
use vera_crypto::webauthn::{AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_BYTES};

/// Authenticator data and client data of a passkey assertion, each in
/// lowercase hexadecimal of the exact bytes the authenticator signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyAssertion {
    /// The 37 bytes of authenticator data.
    pub authenticator_data: String,
    /// The client data JSON, at most 1,024 bytes.
    pub client_data_json: String,
}

impl PasskeyAssertion {
    /// Encode an assertion's bytes as an approval carries them.
    #[must_use]
    pub fn new(authenticator_data: &[u8], client_data_json: &[u8]) -> Self {
        Self {
            authenticator_data: hex::encode(authenticator_data),
            client_data_json: hex::encode(client_data_json),
        }
    }

    /// The authenticator data and client data bytes, refusing a length
    /// outside the verification bounds and any encoding but lowercase hex.
    pub(super) fn decode(&self) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        if self.authenticator_data.len() != 2 * AUTHENTICATOR_DATA_BYTES
            || self.client_data_json.len() > 2 * MAX_CLIENT_DATA_BYTES
        {
            return Err("passkey assertion is outside its length bounds");
        }
        let decode = |text: &str| {
            hex::decode(text)
                .ok()
                .filter(|bytes| hex::encode(bytes) == text)
                .ok_or("passkey assertion must use lowercase hexadecimal")
        };
        Ok((
            decode(&self.authenticator_data)?,
            decode(&self.client_data_json)?,
        ))
    }
}
