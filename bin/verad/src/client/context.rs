//! Client context wrapping `VeraClient` with optional signers.

use vera_client::{BlsSigner, Secp256k1SigningKey, VeraClient};

use super::parse;

#[derive(Debug, thiserror::Error)]
pub(super) enum KeyError {
    #[error("--bls-key is required for write commands")]
    Missing,
    #[error("invalid --key hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("invalid secp256k1 key")]
    InvalidKey,
}

/// Shared context for all client subcommands.
pub(crate) struct ClientContext {
    pub client: VeraClient,
    pub bls_signer: Option<BlsSigner>,
    pub signing_key: Option<Secp256k1SigningKey>,
    pub chain_id: u64,
    pub compact: bool,
}

impl ClientContext {
    /// Build a context from CLI global flags.
    pub(super) fn new(
        url: &str,
        key: Option<&str>,
        bls_key: Option<&str>,
        chain_id: u64,
        compact: bool,
    ) -> eyre::Result<Self> {
        let client = VeraClient::new(url);

        let signing_key = key.map(parse_signing_key).transpose()?;

        let bls_signer = bls_key.map(|k| parse_bls_signer(k, chain_id)).transpose()?;

        Ok(Self {
            client,
            bls_signer,
            signing_key,
            chain_id,
            compact,
        })
    }

    /// The native signer of a write command; `--bls-key` supplies it.
    pub(super) fn require_bls_signer(&self) -> Result<&BlsSigner, KeyError> {
        self.bls_signer.as_ref().ok_or(KeyError::Missing)
    }

    /// Print a serializable value as JSON to stdout.
    pub(super) fn print_json(&self, value: &impl serde::Serialize) -> eyre::Result<()> {
        let output = if self.compact {
            serde_json::to_string(value)?
        } else {
            serde_json::to_string_pretty(value)?
        };
        println!("{output}");
        Ok(())
    }
}

fn parse_signing_key(hex_key: &str) -> Result<Secp256k1SigningKey, KeyError> {
    let bytes = parse::decode_hex(hex_key)?;
    Secp256k1SigningKey::from_slice(&bytes).map_err(|_| KeyError::InvalidKey)
}

fn parse_bls_signer(hex_key: &str, chain_id: u64) -> eyre::Result<BlsSigner> {
    BlsSigner::new(parse::bls_scalar(hex_key)?, chain_id)
        .map_err(|e| eyre::eyre!("BLS signer init: {e}"))
}

#[cfg(test)]
mod tests {
    use super::{ClientContext, parse_signing_key};
    use vera_client::create_bearer_token;

    #[test]
    fn parses_native_keys_and_rejects_invalid_input() {
        let bytes = [7u8; 32];
        let key = parse_signing_key(&format!("0x{}", hex::encode(bytes))).unwrap();
        assert_eq!(&key.to_bytes()[..], &bytes);
        for invalid in ["not-hex", "01", &hex::encode([0u8; 32])] {
            assert!(parse_signing_key(invalid).is_err());
        }
    }

    #[test]
    fn a_write_requires_the_native_key() {
        let hex = hex::encode([7u8; 32]);
        let actor_only =
            ClientContext::new("http://localhost:8545", Some(&hex), None, 42, false).unwrap();
        assert!(matches!(
            actor_only.require_bls_signer(),
            Err(super::KeyError::Missing)
        ));
        let native =
            ClientContext::new("http://localhost:8545", None, Some(&hex), 42, false).unwrap();
        assert!(native.require_bls_signer().is_ok());
    }

    #[test]
    fn native_bearer_preserves_issuer_and_deployment() {
        let hex = hex::encode([7u8; 32]);
        let ctx = ClientContext::new("http://localhost:8545", Some(&hex), None, 42, false).unwrap();
        let token = create_bearer_token(
            ctx.signing_key.as_ref().unwrap(),
            "did:example:worker",
            ctx.chain_id,
            100,
            200,
        )
        .unwrap();
        let claims = vera_crypto::jwt::verify_bearer_token(&token).unwrap();
        assert_eq!(
            claims.iss,
            super::super::keys::actor_did(ctx.signing_key.as_ref().unwrap()).unwrap()
        );
        assert_eq!(claims.sub, "did:example:worker");
        assert_eq!(claims.aud, "vera:42");
        assert_eq!((claims.iat, claims.exp), (100, 200));
    }
}
