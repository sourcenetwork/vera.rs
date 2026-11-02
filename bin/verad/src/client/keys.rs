//! Key generation and display subcommands.

use clap::Subcommand;
use rand::RngCore;
use vera_client::{BlsSigner, EvmSigner, Secp256k1SigningKey, create_bearer_token};
use zeroize::Zeroizing;

use super::context::ClientContext;

#[derive(Subcommand, Debug)]
pub(crate) enum KeysCommand {
    /// Generate a random secp256k1 keypair.
    GenerateEvm,
    /// Generate a random BLS12-381 keypair.
    GenerateBls,
    /// Show address and DID for a secp256k1 private key.
    ShowEvm {
        /// Hex-encoded private key.
        key: String,
    },
    /// Show DID and public key for a BLS12-381 private key.
    ShowBls {
        /// Hex-encoded private key (32 bytes).
        key: String,
    },
    /// Delegate policy operations to a submitting DID using --key.
    BearerToken {
        /// DID allowed to submit the delegated operations.
        subject: String,
        /// Expiry as a Unix timestamp (seconds); defaults to five minutes from now.
        #[arg(long)]
        expiry: Option<u64>,
    },
}

fn generate_evm_key() -> Result<Secp256k1SigningKey, rand::Error> {
    let mut secret = Zeroizing::new([0u8; 32]);
    loop {
        rand::rngs::OsRng.try_fill_bytes(&mut *secret)?;
        if let Ok(key) = Secp256k1SigningKey::from_slice(&*secret) {
            return Ok(key);
        }
    }
}

impl KeysCommand {
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::GenerateEvm => {
                let key = generate_evm_key()?;
                let hex_key = hex::encode(key.to_bytes());
                let signer = EvmSigner::from_native_key(key, 0);
                ctx.print_json(&serde_json::json!({
                    "private_key": hex_key,
                    "address": format!("{:?}", signer.address()),
                    "did": signer.did(),
                }))?;
            }
            Self::GenerateBls => {
                let signer = BlsSigner::random(0)
                    .map_err(|e| eyre::eyre!("BLS key generation failed: {e}"))?;
                ctx.print_json(&serde_json::json!({
                    "did": signer.did(),
                    "pubkey": format!("0x{}", hex::encode(signer.pubkey_bytes())),
                    "private_key": format!("0x{}", hex::encode(signer.secret_key_bytes()?)),
                }))?;
            }
            Self::ShowEvm { key } => {
                let key_hex = key.strip_prefix("0x").unwrap_or(&key);
                let signer =
                    EvmSigner::from_hex(key_hex, 0).map_err(|e| eyre::eyre!("invalid key: {e}"))?;
                ctx.print_json(&serde_json::json!({
                    "address": format!("{:?}", signer.address()),
                    "did": signer.did(),
                }))?;
            }
            Self::ShowBls { key } => {
                let hex_key = key.strip_prefix("0x").unwrap_or(&key);
                let bytes = hex::decode(hex_key).map_err(|e| eyre::eyre!("invalid hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err(eyre::eyre!(
                        "BLS secret key must be 32 bytes, got {}",
                        bytes.len()
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let fr = <ark_bls12_381::Fr as ark_ff::PrimeField>::from_le_bytes_mod_order(&arr);
                let signer =
                    BlsSigner::new(fr, 0).map_err(|e| eyre::eyre!("BLS signer init: {e}"))?;
                ctx.print_json(&serde_json::json!({
                    "did": signer.did(),
                    "pubkey": format!("0x{}", hex::encode(signer.pubkey_bytes())),
                    "private_key": format!("0x{}", hex::encode(signer.secret_key_bytes()?)),
                }))?;
            }
            Self::BearerToken { subject, expiry } => {
                let signing_key = ctx
                    .signing_key
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("--key is required for bearer-token"))?;
                let issued_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                let expires_at = expiry.unwrap_or(issued_at + 300);
                let token =
                    create_bearer_token(signing_key, &subject, ctx.chain_id, issued_at, expires_at)
                        .map_err(|e| eyre::eyre!("bearer token creation failed: {e}"))?;
                ctx.print_json(&serde_json::json!({ "token": token }))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_evm_key_round_trips() {
        let key = generate_evm_key().unwrap();
        let expected = EvmSigner::from_native_key(key.clone(), 1);
        let actual = EvmSigner::from_hex(&hex::encode(key.to_bytes()), 1).unwrap();
        assert_eq!(actual.address(), expected.address());
        assert_eq!(actual.did(), expected.did());
    }
}
