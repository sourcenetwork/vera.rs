//! Key generation and display subcommands.

use clap::Subcommand;
use rand::RngCore;
use vera_client::{BlsSigner, Secp256k1SigningKey, create_bearer_token};
use zeroize::Zeroizing;

use super::{context::ClientContext, parse};

#[derive(Subcommand, Debug)]
pub(crate) enum KeysCommand {
    /// Generate a random secp256k1 actor keypair.
    GenerateActor,
    /// Generate a random BLS12-381 keypair.
    GenerateBls,
    /// Show the DID of a secp256k1 actor private key.
    ShowActor {
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

fn generate_actor_key() -> Result<Secp256k1SigningKey, rand::Error> {
    let mut secret = Zeroizing::new([0u8; 32]);
    loop {
        rand::rngs::OsRng.try_fill_bytes(&mut *secret)?;
        if let Ok(key) = Secp256k1SigningKey::from_slice(&*secret) {
            return Ok(key);
        }
    }
}

/// The canonical `did:key` of a secp256k1 actor key.
pub(super) fn actor_did(key: &Secp256k1SigningKey) -> eyre::Result<String> {
    vera_crypto::secp256k1::did_from_secp256k1_pubkey(&key.verifying_key().to_sec1_bytes())
        .map_err(|error| eyre::eyre!("actor DID: {error}"))
}

impl KeysCommand {
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::GenerateActor => {
                let key = generate_actor_key()?;
                ctx.print_json(&serde_json::json!({
                    "private_key": hex::encode(key.to_bytes()),
                    "did": actor_did(&key)?,
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
            Self::ShowActor { key } => {
                let key = Secp256k1SigningKey::from_slice(&parse::decode_hex(&key)?)
                    .map_err(|_| eyre::eyre!("invalid secp256k1 key"))?;
                ctx.print_json(&serde_json::json!({ "did": actor_did(&key)? }))?;
            }
            Self::ShowBls { key } => {
                let signer = BlsSigner::new(parse::bls_scalar(&key)?, 0)
                    .map_err(|e| eyre::eyre!("BLS signer init: {e}"))?;
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
    fn a_generated_actor_key_round_trips_to_the_same_did() {
        let key = generate_actor_key().unwrap();
        let restored = Secp256k1SigningKey::from_slice(&key.to_bytes()).unwrap();
        let did = actor_did(&key).unwrap();
        assert_eq!(actor_did(&restored).unwrap(), did);
        assert_eq!(vera_crypto::actor::canonical_did(&did), did);
    }
}
