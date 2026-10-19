//! Bounded stdin/stdout adapter for the local status collector; no network or key discovery.
use std::io::{self, Read as _};

use commonware_codec::{Copying, DecodeExt as _};
use serde::Deserialize;
use vera_domain::{ConsensusPublicKey, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock, verify_light_block};

#[derive(Deserialize)]
struct Input {
    trusted_key: String,
    light: LightBlock,
}

fn verify(bytes: &[u8]) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let input: Input = serde_json::from_slice(bytes)?;
    let key = hex::decode(
        input
            .trusted_key
            .strip_prefix("0x")
            .unwrap_or(&input.trusted_key),
    )?;
    let trusted = ConsensusPublicKey::decode(Copying(key.as_slice()))?;
    verify_light_block(&input.light, &trusted)?;
    Ok(serde_json::json!({
        "height": input.light.height,
        "block_hash": input.light.block_hash,
        "timestamp": input.light.timestamp,
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let limit = LIGHT_BLOCK_RESPONSE_BYTES + 4096;
    let mut bytes = Vec::new();
    io::stdin().take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input too large".into());
    }
    println!("{}", verify(&bytes)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_missing_evidence_and_untrusted_input() {
        assert!(super::verify(br#"{}"#).is_err());
        assert!(super::verify(br#"{"trusted_key":"00","light":{}}"#).is_err());
    }
}
