//! Native account key prefixes and builders.
//!
//! Values are a `u64` nonce in 8-byte little-endian form.

/// KV prefix for per-DID nonce tracking.
pub const NATIVE_NONCE_PREFIX: &[u8] = b"native_nonce/";

/// Build a nonce key: `native_nonce/ + did bytes`.
pub fn native_nonce_key(did: &str) -> Vec<u8> {
    let mut key = Vec::from(NATIVE_NONCE_PREFIX);
    key.extend_from_slice(did.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_key_format() {
        let did = "did:key:z6MkTest";
        let key = native_nonce_key(did);
        assert!(key.starts_with(NATIVE_NONCE_PREFIX));
        assert_eq!(&key[NATIVE_NONCE_PREFIX.len()..], did.as_bytes());
    }

    #[test]
    fn nonce_key_different_dids() {
        let a = native_nonce_key("did:key:z6MkAlice");
        let b = native_nonce_key("did:key:z6MkBob");
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_key_deterministic() {
        let a = native_nonce_key("did:key:z6Mk123");
        let b = native_nonce_key("did:key:z6Mk123");
        assert_eq!(a, b);
    }
}
