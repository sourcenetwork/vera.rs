//! Nonces for tests that create one definition more than once.

use std::sync::atomic::{AtomicU64, Ordering};

use super::types::PolicyNonce;

/// A nonce no earlier call in this process returned.
pub(crate) fn fresh_nonce() -> PolicyNonce {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut nonce = [0; 32];
    nonce[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    PolicyNonce(nonce)
}
