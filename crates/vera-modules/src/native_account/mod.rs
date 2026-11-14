//! Native account state — DID-keyed nonce tracking for BLS transactions.

pub mod keys;

use thiserror::Error;

use crate::kv_store::{InMemoryKvStore, ModuleKvStore};

/// Nonce validation error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NonceError {
    /// Transaction nonce does not match the expected value.
    #[error("nonce mismatch for {did}: expected {expected}, got {got}")]
    Mismatch {
        /// The DID of the signer.
        did: String,
        /// The next expected nonce.
        expected: u64,
        /// The nonce present in the transaction.
        got: u64,
    },

    /// Nonce counter would overflow `u64::MAX`.
    #[error("nonce overflow for {0}")]
    Overflow(String),

    /// Stored nonce does not have the shape written by this store.
    #[error("stored nonce for {0} is malformed")]
    Malformed(String),
}

/// Per-DID nonce store for native BLS transactions.
///
/// Tracks the next expected nonce for each DID. New accounts start at 0.
#[derive(Clone, Debug, Default)]
pub struct NativeNonceStore {
    store: InMemoryKvStore,
}

impl NativeNonceStore {
    /// Read access to the underlying KV store (for serialization).
    pub const fn store(&self) -> &InMemoryKvStore {
        &self.store
    }

    /// Reconstruct from a deserialized store.
    pub const fn from_store(store: InMemoryKvStore) -> Self {
        Self { store }
    }

    /// Return the current nonce for the given DID (0 for new accounts).
    ///
    /// A stored value other than the eight bytes this store writes is
    /// corruption, surfaced as an error instead of trusted.
    pub fn get_nonce(&self, did: &str) -> Result<u64, NonceError> {
        self.store
            .get(&keys::native_nonce_key(did))
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_le_bytes)
                    .map_err(|_| NonceError::Malformed(did.to_string()))
            })
            .unwrap_or(Ok(0))
    }

    /// Validate `tx_nonce == stored` and increment. Returns an error on mismatch.
    pub fn check_and_increment(&mut self, did: &str, tx_nonce: u64) -> Result<(), NonceError> {
        let expected = self.get_nonce(did)?;
        if tx_nonce != expected {
            return Err(NonceError::Mismatch {
                did: did.to_string(),
                expected,
                got: tx_nonce,
            });
        }
        let next = expected
            .checked_add(1)
            .ok_or_else(|| NonceError::Overflow(did.to_string()))?;
        self.store
            .put(&keys::native_nonce_key(did), next.to_le_bytes().to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_account_starts_at_zero() {
        let store = NativeNonceStore::default();
        assert_eq!(store.get_nonce("did:key:z6MkNew").unwrap(), 0);
    }

    #[test]
    fn check_and_increment_success() {
        let mut store = NativeNonceStore::default();
        let did = "did:key:z6MkAlice";

        store.check_and_increment(did, 0).unwrap();
        assert_eq!(store.get_nonce(did).unwrap(), 1);

        store.check_and_increment(did, 1).unwrap();
        assert_eq!(store.get_nonce(did).unwrap(), 2);
    }

    #[test]
    fn check_and_increment_mismatch() {
        let mut store = NativeNonceStore::default();
        let did = "did:key:z6MkAlice";

        let err = store.check_and_increment(did, 5).unwrap_err();
        assert_eq!(
            err,
            NonceError::Mismatch {
                did: did.to_string(),
                expected: 0,
                got: 5,
            }
        );
        // Nonce unchanged after rejection.
        assert_eq!(store.get_nonce(did).unwrap(), 0);
    }

    #[test]
    fn independent_dids() {
        let mut store = NativeNonceStore::default();
        store.check_and_increment("did:key:z6MkAlice", 0).unwrap();
        store.check_and_increment("did:key:z6MkBob", 0).unwrap();

        assert_eq!(store.get_nonce("did:key:z6MkAlice").unwrap(), 1);
        assert_eq!(store.get_nonce("did:key:z6MkBob").unwrap(), 1);
    }

    #[test]
    fn clone_isolation() {
        let mut store = NativeNonceStore::default();
        store.check_and_increment("did:key:z6Mk1", 0).unwrap();

        let mut fork = store.clone();
        fork.check_and_increment("did:key:z6Mk1", 1).unwrap();

        assert_eq!(store.get_nonce("did:key:z6Mk1").unwrap(), 1);
        assert_eq!(fork.get_nonce("did:key:z6Mk1").unwrap(), 2);
    }

    #[test]
    fn sequential_nonces_in_block() {
        let mut store = NativeNonceStore::default();
        let did = "did:key:z6MkAlice";

        for i in 0..10 {
            store.check_and_increment(did, i).unwrap();
        }
        assert_eq!(store.get_nonce(did).unwrap(), 10);
    }

    #[test]
    fn replay_rejected() {
        let mut store = NativeNonceStore::default();
        let did = "did:key:z6MkAlice";

        store.check_and_increment(did, 0).unwrap();
        let err = store.check_and_increment(did, 0).unwrap_err();
        assert_eq!(
            err,
            NonceError::Mismatch {
                did: did.to_string(),
                expected: 1,
                got: 0,
            }
        );
    }

    #[test]
    fn error_display() {
        let err = NonceError::Mismatch {
            did: "did:key:z6Mk1".to_string(),
            expected: 3,
            got: 1,
        };
        assert_eq!(
            err.to_string(),
            "nonce mismatch for did:key:z6Mk1: expected 3, got 1"
        );
    }

    #[test]
    fn malformed_stored_nonce_is_an_error() {
        let mut nonce_store = NativeNonceStore::default();
        let did = "did:key:z6MkCorrupt";
        nonce_store
            .store
            .put(&keys::native_nonce_key(did), vec![1; 7]);

        assert_eq!(
            nonce_store.get_nonce(did).unwrap_err(),
            NonceError::Malformed(did.into())
        );
        assert_eq!(
            nonce_store.check_and_increment(did, 0).unwrap_err(),
            NonceError::Malformed(did.into())
        );
    }

    #[test]
    fn overflow_rejected() {
        let mut nonce_store = NativeNonceStore::default();
        let did = "did:key:z6MkMax";
        nonce_store.store.put(
            &keys::native_nonce_key(did),
            u64::MAX.to_le_bytes().to_vec(),
        );

        let err = nonce_store.check_and_increment(did, u64::MAX).unwrap_err();
        assert_eq!(err, NonceError::Overflow(did.to_string()));
        assert_eq!(nonce_store.get_nonce(did).unwrap(), u64::MAX);
    }
}
