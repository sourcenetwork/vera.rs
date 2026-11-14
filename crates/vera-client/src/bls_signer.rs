//! BLS12-381 signer for native transactions.

use std::sync::Mutex;

use alloy_primitives::{Address, Bytes, FixedBytes};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use vera_crypto::bls;
use vera_domain::NativeTx;
use zeroize::{Zeroize, Zeroizing};

use crate::error::ClientError;

/// BLS12-381 signer for native vera transactions.
///
/// Wraps a BLS keypair and deployment ID. Serializes signing for this identity
/// so successful concurrent calls receive distinct local sequences.
///
/// Each worker retains its own key and submission state. Delegation binds this
/// signing identity to a policy actor without sharing the actor's sequence.
pub struct BlsSigner {
    secret_key: Fr,
    pubkey_bytes: FixedBytes<48>,
    did: String,
    chain_id: u64,
    nonce: Mutex<u64>,
    submission: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for BlsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsSigner")
            .field("did", &self.did)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl Drop for BlsSigner {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

impl BlsSigner {
    /// Create a signer from a BLS secret key scalar and chain ID.
    pub fn new(secret_key: Fr, chain_id: u64) -> Result<Self, ClientError> {
        let public_key = (G1Projective::from(G1Affine::generator()) * secret_key).into_affine();

        let mut pk_bytes = Vec::with_capacity(48);
        public_key
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| ClientError::Bls(format!("pubkey serialize: {e}")))?;
        let pubkey_bytes = FixedBytes::from_slice(&pk_bytes);

        let did =
            bls::did_from_bls_pubkey(&public_key).map_err(|e| ClientError::Bls(e.to_string()))?;

        Ok(Self {
            secret_key,
            pubkey_bytes,
            did,
            chain_id,
            nonce: Mutex::new(0),
            submission: tokio::sync::Mutex::new(()),
        })
    }

    /// Restore a worker from a canonical scalar and its durable next sequence.
    /// Pending signed bytes must be recovered before allocating another sequence.
    pub fn from_secret_bytes(
        secret: &[u8],
        deployment: u64,
        next_sequence: u64,
    ) -> Result<Self, ClientError> {
        if secret.len() != 32 {
            return Err(ClientError::Bls("worker key must contain 32 bytes".into()));
        }
        let secret = Fr::deserialize_compressed(secret)
            .map_err(|_| ClientError::Bls("invalid worker key encoding".into()))?;
        let mut signer = Self::new(secret, deployment)?;
        *signer.nonce.get_mut().expect("new sequence lock") = next_sequence;
        Ok(signer)
    }

    /// Export the canonical scalar for encrypted key storage.
    pub fn secret_key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(32));
        self.secret_key
            .serialize_compressed(&mut *bytes)
            .map_err(|_| ClientError::Bls("worker key encoding failed".into()))?;
        Ok(bytes)
    }

    /// Generate an independent random BLS worker identity.
    pub fn random(chain_id: u64) -> Result<Self, ClientError> {
        let mut rng = rand::thread_rng();
        let sk = Fr::rand(&mut rng);
        Self::new(sk, chain_id)
    }

    /// Return the `did:key:` identifier derived from this signer's public key.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Return the compressed G1 public key bytes (48 bytes).
    pub const fn pubkey_bytes(&self) -> &FixedBytes<48> {
        &self.pubkey_bytes
    }

    /// Return the chain ID this signer targets.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Return the current local nonce counter.
    pub fn nonce(&self) -> u64 {
        *self.nonce.lock().expect("native sequence lock poisoned")
    }

    /// Replace the local sequence after a submission whose admission is unknown.
    ///
    /// `vera_getNativeNonce` reports committed module state: it does not count
    /// this signer's requests that a node has admitted but not yet executed,
    /// so a value read while one is pending reuses that request's sequence.
    pub fn set_next_sequence(&self, next: u64) {
        *self.nonce.lock().expect("native sequence lock poisoned") = next;
    }

    /// Serialize sign-and-submit so requests reach the node in sequence order.
    pub(crate) async fn submission(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.submission.lock().await
    }

    /// Record that a node admitted the request signed with `sequence`.
    pub(crate) fn admitted(&self, sequence: u64) {
        let mut nonce = self.nonce.lock().expect("native sequence lock poisoned");
        *nonce = (*nonce).max(sequence.saturating_add(1));
    }

    /// Build, sign, and encode a native transaction in wire format.
    ///
    /// Advances the local sequence on success. Callers must submit in sequence
    /// order and coordinate retries; signing alone does not confirm submission.
    pub fn sign_native_tx(&self, target: Address, calldata: Bytes) -> Result<Vec<u8>, ClientError> {
        let mut nonce = self
            .nonce
            .lock()
            .map_err(|_| ClientError::Signing("native sequence lock poisoned".into()))?;
        let next = nonce
            .checked_add(1)
            .ok_or_else(|| ClientError::Signing("native sequence exhausted".into()))?;

        let wire = self.sign_native_tx_with_sequence(target, calldata, *nonce)?;
        *nonce = next;
        Ok(wire)
    }

    /// Sign with a sequence managed by a durable submission journal.
    /// This does not change the local counter. The caller must prevent sequence
    /// reuse and persist the signed bytes before submitting them.
    pub fn sign_native_tx_with_sequence(
        &self,
        target: Address,
        calldata: Bytes,
        sequence: u64,
    ) -> Result<Vec<u8>, ClientError> {
        if sequence == u64::MAX {
            return Err(ClientError::Signing("native sequence exhausted".into()));
        }

        let mut tx = NativeTx {
            chain_id: self.chain_id,
            nonce: sequence,
            bls_pubkey: self.pubkey_bytes,
            target,
            calldata,
            signature: FixedBytes::from([0u8; 96]),
        };

        let signing_data = tx.signing_data();
        let sig_bytes = bls::sign(&self.secret_key, &signing_data)
            .map_err(|e| ClientError::Bls(e.to_string()))?;
        tx.signature = FixedBytes::from_slice(&sig_bytes);

        Ok(tx.encode_wire())
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use vera_domain::NativeTx;

    use super::*;

    fn test_signer() -> BlsSigner {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        BlsSigner::new(sk, 1337).unwrap()
    }

    #[test]
    fn new_valid_key() {
        let signer = test_signer();
        assert!(signer.did().starts_with("did:key:z"));
        assert_eq!(signer.chain_id(), 1337);
    }

    #[test]
    fn random_produces_valid_signer() {
        let signer = BlsSigner::random(42).unwrap();
        assert!(signer.did().starts_with("did:key:z"));
        assert_eq!(signer.chain_id(), 42);
    }

    #[test]
    fn random_produces_different_signers() {
        let s1 = BlsSigner::random(1).unwrap();
        let s2 = BlsSigner::random(1).unwrap();
        assert_ne!(s1.did(), s2.did());
    }

    #[test]
    fn pubkey_bytes_length() {
        let signer = test_signer();
        assert_eq!(signer.pubkey_bytes().len(), 48);
    }

    #[test]
    fn did_is_deterministic() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let s1 = BlsSigner::new(sk, 1).unwrap();
        let s2 = BlsSigner::new(sk, 1).unwrap();
        assert_eq!(s1.did(), s2.did());
    }

    #[test]
    fn sign_native_tx_produces_valid_wire_format() {
        let signer = test_signer();
        let target = Address::from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x08, 0x10,
        ]);
        let calldata = Bytes::from(vec![0xde, 0xad]);

        let wire = signer.sign_native_tx(target, calldata).unwrap();
        assert_eq!(wire[0], 0x45);

        let decoded = NativeTx::decode_wire(&wire).unwrap();
        assert_eq!(decoded.chain_id, 1337);
        assert_eq!(decoded.nonce, 0);
        assert_eq!(decoded.bls_pubkey, *signer.pubkey_bytes());
        assert_eq!(decoded.target, target);
    }

    #[test]
    fn sign_native_tx_signature_verifies() {
        let signer = test_signer();
        let target = Address::ZERO;
        let calldata = Bytes::from(vec![0x01, 0x02]);

        let wire = signer.sign_native_tx(target, calldata).unwrap();
        let decoded = NativeTx::decode_wire(&wire).unwrap();

        let signing_data = decoded.signing_data();
        let pk = bls::deserialize_pubkey(decoded.bls_pubkey.as_slice()).unwrap();
        bls::verify(&pk, &signing_data, decoded.signature.as_slice()).unwrap();
    }

    #[test]
    fn nonce_increments() {
        let signer = test_signer();
        let target = Address::ZERO;

        let wire1 = signer.sign_native_tx(target, Bytes::new()).unwrap();
        let tx1 = NativeTx::decode_wire(&wire1).unwrap();
        assert_eq!(tx1.nonce, 0);

        let wire2 = signer.sign_native_tx(target, Bytes::new()).unwrap();
        let tx2 = NativeTx::decode_wire(&wire2).unwrap();
        assert_eq!(tx2.nonce, 1);
    }

    #[test]
    fn different_calldata_produces_different_wire() {
        let target = Address::ZERO;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let s1 = BlsSigner::new(sk, 1).unwrap();
        let s2 = BlsSigner::new(sk, 1).unwrap();

        let wire1 = s1.sign_native_tx(target, Bytes::from(vec![0x01])).unwrap();
        let wire2 = s2.sign_native_tx(target, Bytes::from(vec![0x02])).unwrap();
        assert_ne!(wire1, wire2);
    }

    #[test]
    fn concurrent_signing_uses_distinct_sequences() {
        let signer = test_signer();
        let barrier = std::sync::Barrier::new(8);
        let mut sequences = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8u8)
                .map(|index| {
                    let signer = &signer;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        let wire = signer
                            .sign_native_tx(Address::ZERO, Bytes::from(vec![index]))
                            .unwrap();
                        NativeTx::decode_wire(&wire).unwrap().nonce
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        sequences.sort_unstable();
        assert_eq!(sequences, (0..8).collect::<Vec<_>>());
        assert_eq!(signer.nonce(), 8);
    }

    #[test]
    fn failed_or_exhausted_signing_does_not_advance_the_sequence() {
        let mut invalid = test_signer();
        invalid.secret_key = Fr::from(0u64);
        assert!(invalid.sign_native_tx(Address::ZERO, Bytes::new()).is_err());
        assert_eq!(invalid.nonce(), 0);
        let signer = test_signer();
        *signer.nonce.lock().unwrap() = u64::MAX;
        assert!(signer.sign_native_tx(Address::ZERO, Bytes::new()).is_err());
        assert_eq!(signer.nonce(), u64::MAX);
    }

    #[test]
    fn restored_worker_preserves_identity_sequence_and_signed_bytes() {
        let original = test_signer();
        original
            .sign_native_tx(Address::ZERO, Bytes::new())
            .unwrap();
        let key = original.secret_key_bytes().unwrap();
        let restored =
            BlsSigner::from_secret_bytes(&key, original.chain_id(), original.nonce()).unwrap();
        assert_eq!(restored.did(), original.did());
        let expected = original
            .sign_native_tx(Address::ZERO, Bytes::from_static(b"pending"))
            .unwrap();
        let actual = restored
            .sign_native_tx(Address::ZERO, Bytes::from_static(b"pending"))
            .unwrap();
        assert_eq!(actual, expected);
        let tx = NativeTx::decode_wire(&actual).unwrap();
        assert_eq!(tx.nonce, 1);
        let public = bls::deserialize_pubkey(tx.bls_pubkey.as_slice()).unwrap();
        bls::verify(&public, &tx.signing_data(), tx.signature.as_slice()).unwrap();
        assert_eq!(restored.nonce(), 2);
        assert_eq!(
            restored
                .sign_native_tx_with_sequence(Address::ZERO, Bytes::from_static(b"pending"), 1)
                .unwrap(),
            actual
        );
        assert_eq!(restored.nonce(), 2);
        let exhausted = BlsSigner::from_secret_bytes(&key, original.chain_id(), u64::MAX).unwrap();
        assert!(
            exhausted
                .sign_native_tx(Address::ZERO, Bytes::new())
                .is_err()
        );
    }

    #[test]
    fn stored_worker_key_rejects_zero_noncanonical_and_wrong_lengths() {
        for key in [vec![], vec![1; 31], vec![1; 33], vec![0; 32], vec![255; 32]] {
            assert!(BlsSigner::from_secret_bytes(&key, 1, 0).is_err());
        }
        let signer = test_signer();
        let mut key = signer.secret_key_bytes().unwrap();
        key.push(0);
        assert!(BlsSigner::from_secret_bytes(&key, 1, 0).is_err());
    }
}
