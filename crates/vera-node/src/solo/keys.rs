//! A solo deployment's signing material, held in memory.

use commonware_codec::{DecodeExt as _, EncodeSize as _, Write as _};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::group::Share,
    ed25519::{PrivateKey, PublicKey},
};
use zeroize::Zeroizing;

use super::SoloError;

/// The validator key and consensus share of a single-validator deployment.
///
/// Whoever holds both can finalize blocks for the deployment. A node started
/// with them signs from memory and writes neither to its directory.
#[derive(Clone)]
pub struct SoloKeys {
    validator_key: PrivateKey,
    share: Share,
}

impl std::fmt::Debug for SoloKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoloKeys")
            .field("validator", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl SoloKeys {
    /// Decode the bytes [`Self::validator_key`] and [`Self::share`] returned.
    pub fn decode(validator_key: &[u8], share: &[u8]) -> Result<Self, SoloError> {
        let validator_key = PrivateKey::decode(commonware_codec::Copying(validator_key))
            .map_err(|_| SoloError::KeyMaterial("validator key does not decode"))?;
        let share = Share::decode(commonware_codec::Copying(share))
            .map_err(|_| SoloError::KeyMaterial("consensus share does not decode"))?;
        Ok(Self {
            validator_key,
            share,
        })
    }

    pub(crate) const fn new(validator_key: PrivateKey, share: Share) -> Self {
        Self {
            validator_key,
            share,
        }
    }

    /// The validator key's 32-byte seed, erased when dropped.
    #[must_use]
    pub fn validator_key(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(self.validator_key.encode_size()));
        self.validator_key.write(&mut *bytes);
        bytes
    }

    /// The consensus share's encoding, erased when dropped.
    #[must_use]
    pub fn share(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(self.share.encode_size()));
        self.share.write(&mut *bytes);
        bytes
    }

    /// The validator's public identity.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.validator_key.public_key()
    }

    pub(crate) fn signer(&self) -> PrivateKey {
        self.validator_key.clone()
    }

    pub(crate) fn consensus_share(&self) -> Share {
        self.share.clone()
    }
}
