//! An existing solo deployment, as its host holds it.

use commonware_codec::DecodeExt as _;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use vera_genesis::VeraGenesis;

use super::{SoloError, SoloGenesis, SoloKeys};

/// A deployment's stored genesis record with the key material that validates it.
///
/// This is everything a device needs to run as the deployment's validator. It
/// carries no state: a node that opens it in an empty directory starts from
/// the genesis.
#[derive(Clone)]
pub struct SoloDeployment {
    record: Vec<u8>,
    keys: SoloKeys,
}

impl std::fmt::Debug for SoloDeployment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoloDeployment")
            .field("record_bytes", &self.record.len())
            .field("keys", &self.keys)
            .finish()
    }
}

impl SoloDeployment {
    /// Pair a genesis record, the content of `solo-genesis.json`, with its key material.
    ///
    /// Nothing is checked until a node opens the deployment.
    #[must_use]
    pub fn new(record: impl Into<Vec<u8>>, keys: SoloKeys) -> Self {
        Self {
            record: record.into(),
            keys,
        }
    }

    /// Deal a new deployment in memory, with a validator key and consensus
    /// share from operating-system randomness. Nothing is written.
    ///
    /// A host stores the result in its keystore before starting a node with it.
    pub fn create(
        identity: &SoloGenesis,
        p2p_listen: std::net::SocketAddr,
    ) -> Result<Self, SoloError> {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *seed);
        let validator_key = PrivateKey::decode(commonware_codec::Copying(&seed[..]))
            .map_err(|_| SoloError::KeyMaterial("validator key does not decode"))?;
        let (genesis, share) = super::deal(
            identity,
            &validator_key.public_key(),
            &p2p_listen.to_string(),
        )?;
        Ok(Self {
            record: super::encode(&genesis)?,
            keys: SoloKeys::new(validator_key, share),
        })
    }

    /// The genesis record, byte for byte as a node stores it.
    #[must_use]
    pub fn record(&self) -> &[u8] {
        &self.record
    }

    /// The key material.
    #[must_use]
    pub const fn keys(&self) -> &SoloKeys {
        &self.keys
    }

    /// The identity the record describes.
    pub fn identity(&self) -> Result<SoloGenesis, SoloError> {
        super::record::identity(self.genesis()?)
    }

    pub(crate) fn genesis(&self) -> Result<VeraGenesis, SoloError> {
        super::record::decode(&self.record)
    }
}
