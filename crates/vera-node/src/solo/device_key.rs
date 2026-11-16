//! The network identity of a device that follows a deployment without validating it.

use std::path::Path;

use commonware_codec::{DecodeExt as _, EncodeSize as _, Write as _};
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use zeroize::Zeroizing;

use super::{SoloError, io};

const FILE: &str = "transport.key";

/// A backup device's transport key.
///
/// It authenticates the device to the account's other devices and signs
/// nothing else: it finalizes no block and holds no part of the deployment's
/// consensus key.
#[derive(Clone)]
pub struct DeviceKey(PrivateKey);

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("DeviceKey")
            .field(&self.public_key())
            .finish()
    }
}

impl DeviceKey {
    /// A new key from operating-system randomness.
    pub fn generate() -> Result<Self, SoloError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *seed);
        Self::decode(&seed[..])
    }

    /// Decode the 32-byte seed [`Self::encode`] returned.
    pub fn decode(seed: &[u8]) -> Result<Self, SoloError> {
        PrivateKey::decode(commonware_codec::Copying(seed))
            .map(Self)
            .map_err(|_| SoloError::KeyMaterial("transport key does not decode"))
    }

    /// The key's 32-byte seed, erased when dropped.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(self.0.encode_size()));
        self.0.write(&mut *bytes);
        bytes
    }

    /// The identity the account's other devices list for this device.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// The key kept in `directory`, created there on first use.
    pub fn load_or_create(directory: &Path) -> Result<Self, SoloError> {
        let path = directory.join(FILE);
        let stored = vera_cli::open_private(&path).and_then(|file| {
            use std::io::Read as _;
            let mut seed = Zeroizing::new(Vec::new());
            file.take(33).read_to_end(&mut seed)?;
            Ok(seed)
        });
        match stored {
            Ok(seed) => Self::decode(&seed),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                std::fs::create_dir_all(directory).map_err(|source| io(directory, source))?;
                vera_cli::write_private(&path, &key.encode())
                    .map_err(|source| io(&path, source))?;
                Ok(key)
            }
            Err(source) => Err(io(&path, source)),
        }
    }

    pub(crate) fn signer(&self) -> PrivateKey {
        self.0.clone()
    }
}
