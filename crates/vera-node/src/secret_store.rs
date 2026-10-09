//! File-backed secret store for DKG/reshare private material.

use std::{
    collections::BTreeMap,
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use commonware_codec::{Decode, DecodeExt as _, Encode as _};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    PublicKey,
    bls12381::{dkg::feldman_desmedt::DealerPrivMsg, primitives::group::Share},
    transcript::Summary,
};
use commonware_glue::dkg;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// JSON-file-backed [`dkg::SecretStore`] holding shares, dealer seeds, and dealings.
///
/// Updates replace the file atomically after syncing its contents. On Unix, new
/// files are readable and writable only by the owner.
#[derive(Clone)]
pub struct FileSecretStore {
    path: PathBuf,
    inner: Arc<Mutex<SecretData>>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SecretData {
    shares: BTreeMap<u64, String>,
    seeds: BTreeMap<u64, String>,
    dealings: BTreeMap<String, String>,
}

impl std::fmt::Debug for FileSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSecretStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl FileSecretStore {
    /// Open the store at `path`, starting empty if the file does not exist.
    pub fn load(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let inner: SecretData = match vera_cli::open_private(&path).and_then(|mut file| {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            Ok(contents)
        }) {
            Ok(contents) => serde_json::from_str(&contents)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::symlink_metadata(&path) {
                    Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {
                        SecretData::default()
                    }
                    _ => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        };
        for raw in inner.shares.values() {
            decode_secret::<Share>(raw)?;
        }
        for raw in inner.seeds.values() {
            decode_secret::<Summary>(raw)?;
        }
        for (key, raw) in &inner.dealings {
            let valid_key = key.split_once(':').is_some_and(|(epoch, dealer)| {
                epoch
                    .parse::<u64>()
                    .is_ok_and(|value| value.to_string() == epoch)
                    && hex::decode(dealer)
                        .is_ok_and(|bytes| !bytes.is_empty() && hex::encode(bytes) == dealer)
            });
            anyhow::ensure!(valid_key, "invalid stored DKG dealing key");
            decode_secret::<DealerPrivMsg>(raw)?;
        }
        Ok(Self {
            path,
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Seed the store with a trusted-setup share for `epoch`.
    pub fn put_initial_share(&self, epoch: Epoch, share: Share) -> anyhow::Result<()> {
        self.update(|data| {
            data.shares.insert(epoch.get(), hex::encode(share.encode()));
        })
    }

    fn update(&self, change: impl FnOnce(&mut SecretData)) -> anyhow::Result<()> {
        self.update_with_sync(change, fs::File::sync_all)
    }

    fn update_with_sync(
        &self,
        change: impl FnOnce(&mut SecretData),
        mut sync: impl FnMut(&fs::File) -> std::io::Result<()>,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock();
        let mut next = inner.clone();
        change(&mut next);
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(file.as_file_mut(), &next)?;
        sync(file.as_file())?;
        file.persist(&self.path)?;
        sync(&fs::File::open(parent)?)?;
        *inner = next;
        Ok(())
    }

    fn dealing_key<P: PublicKey>(epoch: Epoch, dealer: &P) -> String {
        format!("{}:{}", epoch.get(), hex::encode(dealer.encode()))
    }
}

fn decode_secret<T: Decode<Cfg = ()>>(raw: &str) -> anyhow::Result<T> {
    let bytes = hex::decode(raw).map_err(|_| anyhow::anyhow!("invalid stored DKG encoding"))?;
    T::decode(commonware_codec::Copying(bytes.as_slice()))
        .map_err(|_| anyhow::anyhow!("invalid stored DKG material"))
}

impl dkg::SecretStore for FileSecretStore {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        self.put_initial_share(epoch, share)
            .expect("failed to persist share");
        #[cfg(feature = "fault-injection")]
        {
            let marker = self.path.with_extension("share-crash");
            if marker.is_file() {
                fs::remove_file(&marker).expect("remove share crash marker");
                let parent = marker
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                fs::File::open(parent)
                    .and_then(|file| file.sync_all())
                    .expect("persist share crash marker removal");
                std::process::exit(86);
            }
        }
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        let raw = self.inner.lock().shares.get(&epoch.get()).cloned()?;
        Some(decode_secret(&raw).expect("validated stored DKG share"))
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.update(|data| {
            data.seeds.insert(epoch.get(), hex::encode(seed.encode()));
        })
        .expect("failed to persist seed");
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        let raw = self.inner.lock().seeds.get(&epoch.get()).cloned()?;
        Some(decode_secret(&raw).expect("validated stored DKG seed"))
    }

    async fn put_dealing<P: PublicKey>(&mut self, epoch: Epoch, dealer: P, private: DealerPrivMsg) {
        let key = Self::dealing_key(epoch, &dealer);
        self.update(|data| {
            data.dealings.insert(key, hex::encode(private.encode()));
        })
        .expect("failed to persist dealing");
    }

    async fn get_dealing<P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> Option<DealerPrivMsg> {
        let key = Self::dealing_key(epoch, dealer);
        let raw = self.inner.lock().dealings.get(&key).cloned()?;
        Some(decode_secret(&raw).expect("validated stored DKG dealing"))
    }

    async fn prune(&mut self, min: Epoch) {
        self.update(|inner| {
            inner.shares.retain(|epoch, _| *epoch >= min.get());
            inner.seeds.retain(|epoch, _| *epoch >= min.get());
            inner.dealings.retain(|key, _| {
                key.split_once(':')
                    .and_then(|(epoch, _)| epoch.parse::<u64>().ok())
                    .is_some_and(|epoch| epoch >= min.get())
            });
        })
        .expect("failed to persist prune");
    }
}

#[cfg(test)]
mod tests;
