//! Key management for e2e test clusters.
//!
//! Generates ed25519 identity keys and a trusted-dealer BLS12-381 threshold
//! sharing for epoch 0, exactly as `verad testnet` does.

use std::{collections::BTreeMap, path::Path};

use commonware_codec::Encode;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{Signer as _, bls12381::primitives::group::Share, ed25519};
use commonware_utils::ordered::Map;
use vera_node::{FileSecretStore, GenesisEpochInfo, epoch_info_hex, trusted_setup};

/// Complete key material for a test cluster.
#[derive(Debug)]
pub struct KeySet {
    identity_keys: Vec<ed25519::PrivateKey>,
    participants: Vec<ed25519::PublicKey>,
    threshold: u32,
    epoch_info: GenesisEpochInfo,
    shares: Map<ed25519::PublicKey, Share>,
    seed: u64,
}

impl KeySet {
    /// Create a [`KeySetBuilder`] for configuring key generation.
    pub fn builder() -> KeySetBuilder {
        KeySetBuilder::default()
    }

    /// Number of nodes (validators) in the key set.
    pub const fn node_count(&self) -> usize {
        self.identity_keys.len()
    }

    /// BFT signing threshold for the cluster.
    pub const fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Seed used to derive all keys deterministically.
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Ordered participant public keys for the cluster.
    pub fn participants(&self) -> &[ed25519::PublicKey] {
        &self.participants
    }

    /// Epoch-0 DKG artifact shared by every node.
    pub const fn epoch_info(&self) -> &GenesisEpochInfo {
        &self.epoch_info
    }

    /// Epoch-0 artifact as stored in `genesis.json`.
    pub fn epoch_info_hex(&self) -> String {
        epoch_info_hex(&self.epoch_info)
    }

    /// BLS share for the node at `index`.
    pub fn share(&self, index: usize) -> Option<&Share> {
        self.shares.get_value(&self.participants[index])
    }

    /// Write `validator.key` (raw 32-byte ed25519 private key) and
    /// `secrets.json` (the epoch-0 BLS share) per node.
    pub fn write_to(&self, node_dirs: &[impl AsRef<Path>]) -> eyre::Result<()> {
        assert_eq!(
            node_dirs.len(),
            self.node_count(),
            "expected {} dirs, got {}",
            self.node_count(),
            node_dirs.len()
        );

        for (i, dir) in node_dirs.iter().enumerate() {
            let dir = dir.as_ref();
            std::fs::create_dir_all(dir)?;
            let key_bytes = Encode::encode(&self.identity_keys[i]);
            vera_cli::write_private(dir.join("validator.key"), key_bytes.as_ref())?;
            let share = self
                .share(i)
                .cloned()
                .ok_or_else(|| eyre::eyre!("no BLS share for node {i}"))?;
            FileSecretStore::load(dir.join("secrets.json"))
                .map_err(|e| eyre::eyre!("{e:#}"))?
                .put_initial_share(Epoch::zero(), share)
                .map_err(|e| eyre::eyre!("{e:#}"))?;
        }

        Ok(())
    }

    /// Write a peers.json file for use by validator processes.
    pub fn write_peers(&self, path: &Path, p2p_ports: &[u16]) -> eyre::Result<()> {
        let participants_hex: Vec<String> = self
            .participants
            .iter()
            .map(|pk| hex::encode(Encode::encode(pk)))
            .collect();

        let bootstrappers: BTreeMap<String, String> = self
            .participants
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                let pk_hex = hex::encode(Encode::encode(pk));
                let addr = format!("127.0.0.1:{}", p2p_ports[i]);
                (pk_hex, addr)
            })
            .collect();

        let peers_json = serde_json::json!({
            "participants": participants_hex,
            "bootstrappers": bootstrappers,
        });

        std::fs::write(path, serde_json::to_string_pretty(&peers_json)?)?;
        Ok(())
    }

    /// Whether this key set is for a single-node cluster.
    pub const fn is_single_node(&self) -> bool {
        self.identity_keys.len() == 1
    }
}

/// Builder for [`KeySet`].
#[derive(Debug)]
pub struct KeySetBuilder {
    nodes: usize,
    threshold: Option<u32>,
    seed: Option<u64>,
}

impl Default for KeySetBuilder {
    fn default() -> Self {
        Self {
            nodes: 4,
            threshold: None,
            seed: None,
        }
    }
}

impl KeySetBuilder {
    /// Set the number of nodes (validators) to generate keys for.
    #[must_use]
    pub const fn nodes(mut self, n: usize) -> Self {
        self.nodes = n;
        self
    }

    /// Set an explicit BFT signing threshold.
    #[must_use]
    pub const fn threshold(mut self, t: u32) -> Self {
        self.threshold = Some(t);
        self
    }

    /// Set a deterministic seed for key generation.
    #[must_use]
    pub const fn seed(mut self, s: u64) -> Self {
        self.seed = Some(s);
        self
    }

    /// Build the key set.
    ///
    /// Fails for zero nodes and for multi-node clusters smaller than 4
    /// (below BFT quorum).
    pub fn build(self) -> eyre::Result<KeySet> {
        let n = self.nodes;
        if n == 0 {
            return Err(eyre::eyre!("need at least 1 node"));
        }
        if n > 1 && n < 4 {
            return Err(eyre::eyre!(
                "multi-node clusters need at least 4 nodes for BFT quorum (got {})",
                n
            ));
        }

        let seed = self.seed.unwrap_or_else(rand::random);
        let f = if n > 1 { (n - 1) / 3 } else { 0 };
        let threshold = self
            .threshold
            .unwrap_or(if n == 1 { 1 } else { (n - f) as u32 });

        let seed_keys: Vec<ed25519::PrivateKey> = (0..n)
            .map(|i| ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64)))
            .collect();
        let (epoch_info, shares) = trusted_setup(seed, seed_keys.iter().map(|k| k.public_key()))
            .map_err(|e| eyre::eyre!("{e:#}"))?;

        let participants: Vec<ed25519::PublicKey> = epoch_info.players.iter().cloned().collect();
        let identity_keys: Vec<ed25519::PrivateKey> = participants
            .iter()
            .map(|pk| {
                seed_keys
                    .iter()
                    .find(|k| k.public_key() == *pk)
                    .expect("all participants derived from seed")
                    .clone()
            })
            .collect();

        Ok(KeySet {
            identity_keys,
            participants,
            threshold,
            epoch_info,
            shares,
            seed,
        })
    }
}
