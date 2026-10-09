//! Top-level node configuration.

use std::path::{Path, PathBuf};

use commonware_codec::DecodeExt;
use serde::{Deserialize, Serialize};

use crate::{ConfigError, ExecutionConfig, NetworkConfig, RpcConfig};

/// Default chain ID for local development.
pub const DEFAULT_CHAIN_ID: u64 = 1;

/// Default data directory.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/verad";

/// Bounds for initial snapshot catch-up. Subsequent starts resume durable progress.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SnapshotConfig {
    /// Maximum assembled execution record, including receipts (default 64 MiB).
    pub record_bytes: usize,
    /// Maximum logs in one imported execution record (default 100,000).
    pub logs: usize,
    /// Deadline for one record or finality proof from one peer (default 10 seconds).
    pub peer_timeout_ms: u64,
    /// Deadline for snapshot database and history initialization (default 5 minutes).
    pub initialization_timeout_ms: u64,
    /// Seconds without finalized-processing progress that re-floors snapshot
    /// initialization from the newest stored finalization (default 15, 0 disables).
    pub floor_stall_seconds: u64,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            record_bytes: 64 << 20,
            logs: 100_000,
            peer_timeout_ms: 10_000,
            initialization_timeout_ms: 300_000,
            floor_stall_seconds: 15,
        }
    }
}

/// Coordinated consensus archive and state journal retention.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningConfig {
    /// Finalized revisions between maintenance attempts.
    pub maintenance_interval: std::num::NonZeroUsize,
    /// Consensus revisions retained beyond the acknowledgement safety window.
    pub retained_consensus_revisions: usize,
    /// State revisions retained beyond the acknowledgement safety window.
    pub retained_state_revisions: usize,
}

impl PruningConfig {
    /// Validate retention ordering and room for the acknowledgement safety window.
    pub const fn validate(&self, epoch_length: std::num::NonZeroU64) -> Result<(), &'static str> {
        if self.retained_consensus_revisions < self.retained_state_revisions {
            return Err("consensus retention must cover state retention");
        }
        let Some(window) = self.retained_consensus_revisions.checked_add(2) else {
            return Err("retention exceeds the acknowledgement window limit");
        };
        if (window as u128) < epoch_length.get() as u128 {
            return Err("consensus retention must cover a complete DKG epoch");
        }
        Ok(())
    }
}

/// Complete node configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeConfig {
    /// Chain ID for the network.
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,

    /// Data directory for persistent storage.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Network configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Execution configuration.
    #[serde(default)]
    pub execution: ExecutionConfig,

    /// RPC configuration.
    #[serde(default)]
    pub rpc: RpcConfig,

    /// Request initial authenticated snapshot catch-up. Omit for retained-history replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotConfig>,

    /// Enable coordinated journal pruning; omission retains consensus history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruning: Option<PruningConfig>,

    /// Fail the process after this many seconds without a new finalization
    /// while peer connectivity is observed, so supervision can attempt rejoin.
    /// Unavailable connectivity telemetry leaves it unarmed. Zero disables it.
    #[serde(default = "default_watchdog_stall_seconds")]
    pub watchdog_stall_seconds: u64,
}

const DEFAULT_WATCHDOG_STALL_SECONDS: u64 = 600;

const fn default_watchdog_stall_seconds() -> u64 {
    DEFAULT_WATCHDOG_STALL_SECONDS
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID,
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            network: NetworkConfig::default(),
            execution: ExecutionConfig::default(),
            rpc: RpcConfig::default(),
            snapshot: None,
            pruning: None,
            watchdog_stall_seconds: DEFAULT_WATCHDOG_STALL_SECONDS,
        }
    }
}

impl NodeConfig {
    /// Load configuration from a file path, auto-detecting format by extension.
    ///
    /// If the path is `None`, returns the default configuration.
    /// Supported extensions: `.json` for JSON, all others default to TOML.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        path.map_or_else(
            || Ok(Self::default()),
            |p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("toml");
                match ext {
                    "json" => Self::from_json_file(p),
                    _ => Self::from_toml_file(p),
                }
            },
        )
    }

    /// Load configuration from a TOML file.
    pub fn from_toml_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.into(),
            source: e,
        })?;
        Self::from_toml(&contents)
    }

    /// Parse configuration from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    /// Load configuration from a JSON file.
    pub fn from_json_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.into(),
            source: e,
        })?;
        Self::from_json(&contents)
    }

    /// Parse configuration from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        Ok(serde_json::from_str(s)?)
    }

    /// Serialize configuration to a TOML string.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Serialize configuration to a JSON string.
    pub fn to_json(&self) -> Result<String, ConfigError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Get the validator private key from `{data_dir}/validator.key`.
    pub fn validator_key(
        &self,
    ) -> Result<commonware_cryptography::ed25519::PrivateKey, ConfigError> {
        let key_path = self.data_dir.join("validator.key");

        // Try to load existing key
        match vera_cli::open_private(&key_path).and_then(|mut file| {
            use std::io::Read as _;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(bytes)
        }) {
            Ok(key_bytes) => {
                if key_bytes.len() != 32 {
                    return Err(ConfigError::InvalidKeyLength(key_bytes.len()));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&key_bytes);
                Ok(commonware_cryptography::ed25519::PrivateKey::decode(
                    commonware_codec::Copying(&seed[..]),
                )?)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                for name in ["secrets.json", "native-genesis.bin", "history"] {
                    let path = self.data_dir.join(name);
                    match std::fs::symlink_metadata(&path) {
                        Ok(_) => return Err(ConfigError::MissingValidatorKey(key_path)),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(source) => return Err(ConfigError::Read { path, source }),
                    }
                }
                // Generate new key
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);

                // Ensure parent directory exists
                if let Some(parent) = key_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| ConfigError::CreateDir {
                        path: parent.to_path_buf(),
                        source: e,
                    })?;
                }

                // Write key to disk with owner-only permissions.
                vera_cli::write_private(&key_path, &seed[..]).map_err(|e| ConfigError::Write {
                    path: key_path.clone(),
                    source: e,
                })?;

                Ok(commonware_cryptography::ed25519::PrivateKey::decode(
                    commonware_codec::Copying(&seed[..]),
                )?)
            }
            Err(e) => Err(ConfigError::Read {
                path: key_path,
                source: e,
            }),
        }
    }

    /// Get the validator public key.
    pub fn validator_public_key(
        &self,
    ) -> Result<commonware_cryptography::ed25519::PublicKey, ConfigError> {
        use commonware_cryptography::Signer as _;
        Ok(self.validator_key()?.public_key())
    }
}

const fn default_chain_id() -> u64 {
    DEFAULT_CHAIN_ID
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_requires_valid_explicit_limits() {
        assert!(NodeConfig::from_toml("").unwrap().pruning.is_none());
        let text = "[pruning]\nmaintenance_interval = 1\nretained_consensus_revisions = 18\nretained_state_revisions = 0";
        let config = NodeConfig::from_toml(text).unwrap();
        let mut pruning = config.pruning.clone().unwrap();
        let epoch_length = std::num::NonZeroU64::new(20).unwrap();
        pruning.validate(epoch_length).unwrap();
        pruning.retained_consensus_revisions = 17;
        assert!(pruning.validate(epoch_length).is_err());
        pruning.retained_consensus_revisions = 18;
        assert_eq!(
            NodeConfig::from_json(&config.to_json().unwrap()).unwrap(),
            config
        );
        assert_eq!(
            NodeConfig::from_toml(&config.to_toml().unwrap()).unwrap(),
            config
        );
        assert!(NodeConfig::from_toml(&text.replace("interval = 1", "interval = 0")).is_err());
        pruning.retained_state_revisions = 19;
        assert!(pruning.validate(epoch_length).is_err());
        pruning.retained_consensus_revisions = usize::MAX;
        assert!(pruning.validate(epoch_length).is_err());
    }

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(config.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
    }

    #[test]
    fn snapshot_is_opt_in_and_preserves_configured_bounds() {
        assert!(NodeConfig::from_toml("").unwrap().snapshot.is_none());
        let default = NodeConfig::from_toml("[snapshot]").unwrap();
        assert_eq!(default.snapshot, Some(SnapshotConfig::default()));
        let configured = NodeConfig::from_toml(
            "[snapshot]\nrecord_bytes = 1024\nlogs = 4\npeer_timeout_ms = 500\ninitialization_timeout_ms = 2000\nfloor_stall_seconds = 3",
        )
        .unwrap();
        assert_eq!(configured.snapshot.as_ref().unwrap().record_bytes, 1024);
        assert_eq!(configured.snapshot.as_ref().unwrap().logs, 4);
        assert_eq!(configured.snapshot.as_ref().unwrap().peer_timeout_ms, 500);
        assert_eq!(
            configured
                .snapshot
                .as_ref()
                .unwrap()
                .initialization_timeout_ms,
            2000
        );
        assert_eq!(configured.snapshot.as_ref().unwrap().floor_stall_seconds, 3);
        assert_eq!(
            NodeConfig::from_toml(&configured.to_toml().unwrap()).unwrap(),
            configured
        );
    }

    #[test]
    fn test_toml_roundtrip() {
        let config = NodeConfig::default();
        let toml_str = config.to_toml().unwrap();
        let parsed = NodeConfig::from_toml(&toml_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_json_roundtrip() {
        let config = NodeConfig::default();
        let json_str = config.to_json().unwrap();
        let parsed = NodeConfig::from_json(&json_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_load_none_returns_default() {
        let config = NodeConfig::load(None).unwrap();
        assert_eq!(config, NodeConfig::default());
    }

    #[test]
    fn test_load_toml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let expected = NodeConfig {
            chain_id: 42,
            ..Default::default()
        };
        std::fs::write(&path, expected.to_toml().unwrap()).unwrap();

        let loaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(loaded.chain_id, 42);
    }

    #[test]
    fn test_load_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let expected = NodeConfig {
            chain_id: 99,
            ..Default::default()
        };
        std::fs::write(&path, expected.to_json().unwrap()).unwrap();

        let loaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(loaded.chain_id, 99);
    }

    #[test]
    fn test_load_unknown_extension_defaults_to_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.conf");
        let expected = NodeConfig {
            chain_id: 77,
            ..Default::default()
        };
        std::fs::write(&path, expected.to_toml().unwrap()).unwrap();

        let loaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(loaded.chain_id, 77);
    }

    #[test]
    fn test_load_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.toml");
        assert!(NodeConfig::load(Some(&path)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn validator_rejects_exposed_and_linked_identity_without_regeneration() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let config = NodeConfig {
            data_dir: directory.path().to_path_buf(),
            ..Default::default()
        };
        config.validator_key().unwrap();
        let path = config.data_dir.join("validator.key");
        let original = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            config.validator_key(),
            Err(ConfigError::Read { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o644);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let retained = directory.path().join("retained.key");
        std::fs::rename(&path, &retained).unwrap();
        std::os::unix::fs::symlink(&retained, &path).unwrap();
        assert!(matches!(
            config.validator_key(),
            Err(ConfigError::Read { .. })
        ));
        assert_eq!(std::fs::read_link(&path).unwrap(), retained);
        assert_eq!(std::fs::read(&retained).unwrap(), original);
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&retained, &path).unwrap();
        assert!(config.validator_key().is_ok());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn validator_identity_is_reused_after_initial_creation() {
        use commonware_codec::Encode as _;

        let directory = tempfile::tempdir().unwrap();
        let config = NodeConfig {
            data_dir: directory.path().join("node"),
            ..Default::default()
        };
        let first = config.validator_key().unwrap().encode();
        assert_eq!(config.validator_key().unwrap().encode(), first);
        assert_eq!(
            std::fs::read(config.data_dir.join("validator.key")).unwrap(),
            first.as_ref()
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_validator_link_target_is_not_regenerated() {
        let directory = tempfile::tempdir().unwrap();
        let config = NodeConfig {
            data_dir: directory.path().to_path_buf(),
            ..Default::default()
        };
        let path = config.data_dir.join("validator.key");
        let target = directory.path().join("missing.key");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(config.validator_key().is_err());
        assert_eq!(std::fs::read_link(path).unwrap(), target);
        assert!(!target.exists());
    }

    #[test]
    fn missing_validator_key_preserves_retained_state() {
        for name in ["secrets.json", "native-genesis.bin", "history"] {
            let directory = tempfile::tempdir().unwrap();
            let config = NodeConfig {
                data_dir: directory.path().to_path_buf(),
                ..Default::default()
            };
            let retained = config.data_dir.join(name);
            if name == "history" {
                std::fs::create_dir(&retained).unwrap();
            } else {
                std::fs::write(&retained, b"retained").unwrap();
            }
            let path = config.data_dir.join("validator.key");
            assert!(matches!(
                config.validator_key(),
                Err(ConfigError::MissingValidatorKey(missing)) if missing == path
            ));
            assert!(!path.exists());
            if name == "history" {
                assert_eq!(std::fs::read_dir(retained).unwrap().count(), 0);
            } else {
                assert_eq!(std::fs::read(retained).unwrap(), b"retained");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn retained_state_links_also_prevent_validator_key_regeneration() {
        let directory = tempfile::tempdir().unwrap();
        let config = NodeConfig {
            data_dir: directory.path().to_path_buf(),
            ..Default::default()
        };
        let retained = config.data_dir.join("secrets.json");
        let target = directory.path().join("missing-secrets.json");
        std::os::unix::fs::symlink(&target, &retained).unwrap();
        assert!(matches!(
            config.validator_key(),
            Err(ConfigError::MissingValidatorKey(_))
        ));
        assert!(!config.data_dir.join("validator.key").exists());
        assert_eq!(std::fs::read_link(retained).unwrap(), target);
        assert!(!target.exists());
    }
}
