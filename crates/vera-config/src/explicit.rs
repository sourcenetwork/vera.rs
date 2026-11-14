//! Values a configuration file states itself, as opposed to inheriting a default.

use std::path::Path;

use serde::Deserialize;

use crate::{ConfigError, NodeConfig};

#[derive(Deserialize)]
struct Stated {
    chain_id: Option<u64>,
}

impl NodeConfig {
    /// Chain ID written in the file at `path`, absent when the file leaves it to the default.
    ///
    /// Reads the same formats as [`NodeConfig::load`] and looks at no other field.
    pub fn stated_chain_id(path: &Path) -> Result<Option<u64>, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.into(),
            source,
        })?;
        let stated: Stated = match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") => serde_json::from_str(&contents)?,
            _ => toml::from_str(&contents)?,
        };
        Ok(stated.chain_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stated(name: &str, contents: &str) -> Option<u64> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(name);
        std::fs::write(&path, contents).unwrap();
        NodeConfig::stated_chain_id(&path).unwrap()
    }

    #[test]
    fn only_a_written_chain_id_is_reported() {
        let default = crate::DEFAULT_CHAIN_ID;
        assert_eq!(stated("node.toml", "chain_id = 1234\n"), Some(1234));
        assert_eq!(
            stated("node.toml", &format!("chain_id = {default}\n")),
            Some(default)
        );
        assert_eq!(stated("node.toml", "data_dir = \"/tmp/vera\"\n"), None);
        assert_eq!(stated("node.json", r#"{"chain_id": 77}"#), Some(77));
        assert_eq!(stated("node.json", r#"{"data_dir": "/tmp/vera"}"#), None);
    }

    #[test]
    fn unreadable_files_are_errors() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.toml");
        assert!(matches!(
            NodeConfig::stated_chain_id(&missing),
            Err(ConfigError::Read { .. })
        ));
    }
}
