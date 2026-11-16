//! The newest term a device holds, kept in its directory.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use vera_domain::{TermCertificate, TermChange};

use super::TermRefusal;

const FILE: &str = "term.json";
const PENDING: &str = "term.pending";

/// What a device knows about the deployment's term. Neither part is secret.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TermRecord {
    /// The newest certificate this device verified against its own state.
    pub certificate: Option<TermCertificate>,
    /// A handover this device announced. It proposes nothing until the
    /// handover is certified or the host resumes.
    pub handed_over: Option<TermChange>,
    /// A certificate this device accepted as holder and has not started
    /// under. It becomes `certificate` once the device has started as the
    /// validator with no block above the cut.
    pub taking_over: Option<TermCertificate>,
    /// Whether the consensus journal in the directory holds votes this
    /// device cast as the validator.
    pub voted: bool,
}

impl TermRecord {
    /// The record in `directory`, or an empty one when none was stored.
    pub(crate) fn load(directory: &Path) -> Result<Self, TermRefusal> {
        let path = directory.join(FILE);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| TermRefusal::Record {
                path,
                reason: error.to_string(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(TermRefusal::Io { path, source }),
        }
    }

    /// Replace the record in `directory`. It is durable when this returns.
    pub(crate) fn store(&self, directory: &Path) -> Result<(), TermRefusal> {
        let path = directory.join(FILE);
        let pending = directory.join(PENDING);
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| TermRefusal::Record {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        write(&pending, &path, directory, &bytes).map_err(|source| TermRefusal::Io { path, source })
    }

    /// The change of the newest certified term.
    pub(crate) fn change(&self) -> Option<&TermChange> {
        self.certificate
            .as_ref()
            .map(|certificate| &certificate.change)
    }

    /// The certificate that decides whether this device may validate: the
    /// one it is taking over under, or else the newest it holds.
    pub(crate) fn deciding(&self) -> Option<&TermCertificate> {
        self.taking_over.as_ref().or(self.certificate.as_ref())
    }
}

fn write(pending: &PathBuf, path: &Path, directory: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)?;
    let mut file = std::fs::File::create(pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(pending, path)?;
    std::fs::File::open(directory)?.sync_all()
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use vera_domain::TermCut;

    use super::*;

    fn change(term: u64) -> TermChange {
        TermChange {
            genesis_id: B256::repeat_byte(1),
            term,
            holder: B256::repeat_byte(term as u8),
            cut: TermCut {
                height: 10 * term,
                block: B256::repeat_byte(3),
            },
        }
    }

    #[test]
    fn a_stored_record_is_read_back_and_an_absent_one_is_empty() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            TermRecord::load(directory.path()).unwrap(),
            TermRecord::default()
        );
        let record = TermRecord {
            certificate: Some(TermCertificate {
                change: change(2),
                approvals: Vec::new(),
            }),
            handed_over: Some(change(3)),
            taking_over: None,
            voted: true,
        };
        record.store(directory.path()).unwrap();
        assert_eq!(TermRecord::load(directory.path()).unwrap(), record);
        assert_eq!(record.deciding(), record.certificate.as_ref());
        assert!(!directory.path().join(PENDING).exists());
        TermRecord::default().store(directory.path()).unwrap();
        assert_eq!(
            TermRecord::load(directory.path()).unwrap(),
            TermRecord::default()
        );
    }

    #[test]
    fn a_record_that_does_not_decode_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(FILE), b"{\"term\": 3}").unwrap();
        assert!(matches!(
            TermRecord::load(directory.path()),
            Err(TermRefusal::Record { .. })
        ));
    }
}
