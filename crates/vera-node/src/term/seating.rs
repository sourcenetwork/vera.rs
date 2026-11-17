//! Consensus storage across a change of role.
//!
//! Simplex journals an epoch's votes and certificates, and marshal caches
//! the blocks and certificates of recent views. Both are written in the role
//! a device ran in: a validator's journal holds votes a backup cannot replay,
//! and a backup's may hold certificates of blocks a term voided. A device
//! that changes role removes them and starts consensus on its newest
//! finalized block, which [`super::floor`] selects.

use std::path::Path;

use commonware_codec::{Decode as _, Encode as _};
use commonware_consensus::simplex::types::Finalization;
use commonware_runtime::{Supervisor as _, tokio};
use commonware_storage::{
    archive::{Archive as _, Identifier, prunable},
    translator::TwoCap,
};
use serde::{Deserialize, Serialize};
use vera_app::ConsensusScheme;
use vera_domain::ConsensusDigest;

use super::{TermRecord, TermRefusal, kept};
use crate::node::PARTITION_PREFIX;

/// The partitions Simplex journals an epoch's votes and certificates in.
const JOURNAL: &str = "-orchestrator_consensus_";
/// The partitions marshal caches the blocks and certificates of recent views in.
const CACHE: &str = "-cache-";

pub(crate) type Certificate = Finalization<ConsensusScheme, ConsensusDigest>;
/// Marshal's finalization certificates by height.
pub(crate) type Finalizations =
    prunable::Archive<TwoCap, tokio::Context, ConsensusDigest, Certificate>;

/// The role consensus last opened its storage in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Role {
    Validator,
    Backup,
}

/// Consensus storage a start decided to clear and has not finished clearing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Seating {
    /// Height of the cut of a term this device takes over under. Marshal's
    /// cache and its certificates above the cut are void in that term.
    pub cut: Option<u64>,
}

/// Clear what the role before left in consensus storage, before marshal and
/// Simplex open it.
///
/// - A change of role removes the vote journals.
/// - A term voids every block above its cut in a lower term, and a device
///   may hold the finalization certificate of such a block without the
///   block: marshal stores the two separately, and the device that built it
///   may be gone. Commonware's archive keeps the first certificate stored
///   for a height, so the block the term builds there could not be certified
///   in it. A start as the validator under a certificate this device has not
///   started under therefore removes the vote journals, marshal's cache and
///   every certificate above the cut. A backup that holds the certificate of
///   a term does the same while it holds a certificate above the cut.
/// - A block above the cut is another matter. A validator's start refuses
///   it, a backup holds it because it belongs to the term, and nothing is
///   cleared for the cut.
///
/// The decision is stored before anything is removed, and a start that finds
/// it finishes the clearing first, whichever role it runs in.
pub(crate) async fn settle(
    context: tokio::Context,
    directory: &Path,
    backup: bool,
    mut finalizations: Finalizations,
    newest_block: Option<u64>,
    config: prunable::Config<TwoCap, ()>,
) -> Result<Finalizations, TermRefusal> {
    let mut record = TermRecord::load(directory)?;
    if let Some(pending) = record.seating {
        finalizations = clear(
            context.child("resumed"),
            directory,
            pending,
            finalizations,
            &config,
        )
        .await?;
    }
    let role = if backup {
        Role::Backup
    } else {
        Role::Validator
    };
    let deciding = if backup {
        record
            .certificate
            .as_ref()
            .filter(|certificate| finalizations.last_index() > Some(certificate.change.cut.height))
    } else {
        record.taking_over.as_ref()
    };
    let cut = deciding
        .map(|certificate| certificate.change.cut.height)
        .filter(|cut| newest_block.is_none_or(|newest| newest <= *cut));
    let changed = record.ran.map_or(backup, |ran| ran != role);
    if changed || cut.is_some() {
        let seating = Seating { cut };
        record.seating = Some(seating);
        record.store(directory)?;
        finalizations = clear(
            context.child("cleared"),
            directory,
            seating,
            finalizations,
            &config,
        )
        .await?;
    }
    if record.seating.is_some() || record.ran != Some(role) {
        record.seating = None;
        record.ran = Some(role);
        record.store(directory)?;
    }
    Ok(finalizations)
}

async fn clear(
    context: tokio::Context,
    directory: &Path,
    seating: Seating,
    finalizations: Finalizations,
    config: &prunable::Config<TwoCap, ()>,
) -> Result<Finalizations, TermRefusal> {
    let storage = directory.join("commonware");
    let removed = |source| TermRefusal::Io {
        path: storage.clone(),
        source,
    };
    remove(&storage, JOURNAL).map_err(removed)?;
    let Some(cut) = seating.cut else {
        return Ok(finalizations);
    };
    remove(&storage, CACHE).map_err(removed)?;
    cut_back(context, directory, finalizations, cut, config).await
}

/// Rebuild `archive` without the certificates above `cut`.
///
/// The archive cannot drop an entry, so the certificates up to the cut are
/// copied to a file, the archive is destroyed, and a new one is filled from
/// the file. The file is complete before the archive is touched and is
/// removed last, so an interrupted call is repeated from the file.
async fn cut_back(
    context: tokio::Context,
    directory: &Path,
    archive: Finalizations,
    cut: u64,
    config: &prunable::Config<TwoCap, ()>,
) -> Result<Finalizations, TermRefusal> {
    if !kept::stored(directory) {
        if archive.last_index().is_none_or(|last| last <= cut) {
            return Ok(archive);
        }
        let mut writer = kept::Writer::create(directory)?;
        let ranges: Vec<_> = archive.ranges().collect();
        for (first, last) in ranges {
            for height in first..=last.min(cut) {
                let certificate = archive
                    .get(Identifier::Index(height))
                    .await
                    .map_err(archive_failed)?;
                if let Some(certificate) = certificate {
                    writer.push(height, certificate.encode().as_ref())?;
                }
            }
        }
        writer.finish()?;
    }
    #[cfg(feature = "fault-injection")]
    super::fault::interrupt(directory)?;
    archive.destroy().await.map_err(archive_failed)?;
    let mut archive = prunable::Archive::init(context, config.clone())
        .await
        .map_err(archive_failed)?;
    for entry in kept::read(directory)? {
        let (height, bytes) = entry?;
        let certificate = Certificate::decode_cfg(commonware_codec::Copying(bytes.as_slice()), &())
            .map_err(|error| TermRefusal::Record {
                path: kept::path(directory),
                reason: error.to_string(),
            })?;
        archive = archive
            .put(height, certificate.proposal.payload, &certificate)
            .await
            .map_err(archive_failed)?;
    }
    let archive = archive.sync().await.map_err(archive_failed)?;
    kept::remove(directory)?;
    Ok(archive)
}

fn archive_failed(error: commonware_storage::archive::Error) -> TermRefusal {
    TermRefusal::Archive(error.to_string())
}

/// Remove every partition of `kind`.
fn remove(storage: &Path, kind: &str) -> std::io::Result<()> {
    let prefix = format!("{PARTITION_PREFIX}{kind}");
    let entries = match std::fs::read_dir(storage) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut removed = false;
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            std::fs::remove_dir_all(entry.path())?;
            removed = true;
        }
    }
    if removed {
        std::fs::File::open(storage)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "seating_tests.rs"]
mod tests;
