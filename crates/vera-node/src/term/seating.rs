//! Consensus storage across a change of role.
//!
//! Simplex journals an epoch's votes and certificates, and marshal caches
//! the blocks and certificates of recent views. A validator's journal holds
//! the votes its key cast, which a backup cannot replay and the validator
//! must not cast again, so each role journals in partitions of its own and a
//! backup leaves the validator's alone. A backup's journal may hold
//! certificates of blocks a term voided, and a term voids what either
//! journal and the cache hold above its cut. Consensus starts on the
//! device's newest finalized block, which [`super::floor`] selects.

use std::path::Path;

use alloy_primitives::B256;
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

/// The orchestrator's partition prefix for a validator's journals.
const VALIDATOR: &str = "-orchestrator";
/// The orchestrator's partition prefix for a backup's journals.
const BACKUP: &str = "-observer";
/// What the orchestrator appends to its prefix for an epoch's journal.
const JOURNAL: &str = "_consensus_";
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

impl Role {
    pub(crate) const fn of(backup: bool) -> Self {
        if backup {
            Self::Backup
        } else {
            Self::Validator
        }
    }

    /// The orchestrator's partition prefix for the journals of this role,
    /// after the node's own prefix.
    pub(crate) const fn journals(self) -> &'static str {
        match self {
            Self::Validator => VALIDATOR,
            Self::Backup => BACKUP,
        }
    }
}

/// Consensus storage a start decided to clear and has not finished clearing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Seating {
    /// The role of the start that decided it.
    pub role: Role,
    /// Height of the cut of a term this device takes over under, or follows
    /// past a certificate above it. Both roles' journals, marshal's cache and
    /// its certificates above the cut are void in that term.
    pub cut: Option<u64>,
}

/// What a start knows of the device before consensus opens its storage.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Start {
    /// The identifier term certificates name this device by, when it switches.
    pub this: Option<B256>,
    pub backup: bool,
    /// Height of the newest block in marshal's archive.
    pub newest_block: Option<u64>,
    /// Height of the newest block in finalized history.
    pub executed: u64,
}

/// Clear what the role before left in consensus storage, before marshal and
/// Simplex open it.
///
/// - A start as a backup after a start as the validator removes the
///   backup's journals: they predate the blocks the device built since. The
///   validator's journals are kept, so the votes they hold are not cast
///   again when the device validates once more without a new term.
/// - A term voids every block above its cut in a lower term, and a device
///   may hold the finalization certificate of such a block without the
///   block: marshal stores the two separately, and the device that built it
///   may be gone. Commonware's archive keeps the first certificate stored
///   for a height, so the block the term builds there could not be certified
///   in it. A start as the validator under a certificate this device has not
///   started under therefore removes both roles' journals, marshal's cache
///   and every certificate above the cut.
/// - Such a start is refused with [`TermRefusal::NotAtCut`] before anything
///   is removed unless the device's newest block in history is the cut and
///   marshal holds no block above it. The takeover is then abandoned.
/// - A backup that holds the certificate of a term naming another device
///   does the same as the validator while it holds a certificate above the
///   cut and no block above it. Without the block it cannot tell the
///   replaced device's certificate from the holder's, and the holder's is
///   fetched again with its block. A certificate that names this device
///   clears nothing: the blocks above its cut are this device's own blocks
///   of that term, whose votes and blocks the journal and the cache hold.
/// - A block above the cut is another matter. A backup holds it because it
///   belongs to the term, and nothing is cleared for the cut.
///
/// The decision is stored before anything is removed, and a start that finds
/// it finishes the clearing first, whichever role it runs in.
pub(crate) async fn settle(
    context: tokio::Context,
    directory: &Path,
    start: Start,
    mut finalizations: Finalizations,
    config: prunable::Config<TwoCap, ()>,
) -> Result<Finalizations, TermRefusal> {
    let Start {
        this,
        backup,
        newest_block,
        executed,
    } = start;
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
    let role = Role::of(backup);
    if !backup && let Some(certificate) = &record.taking_over {
        let cut = certificate.change.cut.height;
        let above = newest_block.filter(|newest| *newest > cut);
        if above.is_some() || executed != cut {
            record.taking_over = None;
            record.store(directory)?;
            return Err(TermRefusal::NotAtCut {
                head: above.unwrap_or(executed),
                cut,
            });
        }
    }
    let cut = if backup {
        record
            .certificate
            .as_ref()
            .filter(|certificate| Some(certificate.change.holder) != this)
            .map(|certificate| certificate.change.cut.height)
            .filter(|cut| {
                finalizations.last_index() > Some(*cut)
                    && newest_block.is_none_or(|newest| newest <= *cut)
            })
    } else {
        record
            .taking_over
            .as_ref()
            .map(|certificate| certificate.change.cut.height)
    };
    let changed = record.ran.map_or(backup, |ran| ran != role);
    if (changed && backup) || cut.is_some() {
        let seating = Seating { role, cut };
        record.seating = Some(seating);
        record.store(directory)?;
        #[cfg(feature = "fault-injection")]
        crate::crash::point(directory, "seating-decided");
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
    let Some(cut) = seating.cut else {
        remove(&storage, &journals(seating.role)).map_err(removed)?;
        return Ok(finalizations);
    };
    for role in [Role::Validator, Role::Backup] {
        remove(&storage, &journals(role)).map_err(removed)?;
    }
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

fn journals(role: Role) -> String {
    format!("{}{JOURNAL}", role.journals())
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
