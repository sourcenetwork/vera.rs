//! Storage states a test cannot reach by running nodes, in fault-injection builds.

use std::path::Path;

use alloy_primitives::B256;
use commonware_codec::Decode as _;
use commonware_storage::archive::Archive as _;

use super::{
    TermRefusal,
    seating::{Certificate, Finalizations},
};
use crate::{FinalizedHistory, HistoryMemory};

const ORPHAN: &str = "orphan-finalization";
const INTERRUPT: &str = "seating-interrupt";

/// Store the finalization certificate of the block above this node's newest
/// one, which it never received.
///
/// Marshal writes a block and its certificate separately, and a backup
/// stopped between the two keeps the certificate alone. The marker names the
/// directory of the stopped node that finalized the block.
pub(crate) async fn orphan(
    directory: &Path,
    finalizations: Finalizations,
    newest: Option<u64>,
    genesis: &B256,
    memory: Option<HistoryMemory>,
) -> anyhow::Result<Finalizations> {
    let marker = directory.join(ORPHAN);
    let Ok(source) = std::fs::read_to_string(&marker) else {
        return Ok(finalizations);
    };
    let height = newest.unwrap_or(0) + 1;
    let source = Path::new(source.trim()).join("history");
    let bytes = FinalizedHistory::open_stored(&source, genesis, memory)?
        .finalization(height)?
        .ok_or_else(|| anyhow::anyhow!("no finalization of block {height} to orphan"))?;
    let certificate = Certificate::decode_cfg(commonware_codec::Copying(bytes.as_slice()), &())?;
    let finalizations = finalizations
        .put_sync(height, certificate.proposal.payload, &certificate)
        .await?;
    std::fs::remove_file(marker)?;
    Ok(finalizations)
}

/// Fail once where a crash leaves the archive of certificates to be rebuilt.
pub(crate) fn interrupt(directory: &Path) -> Result<(), TermRefusal> {
    let marker = directory.join(INTERRUPT);
    if !marker.is_file() {
        return Ok(());
    }
    std::fs::remove_file(&marker)
        .and_then(|()| Err(std::io::Error::other("injected interruption")))
        .map_err(|source| TermRefusal::Io {
            path: marker,
            source,
        })
}
