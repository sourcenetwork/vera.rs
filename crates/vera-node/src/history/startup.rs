use std::{sync::Arc, time::Duration};

use super::*;
use vera_domain::{ConsensusPublicKey, PublicKey, verify_finalized_block};

pub(crate) struct SnapshotHistory {
    pub history: Arc<FinalizedHistory>,
    pub genesis: Block,
    pub index: Arc<BlockIndex>,
    pub epochs: Arc<LightBlockIndex>,
    pub trusted: ConsensusPublicKey,
    pub lookup: FinalizationLookup,
    pub limits: HistoryLimits,
    pub deadline: Duration,
    #[cfg(feature = "fault-injection")]
    pub crash_marker: std::path::PathBuf,
}

impl SnapshotHistory {
    pub(crate) async fn recover(
        &self,
        client: &mut HistoryPeer,
        peers: &[PublicKey],
        selected: &Block,
    ) -> Result<()> {
        if self.history.import_anchor()?.is_some() || self.history.head.lock().0 < selected.height {
            let mut selection = Err(anyhow::anyhow!("no history peers available"));
            let mut preferred = 0;
            for (index, peer) in peers.iter().enumerate() {
                selection = async {
                    let proof = client
                        .proof_from(peer, selected.height, self.deadline)
                        .await?;
                    ensure!(
                        verify_finalized_block(&proof, &self.trusted)? == *selected,
                        "snapshot history selection mismatch"
                    );
                    self.history.begin_import(&proof, &self.trusted)
                }
                .await;
                if selection.is_ok() {
                    preferred = index;
                    break;
                }
                tracing::warn!(%peer, error = %selection.as_ref().unwrap_err(), "history selection failed");
            }
            selection?;
            while let Some((height, _)) = self.history.import_next()? {
                let mut imported = Err(anyhow::anyhow!("no history peers available"));
                let mut pruned = None;
                for offset in 0..peers.len() {
                    let index = (preferred + offset) % peers.len();
                    let peer = &peers[index];
                    imported = client
                        .import_next_from(peer.clone(), &self.history, self.limits, self.deadline)
                        .await;
                    if imported.is_ok() {
                        preferred = index;
                        break;
                    }
                    let error = imported.as_ref().unwrap_err();
                    pruned = pruned.or(error.downcast_ref::<HistoryPruned>().copied());
                    tracing::warn!(%peer, height, %error, "history transfer failed");
                }
                // History is imported down to the store's own head, so a peer
                // that pruned below the selected block cannot complete it.
                if let (Err(_), Some(pruned)) = (&imported, pruned) {
                    imported = Err(anyhow::Error::new(pruned)
                        .context("history peers no longer retain the history this device lacks"));
                }
                ensure!(
                    imported.with_context(|| format!("import history at {height}"))?
                        == Some(height),
                    "history import cursor changed"
                );
                tracing::debug!(height, "staged snapshot history");
                #[cfg(feature = "fault-injection")]
                if self.crash_marker.is_file() {
                    std::fs::remove_file(&self.crash_marker)?;
                    std::fs::File::open(
                        self.crash_marker
                            .parent()
                            .context("snapshot crash directory missing")?,
                    )?
                    .sync_all()?;
                    std::process::abort();
                }
            }
        }
        self.history
            .recover(
                &self.genesis,
                selected,
                &self.index,
                &self.epochs,
                &self.lookup,
            )
            .await?;
        tracing::info!(height = selected.height, "snapshot history recovered");
        Ok(())
    }
}
