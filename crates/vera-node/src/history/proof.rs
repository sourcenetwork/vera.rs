use super::*;
use vera_domain::{LIGHT_BLOCK_MAX_ARTIFACT_BYTES, LIGHT_BLOCK_MAX_DESCENDANTS, LightBlock};

#[derive(BorshSerialize, BorshDeserialize)]
pub(super) struct ImportedFinality {
    block: [u8; 32],
    pub(super) certificate: Vec<u8>,
    material: Vec<u8>,
}

/// The revision is retained, but no certificate within the proof limits finalizes it yet.
#[derive(Debug, thiserror::Error)]
#[error("finalization certificate not found for height {height} within retained proof limits")]
pub(super) struct CertificateNotFound {
    height: u64,
}

impl FinalizedHistory {
    pub(super) fn retain_proof_suffix(
        &self,
        anchor: u64,
        head: u64,
        batch: &mut WriteBatch,
    ) -> Result<()> {
        if self.db.get(FORMAT)?.as_deref() != Some(&[3]) {
            return Ok(());
        }
        let mut remaining = LIGHT_BLOCK_MAX_ARTIFACT_BYTES;
        let Some(first) = anchor.checked_add(1) else {
            return Ok(());
        };
        for height in first..=head.min(anchor.saturating_add(LIGHT_BLOCK_MAX_DESCENDANTS as u64)) {
            let record = self
                .db
                .get_pinned(key(RECORD, height))?
                .context("missing finalized history suffix")?;
            let mut encoded = record.as_ref();
            let length = u32::deserialize(&mut encoded)? as usize;
            let Some(budget) = remaining.checked_sub(length) else {
                break;
            };
            remaining = budget;
            let bytes = encoded
                .get(..length)
                .context("truncated finalized history suffix")?;
            batch.put(key(PROOF_BLOCK, height), bytes);
        }
        Ok(())
    }

    pub(super) fn stage_finality(
        &self,
        proof: &LightBlock,
        block: &Block,
        anchor: u64,
        batch: &mut WriteBatch,
    ) -> Result<()> {
        // The caller verifies the entire proof against persisted import trust first.
        let mut certified = (block.height, block.id().0.0);
        for encoded in &proof.descendants {
            let bytes = unhex(encoded)?;
            let descendant = Block::decode_cfg(
                commonware_codec::Copying(bytes.as_slice()),
                &crate::node::block_cfg(),
            )?;
            certified = (descendant.height, descendant.id().0.0);
            if certified.0 > anchor {
                let key = key(PROOF_BLOCK, certified.0);
                if let Some(existing) = self.db.get(key)? {
                    ensure!(existing == bytes, "conflicting finalized proof block");
                }
                batch.put(key, bytes);
            }
        }
        let finality = ImportedFinality {
            block: certified.1,
            certificate: unhex(&proof.finalization)?,
            material: unhex(&proof.epoch_material)?,
        };
        if let Some(bytes) = self.db.get(key(IMPORTED_FINALITY, certified.0))? {
            let previous: ImportedFinality = borsh::from_slice(&bytes)?;
            ensure!(
                previous.block == finality.block,
                "conflicting imported finalization"
            );
        }
        batch.put(
            key(IMPORTED_FINALITY, certified.0),
            borsh::to_vec(&finality)?,
        );
        Ok(())
    }

    /// Assemble a bounded ancestry proof from one durable history snapshot.
    /// A revision below the floor fails with [`HistoryPruned`].
    pub fn light_block(&self, height: u64, epochs: &LightBlockIndex) -> Result<LightBlock> {
        let snapshot = self.db.snapshot();
        ensure!(
            snapshot.get(transfer::IMPORT)?.is_none(),
            "history import is not published"
        );
        let (head, _): (u64, [u8; 32]) =
            borsh::from_slice(&snapshot.get(HEAD)?.context("missing history head")?)?;
        ensure!(
            height > 0 && height <= head,
            "block not found at height {height}"
        );
        check_retained(
            height,
            floor::floor_height(snapshot.get(FLOOR)?.as_deref())?,
        )?;
        let last = height.saturating_add(LIGHT_BLOCK_MAX_DESCENDANTS as u64);
        let mut blocks = Vec::new();
        let mut remaining = LIGHT_BLOCK_MAX_ARTIFACT_BYTES;
        for current in height..=last {
            let record;
            let mut encoded;
            let length = if current <= head {
                record = snapshot
                    .get_pinned(key(RECORD, current))?
                    .context("missing finalized history block")?;
                encoded = record.as_ref();
                u32::deserialize(&mut encoded)? as usize
            } else {
                let Some(bytes) = snapshot.get_pinned(key(PROOF_BLOCK, current))? else {
                    break;
                };
                record = bytes;
                encoded = record.as_ref();
                encoded.len()
            };
            remaining = remaining
                .checked_sub(length)
                .context("light block proof exceeds artifact limits")?;
            let encoded = encoded
                .get(..length)
                .context("truncated finalized history block")?;
            blocks.push(encoded.to_vec());
            let imported = snapshot
                .get(key(IMPORTED_FINALITY, current))?
                .map(|bytes| borsh::from_slice::<ImportedFinality>(&bytes))
                .transpose()?;
            let certificate = snapshot
                .get(key(CERTIFICATE, current))?
                .map(|bytes| borsh::from_slice::<Option<(u64, Vec<u8>)>>(&bytes))
                .transpose()?
                .flatten();
            // Pending finality is polled frequently; decode ancestry only when evidence exists.
            if imported.is_none() && certificate.is_none() {
                continue;
            }
            let mut previous = None;
            let mut certified = None;
            for (offset, encoded) in blocks.iter().enumerate() {
                let block = Block::decode_cfg(
                    commonware_codec::Copying(encoded.as_slice()),
                    &crate::node::block_cfg(),
                )?;
                ensure!(
                    block.height == height + offset as u64,
                    "finalized history height mismatch"
                );
                if let Some(parent) = previous {
                    ensure!(
                        block.parent == parent,
                        "finalized history ancestry mismatch"
                    );
                }
                previous = Some(block.id());
                certified = Some(block);
            }
            let block = certified.expect("requested block is retained");
            let artifacts = if let Some(imported) = imported {
                ensure!(
                    imported.block == block.id().0.0,
                    "imported finalization block mismatch"
                );
                Some((imported.certificate, imported.material))
            } else if let Some((epoch, certificate)) = certificate {
                ensure!(
                    epoch == block.context.round.epoch().get(),
                    "finalized history epoch mismatch"
                );
                let material = match epochs.get_epoch_material(epoch) {
                    Some(material) => material,
                    None => {
                        let boundary = epoch
                            .checked_mul(epochs.epoch_length().get())
                            .and_then(|height| height.checked_sub(1))
                            .context("historical epoch boundary overflow")?;
                        ensure!(boundary <= head, "epoch boundary is not retained");
                        let record = snapshot
                            .get_pinned(key(RECORD, boundary))?
                            .context("missing historical epoch boundary")?;
                        let mut encoded = record.as_ref();
                        let size = u32::deserialize(&mut encoded)? as usize;
                        ensure!(
                            size <= vera_domain::MAX_BLOCK_BYTES,
                            "oversized epoch boundary"
                        );
                        let boundary_block = Block::decode_cfg(
                            commonware_codec::Copying(
                                encoded.get(..size).context("truncated epoch boundary")?,
                            ),
                            &crate::node::block_cfg(),
                        )?;
                        ensure!(
                            boundary_block.height == boundary,
                            "epoch boundary height mismatch"
                        );
                        let Some(Payload::EpochInfo(info)) = boundary_block.payload else {
                            anyhow::bail!("epoch boundary is missing verifier material");
                        };
                        ensure!(
                            info.epoch.get() == epoch,
                            "epoch boundary material mismatch"
                        );
                        StoredEpochMaterial {
                            bytes: EpochMaterial::new(
                                info.output.players().clone(),
                                info.output.public().clone(),
                            )
                            .encode()
                            .to_vec(),
                        }
                    }
                };
                Some((certificate, material.bytes))
            } else {
                None
            };
            if let Some((certificate, material)) = artifacts {
                ensure!(
                    certificate
                        .len()
                        .checked_add(material.len())
                        .is_some_and(|length| length <= remaining),
                    "light block proof exceeds artifact limits"
                );
                let mut blocks = blocks.into_iter();
                let mut light = LightBlock::from_encoded_block(
                    &blocks.next().expect("requested block is retained"),
                    &certificate,
                    &material,
                )?;
                light.descendants = blocks
                    .map(|bytes| format!("0x{}", hex::encode(bytes)))
                    .collect();
                light.check_artifact_limits()?;
                return Ok(light);
            }
        }
        Err(CertificateNotFound { height }.into())
    }

    /// As [`Self::light_block`], with `None` while the revision has no retained certificate.
    pub fn certified_light_block(
        &self,
        height: u64,
        epochs: &LightBlockIndex,
    ) -> Result<Option<LightBlock>> {
        match self.light_block(height, epochs) {
            Ok(light) => Ok(Some(light)),
            Err(error) if error.is::<CertificateNotFound>() => Ok(None),
            Err(error) => Err(error),
        }
    }
}

fn unhex(value: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(value.strip_prefix("0x").unwrap_or(value))?)
}
