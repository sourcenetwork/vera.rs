use std::num::NonZeroU64;

use super::*;
use commonware_codec::DecodeExt as _;
use vera_domain::{ConsensusPublicKey, LightBlock, verify_finalized_block};

pub(super) const IMPORT: &[u8] = b"import";
/// The error of an import whose oldest block does not follow the records the store kept.
pub(crate) const DISCONNECTED: &str = "history import does not connect to committed prefix";

/// Maximum history bytes copied into one transfer response.
pub const HISTORY_CHUNK_BYTES: usize = 64 * 1024;

/// Caller-selected bounds for decoding one assembled history record.
#[derive(Clone, Copy, Debug)]
pub struct HistoryLimits {
    /// Maximum serialized record size, including its canonical revision.
    pub record_bytes: usize,
    /// Maximum logs across all receipts in the record.
    pub logs: usize,
}

/// A portion of one immutable finalized execution record.
#[derive(Debug)]
pub struct HistoryChunk {
    /// Full record length; clients must check their budget before assembling it.
    pub total: u64,
    /// Byte offset represented by this response.
    pub offset: u64,
    /// At most HISTORY_CHUNK_BYTES bytes.
    pub bytes: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub(super) struct Import {
    anchor: Vec<u8>,
    base: (u64, [u8; 32]),
    next: (u64, [u8; 32]),
    trusted: Vec<u8>,
}

impl FinalizedHistory {
    /// Serve a bounded chunk from a durable snapshot, excluding unpublished
    /// imports. The floor's parent is served, so that an importer can adopt
    /// the same floor; a lower height fails with [`HistoryPruned`].
    pub fn record_chunk(&self, height: u64, offset: u64, maximum: usize) -> Result<HistoryChunk> {
        ensure!(
            maximum > 0 && maximum <= HISTORY_CHUNK_BYTES,
            "invalid history chunk limit"
        );
        let snapshot = self.db.snapshot();
        check_published(&snapshot, height)?;
        let record = snapshot
            .get_pinned(key(RECORD, height))?
            .context("history record unavailable")?;
        let start = usize::try_from(offset)?;
        ensure!(start <= record.len(), "history offset exceeds record");
        let end = start.saturating_add(maximum).min(record.len());
        Ok(HistoryChunk {
            total: record.len() as u64,
            offset,
            bytes: record[start..end].to_vec(),
        })
    }

    /// Fail unless `height` is retained and not behind an unpublished import.
    /// A height below the floor's parent fails with [`HistoryPruned`].
    pub(super) fn check_published(&self, height: u64) -> Result<()> {
        check_published(&self.db.snapshot(), height)
    }

    /// Start, resume, or advance an import anchored by independently verified finalization.
    /// An advancing selection restarts the cursor at the same committed-prefix boundary.
    /// Keep admission and query publication stopped until state reaches this anchor
    /// and recover() completes. The destination may already have a committed prefix.
    pub fn begin_import(&self, revision: &LightBlock, trusted: &ConsensusPublicKey) -> Result<()> {
        let anchor = verify_finalized_block(revision, trusted)?;
        let head = self.head.lock();
        let base = if let Some(bytes) = self.db.get(IMPORT)? {
            let import: Import = borsh::from_slice(&bytes)?;
            ensure!(
                import.trusted == trusted.encode().as_ref(),
                "history import trust changed"
            );
            if import.anchor == anchor.encode().as_ref() {
                return Ok(());
            }
            let previous = Block::decode_cfg(
                commonware_codec::Copying(import.anchor.as_slice()),
                &crate::node::block_cfg(),
            )?;
            ensure!(
                anchor.height > previous.height,
                "history import selection must advance"
            );
            import.base
        } else {
            ensure!(
                anchor.height > head.0,
                "history import must advance the committed prefix"
            );
            (head.0, head.1.0.0)
        };
        let import = Import {
            anchor: anchor.encode().to_vec(),
            base,
            next: (anchor.height, anchor.id().0.0),
            trusted: trusted.encode().to_vec(),
        };
        let mut batch = WriteBatch::default();
        batch.put(FORMAT, FORMAT_IMPORTED);
        batch.put(IMPORT, borsh::to_vec(&import)?);
        write(&self.db, batch)
    }

    /// Recover the locally persisted selection, including after all records are staged.
    /// Its finalization was verified by begin_import; history may still be incomplete.
    pub fn import_anchor(&self) -> Result<Option<Block>> {
        let Some(bytes) = self.db.get(IMPORT)? else {
            return Ok(None);
        };
        let import: Import = borsh::from_slice(&bytes)?;
        Ok(Some(Block::decode_cfg(
            commonware_codec::Copying(import.anchor.as_slice()),
            &crate::node::block_cfg(),
        )?))
    }

    /// The next required ancestor, or None when all records are staged (or no import exists).
    pub fn import_next(&self) -> Result<Option<(u64, BlockId)>> {
        let Some(bytes) = self.db.get(IMPORT)? else {
            return Ok(None);
        };
        let import: Import = borsh::from_slice(&bytes)?;
        Ok((import.next.0 > import.base.0)
            .then_some((import.next.0, BlockId(import.next.1.into()))))
    }

    /// Verify and durably stage the next ancestor. Limits apply before field allocation.
    /// A complete import remains unpublished until matching state recovery succeeds.
    pub fn import_record(
        &self,
        bytes: &[u8],
        limits: HistoryLimits,
        proof: &LightBlock,
    ) -> Result<()> {
        let mut head = self.head.lock();
        let mut import: Import =
            borsh::from_slice(&self.db.get(IMPORT)?.context("no history import")?)?;
        ensure!(
            import.next.0 > import.base.0,
            "history import already staged"
        );
        let block = decode_record(bytes, limits)?;
        let id = block.id().0.0;
        ensure!(
            (block.height, id) == import.next,
            "history import ancestry mismatch"
        );
        let trusted =
            ConsensusPublicKey::decode(commonware_codec::Copying(import.trusted.as_slice()))?;
        ensure!(
            verify_finalized_block(proof, &trusted)? == block,
            "history finality does not match record"
        );
        import.next = (block.height - 1, block.parent.0.0);
        if import.next.0 == import.base.0 {
            ensure!(import.next == import.base, DISCONNECTED);
        }
        let mut batch = WriteBatch::default();
        let anchor = Block::decode_cfg(
            commonware_codec::Copying(import.anchor.as_slice()),
            &crate::node::block_cfg(),
        )?;
        self.stage_finality(proof, &block, anchor.height, &mut batch)?;
        batch.put(key(RECORD, block.height), bytes);
        batch.put(key(BLOCK_ID, block.height), id);
        // Imported proofs supply finality without consulting the local marshal archive.
        batch.put(
            key(CERTIFICATE, block.height),
            borsh::to_vec(&None::<(u64, Vec<u8>)>)?,
        );
        batch.put(IMPORT, borsh::to_vec(&import)?);
        let completed = if import.next == import.base {
            batch.put(HEAD, borsh::to_vec(&(anchor.height, anchor.id().0.0))?);
            Some((anchor.height, anchor.id()))
        } else {
            None
        };
        write(&self.db, batch)?;
        if let Some(completed) = completed {
            *head = completed;
        }
        Ok(())
    }

    /// Finish an import whose next record no peer serves at a floor of this
    /// store's own: the lowest epoch start whose parent is already imported,
    /// so the records from the floor's parent through the anchor are one run
    /// authenticated by ancestry from the certified anchor. Peers' floors
    /// are not consulted.
    ///
    /// The floor must not be above the first block of the anchor's epoch:
    /// recovery at the anchor and the anchor epoch's verifier material need
    /// that much. Otherwise, or before the anchor's epoch has begun, this
    /// fails with [`HistoryPruned`] and changes nothing.
    ///
    /// One atomic write removes everything below the floor's parent, this
    /// store's own older records included, with their certificates, imported
    /// finality and every hash mapping, which the recovery that publishes the
    /// import rebuilds. It stores the floor and the anchor as head, and
    /// completes the import at the floor's parent. Returns the floor.
    pub(crate) fn finish_import_at_floor(&self, epoch_length: NonZeroU64) -> Result<u64> {
        let mut head = self.head.lock();
        let mut import: Import =
            borsh::from_slice(&self.db.get(IMPORT)?.context("no history import")?)?;
        let missing = import.next.0;
        ensure!(missing > import.base.0, "history import already staged");
        let anchor = Block::decode_cfg(
            commonware_codec::Copying(import.anchor.as_slice()),
            &crate::node::block_cfg(),
        )?;
        let length = epoch_length.get();
        let floor = missing
            .saturating_add(2)
            .div_ceil(length)
            .saturating_mul(length);
        let anchor_epoch = anchor.height - anchor.height % length;
        if floor > anchor_epoch {
            return Err(HistoryPruned {
                height: missing,
                floor,
            }
            .into());
        }
        if import.base.0 > 0 {
            // They cannot be compared with the deployment's history.
            tracing::warn!(
                from = self.floor_height()?.saturating_sub(1).max(1),
                through = import.base.0,
                floor,
                "dropping this store's own records below the adopted history floor"
            );
        }
        let parent = alloy_primitives::keccak256(&self.record(floor - 1)?.block);
        let id = alloy_primitives::keccak256(&self.record(floor)?.block);
        let mut batch = WriteBatch::default();
        batch.delete_range(key(RECORD, 0), key(RECORD, floor - 1));
        batch.delete_range(key(BLOCK_ID, 0), key(BLOCK_ID, floor - 1));
        for prefix in [CERTIFICATE, IMPORTED_FINALITY, PROOF_BLOCK] {
            batch.delete_range(key(prefix, 0), key(prefix, floor));
        }
        batch.delete_range([BLOCK_HASH], [SUBMISSION_HASH + 1]);
        batch.delete(QUERY_HEAD);
        batch.delete(VALIDATED);
        batch.put(FLOOR, borsh::to_vec(&(floor, id.0))?);
        batch.put(sweep::SWEEP, (floor - 1).to_be_bytes());
        import.base = (floor - 1, parent.0);
        import.next = import.base;
        batch.put(IMPORT, borsh::to_vec(&import)?);
        batch.put(HEAD, borsh::to_vec(&(anchor.height, anchor.id().0.0))?);
        write(&self.db, batch)?;
        *head = (anchor.height, anchor.id());
        Ok(floor)
    }

    pub(super) fn check_import_recovery(&self, anchor: &Block) -> Result<()> {
        if let Some(bytes) = self.db.get(IMPORT)? {
            let import: Import = borsh::from_slice(&bytes)?;
            ensure!(import.next == import.base, "history import incomplete");
            ensure!(
                import.anchor == anchor.encode().as_ref(),
                "history import requires matching state recovery"
            );
        }
        Ok(())
    }
}

fn check_published(snapshot: &regolith_store::Snapshot, height: u64) -> Result<()> {
    ensure!(
        snapshot.get(IMPORT)?.is_none(),
        "history import is not published"
    );
    let (head, _): (u64, [u8; 32]) =
        borsh::from_slice(&snapshot.get(HEAD)?.context("missing history head")?)?;
    ensure!(height > 0 && height <= head, "history height unavailable");
    let floor = floor::floor_height(snapshot.get(FLOOR)?.as_deref())?;
    // An importer adopting this floor needs the floor's parent too.
    if height + 1 < floor {
        return Err(HistoryPruned { height, floor }.into());
    }
    Ok(())
}

fn vector<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let length = u32::deserialize(input)? as usize;
    let (value, rest) = input
        .split_at_checked(length)
        .context("truncated history field")?;
    *input = rest;
    Ok(value)
}

fn decode_record(mut input: &[u8], limits: HistoryLimits) -> Result<Block> {
    ensure!(
        input.len() <= limits.record_bytes,
        "history record byte limit"
    );
    let block = Block::decode_cfg(
        commonware_codec::Copying(vector(&mut input)?),
        &crate::node::block_cfg(),
    )?;
    let gas_limit = u64::deserialize(&mut input)?;
    let count = u32::deserialize(&mut input)? as usize;
    ensure!(count == block.txs.len(), "history receipt count mismatch");
    let mut receipts = Vec::with_capacity(count);
    let mut remaining_logs = limits.logs;
    for _ in 0..count {
        let hash = <[u8; 32]>::deserialize(&mut input)?;
        let gas = u64::deserialize(&mut input)?;
        let success = bool::deserialize(&mut input)?;
        let cumulative = u64::deserialize(&mut input)?;
        let count = u32::deserialize(&mut input)? as usize;
        ensure!(count <= input.len() / 4, "truncated history logs");
        remaining_logs = remaining_logs
            .checked_sub(count)
            .context("history log limit")?;
        let mut logs = Vec::with_capacity(count);
        for _ in 0..count {
            let mut bytes = vector(&mut input)?;
            let log = Log::decode(&mut bytes)?;
            ensure!(bytes.is_empty(), "trailing history log bytes");
            logs.push(log);
        }
        let refusal = Option::<super::StoredRefusal>::deserialize(&mut input)?
            .as_ref()
            .map(super::StoredRefusal::decode)
            .transpose()?;
        receipts.push(
            ExecutionReceipt::new(hash.into(), success, gas, cumulative, logs)
                .with_refusal(refusal),
        );
    }
    ensure!(input.is_empty(), "trailing history record bytes");
    check_receipts(&block, &receipts, gas_limit)?;
    Ok(block)
}

#[cfg(test)]
pub(super) mod tests;
