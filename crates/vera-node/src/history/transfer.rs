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
    /// Serve a bounded chunk from a durable snapshot, excluding unpublished imports.
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
    pub(super) fn check_published(&self, height: u64) -> Result<()> {
        check_published(&self.db.snapshot(), height)
    }

    /// Start, resume, or advance an import anchored by independently verified finalization.
    /// An advancing selection restarts the cursor at the same committed-prefix boundary.
    /// Keep admission and query publication stopped until state reaches this anchor
    /// and recover() completes. The destination may already have a committed prefix.
    pub fn begin_import(&self, revision: &LightBlock, trusted: &ConsensusPublicKey) -> Result<()> {
        let anchor = verify_finalized_block(revision, trusted)?;
        ensure!(
            anchor.native_targets.is_some() && anchor.receipt_commitment.is_some(),
            "native import commitments missing"
        );
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
        // Older binaries must reject the store rather than trim an unfinished import.
        batch.put(FORMAT, [3]);
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
        ensure!(
            (block.height, block.id().0.0) == import.next,
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
    ensure!(
        block.native_targets.is_some() && block.receipt_commitment.is_some(),
        "native import commitments missing"
    );
    let gas_limit = u64::deserialize(&mut input)?;
    let count = u32::deserialize(&mut input)? as usize;
    ensure!(count == block.txs.len(), "history receipt count mismatch");
    let mut receipts = Vec::with_capacity(count);
    let mut remaining_logs = limits.logs;
    for _ in 0..count {
        let hash = <[u8; 32]>::deserialize(&mut input)?;
        let gas = u64::deserialize(&mut input)?;
        let contract = Option::<[u8; 20]>::deserialize(&mut input)?;
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
            ExecutionReceipt::new(
                hash.into(),
                success,
                gas,
                cumulative,
                logs,
                contract.map(Address::from),
            )
            .with_refusal(refusal),
        );
    }
    ensure!(input.is_empty(), "trailing history record bytes");
    check_receipts(&block, &receipts, gas_limit)?;
    Ok(block)
}

#[cfg(test)]
pub(super) mod tests;
