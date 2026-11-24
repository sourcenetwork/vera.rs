//! Durable hash lookups over finalized execution history.

use super::*;
use vera_indexer::IndexQuery;

/// One retained revision and its execution results.
/// Finality evidence must be obtained and verified separately.
#[derive(Debug)]
pub struct HistoricalExecution {
    /// Canonical retained revision.
    pub block: Block,
    /// Results in execution order.
    pub receipts: Vec<ExecutionReceipt>,
    /// Execution budget committed by the receipt root.
    pub gas_limit: u64,
}

pub(super) fn hash_key(prefix: u8, hash: &[u8; 32]) -> [u8; 33] {
    let mut key = [prefix; 33];
    key[1..].copy_from_slice(hash);
    key
}

pub(super) fn index_execution(
    batch: &mut WriteBatch,
    height: u64,
    id: &BlockId,
    receipts: &[StoredReceipt],
) {
    batch.put(hash_key(BLOCK_HASH, &id.0.0), height.to_be_bytes());
    for receipt in receipts {
        index_submission(batch, &receipt.hash, height);
    }
}

pub(super) fn index_submission(batch: &mut WriteBatch, hash: &[u8; 32], height: u64) {
    batch.put(hash_key(SUBMISSION_HASH, hash), height.to_be_bytes());
}

pub(super) fn unindex_execution(batch: &mut WriteBatch, block: &Block, receipts: &[StoredReceipt]) {
    batch.delete(hash_key(BLOCK_HASH, &block.id().0.0));
    for receipt in receipts {
        batch.delete(hash_key(SUBMISSION_HASH, &receipt.hash));
    }
}

impl FinalizedHistory {
    #[cfg(test)]
    pub(super) fn execution_by_hash(&self, hash: B256) -> Result<Option<HistoricalExecution>> {
        self.execution(IndexQuery::RevisionHash(hash))
    }

    /// Assemble complete receipt evidence from durable execution and finality records.
    pub fn receipt_proof(
        &self,
        hash: B256,
        epochs: &LightBlockIndex,
    ) -> Result<Option<vera_domain::ReceiptResponse>> {
        let Some(execution) = self.execution_by_submission(hash)? else {
            return Ok(None);
        };
        let Some(revision) = self.certified_light_block(execution.block.height, epochs)? else {
            return Ok(None);
        };
        ensure!(
            revision.block_hash.parse::<B256>()? == execution.block.id().0,
            "receipt finality differs from execution record"
        );
        Ok(Some(vera_domain::ReceiptResponse {
            revision,
            gas_limit: execution.gas_limit,
            receipts: execution.receipts,
        }))
    }

    pub(super) fn execution_by_submission(
        &self,
        hash: B256,
    ) -> Result<Option<HistoricalExecution>> {
        self.execution(IndexQuery::Submission(hash))
    }

    /// One record's bytes are bounded by the block and receipt limits.
    fn execution(&self, query: IndexQuery) -> Result<Option<HistoricalExecution>> {
        let mut remaining_bytes = usize::MAX;
        self.execution_bounded(query, &mut remaining_bytes)
    }

    /// Charge encoded record bytes before decoding, across a caller's whole query.
    ///
    /// A revision below the floor fails with [`HistoryPruned`]; a hash whose
    /// mapping was removed with its record is not found.
    pub fn execution_bounded(
        &self,
        query: IndexQuery,
        remaining_bytes: &mut usize,
    ) -> Result<Option<HistoricalExecution>> {
        let snapshot = self.db.snapshot();
        ensure!(
            snapshot.get(transfer::IMPORT)?.is_none(),
            "history import is not published"
        );
        let head = snapshot.get(HEAD)?.context("missing history head")?;
        ensure!(
            snapshot.get(QUERY_HEAD)?.as_deref() == Some(head.as_slice()),
            "history query index requires recovery"
        );
        let (maximum, _): (u64, [u8; 32]) = borsh::from_slice(&head)?;
        let height = match query {
            IndexQuery::Revision(height) => {
                if height == 0 || height > maximum {
                    return Ok(None);
                }
                height
            }
            IndexQuery::RevisionHash(hash) | IndexQuery::Submission(hash) => {
                let prefix = if matches!(query, IndexQuery::RevisionHash(_)) {
                    BLOCK_HASH
                } else {
                    SUBMISSION_HASH
                };
                let Some(height) = snapshot.get(hash_key(prefix, &hash.0))? else {
                    return Ok(None);
                };
                u64::from_be_bytes(
                    height
                        .as_slice()
                        .try_into()
                        .context("invalid history query height")?,
                )
            }
        };
        ensure!(
            height > 0 && height <= maximum,
            "history query exceeds published head"
        );
        check_retained(
            height,
            floor::floor_height(snapshot.get(FLOOR)?.as_deref())?,
        )?;
        let bytes = snapshot
            .get_pinned(key(RECORD, height))?
            .context("missing indexed execution record")?;
        *remaining_bytes = remaining_bytes
            .checked_sub(bytes.len())
            .ok_or(vera_indexer::IndexerError::ReadLimit)?;
        let record: Record = borsh::from_slice(&bytes)?;
        let (block, receipts) = record.decode()?;
        ensure!(block.height == height, "indexed execution height mismatch");
        let matches = match query {
            IndexQuery::Revision(_) => true,
            IndexQuery::RevisionHash(hash) => block.id().0 == hash,
            IndexQuery::Submission(hash) => receipts.iter().any(|receipt| receipt.tx_hash == hash),
        };
        ensure!(matches, "execution record differs from its query key");
        Ok(Some(HistoricalExecution {
            block,
            receipts,
            gas_limit: record.gas_limit,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::tests::block;
    use std::{num::NonZeroU64, sync::Arc};

    #[test]
    fn uncertified_revision_is_pending_evidence_not_a_failed_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = block(0, BlockId(B256::ZERO));
        let mut first = block(1, genesis.id());
        first.txs.push(vera_domain::Tx::new(vec![1].into()));
        let receipt = ExecutionReceipt::new(B256::repeat_byte(7), true, 3, 3, vec![], None);
        first.native_targets = [vera_domain::DbTarget::default(); 4];
        first.receipt_commitment =
            vera_executor::receipt_commitment(100, std::slice::from_ref(&receipt));
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        history
            .append_finalized(&first, std::slice::from_ref(&receipt), 100, None)
            .unwrap();
        let epochs = LightBlockIndex::new(NonZeroU64::new(20).unwrap());
        assert!(history.certified_light_block(1, &epochs).unwrap().is_none());
        assert!(
            history
                .receipt_proof(receipt.tx_hash, &epochs)
                .unwrap()
                .is_none()
        );
        // Clients match this text; added context must not hide the condition.
        let error = history.light_block(1, &epochs).unwrap_err();
        assert_eq!(
            error.to_string(),
            "finalization certificate not found for height 1 within retained proof limits"
        );
        assert!(
            error
                .context("assemble proof")
                .is::<proof::CertificateNotFound>()
        );
        assert!(history.certified_light_block(2, &epochs).is_err());
    }

    #[tokio::test]
    async fn durable_queries_survive_reopen_rebuild_and_rewind() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = block(0, BlockId(B256::ZERO));
        let mut first = block(1, genesis.id());
        first.txs.push(vera_domain::Tx::new(vec![1].into()));
        let receipt =
            ExecutionReceipt::new(B256::repeat_byte(7), false, 5_000, 5_000, vec![], None)
                .with_refusal(Some(vera_domain::Refusal::new(
                    vera_domain::RefusingModule::Vera,
                    vera_domain::RefusalKind::NotFound,
                    "JWS token not found: missing",
                )));
        first.native_targets = [vera_domain::DbTarget::default(); 4];
        first.receipt_commitment =
            vera_executor::receipt_commitment(100, std::slice::from_ref(&receipt));
        let second = block(2, first.id());
        {
            let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
            assert!(
                history
                    .append(&first, std::slice::from_ref(&receipt), 101)
                    .is_err()
            );
            assert!(history.execution_by_hash(first.id().0).unwrap().is_none());
            history
                .append(&first, std::slice::from_ref(&receipt), 100)
                .unwrap();
            history.append(&second, &[], 100).unwrap();
        }
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        let memory = history.memory_usage().unwrap();
        assert!(memory["memtables"].is_some_and(|bytes| bytes > 0));
        assert!(memory["memtable_reserved"].is_some());
        assert!(memory["arena_pool"].is_some());
        assert!(memory["block_cache"].is_some());

        assert_eq!(
            history
                .execution(IndexQuery::Revision(1))
                .unwrap()
                .unwrap()
                .block,
            first
        );
        assert!(
            history
                .execution(IndexQuery::Revision(0))
                .unwrap()
                .is_none()
        );
        assert!(
            history
                .execution(IndexQuery::Revision(u64::MAX))
                .unwrap()
                .is_none()
        );
        let first_size = history.db.get(key(RECORD, 1)).unwrap().unwrap().len();
        let mut budget = first_size;
        assert!(
            history
                .execution_bounded(IndexQuery::Revision(1), &mut budget)
                .unwrap()
                .is_some()
        );
        assert_eq!(budget, 0);
        assert!(
            history
                .execution_bounded(IndexQuery::Revision(2), &mut budget)
                .unwrap_err()
                .downcast_ref::<vera_indexer::IndexerError>()
                .is_some()
        );
        let mut short = first_size - 1;
        assert!(
            history
                .execution_bounded(IndexQuery::Revision(1), &mut short)
                .is_err()
        );
        let restored = history
            .execution_by_submission(receipt.tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(restored.block, first);
        assert_eq!(restored.gas_limit, 100);
        assert!(!restored.receipts[0].success());
        assert_eq!(restored.receipts[0].tx_hash, receipt.tx_hash);
        assert_eq!(restored.receipts[0].refusal, receipt.refusal);
        assert_eq!(
            history
                .execution_by_hash(second.id().0)
                .unwrap()
                .unwrap()
                .block,
            second
        );
        assert!(
            history
                .execution_by_submission(B256::ZERO)
                .unwrap()
                .is_none()
        );
        history
            .db
            .put(hash_key(BLOCK_HASH, &first.id().0.0), 2_u64.to_be_bytes())
            .unwrap();
        assert!(
            history
                .execution_by_hash(first.id().0)
                .unwrap_err()
                .to_string()
                .contains("query key")
        );
        history.db.delete(QUERY_HEAD).unwrap();
        assert!(history.execution_by_hash(B256::ZERO).is_err());
        assert!(history.append(&second, &[], 100).is_err());
        let lookup: FinalizationLookup = Arc::new(|_| Box::pin(async { None }));
        let epochs = LightBlockIndex::new(NonZeroU64::new(20).unwrap());
        history
            .recover(&genesis, &second, &BlockIndex::new(), &epochs, &lookup)
            .await
            .unwrap();
        assert_eq!(
            history
                .execution_by_hash(first.id().0)
                .unwrap()
                .unwrap()
                .block,
            first
        );
        history
            .recover(&genesis, &first, &BlockIndex::new(), &epochs, &lookup)
            .await
            .unwrap();
        assert!(history.execution_by_hash(second.id().0).unwrap().is_none());
        assert!(
            history
                .execution_by_submission(receipt.tx_hash)
                .unwrap()
                .is_some()
        );
    }
}
