//! Durable execution records used to restore query indexes after restart.

use std::path::Path;

use alloy_primitives::{Address, B256, Log};
use alloy_rlp::Decodable as _;
use anyhow::{Context as _, Result, ensure};
use borsh::{BorshDeserialize, BorshSerialize};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::Digestible as _;
use commonware_glue::dkg::types::Payload;
use parking_lot::Mutex;
#[cfg(not(feature = "regolith-history"))]
use rocksdb::{DB, IteratorMode, WriteBatch, WriteOptions};
use vera_domain::{Block, BlockId, EpochMaterial};
use vera_executor::ExecutionReceipt;
use vera_indexer::{BlockIndex, LightBlockIndex, StoredEpochMaterial, StoredFinalization};
#[cfg(feature = "regolith-history")]
mod regolith_store;
#[cfg(feature = "regolith-history")]
use regolith_store::{HistoryDb as DB, WriteBatch};

use crate::{FinalizationArtifacts, FinalizationLookup, index_finalized_block};

const RECORD: u8 = 1;
const CERTIFICATE: u8 = 2;
const IMPORTED_FINALITY: u8 = 3;
const PROOF_BLOCK: u8 = 4;
const BLOCK_HASH: u8 = 5;
const SUBMISSION_HASH: u8 = 6;
const QUERY_HEAD: &[u8] = b"query_head";
const FORMAT: &[u8] = b"format";
const GENESIS: &[u8] = b"genesis";
const HEAD: &[u8] = b"head";

mod membership;
pub(crate) use membership::roster_from_boundary;
mod query;
pub use query::HistoricalExecution;
mod peer;
mod proof;
mod startup;
pub use peer::{HistoryPeer, start_history_peer};
pub(crate) use startup::SnapshotHistory;
mod transfer;
pub use transfer::{HISTORY_CHUNK_BYTES, HistoryChunk, HistoryLimits};

#[derive(BorshSerialize, BorshDeserialize)]
struct StoredReceipt {
    hash: [u8; 32],
    gas_used: u64,
    contract: Option<[u8; 20]>,
    success: bool,
    cumulative_gas_used: u64,
    logs: Vec<Vec<u8>>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct Record {
    block: Vec<u8>,
    gas_limit: u64,
    receipts: Vec<StoredReceipt>,
}

impl Record {
    fn decode(&self) -> Result<(Block, Vec<ExecutionReceipt>)> {
        let block = Block::decode_cfg(
            commonware_codec::Copying(self.block.as_slice()),
            &crate::node::block_cfg(),
        )?;
        let receipts = self
            .receipts
            .iter()
            .map(|r| {
                let logs = r
                    .logs
                    .iter()
                    .map(|bytes| {
                        let mut encoded = bytes.as_slice();
                        let log = Log::decode(&mut encoded)?;
                        ensure!(encoded.is_empty(), "trailing log bytes");
                        Ok(log)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(ExecutionReceipt::new(
                    B256::from(r.hash),
                    r.success,
                    r.gas_used,
                    r.cumulative_gas_used,
                    logs,
                    r.contract.map(Address::from),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            receipts.len() == block.txs.len(),
            "incomplete execution record"
        );
        check_receipts(&block, &receipts, self.gas_limit)?;
        Ok((block, receipts))
    }
}

/// Synced records of executed finalizations, independent of RPC process memory.
///
/// Startup must reconcile this store before opening the RPC server. The query
/// indexes are derived from its retained records; they are not recovery metadata.
#[derive(Debug)]
pub struct FinalizedHistory {
    db: DB,
    head: Mutex<(u64, BlockId)>,
}

impl FinalizedHistory {
    /// Height of the durable history head (zero before the first record).
    pub fn head_height(&self) -> u64 {
        self.head.lock().0
    }

    /// Non-atomic backend memory counters; unsupported properties remain absent.
    pub(crate) fn memory_usage(
        &self,
    ) -> Result<std::collections::BTreeMap<&'static str, Option<u64>>> {
        [
            ("memtables", "rocksdb.size-all-mem-tables"),
            ("table_readers", "rocksdb.estimate-table-readers-mem"),
            ("block_cache", "rocksdb.block-cache-usage"),
            ("pinned_table_metadata", "regolith.pinned-metadata-bytes"),
        ]
        .into_iter()
        .map(|(label, property)| Ok((label, self.db.property_int_value(property)?)))
        .collect()
    }

    /// Open the history for a specific genesis identity.
    pub fn open(path: impl AsRef<Path>, genesis: &Block) -> Result<Self> {
        let path = path.as_ref();
        #[cfg(not(feature = "regolith-history"))]
        match std::fs::symlink_metadata(path.join("regolith")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => anyhow::bail!(
                "Regolith history requires a regolith-history build; explicit migration is required"
            ),
        }
        let db = DB::open_default(path)?;
        match db.get(FORMAT)? {
            Some(version) => {
                ensure!(
                    matches!(version.as_slice(), [1] | [2] | [3]),
                    "unsupported finalized history format"
                );
                ensure!(
                    version.as_slice() != [2] || db.get(transfer::IMPORT)?.is_none(),
                    "unfinished format 2 history import requires the previous binary"
                );
                ensure!(
                    db.get(GENESIS)?.as_deref() == Some(genesis.id().0.as_slice()),
                    "finalized history belongs to another genesis"
                );
            }
            None => {
                ensure!(store_is_empty(&db)?, "missing finalized history format");
                let mut batch = WriteBatch::default();
                batch.put(FORMAT, [1]);
                batch.put(GENESIS, genesis.id().0);
                let head = borsh::to_vec(&(0u64, genesis.id().0.0))?;
                batch.put(HEAD, &head);
                batch.put(QUERY_HEAD, &head);
                write(&db, batch)?;
            }
        }
        let (height, hash): (u64, [u8; 32]) =
            borsh::from_slice(&db.get(HEAD)?.context("missing history head")?)?;
        Ok(Self {
            db,
            head: Mutex::new((height, BlockId(hash.into()))),
        })
    }

    /// Persist execution results before publishing receipts or acknowledging execution.
    pub fn append(
        &self,
        block: &Block,
        receipts: &[ExecutionReceipt],
        gas_limit: u64,
    ) -> Result<()> {
        self.append_batch(block, receipts, gas_limit, WriteBatch::default())
    }

    /// Persist execution and marshal's certificate lookup in one durable batch.
    pub fn append_finalized(
        &self,
        block: &Block,
        receipts: &[ExecutionReceipt],
        gas_limit: u64,
        artifacts: Option<&FinalizationArtifacts>,
    ) -> Result<()> {
        self.append_batch(
            block,
            receipts,
            gas_limit,
            Self::finalization_batch(block.height, artifacts)?,
        )
    }

    fn append_batch(
        &self,
        block: &Block,
        receipts: &[ExecutionReceipt],
        gas_limit: u64,
        batch: WriteBatch,
    ) -> Result<()> {
        self.append_batch_with_write(block, receipts, gas_limit, batch, write)
    }

    fn append_batch_with_write(
        &self,
        block: &Block,
        receipts: &[ExecutionReceipt],
        gas_limit: u64,
        mut batch: WriteBatch,
        persist: impl FnOnce(&DB, WriteBatch) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            receipts.len() == block.txs.len(),
            "incomplete execution record"
        );
        check_receipts(block, receipts, gas_limit)?;
        let record = Record {
            block: block.encode().to_vec(),
            gas_limit,
            receipts: receipts
                .iter()
                .map(|r| StoredReceipt {
                    hash: r.tx_hash.0,
                    gas_used: r.gas_used,
                    contract: r.contract_address.map(|a| a.0.0),
                    success: r.success(),
                    cumulative_gas_used: r.cumulative_gas_used(),
                    logs: r.logs().iter().map(alloy_rlp::encode).collect(),
                })
                .collect(),
        };
        let bytes = borsh::to_vec(&record)?;
        let mut head = self.head.lock();
        ensure!(
            self.db.get(transfer::IMPORT)?.is_none(),
            "history import is pending"
        );
        ensure!(
            self.db.get(QUERY_HEAD)?.as_deref()
                == Some(borsh::to_vec(&(head.0, head.1.0.0))?.as_slice()),
            "history query index requires recovery"
        );
        if block.height <= head.0 {
            ensure!(
                self.db.get(key(RECORD, block.height))?.as_deref() == Some(bytes.as_slice()),
                "conflicting finalized history record"
            );
            if !batch.is_empty() {
                persist(&self.db, batch)?;
            }
            return Ok(());
        }
        ensure!(
            block.height == head.0 + 1 && block.parent == head.1,
            "finalized history is not contiguous"
        );
        if let Some(proof) = self.db.get(key(PROOF_BLOCK, block.height))? {
            ensure!(
                proof == record.block,
                "execution conflicts with finalized proof block"
            );
        }
        query::index_execution(&mut batch, block, &record.receipts);
        batch.put(key(RECORD, block.height), bytes);
        batch.delete(key(PROOF_BLOCK, block.height));
        let head_bytes = borsh::to_vec(&(block.height, block.id().0.0))?;
        batch.put(HEAD, &head_bytes);
        batch.put(QUERY_HEAD, &head_bytes);
        persist(&self.db, batch)?;
        *head = (block.height, block.id());
        Ok(())
    }

    /// Persist marshal's lookup result before publishing a light-client proof.
    /// An ancestor finalized through a descendant may have no direct certificate.
    pub fn store_finalization(
        &self,
        height: u64,
        artifacts: Option<&FinalizationArtifacts>,
    ) -> Result<()> {
        write(&self.db, Self::finalization_batch(height, artifacts)?)
    }

    fn finalization_batch(
        height: u64,
        artifacts: Option<&FinalizationArtifacts>,
    ) -> Result<WriteBatch> {
        let mut batch = WriteBatch::default();
        batch.put(
            key(CERTIFICATE, height),
            borsh::to_vec(&artifacts.map(|a| (a.epoch, &a.finalization)))?,
        );
        Ok(batch)
    }

    /// Restore indexes through the same anchor as application state. Later
    /// records are discarded and will be regenerated by Commonware replay.
    pub async fn recover(
        &self,
        genesis: &Block,
        anchor: &Block,
        index: &BlockIndex,
        light: &LightBlockIndex,
        lookup: &FinalizationLookup,
    ) -> Result<()> {
        self.check_import_recovery(anchor)?;
        let anchor_bytes = borsh::to_vec(&(anchor.height, anchor.id().0.0))?;
        let rebuild_queries = self.db.get(QUERY_HEAD)?.as_deref() != Some(anchor_bytes.as_slice());
        let mut query_batch = WriteBatch::default();
        if rebuild_queries {
            query_batch.delete_range([BLOCK_HASH], [SUBMISSION_HASH + 1]);
            query_batch.delete(QUERY_HEAD);
            write(&self.db, std::mem::take(&mut query_batch))?;
        }
        let mut previous = genesis.id();
        for height in 1..=anchor.height {
            let bytes = self
                .db
                .get(key(RECORD, height))?
                .context("missing finalized execution history; restore a complete node backup")?;
            let record: Record = borsh::from_slice(&bytes)?;
            let (block, receipts) = record.decode()?;
            ensure!(
                block.height == height && block.parent == previous,
                "finalized history ancestry mismatch"
            );
            if height == anchor.height {
                ensure!(
                    block.id() == anchor.id(),
                    "finalized history does not match recovery anchor"
                );
            }
            if rebuild_queries {
                query::index_execution(&mut query_batch, &block, &record.receipts);
                if query_batch.size_in_bytes() >= 1 << 20 {
                    write(&self.db, std::mem::take(&mut query_batch))?;
                }
            }
            let gas_used = receipts.iter().map(|r| r.gas_used).sum();
            index_finalized_block(index, &block, record.gas_limit, &receipts, gas_used);
            restore_epoch(light, &block);
            let finalization = match self.db.get(key(CERTIFICATE, height))? {
                Some(bytes) => borsh::from_slice::<Option<(u64, Vec<u8>)>>(&bytes)?,
                None => {
                    let artifacts = lookup(height).await;
                    self.store_finalization(height, artifacts.as_ref())?;
                    artifacts.map(|a| (a.epoch, a.finalization))
                }
            };
            if let Some((epoch, bytes)) = finalization {
                light.insert_finalization(
                    block.digest().0,
                    StoredFinalization {
                        epoch,
                        bytes,
                        block: record.block,
                    },
                );
            }
            previous = block.id();
        }
        let mut head = self.head.lock();
        ensure!(
            head.0 >= anchor.height,
            "finalized history is behind application state"
        );
        let mut batch = query_batch;
        batch.put(QUERY_HEAD, &anchor_bytes);
        self.retain_proof_suffix(anchor.height, head.0, &mut batch)?;
        for prefix in [RECORD, CERTIFICATE] {
            if let Some(next) = anchor.height.checked_add(1) {
                batch.delete_range(key(prefix, next).as_slice(), &[prefix + 1]);
            }
        }
        batch.put(HEAD, borsh::to_vec(&(anchor.height, anchor.id().0.0))?);
        batch.delete(transfer::IMPORT);
        write(&self.db, batch)?;
        *head = (anchor.height, anchor.id());
        Ok(())
    }
}

pub(crate) fn restore_epoch(index: &LightBlockIndex, block: &Block) {
    if let Some(Payload::EpochInfo(info)) = &block.payload {
        let material =
            EpochMaterial::new(info.output.players().clone(), info.output.public().clone());
        index.insert_epoch_material(
            info.epoch.get(),
            StoredEpochMaterial {
                bytes: material.encode().into(),
            },
        );
    }
}

fn check_receipts(block: &Block, receipts: &[ExecutionReceipt], gas_limit: u64) -> Result<()> {
    match block.receipt_commitment {
        Some(expected) => ensure!(
            vera_executor::receipt_commitment(gas_limit, receipts) == expected,
            "execution receipt commitment mismatch"
        ),
        None => ensure!(
            block.native_targets.is_none(),
            "native receipt commitment missing"
        ),
    }
    Ok(())
}

fn key(prefix: u8, height: u64) -> [u8; 9] {
    let mut key = [prefix; 9];
    key[1..].copy_from_slice(&height.to_be_bytes());
    key
}

#[cfg(not(feature = "regolith-history"))]
fn write(db: &DB, batch: WriteBatch) -> Result<()> {
    let mut options = WriteOptions::default();
    options.set_sync(true);
    db.write_opt(batch, &options)
        .context("persist finalized history")
}

fn store_is_empty(db: &DB) -> Result<bool> {
    #[cfg(feature = "regolith-history")]
    {
        db.is_empty()
    }
    #[cfg(not(feature = "regolith-history"))]
    {
        Ok(db
            .iterator(IteratorMode::Start)
            .next()
            .transpose()?
            .is_none())
    }
}

#[cfg(feature = "regolith-history")]
fn write(db: &DB, batch: WriteBatch) -> Result<()> {
    db.write_sync(batch).context("persist finalized history")
}

#[cfg(test)]
mod tests;
