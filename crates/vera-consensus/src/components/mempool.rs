//! In-memory mempool implementation.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    time::{Duration, SystemTime},
};

use commonware_codec::EncodeSize as _;
use parking_lot::RwLock;
use vera_domain::Tx;

use crate::traits::{Mempool, TxId};

/// Bounded pending transactions selected in local admission order.
#[derive(Debug, Clone)]
pub struct InMemoryMempool {
    inner: Arc<RwLock<Pending>>,
    changed: Arc<tokio::sync::Notify>,
}

const MAX_PENDING_BYTES: usize = 64 << 20;
const MAX_PENDING_TXS: usize = 4096;
const LOCAL_RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
struct Pending {
    txs: BTreeMap<TxId, Tx>,
    order: VecDeque<TxId>,
    bytes: usize,
    local: BTreeSet<TxId>,
    local_order: VecDeque<(TxId, SystemTime)>,
}

impl Pending {
    fn ordered(&self) -> impl Iterator<Item = (&TxId, &Tx)> {
        self.order
            .iter()
            .map(|id| (id, self.txs.get(id).expect("queued transaction")))
    }

    fn accepts(&self, id: &TxId, tx: &Tx) -> bool {
        tx.bytes.len() <= vera_domain::MAX_TX_BYTES
            && (self.txs.contains_key(id)
                || (self.txs.len() < MAX_PENDING_TXS
                    && tx.bytes.len() <= MAX_PENDING_BYTES - self.bytes))
    }
}

impl InMemoryMempool {
    /// Whether the exact wire transaction remains pending.
    pub fn contains(&self, id: &TxId) -> bool {
        self.inner.read().txs.contains_key(id)
    }

    /// Track a locally admitted transaction for retries while it remains pending.
    /// Peer admission does not call this method.
    pub fn mark_local(&self, id: &TxId, now: SystemTime) -> bool {
        let mut inner = self.inner.write();
        if !inner.txs.contains_key(id) || !inner.local.insert(*id) {
            return false;
        }
        let due =
            (now + LOCAL_RETRY_DELAY).max(inner.local_order.back().map_or(now, |(_, due)| *due));
        inner.local_order.push_back((*id, due));
        true
    }

    /// Whether a local retry is due, without inspecting unrelated requests.
    pub fn has_due_local(&self, now: SystemTime) -> bool {
        self.inner
            .read()
            .local_order
            .front()
            .is_some_and(|(_, due)| *due <= now)
    }

    /// Select due local transactions once each, within both work limits.
    /// A byte-limited head remains first for the next tick's fresh allowance.
    pub fn local_reannouncement(
        &self,
        now: SystemTime,
        max_txs: usize,
        max_bytes: usize,
    ) -> Vec<Tx> {
        let mut inner = self.inner.write();
        let mut selected = Vec::new();
        let mut remaining = max_bytes;
        for _ in 0..max_txs.min(inner.local_order.len()) {
            let (id, due) = *inner.local_order.front().expect("local retry head");
            if due > now {
                break;
            }
            let tx = inner.txs.get(&id).expect("pending local transaction");
            if tx.bytes.len() > remaining {
                break;
            }
            remaining -= tx.bytes.len();
            selected.push(tx.clone());
            inner.local_order.pop_front();
            let due = (now + LOCAL_RETRY_DELAY)
                .max(inner.local_order.back().map_or(now, |(_, due)| *due));
            inner.local_order.push_back((id, due));
        }
        selected
    }

    /// Check capacity while the caller holds the admission validator lock.
    pub fn can_insert(&self, tx: &Tx) -> bool {
        self.inner.read().accepts(&tx.id(), tx)
    }

    /// Select a prefix that fits the encoded transaction budget of one block.
    pub fn build_block(
        &self,
        max_txs: usize,
        excluded: &std::collections::BTreeSet<TxId>,
    ) -> Vec<Tx> {
        let mut remaining = vera_domain::MAX_BLOCK_TX_BYTES - 5;
        self.inner
            .read()
            .ordered()
            .filter(|(id, _)| !excluded.contains(id))
            .take(max_txs.min(vera_domain::MAX_BLOCK_TXS))
            .take_while(|(_, tx)| {
                if tx.bytes.len() > vera_domain::MAX_TX_BYTES || tx.encode_size() > remaining {
                    return false;
                }
                remaining -= tx.encode_size();
                true
            })
            .map(|(_, tx)| tx.clone())
            .collect()
    }

    /// Collect until the request-count limit or deadline, preserving the encoded byte limit.
    pub async fn build_block_wait(
        &self,
        max_txs: usize,
        excluded: &std::collections::BTreeSet<TxId>,
        wait: std::time::Duration,
    ) -> Vec<Tx> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let batch = self.build_block(max_txs, excluded);
            if batch.len() >= max_txs.min(vera_domain::MAX_BLOCK_TXS)
                || tokio::time::Instant::now() >= deadline
            {
                return batch;
            }
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep_until(deadline) => return self.build_block(max_txs, excluded),
            }
        }
    }

    /// Create a new empty mempool.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Pending::default())),
            changed: Arc::default(),
        }
    }
}

impl Default for InMemoryMempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool for InMemoryMempool {
    fn insert(&self, tx: Tx) -> bool {
        let id = tx.id();
        let mut inner = self.inner.write();
        if !inner.accepts(&id, &tx) || inner.txs.contains_key(&id) {
            return false;
        }
        inner.bytes += tx.bytes.len();
        inner.order.push_back(id);
        inner.txs.insert(id, tx);
        drop(inner);
        self.changed.notify_waiters();
        true
    }

    fn build(&self, max_txs: usize, excluded: &std::collections::BTreeSet<TxId>) -> Vec<Tx> {
        let inner = self.inner.read();
        inner
            .ordered()
            .filter(|(id, _)| !excluded.contains(id))
            .take(max_txs)
            .map(|(_, tx)| tx.clone())
            .collect()
    }

    fn prune(&self, tx_ids: &[TxId]) {
        if tx_ids.is_empty() {
            return;
        }
        let mut inner = self.inner.write();
        for id in tx_ids {
            if let Some(tx) = inner.txs.remove(id) {
                inner.bytes -= tx.bytes.len();
                inner.local.remove(id);
            }
        }
        let Pending {
            txs,
            order,
            local,
            local_order,
            ..
        } = &mut *inner;
        order.retain(|id| txs.contains_key(id));
        local_order.retain(|(id, _)| local.contains(id));
    }

    fn len(&self) -> usize {
        self.inner.read().txs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_count_respects_protocol_and_caller_limits() {
        let pool = InMemoryMempool::new();
        let txs: Vec<_> = (0..vera_domain::MAX_BLOCK_TXS + 1)
            .map(|i| Tx::new(i.to_be_bytes().to_vec().into()))
            .collect();
        for tx in &txs {
            assert!(pool.insert(tx.clone()));
        }
        let selected = pool.build_block(usize::MAX, &Default::default());
        assert_eq!(selected, txs[..vera_domain::MAX_BLOCK_TXS]);
        assert_eq!(pool.build_block(17, &Default::default()), txs[..17]);
        let excluded = txs[..1].iter().map(Tx::id).collect();
        assert_eq!(pool.build_block(usize::MAX, &excluded), txs[1..]);
    }

    #[test]
    fn large_requests_respect_proposal_and_pending_budgets() {
        let pool = InMemoryMempool::new();
        let txs: Vec<_> = (0..6)
            .map(|i| Tx::new(vec![i; vera_domain::MAX_TX_BYTES].into()))
            .collect();
        for tx in &txs[..5] {
            assert!(pool.insert(tx.clone()));
        }
        assert!(!pool.can_insert(&txs[5]));
        assert!(!pool.insert(txs[5].clone()));
        let block = pool.build_block(64, &Default::default());
        assert_eq!(block.len(), 1);
        assert!(block.encode_size() <= vera_domain::MAX_BLOCK_TX_BYTES);
        pool.prune(&[block[0].id()]);
        assert!(pool.insert(txs[5].clone()));
        let excluded = txs.iter().map(Tx::id).collect();
        assert!(pool.build_block(64, &excluded).is_empty());
    }

    #[test]
    fn admission_order_survives_hash_priority_duplicates_exclusions_and_pruning() {
        let pool = InMemoryMempool::new();
        let mut txs: Vec<_> = (0..8).map(|i| Tx::new(vec![i].into())).collect();
        txs.sort_by_key(|tx| std::cmp::Reverse(tx.id()));
        for tx in &txs {
            assert!(pool.insert(tx.clone()));
        }
        assert!(!pool.insert(txs[0].clone()));
        assert_eq!(pool.build(3, &Default::default()), txs[..3]);
        assert_eq!(pool.build_block(3, &Default::default()), txs[..3]);
        let excluded = [txs[0].id()].into_iter().collect();
        assert_eq!(pool.build_block(2, &excluded), txs[1..3]);
        pool.prune(&[txs[0].id(), txs[3].id()]);
        assert!(pool.insert(txs[0].clone()));
        let expected: Vec<_> = txs[1..3]
            .iter()
            .chain(txs[4..].iter())
            .chain([&txs[0]])
            .cloned()
            .collect();
        assert_eq!(pool.build(10, &Default::default()), expected);
        let ids: Vec<_> = txs.iter().map(Tx::id).collect();
        pool.prune(&ids);
        assert!(pool.inner.read().order.is_empty());
        assert_eq!(pool.inner.read().bytes, 0);
    }

    #[test]
    fn mempool_insert_and_build() {
        let mempool = InMemoryMempool::new();

        let tx1 = Tx::new(vec![1, 2, 3].into());
        let tx2 = Tx::new(vec![4, 5, 6].into());

        assert!(mempool.insert(tx1.clone()));
        assert!(mempool.insert(tx2));
        assert!(!mempool.insert(tx1)); // Duplicate

        assert_eq!(mempool.len(), 2);

        let txs = mempool.build(10, &std::collections::BTreeSet::new());
        assert_eq!(txs.len(), 2);
    }

    #[test]
    fn mempool_prune() {
        let mempool = InMemoryMempool::new();

        let tx = Tx::new(vec![1, 2, 3].into());
        let id = tx.id();

        mempool.insert(tx);
        assert_eq!(mempool.len(), 1);

        mempool.prune(&[id]);
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn mempool_build_with_exclusions() {
        let mempool = InMemoryMempool::new();

        let tx1 = Tx::new(vec![1, 2, 3].into());
        let tx2 = Tx::new(vec![4, 5, 6].into());
        let id1 = tx1.id();

        mempool.insert(tx1);
        mempool.insert(tx2.clone());

        let mut excluded = std::collections::BTreeSet::new();
        excluded.insert(id1);

        let txs = mempool.build(10, &excluded);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0], tx2);
    }
}

#[cfg(test)]
mod batching_tests {
    use super::*;
    use std::{collections::BTreeSet, time::Duration};

    #[tokio::test]
    async fn batching_wakes_when_full_and_excludes_pending_ancestry() {
        let pool = InMemoryMempool::new();
        let first = Tx::new(vec![1].into());
        let second = Tx::new(vec![2].into());
        let third = Tx::new(vec![3].into());
        pool.insert(first.clone());
        let excluded = BTreeSet::from([first.id()]);
        let mut waiting = Box::pin(pool.build_block_wait(2, &excluded, Duration::from_secs(60)));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut waiting)
                .await
                .is_err()
        );
        pool.insert(second.clone());
        pool.insert(third.clone());
        let batch = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap();
        assert_eq!(batch, vec![second, third]);
    }

    #[tokio::test]
    async fn batching_deadline_preserves_idle_progress() {
        let pool = InMemoryMempool::new();
        let batch = tokio::time::timeout(
            Duration::from_secs(1),
            pool.build_block_wait(256, &BTreeSet::new(), Duration::from_millis(1)),
        )
        .await
        .unwrap();
        assert!(batch.is_empty());
    }
}

#[cfg(test)]
#[path = "mempool_reannouncement_tests.rs"]
mod reannouncement_tests;
