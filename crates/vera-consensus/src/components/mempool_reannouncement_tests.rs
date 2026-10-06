use super::*;

#[test]
fn only_local_pending_transactions_retry_and_pruning_removes_tracking() {
    let pool = InMemoryMempool::new();
    let now = SystemTime::UNIX_EPOCH;
    let local = Tx::new(vec![1].into());
    let peer = Tx::new(vec![2].into());
    assert!(!pool.mark_local(&local.id(), now));
    assert!(pool.insert(local.clone()));
    assert!(pool.insert(peer));
    assert!(pool.mark_local(&local.id(), now));
    assert!(!pool.mark_local(&local.id(), now));
    assert!(
        pool.local_reannouncement(now + Duration::from_millis(1999), 16, 100)
            .is_empty()
    );
    assert_eq!(
        pool.local_reannouncement(now + LOCAL_RETRY_DELAY, 16, 100),
        vec![local.clone()]
    );
    assert!(
        pool.local_reannouncement(now + LOCAL_RETRY_DELAY, 16, 100)
            .is_empty()
    );
    pool.prune(&[local.id()]);
    assert!(!pool.contains(&local.id()));
    assert!(
        pool.local_reannouncement(now + Duration::from_secs(20), 16, 100)
            .is_empty()
    );
    let pending = pool.inner.read();
    assert!(pending.local.is_empty());
    assert!(pending.local_order.is_empty());
}

#[test]
fn local_reannouncement_preserves_byte_limited_head_and_count_fairness() {
    let pool = InMemoryMempool::new();
    let now = SystemTime::UNIX_EPOCH;
    let records: Vec<_> = [(1, 4), (2, 7), (3, 3), (4, 2)]
        .into_iter()
        .map(|(byte, len)| Tx::new(vec![byte; len].into()))
        .collect();
    for tx in &records {
        assert!(pool.insert(tx.clone()));
        assert!(pool.mark_local(&tx.id(), now));
    }
    let due = now + LOCAL_RETRY_DELAY;
    assert_eq!(pool.local_reannouncement(due, 4, 10), records[..1]);
    assert_eq!(
        pool.local_reannouncement(due + Duration::from_millis(250), 4, 10),
        records[1..3]
    );
    assert_eq!(
        pool.local_reannouncement(due + Duration::from_millis(500), 1, 10),
        records[3..]
    );
    assert!(
        pool.local_reannouncement(due + Duration::from_millis(750), 4, 10)
            .is_empty()
    );
    assert_eq!(
        pool.local_reannouncement(due + LOCAL_RETRY_DELAY, 1, 10),
        records[..1]
    );
}

#[test]
fn maximum_pending_count_is_visited_without_a_full_pool_scan() {
    let pool = InMemoryMempool::new();
    let now = SystemTime::UNIX_EPOCH;
    let ids: BTreeSet<_> = (0..MAX_PENDING_TXS)
        .map(|i| {
            let tx = Tx::new(i.to_be_bytes().to_vec().into());
            let id = tx.id();
            assert!(pool.insert(tx));
            assert!(pool.mark_local(&id, now));
            id
        })
        .collect();
    let mut visited = BTreeSet::new();
    for tick in 0..MAX_PENDING_TXS / 16 {
        let batch = pool.local_reannouncement(
            now + LOCAL_RETRY_DELAY + Duration::from_millis(250 * tick as u64),
            16,
            vera_domain::MAX_TX_BYTES,
        );
        assert_eq!(batch.len(), 16);
        for tx in batch {
            assert!(visited.insert(tx.id()));
        }
    }
    assert_eq!(visited, ids);
}

#[test]
fn maximum_size_record_fits_fresh_retry_allowance() {
    let pool = InMemoryMempool::new();
    let now = SystemTime::UNIX_EPOCH;
    let small = Tx::new(vec![1].into());
    let large = Tx::new(vec![2; vera_domain::MAX_TX_BYTES].into());
    for tx in [&small, &large] {
        assert!(pool.insert(tx.clone()));
        assert!(pool.mark_local(&tx.id(), now));
    }
    assert_eq!(
        pool.local_reannouncement(now + LOCAL_RETRY_DELAY, 16, vera_domain::MAX_TX_BYTES),
        vec![small]
    );
    assert_eq!(
        pool.local_reannouncement(
            now + LOCAL_RETRY_DELAY + Duration::from_millis(250),
            16,
            vera_domain::MAX_TX_BYTES
        ),
        vec![large]
    );
}
