use super::*;
use commonware_actor::{Feedback, Unreliable};
use commonware_cryptography::{Signer as _, ed25519};
use commonware_p2p::{CheckedSender, LimitedSender};
use commonware_runtime::{IoBufs, Runner as _, Supervisor as _, deterministic::Runner};
use futures::FutureExt as _;
use std::{
    collections::VecDeque,
    time::{Duration, SystemTime},
};

#[derive(Clone, Copy)]
enum Delivery {
    Dropped,
    PeerRejected,
    Accepted,
}

#[derive(Default)]
struct Observations {
    outcomes: VecDeque<Delivery>,
    attempts: Vec<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
}

#[derive(Clone, Default)]
struct MockSender(Arc<parking_lot::Mutex<Observations>>);

impl LimitedSender for MockSender {
    type PublicKey = ed25519::PublicKey;
    type Checked<'a> = Self;

    fn check(&mut self, recipients: Recipients<Self::PublicKey>) -> Result<Self, SystemTime> {
        assert!(matches!(recipients, Recipients::All));
        Ok(self.clone())
    }
}

impl CheckedSender for MockSender {
    type PublicKey = ed25519::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        vec![ed25519::PrivateKey::from_seed(1).public_key()]
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        assert!(!priority);
        let bytes = message.into().coalesce().as_ref().to_vec();
        let mut observed = self.0.lock();
        observed.attempts.push(bytes.clone());
        match observed.outcomes.pop_front().unwrap_or(Delivery::Accepted) {
            Delivery::Dropped => Unreliable::rejected(),
            Delivery::PeerRejected => Unreliable::new(Feedback::Ok),
            Delivery::Accepted => {
                observed.delivered.push(bytes);
                Unreliable::new(Feedback::Ok)
            }
        }
    }
}

#[test]
fn dropped_and_peer_rejected_initial_delivery_remains_retryable() {
    Runner::default().start(|context| async move {
        let pool = InMemoryMempool::new();
        let tx = Tx::new(vec![1, 2, 3].into());
        assert!(pool.insert(tx.clone()));
        let sender = MockSender::default();
        sender.0.lock().outcomes.extend([
            Delivery::Dropped,
            Delivery::PeerRejected,
            Delivery::Accepted,
        ]);
        let gossip = TxGossip::new(
            context.child("tx_clock"),
            pool.clone(),
            Arc::new(OnceLock::new()),
            1,
            sender.clone(),
        );
        gossip.forward_local(tx.clone()).await;
        gossip.forward_local(tx.clone()).await;
        let held_sender = gossip.sender.lock().await;
        assert!(gossip.reannounce().now_or_never().is_some());
        drop(held_sender);
        assert_eq!(sender.0.lock().attempts.len(), 1);
        context.sleep(Duration::from_secs(2)).await;
        gossip.reannounce().await;
        assert_eq!(sender.0.lock().attempts.len(), 2);
        assert!(sender.0.lock().delivered.is_empty());
        context.sleep(Duration::from_secs(2)).await;
        gossip.reannounce().await;
        assert_eq!(sender.0.lock().attempts, vec![vec![1, 2, 3]; 3]);
        assert_eq!(sender.0.lock().delivered, vec![vec![1, 2, 3]]);
        pool.prune(&[tx.id()]);
        context.sleep(Duration::from_secs(2)).await;
        gossip.reannounce().await;
        assert_eq!(sender.0.lock().attempts.len(), 3);
    });
}

#[test]
fn peer_transactions_and_pruned_local_entries_are_not_reannounced() {
    Runner::default().start(|context| async move {
        let pool = InMemoryMempool::new();
        let local = Tx::new(vec![4].into());
        let peer = Tx::new(vec![5].into());
        assert!(pool.insert(local.clone()));
        assert!(pool.insert(peer));
        let sender = MockSender::default();
        let gossip = TxGossip::new(
            context.child("tx_clock"),
            pool.clone(),
            Arc::new(OnceLock::new()),
            1,
            sender.clone(),
        );
        gossip.forward_local(local.clone()).await;
        pool.prune(&[local.id()]);
        context.sleep(Duration::from_secs(20)).await;
        gossip.reannounce().await;
        assert_eq!(sender.0.lock().attempts, vec![vec![4]]);
        assert_eq!(pool.len(), 1);

        let cancelled = Tx::new(vec![6].into());
        assert!(pool.insert(cancelled.clone()));
        let held_sender = gossip.sender.lock().await;
        let mut forwarding = Box::pin(gossip.forward_local(cancelled.clone()));
        assert!(forwarding.as_mut().now_or_never().is_none());
        drop(forwarding);
        drop(held_sender);
        context.sleep(Duration::from_secs(2)).await;
        gossip.reannounce().await;
        assert_eq!(sender.0.lock().attempts, vec![vec![4], vec![6]]);
        pool.prune(&[cancelled.id()]);
    });
}
