//! Admission of an account's backup devices as peers of every epoch.
//!
//! Commonware accepts a connection only from a peer it tracks, and the peers
//! tracked for an epoch are that epoch's committee. A backup is in no
//! committee, so each tracked set also names the account's backups as
//! secondary peers: they are accepted when they dial and served like any
//! peer, and nothing dials them or counts them towards a quorum.

use commonware_actor::Feedback;
use commonware_p2p::{Manager, PeerSetSubscription, Provider, TrackedPeers};
use commonware_utils::ordered::Set;
use vera_domain::PublicKey;

/// A peer manager that adds a fixed set of devices to every tracked peer set.
#[derive(Clone, Debug)]
pub(crate) struct DeviceManager<M> {
    manager: M,
    devices: Vec<PublicKey>,
}

impl<M> DeviceManager<M> {
    /// `devices` must not name the local identity.
    pub(crate) const fn new(manager: M, devices: Vec<PublicKey>) -> Self {
        Self { manager, devices }
    }
}

impl<M: Provider<PublicKey = PublicKey>> Provider for DeviceManager<M> {
    type PublicKey = PublicKey;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<PublicKey>> {
        self.manager.peer_set(id).await
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<PublicKey> {
        self.manager.subscribe().await
    }
}

impl<M: Manager<PublicKey = PublicKey>> Manager for DeviceManager<M> {
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<TrackedPeers<PublicKey>> + Send,
    {
        let TrackedPeers { primary, secondary } = peers.into();
        let secondary = Set::from_iter_dedup(secondary.into_iter().chain(self.devices.clone()));
        self.manager
            .track(id, TrackedPeers::new(primary, secondary))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_utils::channel::mpsc;

    use super::*;

    type Tracked = Vec<(u64, TrackedPeers<PublicKey>)>;

    #[derive(Clone, Debug, Default)]
    struct Recorded(Arc<Mutex<Tracked>>);

    impl Provider for Recorded {
        type PublicKey = PublicKey;

        async fn peer_set(&mut self, _: u64) -> Option<TrackedPeers<PublicKey>> {
            None
        }

        async fn subscribe(&mut self) -> PeerSetSubscription<PublicKey> {
            mpsc::unbounded_channel().1
        }
    }

    impl Manager for Recorded {
        fn track<R>(&mut self, id: u64, peers: R) -> Feedback
        where
            R: Into<TrackedPeers<PublicKey>> + Send,
        {
            self.0.lock().unwrap().push((id, peers.into()));
            Feedback::Ok
        }
    }

    fn key(seed: u64) -> PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    #[test]
    fn every_tracked_set_gains_the_devices_as_secondary_peers() {
        let recorded = Recorded::default();
        let mut manager = DeviceManager::new(recorded.clone(), vec![key(8), key(9)]);

        let _ = manager.track(3, Set::from_iter_dedup([key(1)]));
        let _ = manager.track(
            4,
            TrackedPeers::new(
                Set::from_iter_dedup([key(1), key(9)]),
                Set::from_iter_dedup([key(2)]),
            ),
        );

        let tracked = recorded.0.lock().unwrap();
        assert_eq!(tracked[0].0, 3);
        assert_eq!(tracked[0].1.primary, Set::from_iter_dedup([key(1)]));
        assert_eq!(
            tracked[0].1.secondary,
            Set::from_iter_dedup([key(8), key(9)])
        );
        assert_eq!(tracked[1].1.primary, Set::from_iter_dedup([key(1), key(9)]));
        assert_eq!(
            tracked[1].1.secondary,
            Set::from_iter_dedup([key(2), key(8), key(9)])
        );
    }

    #[test]
    fn a_node_without_devices_tracks_what_it_was_given() {
        let recorded = Recorded::default();
        let mut manager = DeviceManager::new(recorded.clone(), Vec::new());
        let peers = TrackedPeers::new(
            Set::from_iter_dedup([key(1)]),
            Set::from_iter_dedup([key(2)]),
        );

        let _ = manager.track(0, peers.clone());

        assert_eq!(*recorded.0.lock().unwrap(), [(0, peers)]);
    }
}
