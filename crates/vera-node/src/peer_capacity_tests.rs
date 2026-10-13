use super::*;

use commonware_actor::Feedback;
use commonware_cryptography::{ChaCha20Poly1305, Signer as _, ed25519};
use commonware_glue::dkg::types::Participants;
use commonware_p2p::{Manager as _, authenticated::discovery};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_stream::{
    cups::{self, Cups},
    sake::{self, Sake},
};
use commonware_utils::{NZU64, NZUsize, ordered::Set};
use std::{panic::AssertUnwindSafe, time::Duration};
use vera_domain::PublicKey;

fn network_config(
    max_peers_per_set: NonZeroUsize,
) -> discovery::Config<Cups<Sake<ed25519::PrivateKey>, ChaCha20Poly1305>> {
    let address = ([127, 0, 0, 1], 7000).into();
    discovery::Config::local(
        Cups::new(
            Sake {
                signer: ed25519::PrivateKey::from_seed(u64::MAX),
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(10),
                version: sake::Version::V1,
            },
            cups::Version::V1,
        ),
        b"vera-peer-capacity-test",
        address,
        address,
        Vec::new(),
        max_peers_per_set,
        crate::MAX_MESSAGE_SIZE,
    )
}

fn keys(seeds: std::ops::Range<u64>) -> Set<PublicKey> {
    Set::from_iter_dedup(seeds.map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()))
}

#[test]
fn tracking_accepts_disjoint_maximum_committees_and_external_local_identity() {
    deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
        let capacity = PeerCapacity::new(NZU64!(2048), NZU64!(16)).unwrap();
        assert_eq!(capacity.participants(), 64);
        let participants = Participants {
            dealers: keys(0..64),
            players: keys(64..128),
            next_players: keys(128..192),
        };
        participants
            .validate::<commonware_cryptography::bls12381::primitives::variant::MinSig>(
                crate::MAX_PARTICIPANTS,
                None,
                0,
            )
            .unwrap();
        let tracked = participants.tracked_peers();
        assert_eq!(tracked.clone().union().len(), 192);

        let (_old_network, mut old_oracle) =
            discovery::Network::new(context.child("old"), network_config(NZUsize!(64)));
        assert!(
            std::panic::catch_unwind(AssertUnwindSafe(|| old_oracle.track(0, tracked.clone())))
                .is_err()
        );

        let (_network, mut oracle) =
            discovery::Network::new(context.child("fixed"), network_config(capacity.tracked()));
        assert_eq!(oracle.track(0, tracked.clone()), Feedback::Ok);

        let oversized = commonware_p2p::TrackedPeers::new(
            tracked.primary,
            Set::from_iter_dedup(tracked.secondary.into_iter().chain(keys(192..193))),
        );
        assert!(std::panic::catch_unwind(AssertUnwindSafe(|| oracle.track(1, oversized))).is_err());
    });
}

#[test]
fn small_epoch_tracks_disjoint_and_overlapping_memberships() {
    deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
        let capacity = PeerCapacity::new(NZU64!(100), NZU64!(16)).unwrap();
        assert_eq!(capacity.participants(), 4);
        assert_eq!(capacity.tracked().get(), 13);
        let (_network, mut oracle) =
            discovery::Network::new(context.child("network"), network_config(capacity.tracked()));
        let mut participants = Participants {
            dealers: keys(0..4),
            players: keys(4..8),
            next_players: keys(8..12),
        };
        assert_eq!(oracle.track(0, participants.tracked_peers()), Feedback::Ok);
        participants.players = participants.dealers.clone();
        participants.next_players = participants.dealers.clone();
        assert_eq!(oracle.track(1, participants.tracked_peers()), Feedback::Ok);
    });
}

#[test]
fn unsupported_epoch_has_no_network_capacity() {
    for blocks in 1..=3 {
        let blocks_per_epoch = NonZeroU64::new(blocks).unwrap();
        assert!(matches!(
            PeerCapacity::new(blocks_per_epoch, NZU64!(16)),
            Err(PeerCapacityError { blocks_per_epoch: actual, term_length })
                if actual == blocks_per_epoch && term_length == NZU64!(16)
        ));
    }
    let rotating = PeerCapacity::new(NZU64!(100), NZU64!(1)).unwrap();
    assert_eq!(rotating.participants(), 64);
    assert_eq!(rotating.tracked().get(), 193);
}
