use super::*;
use commonware_cryptography::ChaCha20Poly1305;
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{
    Address, AddressableManager as _, BlockedSubscription, Blocker as _, authenticated::lookup,
};
use commonware_stream::{
    cups::{self, Cups},
    sake::{self, Sake},
};

use commonware_runtime::{Handle, Quota};
use commonware_utils::{NZU32, ordered::Map};

pub(super) struct Peers {
    pub resolvers: Vec<Resolver>,
    pub identities: [PublicKey; 2],
    pub blocked: Vec<BlockedSubscription<PublicKey>>,
    tasks: Vec<Handle<()>>,
}

impl Peers {
    pub(super) fn start(context: &tokio::Context) -> Self {
        let keys = [PrivateKey::from_seed(1), PrivateKey::from_seed(2)];
        let listeners = keys
            .each_ref()
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        let addresses = listeners
            .each_ref()
            .map(|listener| listener.local_addr().unwrap());
        let peers = keys.each_ref().map(|key| key.public_key());
        let membership: Map<_, Address> = peers
            .iter()
            .cloned()
            .zip(addresses.map(Into::into))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let mut resolvers = Vec::new();
        let mut actors = Vec::new();
        let mut networks = Vec::new();
        let mut blocked = Vec::new();
        for (i, (key, listener)) in keys.into_iter().zip(listeners).enumerate() {
            let mut cfg = lookup::Config::local(
                Cups::<_, ChaCha20Poly1305>::new(
                    Sake {
                        signer: key,
                        synchrony_bound: std::time::Duration::from_secs(5),
                        max_handshake_age: std::time::Duration::from_secs(10),
                        version: sake::Version::V1,
                    },
                    cups::Version::V1,
                ),
                b"vera-native-sync-test",
                addresses[i],
                NZUsize!(2),
                MAX_MESSAGE_BYTES,
            );
            cfg.dial_frequency = Duration::from_millis(10);
            cfg.peer_connection_cooldown = Duration::from_millis(10);
            let (mut network, mut oracle) =
                lookup::Network::new(context.child(["network_source", "network_replica"][i]), cfg);
            oracle.track(0, membership.clone());
            blocked.push(oracle.blocked());
            let (actor, mailbox) = p2p::Actor::new(
                context.child(["resolver_source", "resolver_replica"][i]),
                p2p::Config {
                    peer_provider: oracle.clone(),
                    blocker: oracle,
                    database: None::<Shared<WireDatabase>>,
                    mailbox_size: NZUsize!(4),
                    me: Some(peers[i].clone()),
                    timeout: Duration::from_secs(2),
                    fetch_retry_timeout: Duration::from_millis(10),
                    max_serve_ops: MAX_FETCH_OPS,
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            let net = network.register(0, Quota::per_second(NZU32!(100)));
            drop(listener);
            networks.push(network.start());
            actors.push(actor.start(net));
            resolvers.push(Resolver::new(mailbox));
        }
        actors.extend(networks);
        Self {
            resolvers,
            identities: peers,
            blocked,
            tasks: actors,
        }
    }
}

impl Drop for Peers {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
