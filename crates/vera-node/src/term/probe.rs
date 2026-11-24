//! Asking another device for the term over a connection of its own.
//!
//! Two devices that both run as the deployment's validator share one network
//! key and cannot connect to each other. A device that may have been replaced
//! therefore asks under its transport key, which the device that replaced it
//! admits as a backup's.

use std::{net::SocketAddr, num::NonZeroUsize, time::Duration};

use commonware_cryptography::ed25519::PrivateKey;
use commonware_p2p::{
    Ingress, Manager as _, Receiver as _, Recipients, Sender as _, authenticated::discovery,
};
use commonware_runtime::{Quota, Supervisor as _, tokio::Context};
use commonware_utils::ordered::Set;
use vera_config::DiscoveryConfig;
use vera_domain::PublicKey;

use super::wire::Message;

/// Every channel a validator sends on. A message on a channel the receiver
/// never registered ends the connection.
const CHANNELS: [u64; 14] = [
    crate::VOTE_CHANNEL,
    crate::CERTIFICATE_CHANNEL,
    crate::RESOLVER_CHANNEL,
    crate::BACKFILL_CHANNEL,
    crate::BROADCAST_CHANNEL,
    crate::DKG_CHANNEL,
    crate::DKG_PROBE_CHANNEL,
    crate::MEMPOOL_CHANNEL,
    crate::QMDB_CHANNELS[0],
    crate::QMDB_CHANNELS[1],
    crate::QMDB_CHANNELS[2],
    crate::QMDB_CHANNELS[3],
    crate::HISTORY_CHANNEL,
    crate::TERM_CHANNEL,
];

const RETRY: Duration = Duration::from_millis(200);

/// What a device asks with.
#[derive(Clone)]
pub(crate) struct Probe {
    /// This device's transport key.
    pub signer: PrivateKey,
    /// The deployment's validator, which the active device answers as.
    pub validator: PublicKey,
    pub max_peers: NonZeroUsize,
    pub rate: Quota,
    pub timeout: Duration,
}

impl Probe {
    /// Send `question` to the device listening at `address`, if it answers
    /// as the deployment's validator, and return the first answer `expected`
    /// accepts within the timeout.
    pub(crate) async fn exchange<T>(
        &self,
        context: Context,
        address: SocketAddr,
        question: &Message,
        expected: impl Fn(Message) -> Option<T>,
    ) -> Option<T> {
        let listen = SocketAddr::from(([127, 0, 0, 1], 0));
        let config = crate::peer_discovery::config(
            self.signer.clone(),
            listen,
            listen,
            vec![(self.validator.clone(), Ingress::Socket(address))],
            self.max_peers,
            &DiscoveryConfig::local(),
        )
        .ok()?;
        let (mut network, mut oracle) =
            discovery::Network::new(context.child("term_probe"), config);
        let mut term = None;
        for channel in CHANNELS {
            let registered = network.register(channel, self.rate);
            if channel == crate::TERM_CHANNEL {
                term = Some(registered);
            }
        }
        let (mut sender, mut receiver) = term?;
        let _ = oracle.track(0, Set::from_iter_dedup([self.validator.clone()]));
        let network = network.start();
        let deadline = tokio::time::Instant::now() + self.timeout;
        let question = question.encode();
        let answer = loop {
            let _ = sender.send(
                Recipients::One(self.validator.clone()),
                question.clone(),
                true,
            );
            let heard = tokio::time::timeout(RETRY, receiver.recv()).await;
            match heard {
                Ok(Ok((_, bytes))) => {
                    if let Some(answer) = Message::decode(bytes.as_ref()).and_then(&expected) {
                        break Some(answer);
                    }
                }
                Ok(Err(_)) => break None,
                Err(_) => {}
            }
            if tokio::time::Instant::now() >= deadline {
                break None;
            }
        };
        network.abort();
        answer
    }
}
