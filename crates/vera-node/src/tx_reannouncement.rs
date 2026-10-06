//! Paced retries for locally submitted transactions that remain pending.

use crate::TxGossip;
use commonware_p2p::Sender;
use commonware_runtime::Clock;
use std::time::Duration;

pub(crate) const MAX_TRANSACTIONS: usize = 16;
const TICK: Duration = Duration::from_millis(250);

pub(crate) async fn run<E: Clock, S: Sender>(context: E, gossip: TxGossip<S, E>) {
    loop {
        context.sleep(TICK).await;
        gossip.reannounce().await;
    }
}
