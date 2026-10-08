//! WebSocket subscription support for `eth_subscribe` / `eth_unsubscribe`.

use alloy_primitives::{Address, B256};
use jsonrpsee::{PendingSubscriptionSink, SubscriptionMessage, proc_macros::rpc};
use tokio::sync::broadcast;
use tracing::{trace, warn};

use vera_domain::GossipHeader;

use crate::types::{AddressFilter, RpcBlock, RpcLog, TopicFilter};

/// Parsed log filter for subscription-time matching.
#[derive(Clone, Debug, Default)]
struct SubscriptionLogFilter {
    /// Addresses to match (empty = match all).
    addresses: Vec<Address>,
    /// Positional topic filters. Each position is OR-matched within, AND across.
    topics: Vec<Vec<B256>>,
}

/// Parameters for `eth_subscribe("logs", ...)`.
#[derive(Clone, Debug, Default, serde::Deserialize)]
struct LogSubscriptionParams {
    /// Contract address or list of addresses to filter by.
    #[serde(default)]
    address: Option<AddressFilter>,
    /// Topics to filter by.
    #[serde(default)]
    topics: Option<Vec<Option<TopicFilter>>>,
}

impl From<LogSubscriptionParams> for SubscriptionLogFilter {
    fn from(params: LogSubscriptionParams) -> Self {
        let addresses = params
            .address
            .map(AddressFilter::into_vec)
            .unwrap_or_default();
        let topics = params
            .topics
            .unwrap_or_default()
            .into_iter()
            .map(|t| t.map(TopicFilter::into_vec).unwrap_or_default())
            .collect();
        Self { addresses, topics }
    }
}

/// Returns `true` if the log matches the subscription filter.
fn matches_filter(log: &RpcLog, filter: &SubscriptionLogFilter) -> bool {
    // Address check: if addresses are specified, log must match one.
    if !filter.addresses.is_empty() && !filter.addresses.contains(&log.address) {
        return false;
    }

    // Topic check: positional AND, with OR within each position.
    for (i, position_topics) in filter.topics.iter().enumerate() {
        if position_topics.is_empty() {
            // Wildcard position — matches any topic.
            continue;
        }
        match log.topics.get(i) {
            Some(log_topic) => {
                if !position_topics.contains(log_topic) {
                    return false;
                }
            }
            // Log has fewer topics than the filter requires.
            None => return false,
        }
    }

    true
}

/// Ethereum subscription JSON-RPC API.
#[rpc(server, namespace = "eth")]
pub trait EthSubscriptionApi {
    /// Create a new subscription for the given event kind.
    #[subscription(name = "subscribe" => "subscription", unsubscribe = "unsubscribe", item = serde_json::Value)]
    async fn subscribe(
        &self,
        kind: String,
        params: Option<serde_json::Value>,
    ) -> jsonrpsee::core::SubscriptionResult;
}

/// Implementation of `eth_subscribe` / `eth_unsubscribe`.
pub struct EthSubscriptionApiImpl {
    heads_tx: broadcast::Sender<RpcBlock>,
    logs_tx: broadcast::Sender<Vec<RpcLog>>,
    headers_tx: Option<broadcast::Sender<GossipHeader>>,
}

impl std::fmt::Debug for EthSubscriptionApiImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthSubscriptionApiImpl")
            .finish_non_exhaustive()
    }
}

impl EthSubscriptionApiImpl {
    /// Create a new subscription API implementation.
    pub const fn new(
        heads_tx: broadcast::Sender<RpcBlock>,
        logs_tx: broadcast::Sender<Vec<RpcLog>>,
    ) -> Self {
        Self {
            heads_tx,
            logs_tx,
            headers_tx: None,
        }
    }

    /// Enable gossip header subscriptions via `eth_subscribe("headers")`.
    #[must_use]
    pub fn with_headers(mut self, tx: broadcast::Sender<GossipHeader>) -> Self {
        self.headers_tx = Some(tx);
        self
    }
}

#[jsonrpsee::core::async_trait]
impl EthSubscriptionApiServer for EthSubscriptionApiImpl {
    async fn subscribe(
        &self,
        pending: PendingSubscriptionSink,
        kind: String,
        params: Option<serde_json::Value>,
    ) -> jsonrpsee::core::SubscriptionResult {
        match kind.as_str() {
            "newHeads" => {
                let sink = pending.accept().await?;
                let mut rx = self.heads_tx.subscribe();
                tokio::spawn(async move {
                    loop {
                        let received = tokio::select! {
                            biased;
                            () = sink.closed() => break,
                            received = rx.recv() => received,
                        };
                        match received {
                            Ok(block) => {
                                let value = match serde_json::to_value(&block) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        warn!(error = %e, "failed to serialize newHeads block");
                                        break;
                                    }
                                };
                                let msg = match SubscriptionMessage::new(
                                    "eth_subscription",
                                    sink.subscription_id(),
                                    &value,
                                ) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        warn!(error = %e, "failed to build newHeads subscription message");
                                        break;
                                    }
                                };
                                if sink.send(msg).await.is_err() {
                                    trace!("newHeads subscriber disconnected");
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!(lagged = n, "newHeads subscriber lagged, dropping");
                                signal_lag(&sink, n).await;
                                break;
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
            }
            "headers" => {
                let Some(ref headers_tx) = self.headers_tx else {
                    let _ = pending
                        .reject(jsonrpsee::types::ErrorObjectOwned::owned(
                            crate::error::codes::INVALID_PARAMS,
                            "headers subscription not enabled on this node",
                            None::<()>,
                        ))
                        .await;
                    return Ok(());
                };
                crate::header_subscribe::stream_headers(pending, headers_tx).await?;
            }
            "logs" => {
                let filter: SubscriptionLogFilter = match params {
                    Some(v) => match serde_json::from_value::<LogSubscriptionParams>(v) {
                        Ok(p) => p.into(),
                        Err(e) => {
                            let _ = pending
                                .reject(jsonrpsee::types::ErrorObjectOwned::owned(
                                    crate::error::codes::INVALID_PARAMS,
                                    format!("invalid log filter parameters: {e}"),
                                    None::<()>,
                                ))
                                .await;
                            return Ok(());
                        }
                    },
                    None => SubscriptionLogFilter::default(),
                };

                let sink = pending.accept().await?;
                let mut rx = self.logs_tx.subscribe();
                tokio::spawn(async move {
                    loop {
                        // Observe disconnects even when the filter never
                        // matches: without this select a quiet filter keeps
                        // the task and its broadcast receiver alive forever.
                        let received = tokio::select! {
                            biased;
                            () = sink.closed() => break,
                            received = rx.recv() => received,
                        };
                        match received {
                            Ok(logs) => {
                                for log in &logs {
                                    if !matches_filter(log, &filter) {
                                        continue;
                                    }
                                    let value = match serde_json::to_value(log) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            warn!(error = %e, "failed to serialize log for subscription");
                                            return;
                                        }
                                    };
                                    let msg = match SubscriptionMessage::new(
                                        "eth_subscription",
                                        sink.subscription_id(),
                                        &value,
                                    ) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            warn!(error = %e, "failed to build log subscription message");
                                            return;
                                        }
                                    };
                                    if sink.send(msg).await.is_err() {
                                        trace!("logs subscriber disconnected");
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!(lagged = n, "logs subscriber lagged, dropping");
                                signal_lag(&sink, n).await;
                                break;
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
            }
            other => {
                let _ = pending
                    .reject(jsonrpsee::types::ErrorObjectOwned::owned(
                        crate::error::codes::INVALID_PARAMS,
                        format!("unsupported subscription kind: {other}"),
                        None::<()>,
                    ))
                    .await;
            }
        }
        Ok(())
    }
}

/// Deliver a terminal signal to a subscriber dropped for lagging, so a slow
/// consumer learns the feed ended instead of waiting on silence.
async fn signal_lag(sink: &jsonrpsee::core::server::SubscriptionSink, missed: u64) {
    let notice = serde_json::json!({
        "error": format!("subscription lagged by {missed} messages; resubscribe"),
    });
    if let Ok(message) =
        SubscriptionMessage::new("eth_subscription", sink.subscription_id(), &notice)
        && sink.send(message).await.is_err()
    {
        trace!("lagging subscriber already disconnected");
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Bytes, U64};

    use super::*;
    use crate::server::JsonRpcServer;

    /// Spins up a [`JsonRpcServer`] on an ephemeral port with subscription support.
    ///
    /// Returns the server handle, the bound address, and the broadcast senders
    /// for heads and logs.
    async fn setup_test_server() -> (
        jsonrpsee_server::ServerHandle,
        std::net::SocketAddr,
        broadcast::Sender<RpcBlock>,
        broadcast::Sender<Vec<RpcLog>>,
    ) {
        let heads_tx = broadcast::channel::<RpcBlock>(16).0;
        let logs_tx = broadcast::channel::<Vec<RpcLog>>(16).0;

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server =
            JsonRpcServer::new(addr, 1).with_subscriptions(heads_tx.clone(), logs_tx.clone());

        let (handle, bound_addr) = server.start().await.expect("server should start");
        (handle, bound_addr, heads_tx, logs_tx)
    }

    fn make_log(address: Address, topics: Vec<B256>) -> RpcLog {
        RpcLog {
            address,
            topics,
            data: Bytes::new(),
            block_number: U64::from(1),
            transaction_hash: B256::ZERO,
            transaction_index: U64::ZERO,
            block_hash: B256::ZERO,
            log_index: U64::ZERO,
            removed: false,
        }
    }

    #[test]
    fn empty_filter_matches_all() {
        let filter = SubscriptionLogFilter::default();
        let log = make_log(Address::repeat_byte(0x01), vec![B256::repeat_byte(0xaa)]);
        assert!(matches_filter(&log, &filter));
    }

    #[test]
    fn address_filter_matches() {
        let addr = Address::repeat_byte(0x42);
        let filter = SubscriptionLogFilter {
            addresses: vec![addr],
            ..Default::default()
        };
        let log = make_log(addr, vec![]);
        assert!(matches_filter(&log, &filter));
    }

    #[test]
    fn address_filter_rejects() {
        let addr = Address::repeat_byte(0x42);
        let other = Address::repeat_byte(0x99);
        let filter = SubscriptionLogFilter {
            addresses: vec![addr],
            ..Default::default()
        };
        let log = make_log(other, vec![]);
        assert!(!matches_filter(&log, &filter));
    }

    #[test]
    fn multiple_addresses_or_match() {
        let a1 = Address::repeat_byte(0x01);
        let a2 = Address::repeat_byte(0x02);
        let filter = SubscriptionLogFilter {
            addresses: vec![a1, a2],
            ..Default::default()
        };
        assert!(matches_filter(&make_log(a1, vec![]), &filter));
        assert!(matches_filter(&make_log(a2, vec![]), &filter));
        assert!(!matches_filter(
            &make_log(Address::repeat_byte(0x03), vec![]),
            &filter
        ));
    }

    #[test]
    fn single_topic_filter_matches() {
        let topic = B256::repeat_byte(0xaa);
        let filter = SubscriptionLogFilter {
            topics: vec![vec![topic]],
            ..Default::default()
        };
        let log = make_log(Address::ZERO, vec![topic]);
        assert!(matches_filter(&log, &filter));
    }

    #[test]
    fn single_topic_filter_rejects() {
        let topic = B256::repeat_byte(0xaa);
        let other = B256::repeat_byte(0xbb);
        let filter = SubscriptionLogFilter {
            topics: vec![vec![topic]],
            ..Default::default()
        };
        let log = make_log(Address::ZERO, vec![other]);
        assert!(!matches_filter(&log, &filter));
    }

    #[test]
    fn wildcard_topic_position() {
        let topic1 = B256::repeat_byte(0xbb);
        // Position 0 = wildcard (empty), position 1 = specific topic
        let filter = SubscriptionLogFilter {
            topics: vec![vec![], vec![topic1]],
            ..Default::default()
        };
        let log = make_log(Address::ZERO, vec![B256::repeat_byte(0xff), topic1]);
        assert!(matches_filter(&log, &filter));
    }

    #[test]
    fn topic_or_within_position() {
        let t1 = B256::repeat_byte(0x01);
        let t2 = B256::repeat_byte(0x02);
        let filter = SubscriptionLogFilter {
            topics: vec![vec![t1, t2]],
            ..Default::default()
        };
        assert!(matches_filter(&make_log(Address::ZERO, vec![t1]), &filter));
        assert!(matches_filter(&make_log(Address::ZERO, vec![t2]), &filter));
        assert!(!matches_filter(
            &make_log(Address::ZERO, vec![B256::repeat_byte(0x03)]),
            &filter
        ));
    }

    #[test]
    fn log_fewer_topics_than_filter_rejects() {
        let topic = B256::repeat_byte(0xaa);
        let filter = SubscriptionLogFilter {
            topics: vec![vec![], vec![topic]],
            ..Default::default()
        };
        // Log only has 1 topic, filter needs 2 positions.
        let log = make_log(Address::ZERO, vec![B256::ZERO]);
        assert!(!matches_filter(&log, &filter));
    }

    #[test]
    fn combined_address_and_topic_filter() {
        let addr = Address::repeat_byte(0x42);
        let topic = B256::repeat_byte(0xaa);
        let filter = SubscriptionLogFilter {
            addresses: vec![addr],
            topics: vec![vec![topic]],
        };
        // Matches both.
        assert!(matches_filter(&make_log(addr, vec![topic]), &filter));
        // Wrong address.
        assert!(!matches_filter(
            &make_log(Address::repeat_byte(0x99), vec![topic]),
            &filter
        ));
        // Wrong topic.
        assert!(!matches_filter(
            &make_log(addr, vec![B256::repeat_byte(0xbb)]),
            &filter
        ));
    }

    #[test]
    fn log_subscription_params_deserialize() {
        let json = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "topics": [
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                null
            ]
        });
        let params: LogSubscriptionParams = serde_json::from_value(json).unwrap();
        assert!(params.address.is_some());
        let topics = params.topics.unwrap();
        assert_eq!(topics.len(), 2);
        assert!(topics[0].is_some());
        assert!(topics[1].is_none());
    }

    #[test]
    fn log_subscription_params_to_filter() {
        let params = LogSubscriptionParams {
            address: Some(AddressFilter::Single(Address::repeat_byte(0x42))),
            topics: Some(vec![
                Some(TopicFilter::Single(B256::repeat_byte(0xaa))),
                None,
            ]),
        };
        let filter: SubscriptionLogFilter = params.into();
        assert_eq!(filter.addresses.len(), 1);
        assert_eq!(filter.topics.len(), 2);
        assert_eq!(filter.topics[0].len(), 1);
        assert!(filter.topics[1].is_empty()); // None -> wildcard
    }

    // ---- Integration tests exercising real WebSocket subscriptions ----

    use std::time::Duration;

    use jsonrpsee::core::client::SubscriptionClientT;

    use crate::types::BlockTransactions;

    fn make_rpc_block(number: u64, hash: B256) -> RpcBlock {
        RpcBlock {
            hash,
            number: U64::from(number),
            timestamp: U64::from(1_000_000 + number),
            gas_limit: U64::from(30_000_000u64),
            transactions: BlockTransactions::Hashes(vec![]),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_newheads_subscription() {
        let (_handle, addr, heads_tx, _logs_tx) = setup_test_server().await;
        let url = format!("ws://127.0.0.1:{}", addr.port());
        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await
            .expect("ws client should connect");

        let mut sub = client
            .subscribe::<serde_json::Value, _>(
                "eth_subscribe",
                jsonrpsee::rpc_params!["newHeads"],
                "eth_unsubscribe",
            )
            .await
            .expect("subscribe should succeed");

        let block = make_rpc_block(42, B256::repeat_byte(0xab));
        heads_tx.send(block).unwrap();

        let notif = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("should receive within timeout")
            .expect("subscription should yield a value");

        let value = notif.expect("notification should not be an error");
        assert_eq!(value["number"], serde_json::json!(U64::from(42)));
        assert_eq!(value["hash"], serde_json::json!(B256::repeat_byte(0xab)));
    }

    #[tokio::test]
    async fn test_logs_subscription_no_filter() {
        let (_handle, addr, _heads_tx, logs_tx) = setup_test_server().await;
        let url = format!("ws://127.0.0.1:{}", addr.port());
        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await
            .unwrap();

        let mut sub = client
            .subscribe::<serde_json::Value, _>(
                "eth_subscribe",
                jsonrpsee::rpc_params!["logs"],
                "eth_unsubscribe",
            )
            .await
            .unwrap();

        let log = make_log(Address::repeat_byte(0x11), vec![B256::repeat_byte(0xcc)]);
        logs_tx.send(vec![log]).unwrap();

        let notif = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("should receive within timeout")
            .expect("subscription should yield")
            .expect("should not be error");

        assert_eq!(
            notif["address"],
            serde_json::json!(Address::repeat_byte(0x11))
        );
    }

    #[tokio::test]
    async fn test_logs_subscription_address_filter() {
        let (_handle, addr, _heads_tx, logs_tx) = setup_test_server().await;
        let url = format!("ws://127.0.0.1:{}", addr.port());
        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await
            .unwrap();

        let target = Address::repeat_byte(0x42);
        let filter_params = serde_json::json!({"address": format!("{target}")});
        let mut sub = client
            .subscribe::<serde_json::Value, _>(
                "eth_subscribe",
                jsonrpsee::rpc_params!["logs", filter_params],
                "eth_unsubscribe",
            )
            .await
            .unwrap();

        // Send logs from two different addresses.
        let other = Address::repeat_byte(0x99);
        let log_match = make_log(target, vec![]);
        let log_other = make_log(other, vec![]);
        logs_tx.send(vec![log_other, log_match]).unwrap();

        // Only the matching log should arrive.
        let notif = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("should receive within timeout")
            .expect("subscription should yield")
            .expect("should not be error");

        assert_eq!(notif["address"], serde_json::json!(target));

        // No second notification should arrive (the non-matching log is filtered).
        let timeout_result = tokio::time::timeout(Duration::from_millis(200), sub.next()).await;
        assert!(timeout_result.is_err(), "should not receive a second log");
    }

    #[tokio::test]
    async fn test_logs_subscription_topic_filter() {
        let (_handle, addr, _heads_tx, logs_tx) = setup_test_server().await;
        let url = format!("ws://127.0.0.1:{}", addr.port());
        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await
            .unwrap();

        let wanted_topic = B256::repeat_byte(0xaa);
        let filter_params = serde_json::json!({
            "topics": [format!("{wanted_topic}")]
        });
        let mut sub = client
            .subscribe::<serde_json::Value, _>(
                "eth_subscribe",
                jsonrpsee::rpc_params!["logs", filter_params],
                "eth_unsubscribe",
            )
            .await
            .unwrap();

        let log_match = make_log(Address::ZERO, vec![wanted_topic]);
        let log_miss = make_log(Address::ZERO, vec![B256::repeat_byte(0xbb)]);
        logs_tx.send(vec![log_miss, log_match]).unwrap();

        let notif = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("should receive within timeout")
            .expect("subscription should yield")
            .expect("should not be error");

        assert_eq!(notif["topics"][0], serde_json::json!(wanted_topic));

        // Non-matching log should have been filtered out.
        let timeout_result = tokio::time::timeout(Duration::from_millis(200), sub.next()).await;
        assert!(timeout_result.is_err(), "should not receive a second log");
    }

    #[tokio::test]
    async fn test_unknown_subscription_rejected() {
        let (_handle, addr, _heads_tx, _logs_tx) = setup_test_server().await;
        let url = format!("ws://127.0.0.1:{}", addr.port());
        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await
            .unwrap();

        let result = client
            .subscribe::<serde_json::Value, _>(
                "eth_subscribe",
                jsonrpsee::rpc_params!["newPendingTransactions"],
                "eth_unsubscribe",
            )
            .await;

        assert!(
            result.is_err(),
            "unsupported subscription kind should be rejected"
        );
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let (_handle, addr, heads_tx, _logs_tx) = setup_test_server().await;
        let url = format!("ws://127.0.0.1:{}", addr.port());

        let client_a = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await
            .unwrap();
        let client_b = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await
            .unwrap();

        let mut sub_a = client_a
            .subscribe::<serde_json::Value, _>(
                "eth_subscribe",
                jsonrpsee::rpc_params!["newHeads"],
                "eth_unsubscribe",
            )
            .await
            .unwrap();
        let mut sub_b = client_b
            .subscribe::<serde_json::Value, _>(
                "eth_subscribe",
                jsonrpsee::rpc_params!["newHeads"],
                "eth_unsubscribe",
            )
            .await
            .unwrap();

        let block = make_rpc_block(7, B256::repeat_byte(0x77));
        heads_tx.send(block).unwrap();

        let notif_a = tokio::time::timeout(Duration::from_secs(2), sub_a.next())
            .await
            .expect("sub_a should receive")
            .expect("sub_a should yield")
            .expect("sub_a should not error");
        let notif_b = tokio::time::timeout(Duration::from_secs(2), sub_b.next())
            .await
            .expect("sub_b should receive")
            .expect("sub_b should yield")
            .expect("sub_b should not error");

        assert_eq!(notif_a["number"], serde_json::json!(U64::from(7)));
        assert_eq!(notif_b["number"], serde_json::json!(U64::from(7)));
    }

    #[tokio::test]
    async fn test_newheads_receives_multiple_blocks() {
        let (_handle, addr, heads_tx, _logs_tx) = setup_test_server().await;
        let url = format!("ws://127.0.0.1:{}", addr.port());
        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await
            .unwrap();

        let mut sub = client
            .subscribe::<serde_json::Value, _>(
                "eth_subscribe",
                jsonrpsee::rpc_params!["newHeads"],
                "eth_unsubscribe",
            )
            .await
            .unwrap();

        // Send two blocks sequentially and verify both arrive in order.
        heads_tx
            .send(make_rpc_block(1, B256::repeat_byte(0x11)))
            .unwrap();
        heads_tx
            .send(make_rpc_block(2, B256::repeat_byte(0x22)))
            .unwrap();

        let notif1 = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("should receive block 1")
            .expect("should yield")
            .expect("should not error");
        let notif2 = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("should receive block 2")
            .expect("should yield")
            .expect("should not error");

        assert_eq!(notif1["number"], serde_json::json!(U64::from(1)));
        assert_eq!(notif2["number"], serde_json::json!(U64::from(2)));
    }

    #[tokio::test]
    async fn test_logs_subscription_invalid_filter_rejected() {
        let (_handle, addr, _heads_tx, _logs_tx) = setup_test_server().await;
        let url = format!("ws://127.0.0.1:{}", addr.port());
        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await
            .unwrap();

        // Pass an invalid filter (address should be a hex string, not a number).
        let bad_filter = serde_json::json!({"address": 12345});
        let result = client
            .subscribe::<serde_json::Value, _>(
                "eth_subscribe",
                jsonrpsee::rpc_params!["logs", bad_filter],
                "eth_unsubscribe",
            )
            .await;

        assert!(result.is_err(), "invalid filter params should be rejected");
    }
}
