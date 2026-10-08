use jsonrpsee::{PendingSubscriptionSink, SubscriptionMessage, proc_macros::rpc};
use tokio::sync::broadcast;
use vera_domain::GossipHeader;

#[rpc(server, namespace = "vera")]
pub(crate) trait HeaderSubscriptionApi {
    #[subscription(name = "subscribeHeaders" => "header", unsubscribe = "unsubscribeHeaders", item = GossipHeader)]
    async fn subscribe_headers(&self) -> jsonrpsee::core::SubscriptionResult;
}

#[derive(Debug)]
pub(crate) struct HeaderSubscriptionApiImpl(pub broadcast::Sender<GossipHeader>);

#[jsonrpsee::core::async_trait]
impl HeaderSubscriptionApiServer for HeaderSubscriptionApiImpl {
    async fn subscribe_headers(
        &self,
        pending: PendingSubscriptionSink,
    ) -> jsonrpsee::core::SubscriptionResult {
        stream_headers(pending, &self.0).await
    }
}

pub(crate) async fn stream_headers(
    pending: PendingSubscriptionSink,
    headers: &broadcast::Sender<GossipHeader>,
) -> jsonrpsee::core::SubscriptionResult {
    let mut receiver = headers.subscribe();
    let sink = pending.accept().await?;
    tokio::spawn(async move {
        loop {
            let header = tokio::select! {
                () = sink.closed() => break,
                result = receiver.recv() => match result {
                    Ok(header) => header,
                    Err(_) => break,
                },
            };
            let Ok(message) =
                SubscriptionMessage::new("vera_subscribeHeaders", sink.subscription_id(), &header)
            else {
                break;
            };
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::core::{
        client::{ClientT, SubscriptionClientT},
        params::BatchRequestBuilder,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn native_headers_stream_and_release_idle_subscription() {
        let headers = broadcast::channel(4).0;
        let (handle, addr) = crate::JsonRpcServer::new("127.0.0.1:0".parse().unwrap(), 1)
            .with_headers_subscription(headers.clone())
            .start()
            .await
            .unwrap();
        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(format!("ws://{addr}"))
            .await
            .unwrap();
        let mut subscription = client
            .subscribe::<GossipHeader, _>(
                "vera_subscribeHeaders",
                jsonrpsee::rpc_params![],
                "vera_unsubscribeHeaders",
            )
            .await
            .unwrap();
        let header = GossipHeader {
            chain_id: 1,
            height: 7,
            block_hash: Default::default(),
            parent_hash: Default::default(),
            timestamp: 123,
            state_root: Default::default(),
            module_state_root: Default::default(),
            tx_count: 2,
            publisher_index: 0,
            signature: vec![3; 96],
        };
        headers.send(header.clone()).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), subscription.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(received, header);
        subscription.unsubscribe().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while headers.receiver_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle subscription receiver released");
        let mut subscriptions = Vec::new();
        for _ in 0..8 {
            subscriptions.push(
                client
                    .subscribe::<GossipHeader, _>(
                        "vera_subscribeHeaders",
                        jsonrpsee::rpc_params![],
                        "vera_unsubscribeHeaders",
                    )
                    .await
                    .unwrap(),
            );
        }
        assert!(
            client
                .subscribe::<GossipHeader, _>(
                    "vera_subscribeHeaders",
                    jsonrpsee::rpc_params![],
                    "vera_unsubscribeHeaders",
                )
                .await
                .is_err()
        );
        for subscription in subscriptions {
            subscription.unsubscribe().await.unwrap();
        }
        let mut batch = BatchRequestBuilder::new();
        for _ in 0..64 {
            batch
                .insert("net_version", jsonrpsee::rpc_params![])
                .unwrap();
        }
        assert!(client.batch_request::<String>(batch.clone()).await.is_ok());
        batch
            .insert("net_version", jsonrpsee::rpc_params![])
            .unwrap();
        assert!(client.batch_request::<String>(batch).await.is_err());
        handle.stop().unwrap();
        handle.stopped().await;
    }
}
