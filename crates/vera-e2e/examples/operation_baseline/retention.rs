//! Historical query checks outside the measured arrival interval.

use alloy_primitives::B256;
use serde_json::{Value, json};
use std::time::Duration;
use vera_client::VeraClient;

pub(super) struct Probe {
    queries: Vec<(&'static str, Value, Value)>,
}

impl Probe {
    pub(super) async fn capture(client: &VeraClient, hash: B256, height: u64) -> Self {
        let requests = [
            ("vera_getLightBlock", json!([height])),
            ("vera_getTransactionReceipt", json!([hash])),
        ];
        let mut queries = Vec::new();
        for (method, params) in requests {
            let expected: Value = client.rpc_call_typed(method, params.clone()).await.unwrap();
            assert!(!expected.is_null(), "missing initial {method}");
            if method == "vera_getTransactionReceipt" {
                assert!(
                    !expected["logs"].as_array().unwrap().is_empty(),
                    "probe must include logs"
                );
            }
            queries.push((method, params, expected));
        }
        Self { queries }
    }

    pub(super) async fn check(&self, client: &VeraClient) {
        for (method, params, expected) in &self.queries {
            let actual: Value = client.rpc_call_typed(method, params.clone()).await.unwrap();
            assert_eq!(&actual, expected, "historical {method} changed");
        }
    }
}

pub(super) async fn wait(clients: &[VeraClient], height: u64) {
    tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            let mut ready = true;
            for client in clients {
                ready &= client
                    .node_status()
                    .await
                    .unwrap()
                    .finalized_height
                    .is_some_and(|finalized| finalized >= height);
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("historical retention revision deadline");
}
