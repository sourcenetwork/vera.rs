//! HTTP-based RPC poller for monitoring node state.

use std::{sync::Arc, time::Duration};

use tokio::sync::broadcast;

use super::{rpc_events::RpcEvent, rpc_snapshot::NodeSnapshot};

/// Polls node RPC endpoints at a regular interval and emits events.
#[derive(Debug)]
pub struct RpcPoller {
    tx: broadcast::Sender<RpcEvent>,
    snapshots: Arc<parking_lot::RwLock<Vec<NodeSnapshot>>>,
    _handles: Vec<tokio::task::JoinHandle<()>>,
}

impl RpcPoller {
    /// Create a new poller for the given node RPC URLs.
    pub fn new(rpc_urls: Vec<String>, poll_interval: Duration) -> Self {
        let (tx, _) = broadcast::channel(1024);
        let n = rpc_urls.len();
        let snapshots = Arc::new(parking_lot::RwLock::new(
            (0..n)
                .map(|i| NodeSnapshot {
                    node_index: i,
                    ..Default::default()
                })
                .collect(),
        ));

        let mut handles = Vec::with_capacity(n);

        for (i, url) in rpc_urls.into_iter().enumerate() {
            let tx = tx.clone();
            let snapshots = snapshots.clone();

            let handle = tokio::spawn(async move {
                Self::poll_loop(i, url, poll_interval, tx, snapshots).await;
            });
            handles.push(handle);
        }

        Self {
            tx,
            snapshots,
            _handles: handles,
        }
    }

    /// Subscribe to RPC events.
    pub fn subscribe(&self) -> broadcast::Receiver<RpcEvent> {
        self.tx.subscribe()
    }

    /// Get the latest snapshot for a specific node.
    pub fn snapshot(&self, node_index: usize) -> NodeSnapshot {
        self.snapshots.read()[node_index].clone()
    }

    /// Get snapshots for all nodes.
    pub fn all_snapshots(&self) -> Vec<NodeSnapshot> {
        self.snapshots.read().clone()
    }

    async fn poll_loop(
        node_index: usize,
        rpc_url: String,
        interval: Duration,
        tx: broadcast::Sender<RpcEvent>,
        snapshots: Arc<parking_lot::RwLock<Vec<NodeSnapshot>>>,
    ) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("http client");

        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            // Poll vera_nodeStatus.
            let status = Self::call_node_status(&client, &rpc_url).await;
            let block_height = Self::call_latest_block(&client, &rpc_url).await;

            let mut snaps = snapshots.write();
            let snap = &mut snaps[node_index];
            let prev_height = snap.latest_block_height;

            if let Some(status) = status {
                Self::observe_status(snap, &status, &tx);
            } else {
                snap.is_healthy = false;
            }
            if let Some(height) = block_height {
                snap.latest_block_height = height;
            }

            if let Some(height) = block_height
                && height != prev_height
            {
                let _ = tx.send(RpcEvent::NewBlock {
                    node: node_index,
                    height,
                });
            }
        }
    }

    fn observe_status(
        snap: &mut NodeSnapshot,
        status: &NodeStatusResponse,
        tx: &broadcast::Sender<RpcEvent>,
    ) {
        let node = snap.node_index;
        if status.current_view != snap.current_view {
            let _ = tx.send(RpcEvent::ViewAdvanced {
                node,
                view: status.current_view,
            });
        }
        if status.finalized_count != snap.finalized_count {
            let _ = tx.send(RpcEvent::Finalized {
                node,
                count: status.finalized_count,
            });
        }
        if status.peer_count != snap.peer_count {
            let _ = tx.send(RpcEvent::PeerCountChanged {
                node,
                peers: status.peer_count,
            });
        }
        if status.is_leader != snap.is_leader {
            let _ = tx.send(RpcEvent::LeaderChanged {
                node,
                is_leader: status.is_leader,
            });
        }
        snap.chain_id = status.chain_id;
        snap.validator_index = status.validator_index;
        snap.validator_count = status.validator_count;
        snap.uptime_secs = status.uptime_secs;
        snap.current_view = status.current_view;
        snap.finalized_height = status.finalized_height;
        snap.finalized_epoch = status.finalized_epoch;
        snap.finalized_view = status.finalized_view;
        snap.snapshot_revision = status.snapshot_revision;
        snap.finalized_count = status.finalized_count;
        snap.proposed_count = status.proposed_count;
        snap.nullified_count = status.nullified_count;
        snap.peer_count = status.peer_count;
        snap.is_leader = status.is_leader;
        snap.backfilling = status.backfilling;
        snap.is_healthy = true;
    }

    async fn call_node_status(client: &reqwest::Client, url: &str) -> Option<NodeStatusResponse> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "vera_nodeStatus",
            "params": [],
            "id": 1
        });

        let resp = client.post(url).json(&body).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let result = json.get("result")?;
        serde_json::from_value(result.clone()).ok()
    }

    async fn call_latest_block(client: &reqwest::Client, url: &str) -> Option<u64> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": ["latest", false],
            "id": 2
        });

        let resp = client.post(url).json(&body).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let result = json.get("result")?;
        let number_hex = result.get("number")?.as_str()?;
        u64::from_str_radix(number_hex.trim_start_matches("0x"), 16).ok()
    }
}

impl Drop for RpcPoller {
    fn drop(&mut self) {
        for handle in &self._handles {
            handle.abort();
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeStatusResponse {
    chain_id: u64,
    validator_index: u32,
    #[serde(default)]
    validator_count: u32,
    uptime_secs: u64,
    current_view: Option<u64>,
    finalized_height: Option<u64>,
    finalized_epoch: Option<u64>,
    finalized_view: Option<u64>,
    snapshot_revision: Option<u64>,
    finalized_count: u64,
    proposed_count: u64,
    nullified_count: Option<u64>,
    peer_count: Option<u64>,
    is_leader: Option<bool>,
    #[serde(default)]
    backfilling: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_telemetry_survives_polling_and_events() {
        let mut value = serde_json::json!({
            "chainId": 7, "validatorIndex": 0, "validatorCount": 4, "uptimeSecs": 1,
            "currentView": null, "finalizedCount": 1, "proposedCount": 2,
            "nullifiedCount": null, "peerCount": null, "isLeader": null,
            "finalizedHeight": 8, "finalizedEpoch": 2, "finalizedView": 3,
            "snapshotRevision": 7
        });
        let (tx, mut events) = broadcast::channel(8);
        let mut snapshot = NodeSnapshot {
            current_view: Some(10),
            peer_count: Some(3),
            is_leader: Some(true),
            ..NodeSnapshot::default()
        };
        RpcPoller::observe_status(
            &mut snapshot,
            &serde_json::from_value(value.clone()).unwrap(),
            &tx,
        );
        assert!(snapshot.is_healthy);
        assert_eq!(snapshot.current_view, None);
        assert_eq!(snapshot.nullified_count, None);
        assert_eq!(snapshot.peer_count, None);
        assert_eq!(snapshot.is_leader, None);
        assert_eq!(snapshot.finalized_height, Some(8));
        assert_eq!(
            snapshot.finalized_epoch.zip(snapshot.finalized_view),
            Some((2, 3))
        );
        assert_eq!(snapshot.snapshot_revision, Some(7));
        assert!(matches!(
            events.try_recv().unwrap(),
            RpcEvent::ViewAdvanced { view: None, .. }
        ));
        assert!(matches!(
            events.try_recv().unwrap(),
            RpcEvent::Finalized { count: 1, .. }
        ));
        assert!(matches!(
            events.try_recv().unwrap(),
            RpcEvent::PeerCountChanged { peers: None, .. }
        ));
        assert!(matches!(
            events.try_recv().unwrap(),
            RpcEvent::LeaderChanged {
                is_leader: None,
                ..
            }
        ));
        value["currentView"] = serde_json::json!(0);
        value["peerCount"] = serde_json::json!(0);
        value["isLeader"] = serde_json::json!(false);
        RpcPoller::observe_status(&mut snapshot, &serde_json::from_value(value).unwrap(), &tx);
        assert_eq!(snapshot.current_view, Some(0));
        assert_eq!(snapshot.peer_count, Some(0));
        assert_eq!(snapshot.is_leader, Some(false));
    }
}
