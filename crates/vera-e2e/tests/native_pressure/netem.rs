use std::{collections::BTreeSet, io, process::Command, time::Duration};

use serde_json::Value;
use vera_e2e::cluster::TestNode;

#[path = "netem_flows.rs"]
mod selection;

use selection::{Peer, complete_mesh, flows, packet_pairs};

const ROOT: &str = "7eaa:";
const CLASS: &str = "7eaa:3";
const QUEUE: &str = "7eab:";

fn tc(args: &[&str]) -> io::Result<Vec<u8>> {
    let output = Command::new("/usr/bin/sudo")
        .args(["-n", "tc"])
        .args(args)
        .output()?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(4096)]);
        return Err(io::Error::other(format!(
            "owned network fault command failed: {detail}"
        )));
    }
    if output.stdout.len() > 256 * 1024 {
        return Err(io::Error::other("network fault status exceeds its limit"));
    }
    Ok(output.stdout)
}

/// Delay only the managed validator's established P2P flows, in both directions.
pub(super) struct Delayed<'a> {
    node: &'a TestNode,
    peers: Vec<Peer>,
    flows: BTreeSet<(u16, u16)>,
    owns_root: bool,
}

impl<'a> Delayed<'a> {
    pub(super) async fn install(node: &'a TestNode, peers: Vec<&TestNode>) -> Self {
        assert_eq!(std::env::var("VERA_E2E_NETEM").as_deref(), Ok("1"));
        let mut fault = Self {
            node,
            peers: peers
                .iter()
                .map(|peer| Peer {
                    pid: peer.process.id().unwrap(),
                    port: peer.p2p_port,
                })
                .collect(),
            flows: BTreeSet::new(),
            owns_root: false,
        };
        fault.flows = tokio::time::timeout(Duration::from_secs(30), async {
            let mut previous = fault.connections().0;
            let mut changed_at = tokio::time::Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let (current, complete) = fault.connections();
                assert!(current.len() <= 16, "validator P2P flow limit");
                if current != previous || !complete {
                    previous = current;
                    changed_at = tokio::time::Instant::now();
                }
                if complete && changed_at.elapsed() >= Duration::from_secs(2) {
                    break previous;
                }
            }
        })
        .await
        .expect("validator P2P mesh did not fully connect and stabilize before fault installation");
        let prior: Vec<Value> =
            serde_json::from_slice(&tc(&["-j", "qdisc", "show", "dev", "lo"]).unwrap()).unwrap();
        assert!(
            prior.iter().all(|q| q["kind"] == "noqueue"),
            "loopback already has a configured queue"
        );
        tc(&[
            "qdisc", "add", "dev", "lo", "root", "handle", ROOT, "prio", "bands", "3", "priomap",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        ])
        .unwrap();
        fault.owns_root = true;
        tc(&[
            "qdisc", "add", "dev", "lo", "parent", CLASS, "handle", QUEUE, "netem", "delay",
            "100ms", "rate", "20mbit", "limit", "1024",
        ])
        .unwrap();
        let pairs = packet_pairs(&fault.flows);
        for (index, (source, destination)) in pairs.into_iter().enumerate() {
            tc(&[
                "filter",
                "add",
                "dev",
                "lo",
                "parent",
                ROOT,
                "protocol",
                "ip",
                "pref",
                &(index + 1).to_string(),
                "flower",
                "skip_hw",
                "ip_proto",
                "tcp",
                "src_ip",
                "127.0.0.1",
                "dst_ip",
                "127.0.0.1",
                "src_port",
                &source.to_string(),
                "dst_port",
                &destination.to_string(),
                "classid",
                CLASS,
            ])
            .unwrap();
        }
        fault.assert_active();
        fault
    }

    fn connections(&self) -> (BTreeSet<(u16, u16)>, bool) {
        let output = Command::new("ss").args(["-Htnp"]).output().unwrap();
        assert!(output.status.success() && output.stdout.len() <= 256 * 1024);
        let text = std::str::from_utf8(&output.stdout).unwrap();
        let active = flows(
            text,
            self.node.process.id().unwrap(),
            self.node.p2p_port,
            &self.peers.iter().map(|peer| peer.port).collect::<Vec<_>>(),
        );
        let complete = complete_mesh(text, &active, self.node.p2p_port, &self.peers);
        (active, complete)
    }

    pub(super) fn assert_active(&self) -> u64 {
        let (active, _) = self.connections();
        let filtered = packet_pairs(&self.flows);
        let uncovered = active.difference(&filtered).count();
        if uncovered != 0 {
            eprintln!(
                "netem_coverage active={} installed={} uncovered={}",
                active.len(),
                filtered.len(),
                uncovered
            );
        }
        // Closed sockets retain their filters; only new, unfiltered flows lose coverage.
        assert_eq!(uncovered, 0, "P2P impairment coverage is incomplete");
        let queues: Vec<Value> =
            serde_json::from_slice(&tc(&["-s", "-j", "qdisc", "show", "dev", "lo"]).unwrap())
                .unwrap();
        let queue = queues
            .iter()
            .find(|q| q["kind"] == "netem" && q["handle"] == QUEUE && q["parent"] == CLASS)
            .expect("owned delay queue is missing");
        queue["packets"]
            .as_u64()
            .expect("delay queue packet counter")
    }

    pub(super) fn restore(mut self) {
        tc(&["qdisc", "del", "dev", "lo", "root", "handle", ROOT]).unwrap();
        self.owns_root = false;
    }
}

impl Drop for Delayed<'_> {
    fn drop(&mut self) {
        if self.owns_root {
            let _ = tc(&["qdisc", "del", "dev", "lo", "root", "handle", ROOT]);
        }
    }
}
