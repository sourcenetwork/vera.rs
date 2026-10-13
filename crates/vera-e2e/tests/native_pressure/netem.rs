use std::{collections::BTreeSet, io, net::SocketAddrV4, process::Command, time::Duration};

use serde_json::Value;
use vera_e2e::cluster::TestNode;

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

fn flows(text: &str, pid: u32, port: u16, peers: &[u16]) -> BTreeSet<(u16, u16)> {
    let owner = format!("pid={pid},");
    text.lines()
        .filter(|line| line.contains(&owner))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != "ESTAB" {
                return None;
            }
            fields.next()?;
            fields.next()?;
            let local: SocketAddrV4 = fields.next()?.parse().ok()?;
            let remote: SocketAddrV4 = fields.next()?.parse().ok()?;
            (local.ip().is_loopback()
                && remote.ip().is_loopback()
                && (local.port() == port || peers.contains(&remote.port())))
            .then_some((local.port(), remote.port()))
        })
        .collect()
}

/// Delay only the managed validator's established P2P flows, in both directions.
pub(super) struct Delayed<'a> {
    node: &'a TestNode,
    peers: Vec<u16>,
    flows: BTreeSet<(u16, u16)>,
    owns_root: bool,
}

impl<'a> Delayed<'a> {
    pub(super) async fn install(node: &'a TestNode, peers: Vec<u16>) -> Self {
        assert_eq!(std::env::var("VERA_E2E_NETEM").as_deref(), Ok("1"));
        let mut fault = Self {
            node,
            peers,
            flows: BTreeSet::new(),
            owns_root: false,
        };
        fault.flows = tokio::time::timeout(Duration::from_secs(10), async {
            let mut previous = fault.connections();
            let mut changed_at = tokio::time::Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let current = fault.connections();
                assert!(current.len() <= 16, "validator P2P flow limit");
                if current != previous {
                    previous = current;
                    changed_at = tokio::time::Instant::now();
                }
                if !previous.is_empty() && changed_at.elapsed() >= Duration::from_secs(2) {
                    break previous;
                }
            }
        })
        .await
        .expect("validator P2P topology did not stabilize before fault installation");
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
        let pairs: BTreeSet<_> = fault
            .flows
            .iter()
            .flat_map(|&(a, b)| [(a, b), (b, a)])
            .collect();
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

    fn connections(&self) -> BTreeSet<(u16, u16)> {
        let output = Command::new("ss").args(["-Htnp"]).output().unwrap();
        assert!(output.status.success() && output.stdout.len() <= 256 * 1024);
        let text = std::str::from_utf8(&output.stdout).unwrap();
        flows(
            text,
            self.node.process.id().unwrap(),
            self.node.p2p_port,
            &self.peers,
        )
    }

    pub(super) fn assert_active(&self) -> u64 {
        assert_eq!(
            self.connections(),
            self.flows,
            "P2P flows changed; impairment coverage is no longer complete"
        );
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

#[test]
fn flow_selection_excludes_rpc_and_other_processes_and_retains_outbound_peers() {
    let text = "ESTAB 0 0 127.0.0.1:9003 127.0.0.1:42000 users:((\"verad\",pid=12,fd=1))\n\
                ESTAB 0 0 127.0.0.1:42001 127.0.0.1:9001 users:((\"verad\",pid=12,fd=2))\n\
                ESTAB 0 0 127.0.0.1:8545 127.0.0.1:42002 users:((\"verad\",pid=12,fd=3))\n\
                ESTAB 0 0 127.0.0.1:9003 127.0.0.1:42003 users:((\"verad\",pid=123,fd=4))\n\
                ESTAB 0 0 127.0.0.1:9003 10.0.0.1:42004 users:((\"verad\",pid=12,fd=5))";
    assert_eq!(
        flows(text, 12, 9003, &[9000, 9001, 9002]),
        BTreeSet::from([(9003, 42000), (42001, 9001)])
    );
}
