use std::{collections::BTreeSet, net::SocketAddrV4};

pub(super) fn flows(text: &str, pid: u32, port: u16, peers: &[u16]) -> BTreeSet<(u16, u16)> {
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

pub(super) fn packet_pairs(flows: &BTreeSet<(u16, u16)>) -> BTreeSet<(u16, u16)> {
    flows
        .iter()
        .flat_map(|&(source, destination)| [(source, destination), (destination, source)])
        .collect()
}

pub(super) struct Peer {
    pub pid: u32,
    pub port: u16,
}

// A stable subset is not enough: a late peer would bypass the installed filters.
pub(super) fn complete_mesh(
    text: &str,
    active: &BTreeSet<(u16, u16)>,
    port: u16,
    peers: &[Peer],
) -> bool {
    !peers.is_empty()
        && peers.iter().all(|peer| {
            flows(text, peer.pid, peer.port, &[port])
                .iter()
                .any(|&(source, destination)| active.contains(&(destination, source)))
        })
}

#[test]
fn fault_filters_cover_closed_and_bidirectional_flows_but_reject_new_connections() {
    let initial = flows(
        "ESTAB 0 0 127.0.0.1:9003 127.0.0.1:42000 users:((\"verad\",pid=12,fd=1))\n\
         ESTAB 0 0 127.0.0.1:42001 127.0.0.1:9001 users:((\"verad\",pid=12,fd=2))",
        12,
        9003,
        &[9000, 9001, 9002],
    );
    let filters = packet_pairs(&initial);
    assert_eq!(filters.len(), 4);
    assert!(filters.contains(&(42000, 9003)));
    let surviving = flows(
        "ESTAB 0 0 127.0.0.1:42001 127.0.0.1:9001 users:((\"verad\",pid=12,fd=2))",
        12,
        9003,
        &[9000, 9001, 9002],
    );
    assert_eq!(surviving.difference(&filters).count(), 0);
    let new_connection = flows(
        "ESTAB 0 0 127.0.0.1:42002 127.0.0.1:9001 users:((\"verad\",pid=12,fd=3))",
        12,
        9003,
        &[9000, 9001, 9002],
    );
    assert_eq!(new_connection.difference(&filters).count(), 1);
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

#[test]
fn mesh_requires_every_peer_not_just_enough_connections() {
    let peers = [
        Peer {
            pid: 10,
            port: 9000,
        },
        Peer {
            pid: 11,
            port: 9001,
        },
        Peer {
            pid: 13,
            port: 9002,
        },
    ];
    // Three sockets still cover only two peers, including a duplicate connection.
    let partial = "ESTAB 0 0 127.0.0.1:9003 127.0.0.1:42000 users:((\"verad\",pid=12,fd=1))\n\
                   ESTAB 0 0 127.0.0.1:42000 127.0.0.1:9003 users:((\"verad\",pid=10,fd=1))\n\
                   ESTAB 0 0 127.0.0.1:42001 127.0.0.1:9001 users:((\"verad\",pid=12,fd=2))\n\
                   ESTAB 0 0 127.0.0.1:9001 127.0.0.1:42001 users:((\"verad\",pid=11,fd=2))\n\
                   ESTAB 0 0 127.0.0.1:42002 127.0.0.1:9000 users:((\"verad\",pid=12,fd=3))\n\
                   ESTAB 0 0 127.0.0.1:9000 127.0.0.1:42002 users:((\"verad\",pid=10,fd=3))";
    let active = flows(partial, 12, 9003, &[9000, 9001, 9002]);
    assert_eq!(active.len(), 3);
    assert!(!complete_mesh(partial, &active, 9003, &peers));
    let full = format!(
        "{partial}\n\
        ESTAB 0 0 127.0.0.1:9003 127.0.0.1:42003 users:((\"verad\",pid=12,fd=4))\n\
        ESTAB 0 0 127.0.0.1:42003 127.0.0.1:9003 users:((\"verad\",pid=13,fd=4))"
    );
    let connected = flows(&full, 12, 9003, &[9000, 9001, 9002]);
    assert!(complete_mesh(&full, &connected, 9003, &peers));
    assert_eq!(connected.difference(&packet_pairs(&active)).count(), 1);
    assert_eq!(connected.difference(&packet_pairs(&connected)).count(), 0);
    assert!(!complete_mesh(&full, &connected, 9003, &[]));
    let wrong_owner = full.replace("pid=13,", "pid=130,");
    assert!(!complete_mesh(&wrong_owner, &connected, 9003, &peers));
}
