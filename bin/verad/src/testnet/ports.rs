//! Port assignment for a local testnet.

use std::{collections::BTreeSet, net::TcpListener};

#[derive(Debug)]
pub(super) struct Ports {
    pub(super) p2p: Vec<u16>,
    pub(super) rpc: Vec<u16>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum PortError {
    #[error("failed to allocate a local port")]
    Allocate(#[from] std::io::Error),
    #[error("{flag} {base} leaves no room for {nodes} nodes")]
    Range {
        flag: &'static str,
        base: u16,
        nodes: usize,
    },
    #[error("the P2P and RPC port ranges overlap")]
    Overlap,
}

/// Assign one P2P and one RPC port per node; a zero base asks the system for free ports.
pub(super) fn resolve(nodes: usize, base_p2p: u16, base_rpc: u16) -> Result<Ports, PortError> {
    let explicit = |flag, base| (base != 0).then(|| range(flag, base, nodes)).transpose();
    let p2p = explicit("--base-p2p-port", base_p2p)?;
    let rpc = explicit("--base-rpc-port", base_rpc)?;
    let automatic = usize::from(p2p.is_none()) + usize::from(rpc.is_none());
    let mut free = allocate(nodes.saturating_mul(automatic))?.into_iter();
    let mut assigned =
        |ports: Option<Vec<u16>>| ports.unwrap_or_else(|| free.by_ref().take(nodes).collect());
    let p2p = assigned(p2p);
    let rpc = assigned(rpc);
    let distinct: BTreeSet<u16> = p2p.iter().chain(&rpc).copied().collect();
    if distinct.len() != p2p.len() + rpc.len() {
        return Err(PortError::Overlap);
    }
    Ok(Ports { p2p, rpc })
}

fn range(flag: &'static str, base: u16, nodes: usize) -> Result<Vec<u16>, PortError> {
    (0..nodes)
        .map(|index| {
            u16::try_from(index)
                .ok()
                .and_then(|index| base.checked_add(index))
                .ok_or(PortError::Range { flag, base, nodes })
        })
        .collect()
}

/// Every listener stays open until all ports are known, so the system cannot hand one out twice.
fn allocate(count: usize) -> Result<Vec<u16>, PortError> {
    let mut listeners = Vec::new();
    for _ in 0..count {
        listeners.push(TcpListener::bind("127.0.0.1:0")?);
    }
    listeners
        .iter()
        .map(|listener| Ok(listener.local_addr()?.port()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_bases_count_up_and_reject_a_range_past_the_last_port() {
        let ports = resolve(4, 30_000, 65_532).unwrap();
        assert_eq!(ports.p2p, [30_000, 30_001, 30_002, 30_003]);
        assert_eq!(ports.rpc, [65_532, 65_533, 65_534, u16::MAX]);
        assert!(matches!(
            resolve(4, 30_000, 65_534),
            Err(PortError::Range {
                flag: "--base-rpc-port",
                base: 65_534,
                nodes: 4
            })
        ));
        assert!(matches!(
            resolve(70_000, 1, 1),
            Err(PortError::Range {
                flag: "--base-p2p-port",
                ..
            })
        ));
    }

    #[test]
    fn overlapping_explicit_ranges_are_rejected() {
        assert!(matches!(resolve(4, 9_000, 9_003), Err(PortError::Overlap)));
        assert!(resolve(4, 9_000, 9_004).is_ok());
    }

    #[test]
    fn automatic_ports_are_distinct_across_both_roles() {
        let ports = resolve(4, 0, 0).unwrap();
        let distinct: BTreeSet<u16> = ports.p2p.iter().chain(&ports.rpc).copied().collect();
        assert_eq!((ports.p2p.len(), ports.rpc.len()), (4, 4));
        assert_eq!(distinct.len(), 8);
        assert!(!distinct.contains(&0));
    }
}
