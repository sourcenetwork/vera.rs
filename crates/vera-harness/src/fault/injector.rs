//! BFT fault injection for distributed systems testing.

use std::time::Duration;

use rand::seq::SliceRandom;

use crate::cluster::runtime::TestCluster;
use crate::observe::{ClusterState, NodeSnapshot};

/// Wraps a TestCluster + ClusterState for fault injection patterns.
#[derive(Debug)]
pub struct FaultInjector<'a> {
    cluster: &'a mut TestCluster,
    state: &'a ClusterState,
}

impl<'a> FaultInjector<'a> {
    /// Create an injector over a running cluster and its observability state.
    pub const fn new(cluster: &'a mut TestCluster, state: &'a ClusterState) -> Self {
        Self { cluster, state }
    }

    /// Identify a uniquely observed healthy leader, if actual telemetry is available.
    pub fn find_leader(&self) -> Option<usize> {
        observed_leader(&self.state.all_nodes())
    }

    /// Kill the current leader, return its index.
    pub fn kill_leader(&mut self) -> eyre::Result<usize> {
        let leader = self.find_leader().ok_or_else(|| {
            eyre::eyre!(
                "no uniquely observed healthy leader; live leader telemetry may be unavailable"
            )
        })?;
        self.cluster.kill_node(leader);
        Ok(leader)
    }

    /// Kill specific nodes by index.
    pub fn kill_nodes(&mut self, indices: &[usize]) -> eyre::Result<()> {
        for &i in indices {
            if i >= self.cluster.node_count() {
                return Err(eyre::eyre!(
                    "node index {} out of range (cluster has {} nodes)",
                    i,
                    self.cluster.node_count()
                ));
            }
            self.cluster.kill_node(i);
        }
        Ok(())
    }

    /// Kill n random nodes, excluding a uniquely observed leader when available.
    ///
    /// When leader telemetry is unavailable, selection cannot promise to spare it.
    pub fn kill_random(&mut self, n: usize) -> eyre::Result<Vec<usize>> {
        let leader = self.find_leader();
        let mut candidates: Vec<usize> = (0..self.cluster.node_count())
            .filter(|i| Some(*i) != leader)
            .collect();

        if n > candidates.len() {
            return Err(eyre::eyre!(
                "cannot kill {} eligible random nodes (only {} available)",
                n,
                candidates.len()
            ));
        }

        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
        let killed: Vec<usize> = candidates.into_iter().take(n).collect();

        for &i in &killed {
            self.cluster.kill_node(i);
        }

        Ok(killed)
    }

    /// Restart a previously killed node.
    pub fn restart_node(&mut self, index: usize) -> eyre::Result<()> {
        self.cluster.restart_node(index)
    }

    /// Rolling restart: kill and restart each node sequentially.
    pub async fn rolling_restart(&mut self, settle_time: Duration) -> eyre::Result<()> {
        for i in 0..self.cluster.node_count() {
            self.cluster.kill_node(i);
            tokio::time::sleep(settle_time).await;
            self.cluster.restart_node(i)?;
            tokio::time::sleep(settle_time).await;
        }
        Ok(())
    }

    /// Kill f nodes (max Byzantine tolerance), assert cluster continues producing blocks.
    pub async fn assert_survives_f_faults(&mut self, timeout: Duration) -> eyre::Result<()> {
        let n = self.cluster.node_count();
        let f = (n - 1) / 3;

        let before_height = self
            .state
            .all_nodes()
            .iter()
            .filter(|s| s.is_healthy)
            .map(|s| s.effective_height())
            .max()
            .unwrap_or(0);

        let killed = self.kill_random(f)?;
        tracing::info!(f, killed = ?killed, "killed f nodes for fault tolerance test");

        let target = before_height + 3;
        self.state.wait_for_height(target, timeout).await?;

        for i in killed {
            self.cluster.restart_node(i)?;
        }

        Ok(())
    }

    /// Kill f+1 nodes, assert cluster stalls (no new blocks within timeout).
    pub async fn assert_stalls_above_threshold(
        &mut self,
        stall_check: Duration,
    ) -> eyre::Result<Vec<usize>> {
        let n = self.cluster.node_count();
        let f = (n - 1) / 3;
        let kill_count = f + 1;

        let before_height = self
            .state
            .all_nodes()
            .iter()
            .filter(|s| s.is_healthy)
            .map(|s| s.effective_height())
            .max()
            .unwrap_or(0);

        let killed = self.kill_random(kill_count)?;
        tracing::info!(
            kill_count,
            killed = ?killed,
            "killed f+1 nodes — cluster should stall"
        );

        tokio::time::sleep(stall_check).await;

        let after_height = self
            .state
            .all_nodes()
            .iter()
            .filter(|s| s.is_healthy)
            .map(|s| s.effective_height())
            .max()
            .unwrap_or(0);

        if after_height > before_height + 1 {
            return Err(eyre::eyre!(
                "cluster did NOT stall: height advanced from {} to {} with f+1 nodes down",
                before_height,
                after_height
            ));
        }

        Ok(killed)
    }

    /// After faults, verify all surviving healthy nodes have consistent state.
    pub fn assert_state_consistent(&self, tolerance: u64) -> eyre::Result<()> {
        let snaps = self.state.all_nodes();
        let healthy: Vec<_> = snaps.iter().filter(|s| s.is_healthy).collect();

        if healthy.is_empty() {
            return Err(eyre::eyre!("no healthy nodes to check consistency"));
        }

        let chain_ids: Vec<u64> = healthy.iter().map(|s| s.chain_id).collect();
        if !chain_ids.windows(2).all(|w| w[0] == w[1]) {
            return Err(eyre::eyre!(
                "chain ID mismatch across healthy nodes: {:?}",
                chain_ids
            ));
        }

        let min = healthy
            .iter()
            .map(|s| s.effective_height())
            .min()
            .unwrap_or(0);
        let max = healthy
            .iter()
            .map(|s| s.effective_height())
            .max()
            .unwrap_or(0);

        if max - min > tolerance {
            return Err(eyre::eyre!(
                "block heights diverged: min={}, max={}, tolerance={}",
                min,
                max,
                tolerance
            ));
        }

        Ok(())
    }
}

fn observed_leader(snapshots: &[NodeSnapshot]) -> Option<usize> {
    let mut leaders = snapshots
        .iter()
        .filter(|snapshot| snapshot.is_healthy && snapshot.is_leader == Some(true));
    let leader = leaders.next()?.node_index;
    leaders.next().is_none().then_some(leader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_selection_requires_unique_live_evidence() {
        let mut snapshots = vec![NodeSnapshot {
            is_healthy: true,
            ..NodeSnapshot::default()
        }];
        assert_eq!(observed_leader(&snapshots), None);
        snapshots[0].is_leader = Some(false);
        assert_eq!(observed_leader(&snapshots), None);
        snapshots[0].is_leader = Some(true);
        assert_eq!(observed_leader(&snapshots), Some(0));
        snapshots[0].is_healthy = false;
        assert_eq!(observed_leader(&snapshots), None);
        snapshots[0].is_healthy = true;
        snapshots.push(NodeSnapshot {
            node_index: 1,
            is_healthy: true,
            is_leader: Some(true),
            ..NodeSnapshot::default()
        });
        assert_eq!(observed_leader(&snapshots), None);
    }
}
