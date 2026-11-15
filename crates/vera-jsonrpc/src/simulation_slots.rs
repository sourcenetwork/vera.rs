//! Admission for `eth_call`, `eth_estimateGas` and `vera_simulateNativeCall` executions.

use std::{sync::Arc, time::Duration};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::RpcError;

/// Executions that run at a time per node.
pub(crate) const SIMULATION_SLOTS: usize = 4;

/// Callers that may wait for a slot; one more is refused at once.
pub(crate) const SIMULATION_WAITERS: usize = 64;

/// Longest a caller waits for a slot before it is refused.
pub(crate) const SIMULATION_WAIT: Duration = Duration::from_secs(2);

/// Running slots with a bounded queue of callers waiting for one.
#[derive(Clone, Debug)]
pub(crate) struct SimulationSlots {
    running: Arc<Semaphore>,
    admitted: Arc<Semaphore>,
    wait: Duration,
}

/// Held until the execution ends, which keeps its slot and its place taken.
#[derive(Debug)]
pub(crate) struct SimulationPermit {
    _running: OwnedSemaphorePermit,
    _admitted: OwnedSemaphorePermit,
}

impl SimulationSlots {
    pub(crate) fn new(slots: usize, waiters: usize, wait: Duration) -> Self {
        Self {
            running: Arc::new(Semaphore::new(slots)),
            admitted: Arc::new(Semaphore::new(slots + waiters)),
            wait,
        }
    }

    /// Take a slot, waiting for one behind at most the configured waiters.
    pub(crate) async fn acquire(&self) -> Result<SimulationPermit, RpcError> {
        let admitted = self
            .admitted
            .clone()
            .try_acquire_owned()
            .map_err(|_| RpcError::SimulationBusy)?;
        let running = tokio::time::timeout(self.wait, self.running.clone().acquire_owned())
            .await
            .map_err(|_| RpcError::SimulationBusy)?
            .map_err(|_| RpcError::SimulationBusy)?;
        Ok(SimulationPermit {
            _running: running,
            _admitted: admitted,
        })
    }
}

#[cfg(test)]
impl SimulationSlots {
    /// Places left for callers, running or waiting.
    pub(crate) fn free_places(&self) -> usize {
        self.admitted.available_permits()
    }
}

impl Default for SimulationSlots {
    fn default() -> Self {
        Self::new(SIMULATION_SLOTS, SIMULATION_WAITERS, SIMULATION_WAIT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG: Duration = Duration::from_secs(3600);

    async fn queued(slots: &SimulationSlots, waiters: usize) -> Vec<tokio::task::JoinHandle<bool>> {
        let before = slots.admitted.available_permits();
        let tasks = (0..waiters)
            .map(|_| {
                let slots = slots.clone();
                tokio::spawn(async move { slots.acquire().await.is_ok() })
            })
            .collect();
        while slots.admitted.available_permits() != before - waiters {
            tokio::task::yield_now().await;
        }
        tasks
    }

    #[tokio::test]
    async fn a_caller_beyond_the_slots_waits_and_runs_when_one_frees() {
        let slots = SimulationSlots::new(2, 2, LONG);
        let first = slots.acquire().await.unwrap();
        let _second = slots.acquire().await.unwrap();
        let mut waiting = queued(&slots, 1).await;
        assert!(!waiting[0].is_finished());
        drop(first);
        assert!(waiting.pop().unwrap().await.unwrap());
    }

    #[tokio::test]
    async fn a_caller_beyond_the_waiters_is_refused_at_once() {
        let slots = SimulationSlots::new(2, 2, LONG);
        let running = [
            slots.acquire().await.unwrap(),
            slots.acquire().await.unwrap(),
        ];
        let waiting = queued(&slots, 2).await;
        let refused = tokio::time::timeout(Duration::from_secs(5), slots.acquire())
            .await
            .expect("a full queue must not be waited behind");
        assert!(matches!(refused, Err(RpcError::SimulationBusy)));
        drop(running);
        for task in waiting {
            assert!(task.await.unwrap());
        }
        assert_eq!(slots.admitted.available_permits(), 4);
    }

    #[tokio::test]
    async fn a_waiter_is_refused_when_no_slot_frees_before_the_deadline() {
        let slots = SimulationSlots::new(1, 1, Duration::from_millis(20));
        let _running = slots.acquire().await.unwrap();
        assert!(matches!(
            slots.acquire().await,
            Err(RpcError::SimulationBusy)
        ));
        assert_eq!(slots.admitted.available_permits(), 1);
    }

    #[tokio::test]
    async fn a_caller_that_leaves_the_queue_frees_its_place() {
        let slots = SimulationSlots::new(1, 1, LONG);
        let _running = slots.acquire().await.unwrap();
        let waiting = queued(&slots, 1).await;
        waiting[0].abort();
        assert!(waiting.into_iter().next().unwrap().await.is_err());
        assert_eq!(slots.admitted.available_permits(), 1);
    }
}
