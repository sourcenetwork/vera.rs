use std::convert::Infallible;

use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{
    AttachableResolver, BatchContext, InitError, ManagedDb, Merkleized, Shared, StateSyncDb,
    SyncEngineConfig, Unmerkleized,
};
use commonware_runtime::Handle;
use commonware_utils::channel::{mpsc, ring};
use futures::future::{Either, pending, select};
use vera_backend::Ctx;

/// The module root selected by the same coordinator generation as the seven logs.
/// This is not a database: OrderedState checks the rebuilt records against this root
/// before publishing them. Startup reconstructs the selection from its durable anchor.
#[derive(Clone, Debug)]
pub struct Commitment(pub(super) Option<Digest>);

impl Unmerkleized for Commitment {
    type Merkleized = Self;
    type Error = Infallible;
    async fn merkleize(self) -> Result<Self, Infallible> {
        Ok(self)
    }
}

impl Merkleized for Commitment {
    type Digest = Digest;
    type Unmerkleized = Self;
    fn root(&self) -> Digest {
        self.0.unwrap_or(Digest::from([0; 32]))
    }
    fn new_batch(&self) -> Self {
        self.clone()
    }
}

impl ManagedDb<Ctx> for Commitment {
    type Unmerkleized = Self;
    type Merkleized = Self;
    type Config = ();
    type SyncTarget = Option<Digest>;
    type Error = Infallible;

    async fn init(
        _: Ctx,
        _: (),
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Infallible, Self::SyncTarget>> {
        Ok(Self(expected.flatten()))
    }
    fn initial_sync_target() -> Self::SyncTarget {
        None
    }
    fn new_batch(context: BatchContext<'_, Self>) -> Self {
        context.into_parts().0.clone()
    }
    fn matches_sync_target(batch: &Self, target: &Self::SyncTarget) -> bool {
        batch.0 == *target
    }
    async fn apply(self, batch: Self) -> Result<Self, Infallible> {
        Ok(batch)
    }
    async fn finalize(self) -> Result<(Self, Handle<()>), Infallible> {
        Ok((self, Handle::ready(Ok(()))))
    }
    fn sync_target(&self) -> Self::SyncTarget {
        self.0
    }
}

impl AttachableResolver<Commitment> for () {
    async fn attach_database(&self, _: Shared<Commitment>) {}
}

impl StateSyncDb<Ctx, ()> for Commitment {
    type SyncError = Infallible;
    async fn sync_db(
        _: Ctx,
        _: (),
        _: (),
        mut target: Self::SyncTarget,
        mut updates: ring::Receiver<Self::SyncTarget>,
        mut finish: Option<mpsc::Receiver<()>>,
        reached: Option<ring::Sender<Self::SyncTarget>>,
        _: SyncEngineConfig,
    ) -> Result<Self, Infallible> {
        let mut reported = None;
        loop {
            if reported != Some(target) {
                if let Some(sender) = &reached {
                    sender.send_lossy(target);
                }
                reported = Some(target);
            }
            if finish.is_none() {
                return Ok(Self(target));
            }
            let completed = async {
                match &mut finish {
                    Some(receiver) => {
                        receiver.recv().await;
                    }
                    None => pending().await,
                }
            };
            match select(Box::pin(updates.recv()), Box::pin(completed)).await {
                Either::Left((Some(next), _)) => target = next,
                Either::Left((None, completed)) => {
                    completed.await;
                    return Ok(Self(target));
                }
                Either::Right(_) => return Ok(Self(target)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, tokio};
    use commonware_utils::{NZU64, NZUsize, channel::fallible::AsyncFallibleExt as _};
    use futures::FutureExt as _;
    use std::time::Duration;

    fn config() -> SyncEngineConfig {
        SyncEngineConfig {
            fetch_batch_size: NZU64!(8),
            apply_batch_size: NZU64!(8),
            max_outstanding_requests: NZUsize!(1),
        }
    }

    #[test]
    fn a_reached_commitment_does_not_wait_for_report_capacity_or_absent_finish() {
        tokio::Runner::default().start(|context| async move {
            let (_updates, incoming) = ring::channel(NZUsize!(1));
            let (reports, mut reported) = ring::channel(NZUsize!(1));
            assert!(reports.send_lossy(None));
            let target = Some(Digest::from([7; 32]));
            let result = ::tokio::time::timeout(
                Duration::from_secs(1),
                Commitment::sync_db(
                    context,
                    (),
                    (),
                    target,
                    incoming,
                    None,
                    Some(reports),
                    config(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(result.0, target);
            assert_eq!(reported.recv().await, Some(target));
        });
    }

    #[test]
    fn closing_updates_still_waits_for_finish_without_repeating_reports() {
        tokio::Runner::default().start(|context| async move {
            let (updates, incoming) = ring::channel(NZUsize!(1));
            let (finish, finished) = mpsc::channel(1);
            let (reports, mut reported) = ring::channel(NZUsize!(1));
            let target = Some(Digest::from([7; 32]));
            let mut result = Box::pin(Commitment::sync_db(
                context,
                (),
                (),
                target,
                incoming,
                Some(finished),
                Some(reports),
                config(),
            ));
            assert!((&mut result).now_or_never().is_none());
            assert_eq!(reported.try_recv().unwrap(), target);
            assert!(updates.send_lossy(target));
            assert!((&mut result).now_or_never().is_none());
            assert!(matches!(
                reported.try_recv(),
                Err(ring::TryRecvError::Empty)
            ));
            drop(updates);
            assert!((&mut result).now_or_never().is_none());
            finish.send_lossy(()).await;
            assert_eq!(
                ::tokio::time::timeout(Duration::from_secs(1), result)
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
                target
            );
        });
    }
}
