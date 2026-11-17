//! Keeping consensus messages of an epoch a backup has not entered yet.
//!
//! Commonware's orchestrator routes a message for an epoch it has not entered
//! to its backup queue, asks marshal for the final block of its own epoch, and
//! drops the message. A backup that is behind when the active device crosses
//! an epoch boundary therefore discards the certificates of the blocks above
//! it, and enters the epoch with nothing to finalize until the active device
//! sends another certificate. While that device is away, the backup stays at
//! the last block of the epoch before.
//!
//! On a backup, the certificate channel keeps the newest messages of later
//! epochs and delivers them again once marshal has processed the final block
//! of the epoch before, which the orchestrator acknowledges only after it
//! entered the next epoch. Simplex verifies them as it does any message.

use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc, time::Duration};

use commonware_consensus::types::{Epocher, FixedEpocher, Height};
use commonware_p2p::{Message, Receiver};
use futures::future::BoxFuture;

/// Messages kept for later epochs, oldest dropped first.
const KEPT: usize = 256;
/// Bytes kept for later epochs. The messages are unverified until their epoch
/// is entered, and the channel admits far larger ones than a certificate.
const KEPT_BYTES: usize = 1024 * 1024;
const RECHECK: Duration = Duration::from_millis(200);

/// Reads the newest height marshal has processed.
pub(crate) type ProcessedHeight = Arc<dyn Fn() -> BoxFuture<'static, Option<u64>> + Send + Sync>;

struct Kept<P> {
    epocher: FixedEpocher,
    processed: ProcessedHeight,
    entered: u64,
    messages: VecDeque<(u64, Message<P>)>,
    bytes: usize,
}

/// A consensus channel receiver, keeping later epochs' messages when it is
/// a backup's certificate channel.
pub(crate) struct EpochReplay<R: Receiver> {
    inner: R,
    kept: Option<Kept<R::PublicKey>>,
}

impl<R: Receiver> std::fmt::Debug for EpochReplay<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EpochReplay")
            .field("inner", &self.inner)
            .field("kept", &self.kept.as_ref().map(|kept| kept.messages.len()))
            .finish()
    }
}

impl<R: Receiver> EpochReplay<R> {
    pub(crate) const fn passing(inner: R) -> Self {
        Self { inner, kept: None }
    }

    pub(crate) const fn keeping(
        inner: R,
        epocher: FixedEpocher,
        processed: ProcessedHeight,
    ) -> Self {
        Self {
            inner,
            kept: Some(Kept {
                epocher,
                processed,
                entered: 0,
                messages: VecDeque::new(),
                bytes: 0,
            }),
        }
    }
}

impl<P> Kept<P> {
    /// The epoch the orchestrator has entered, at least: the one holding the
    /// block after the newest processed one.
    async fn refresh(&mut self) {
        let next = (self.processed)()
            .await
            .map_or(Height::zero(), |height| Height::new(height).next());
        if let Some(epoch) = self.epocher.containing(next) {
            self.entered = self.entered.max(epoch.epoch().get());
        }
    }

    fn due(&mut self) -> Option<Message<P>> {
        let entered = self.entered;
        while let Some(position) = self
            .messages
            .iter()
            .position(|(epoch, _)| *epoch <= entered)
        {
            let (epoch, message) = self.take(position)?;
            if epoch == entered {
                return Some(message);
            }
        }
        None
    }

    fn take(&mut self, position: usize) -> Option<(u64, Message<P>)> {
        let kept = self.messages.remove(position)?;
        self.bytes -= kept.1.1.len();
        Some(kept)
    }

    /// Keep `message` if it belongs to an epoch the orchestrator has not entered.
    async fn keep(&mut self, message: &Message<P>)
    where
        P: Clone,
    {
        let Ok((epoch, _)) = commonware_p2p::utils::mux::parse(message.1.clone()) else {
            return;
        };
        if epoch <= self.entered {
            return;
        }
        self.refresh().await;
        if epoch <= self.entered {
            return;
        }
        let size = message.1.len();
        if size > KEPT_BYTES {
            return;
        }
        while self.messages.len() == KEPT || self.bytes + size > KEPT_BYTES {
            if self.take(0).is_none() {
                break;
            }
        }
        self.bytes += size;
        self.messages.push_back((epoch, message.clone()));
    }
}

impl<R: Receiver> Receiver for EpochReplay<R> {
    type Error = R::Error;
    type PublicKey = R::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        let Some(kept) = self.kept.as_mut() else {
            return self.inner.recv().await;
        };
        loop {
            if let Some(message) = kept.due() {
                return Ok(message);
            }
            let waiting = !kept.messages.is_empty();
            tokio::select! {
                message = self.inner.recv() => {
                    let message = message?;
                    kept.keep(&message).await;
                    return Ok(message);
                }
                () = tokio::time::sleep(RECHECK), if waiting => kept.refresh().await,
            }
        }
    }

    fn capacity(&self) -> NonZeroUsize {
        self.inner.capacity()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use commonware_codec::{Encode as _, varint::UInt};
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_runtime::IoBuf;
    use vera_domain::PublicKey;

    use super::*;

    #[derive(Debug)]
    struct Queue(tokio::sync::mpsc::UnboundedReceiver<Message<PublicKey>>);

    impl Receiver for Queue {
        type Error = std::io::Error;
        type PublicKey = PublicKey;

        async fn recv(&mut self) -> Result<Message<PublicKey>, Self::Error> {
            self.0
                .recv()
                .await
                .ok_or_else(|| std::io::Error::other("closed"))
        }

        fn capacity(&self) -> NonZeroUsize {
            NonZeroUsize::MIN
        }
    }

    fn muxed(epoch: u64, payload: u8) -> IoBuf {
        let mut bytes = UInt(epoch).encode().to_vec();
        bytes.push(payload);
        IoBuf::from(bytes)
    }

    #[tokio::test]
    async fn a_later_epochs_message_is_delivered_again_once_the_epoch_is_entered() {
        let (sender, queue) = tokio::sync::mpsc::unbounded_channel();
        let processed = Arc::new(AtomicU64::new(30));
        let reader = processed.clone();
        let mut replay = EpochReplay::keeping(
            Queue(queue),
            FixedEpocher::new(32.try_into().unwrap()),
            Arc::new(move || {
                let height = reader.load(Ordering::Acquire);
                Box::pin(async move { Some(height) })
            }),
        );
        let peer = PrivateKey::from_seed(1).public_key();
        // The block after 30 is in epoch 0: a message of epoch 1 is early.
        for message in [muxed(0, 1), muxed(1, 2)] {
            sender.send((peer.clone(), message)).unwrap();
            replay.recv().await.unwrap();
        }
        let early = tokio::time::timeout(Duration::from_millis(500), replay.recv()).await;
        assert!(
            early.is_err(),
            "a message was delivered again before its epoch"
        );

        // Marshal processed the epoch's last block, which the orchestrator
        // acknowledges after it entered the next epoch.
        processed.store(31, Ordering::Release);
        let (from, again) = replay.recv().await.unwrap();
        assert_eq!(
            (from, again.as_ref().to_vec()),
            (peer, muxed(1, 2).as_ref().to_vec())
        );
        let more = tokio::time::timeout(Duration::from_millis(500), replay.recv()).await;
        assert!(more.is_err(), "a message was delivered again twice");
    }

    fn sized(epoch: u64, size: usize) -> Message<PublicKey> {
        let mut bytes = UInt(epoch).encode().to_vec();
        bytes.resize(size, 0);
        (PrivateKey::from_seed(1).public_key(), IoBuf::from(bytes))
    }

    #[tokio::test]
    async fn kept_messages_stay_within_the_byte_budget() {
        let mut kept = Kept {
            epocher: FixedEpocher::new(32.try_into().unwrap()),
            processed: Arc::new(|| Box::pin(async { Some(0) })),
            entered: 0,
            messages: VecDeque::new(),
            bytes: 0,
        };
        kept.keep(&sized(1, KEPT_BYTES + 1)).await;
        assert!(kept.messages.is_empty(), "an oversized message was kept");

        let third = KEPT_BYTES / 3;
        for epoch in 1..=5 {
            kept.keep(&sized(epoch, third)).await;
            assert!(kept.bytes <= KEPT_BYTES);
        }
        let epochs: Vec<u64> = kept.messages.iter().map(|(epoch, _)| *epoch).collect();
        assert_eq!(
            epochs,
            [3, 4, 5],
            "the oldest messages were not dropped first"
        );
        assert_eq!(kept.bytes, 3 * third);

        kept.entered = 4;
        assert!(kept.due().is_some());
        assert_eq!(
            kept.bytes, third,
            "delivered and passed messages still count"
        );
    }
}
