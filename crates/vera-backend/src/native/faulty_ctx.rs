//! Test-only storage failure injection: a `Storage` wrapper that fails the
//! next write, sync, or truncates the next write, plus a context delegating
//! every other runtime trait to tokio.

use commonware_runtime::{
    Blob, BlobVersion, BufferPool, BufferPooler, Clock, Error, Handle, IoBufs, IoBufsMut, Spawner,
    Storage, Supervisor, tokio,
};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const FAIL_NEXT_WRITE: u64 = 1;
const FAIL_NEXT_SYNC: u64 = 2;
const TRUNCATE_NEXT_WRITE: u64 = 3;

#[derive(Default)]
struct Faults {
    armed: Option<u64>,
}

/// The injected failure to trigger on the next matching operation.
pub(super) enum Failure {
    Write,
    Sync,
    TruncatedWrite,
}

pub(super) struct FaultyCtx {
    inner: Arc<tokio::Context>,
    faults: Arc<Mutex<Faults>>,
}

impl Clone for FaultyCtx {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            faults: self.faults.clone(),
        }
    }
}

impl FaultyCtx {
    pub(super) fn new(inner: tokio::Context) -> Self {
        Self {
            inner: Arc::new(inner),
            faults: Arc::default(),
        }
    }

    /// Arm `failure` for the next matching storage operation.
    pub(super) fn arm(&self, failure: Failure) {
        let code = match failure {
            Failure::Write => FAIL_NEXT_WRITE,
            Failure::Sync => FAIL_NEXT_SYNC,
            Failure::TruncatedWrite => TRUNCATE_NEXT_WRITE,
        };
        self.faults.lock().unwrap().armed = Some(code);
    }

    fn take(&self, code: u64) -> bool {
        let mut faults = self.faults.lock().unwrap();
        if faults.armed == Some(code) {
            faults.armed = None;
            true
        } else {
            false
        }
    }
}

impl commonware_runtime::Supervisor for FaultyCtx {
    fn name(&self) -> commonware_runtime::Name {
        (*self.inner).name()
    }

    fn child(&self, label: &'static str) -> Self {
        Self {
            inner: Arc::new(self.inner.child(label)),
            faults: self.faults.clone(),
        }
    }

    fn with_attribute(self, key: &'static str, value: impl std::fmt::Display) -> Self {
        Self {
            inner: Arc::new(self.inner.child("attr").with_attribute(key, value)),
            faults: self.faults,
        }
    }
}

impl Spawner for FaultyCtx {
    fn shared(self, blocking: bool) -> Self {
        Self {
            inner: Arc::new(self.inner.child("shared").shared(blocking)),
            faults: self.faults,
        }
    }

    fn dedicated(self) -> Self {
        Self {
            inner: Arc::new(self.inner.child("dedicated").dedicated()),
            faults: self.faults,
        }
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        self.inner.child("stop").stop(value, timeout).await
    }

    fn stopped(&self) -> commonware_runtime::signal::Signal {
        (*self.inner).stopped()
    }

    fn spawn<F, Fut, T>(self, future: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let faults = self.faults.clone();
        let inner = (*self.inner).child("task");
        inner.spawn(move |inner| {
            let ctx = Self {
                inner: Arc::new(inner),
                faults,
            };
            future(ctx)
        })
    }
}

impl Storage for FaultyCtx {
    type Blob = FaultyBlob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Self::Blob, u64), Error> {
        let (blob, size) = (*self.inner).open(partition, name).await?;
        Ok((FaultyBlob::new(blob, self), size))
    }

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        let (blob, size, version) = (*self.inner)
            .open_versioned(partition, name, versions)
            .await?;
        Ok((FaultyBlob::new(blob, self), size, version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        (*self.inner).remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        (*self.inner).scan(partition).await
    }
}

impl governor::clock::Clock for FaultyCtx {
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        (*self.inner).now()
    }
}

impl governor::clock::ReasonablyRealtime for FaultyCtx {}

impl Clock for FaultyCtx {
    fn current(&self) -> SystemTime {
        (*self.inner).current()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static + use<> {
        let inner = Arc::clone(&self.inner);
        async move {
            (*inner).sleep(duration).await;
        }
    }

    fn sleep_until(
        &self,
        deadline: SystemTime,
    ) -> impl Future<Output = ()> + Send + 'static + use<> {
        let inner = Arc::clone(&self.inner);
        async move {
            (*inner).sleep_until(deadline).await;
        }
    }
}

impl BufferPooler for FaultyCtx {
    fn network_buffer_pool(&self) -> &BufferPool {
        (*self.inner).network_buffer_pool()
    }

    fn storage_buffer_pool(&self) -> &BufferPool {
        (*self.inner).storage_buffer_pool()
    }
}

impl commonware_runtime::Metrics for FaultyCtx {
    fn register<
        N: Into<String>,
        H: Into<String>,
        M: commonware_runtime::telemetry::metrics::Metric,
    >(
        &self,
        name: N,
        help: H,
        metric: M,
    ) -> commonware_runtime::telemetry::metrics::Registered<M> {
        (*self.inner).register(name, help, metric)
    }

    fn encode(&self) -> String {
        (*self.inner).encode()
    }
}

pub(super) struct FaultyBlob {
    inner: <tokio::Context as Storage>::Blob,
    ctx: FaultyCtx,
}

impl FaultyBlob {
    fn new(inner: <tokio::Context as Storage>::Blob, ctx: &FaultyCtx) -> Self {
        Self {
            inner,
            ctx: ctx.clone(),
        }
    }
}

impl Blob for FaultyBlob {
    fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: commonware_runtime::ReadOptions,
    ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send {
        self.inner.read_at_buf(offset, len, bufs, options)
    }

    fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: commonware_runtime::ReadOptions,
    ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send {
        self.inner.read_at(offset, len, options)
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: commonware_runtime::WriteOptions,
    ) -> Result<(), Error> {
        use bytes::Buf as _;
        if self.ctx.take(FAIL_NEXT_WRITE) {
            return Err(Error::WriteFailed);
        }
        if self.ctx.take(TRUNCATE_NEXT_WRITE) {
            let mut bufs: IoBufs = bufs.into();
            let keep = bufs.copy_to_bytes(bufs.remaining() / 2);
            self.inner.write_at(offset, keep, options).await?;
            return Err(Error::WriteFailed);
        }
        self.inner.write_at(offset, bufs, options).await
    }

    fn resize(&self, len: u64) -> impl Future<Output = Result<(), Error>> + Send {
        self.inner.resize(len)
    }

    #[allow(clippy::async_yields_async)]
    async fn start_sync(&self) -> Handle<()> {
        if self.ctx.take(FAIL_NEXT_SYNC) {
            return Handle::ready(Err(Error::WriteFailed));
        }
        self.inner.start_sync().await
    }

    async fn sync(&self) -> Result<(), Error> {
        if self.ctx.take(FAIL_NEXT_SYNC) {
            return Err(Error::WriteFailed);
        }
        self.inner.sync().await
    }
}
