//! In-process access to the node's JSON-RPC method table.

use std::sync::{Arc, PoisonError, RwLock};

use jsonrpsee::core::params::ArrayParams;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;

/// Error returned by an in-process call.
#[derive(Debug, thiserror::Error)]
pub enum LocalRpcError {
    /// The method rejected the call; carries the same JSON-RPC error object a network client receives.
    #[error("JSON-RPC error {code}: {message}")]
    Call {
        /// JSON-RPC error code.
        code: i32,
        /// JSON-RPC error message.
        message: String,
        /// Serialized error data, when the method supplied any.
        data: Option<String>,
    },
    /// Parameters or the result could not be encoded or decoded.
    #[error("invalid JSON-RPC payload: {0}")]
    Payload(String),
    /// A subscription could not be established.
    #[error("subscription failed: {0}")]
    Subscription(String),
    /// The node that served these methods has stopped.
    #[error("node stopped")]
    Stopped,
}

impl LocalRpcError {
    /// Whether the node asked the caller to retry later, as for an occupied proof slot.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Call { code: -32002, data: Some(data), .. } if data.contains("\"retryable\":true"))
    }
}

/// Calls node methods directly, without a socket.
///
/// Method bodies run on the runtime that built this value, which for a hosted
/// node is the node's own runtime. The returned futures can be awaited from any
/// executor, and fail with [`LocalRpcError::Stopped`] once that runtime is gone.
///
/// Method-level limits and errors match the network server. Transport limits
/// (request size, batching, per-connection subscriptions) do not apply.
///
/// Clones share one method table. [`Self::close`] drops it for all of them, so
/// a clone that outlives its node retains none of the node's state.
#[derive(Clone, Debug)]
pub struct LocalRpc {
    methods: Arc<RwLock<Option<jsonrpsee::Methods>>>,
    runtime: Option<tokio::runtime::Handle>,
}

impl LocalRpc {
    pub(crate) fn new(module: jsonrpsee::RpcModule<()>) -> Self {
        Self {
            methods: Arc::new(RwLock::new(Some(module.into()))),
            runtime: tokio::runtime::Handle::try_current().ok(),
        }
    }

    /// Names of the registered methods; none once closed.
    #[must_use]
    pub fn method_names(&self) -> Vec<&'static str> {
        self.methods()
            .map(|methods| methods.method_names().collect())
            .unwrap_or_default()
    }

    /// Release the method table for every clone. Later calls fail with [`LocalRpcError::Stopped`].
    pub fn close(&self) {
        self.methods
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    fn methods(&self) -> Result<jsonrpsee::Methods, LocalRpcError> {
        self.methods
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(LocalRpcError::Stopped)
    }

    /// Call `method` with positional JSON parameters and return its result as JSON text.
    ///
    /// The text is what a network client would receive in `result`, so a caller
    /// can apply the same response byte limits.
    pub async fn request_raw(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<String, LocalRpcError> {
        let params = positional(params)?;
        let (methods, method) = (self.methods()?, method.to_owned());
        let result: Box<RawValue> = self
            .on_runtime(async move { methods.call(&method, params).await })
            .await??;
        Ok(result.get().to_owned())
    }

    /// Call `method` with positional JSON parameters, as a network client would send them.
    pub async fn request<R>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<R, LocalRpcError>
    where
        R: DeserializeOwned,
    {
        let raw = self.request_raw(method, params).await?;
        serde_json::from_str(&raw).map_err(|error| LocalRpcError::Payload(error.to_string()))
    }

    /// Call a method that takes no parameters.
    pub async fn call_empty<R>(&self, method: &str) -> Result<R, LocalRpcError>
    where
        R: DeserializeOwned,
    {
        self.request(method, Vec::new()).await
    }

    /// Subscribe to `method`, buffering up to `capacity` notifications.
    pub async fn subscribe(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
        capacity: usize,
    ) -> Result<LocalSubscription, LocalRpcError> {
        let params = positional(params)?;
        let (methods, method) = (self.methods()?, method.to_owned());
        self.on_runtime(async move { methods.subscribe(&method, params, capacity).await })
            .await?
            .map(LocalSubscription)
            .map_err(|error| LocalRpcError::Subscription(error.to_string()))
    }

    async fn on_runtime<T>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> Result<T, LocalRpcError>
    where
        T: Send + 'static,
    {
        match &self.runtime {
            // A join error means the runtime shut down before or during the call.
            Some(runtime) => runtime
                .spawn(work)
                .await
                .map_err(|_| LocalRpcError::Stopped),
            None => Ok(work.await),
        }
    }
}

/// Notifications from an in-process subscription.
///
/// Dropping it ends the subscription.
#[derive(Debug)]
pub struct LocalSubscription(jsonrpsee::core::server::Subscription);

impl LocalSubscription {
    /// Wait for the next notification. `None` means the subscription ended.
    pub async fn next<T>(&mut self) -> Option<Result<T, LocalRpcError>>
    where
        T: DeserializeOwned,
    {
        let item = self.0.next::<T>().await?;
        Some(item.map(|(value, _)| value).map_err(Into::into))
    }
}

fn positional(params: Vec<serde_json::Value>) -> Result<ArrayParams, LocalRpcError> {
    let mut array = ArrayParams::new();
    for value in params {
        array
            .insert(value)
            .map_err(|error| LocalRpcError::Payload(error.to_string()))?;
    }
    Ok(array)
}

impl From<jsonrpsee::core::server::MethodsError> for LocalRpcError {
    fn from(error: jsonrpsee::core::server::MethodsError) -> Self {
        use jsonrpsee::core::server::MethodsError;
        match error {
            MethodsError::JsonRpc(object) => Self::Call {
                code: object.code(),
                message: object.message().to_owned(),
                data: object.data().map(|data| data.get().to_owned()),
            },
            MethodsError::Parse(error) => Self::Payload(error.to_string()),
            MethodsError::InvalidSubscriptionId(id) => Self::Subscription(id),
        }
    }
}
