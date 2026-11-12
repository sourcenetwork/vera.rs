//! In-process access to the node's JSON-RPC method table.

use jsonrpsee::core::{params::ArrayParams, traits::ToRpcParams};
use serde::de::DeserializeOwned;

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
/// Method-level limits and errors match the network server. Transport limits
/// (request size, batching, per-connection subscriptions) do not apply.
#[derive(Clone, Debug)]
pub struct LocalRpc(jsonrpsee::Methods);

impl LocalRpc {
    pub(crate) fn new(module: jsonrpsee::RpcModule<()>) -> Self {
        Self(module.into())
    }

    /// Names of the registered methods.
    pub fn method_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.method_names()
    }

    /// Call `method` and decode its result.
    pub async fn call<P, R>(&self, method: &str, params: P) -> Result<R, LocalRpcError>
    where
        P: ToRpcParams + Send,
        R: DeserializeOwned + Clone,
    {
        self.0.call(method, params).await.map_err(Into::into)
    }

    /// Call `method` with positional JSON parameters, as a network client would send them.
    pub async fn request<R>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<R, LocalRpcError>
    where
        R: DeserializeOwned + Clone,
    {
        let mut array = ArrayParams::new();
        for value in params {
            array
                .insert(value)
                .map_err(|error| LocalRpcError::Payload(error.to_string()))?;
        }
        self.call(method, array).await
    }

    /// Call a method that takes no parameters.
    pub async fn call_empty<R>(&self, method: &str) -> Result<R, LocalRpcError>
    where
        R: DeserializeOwned + Clone,
    {
        self.call(method, ArrayParams::new()).await
    }

    /// Subscribe to `method`, buffering up to `capacity` notifications.
    pub async fn subscribe<P>(
        &self,
        method: &str,
        params: P,
        capacity: usize,
    ) -> Result<jsonrpsee::core::server::Subscription, LocalRpcError>
    where
        P: ToRpcParams + Send,
    {
        self.0
            .subscribe(method, params, capacity)
            .await
            .map_err(|error| LocalRpcError::Subscription(error.to_string()))
    }
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
