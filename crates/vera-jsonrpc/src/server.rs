//! JSON-RPC server assembly: the node's method table and its network listener.

use std::{
    net::{SocketAddr, TcpListener},
    sync::Arc,
};

#[cfg(not(feature = "nuclei-rpc"))]
use jsonrpsee_server::Server;
use jsonrpsee_server::{BatchRequestConfig, PingConfig, ServerConfig, ServerHandle};
use tokio::sync::broadcast;
use tracing::info;

use vera_executor::SharedModuleState;
use vera_indexer::{BlockIndex, LightBlockIndex};

use vera_domain::GossipHeader;

use crate::header_subscribe::{HeaderSubscriptionApiImpl, HeaderSubscriptionApiServer};

use crate::{
    state::NodeState,
    state_provider::{NoopStateProvider, StateProvider},
    tx_submit::TxSubmitCallback,
    vera_api::{
        AncestryProofLookup, LightBlockLookup, ReceiptProofLookup, VeraApiImpl, VeraApiServer,
    },
};

/// Error type for RPC server operations.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Failed to bind server.
    #[error("failed to bind server: {0}")]
    Bind(std::io::Error),
    /// Failed to build server.
    #[error("failed to build server: {0}")]
    Build(String),
    /// Failed to register RPC methods.
    #[error("failed to register RPC methods: {0}")]
    RegisterMethod(#[from] jsonrpsee::core::RegisterMethodError),
}

/// The node's JSON-RPC method table, served over HTTP and WebSocket or in-process.
pub struct RpcServer<S: StateProvider = NoopStateProvider> {
    state: NodeState,
    addr: SocketAddr,
    tx_submit: Option<TxSubmitCallback>,
    state_provider: S,
    max_connections: u32,
    subscription_headers: Option<broadcast::Sender<GossipHeader>>,
    extra_modules: Vec<jsonrpsee::RpcModule<()>>,
    vera_index: Option<Arc<BlockIndex>>,
    vera_modules: Option<SharedModuleState>,
    vera_native_modules: Option<(vera_backend::native::NativeStateSet, SharedModuleState)>,
    vera_light_block_index: Option<Arc<LightBlockIndex>>,
    vera_light_block_lookup: Option<LightBlockLookup>,
    vera_ancestry_proof_lookup: Option<AncestryProofLookup>,
    vera_receipt_proof_lookup: Option<ReceiptProofLookup>,
    vera_archive: Option<crate::ArchiveReader>,
}

impl<S: StateProvider> std::fmt::Debug for RpcServer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcServer")
            .field("state", &self.state)
            .field("addr", &self.addr)
            .field("tx_submit", &self.tx_submit.is_some())
            .field("headers", &self.subscription_headers.is_some())
            .finish()
    }
}

impl RpcServer<NoopStateProvider> {
    /// Create a new RPC server with default (noop) state provider.
    pub fn new(state: NodeState, addr: SocketAddr) -> Self {
        Self {
            state,
            addr,
            tx_submit: None,
            state_provider: NoopStateProvider,
            max_connections: 100,
            subscription_headers: None,
            extra_modules: Vec::new(),
            vera_index: None,
            vera_modules: None,
            vera_native_modules: None,
            vera_light_block_index: None,
            vera_light_block_lookup: None,
            vera_ancestry_proof_lookup: None,
            vera_receipt_proof_lookup: None,
            vera_archive: None,
        }
    }
}

impl<S: StateProvider + Clone + 'static> RpcServer<S> {
    /// Create a new RPC server with a custom state provider.
    pub fn with_state_provider(state: NodeState, addr: SocketAddr, state_provider: S) -> Self {
        Self {
            state,
            addr,
            tx_submit: None,
            state_provider,
            max_connections: 100,
            subscription_headers: None,
            extra_modules: Vec::new(),
            vera_index: None,
            vera_modules: None,
            vera_native_modules: None,
            vera_light_block_index: None,
            vera_light_block_lookup: None,
            vera_ancestry_proof_lookup: None,
            vera_receipt_proof_lookup: None,
            vera_archive: None,
        }
    }

    /// Set the transaction submission callback.
    #[must_use]
    pub fn with_tx_submit(mut self, tx_submit: TxSubmitCallback) -> Self {
        self.tx_submit = Some(tx_submit);
        self
    }

    /// Set maximum concurrent connections.
    #[must_use]
    pub const fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Enable native finalized-header subscriptions via `vera_subscribeHeaders`.
    #[must_use]
    pub fn with_headers_subscription(
        mut self,
        headers_tx: broadcast::Sender<GossipHeader>,
    ) -> Self {
        self.subscription_headers = Some(headers_tx);
        self
    }

    /// Merge an additional JSON-RPC module into the server.
    #[must_use]
    pub fn with_extra_module(mut self, module: jsonrpsee::RpcModule<()>) -> Self {
        self.extra_modules.push(module);
        self
    }

    /// Set the block index and shared module state for vera API receipt/nonce queries.
    #[must_use]
    pub fn with_vera_index_and_modules(
        mut self,
        index: Arc<BlockIndex>,
        modules: SharedModuleState,
    ) -> Self {
        self.vera_index = Some(index);
        self.vera_modules = Some(modules);
        self
    }

    /// Serve native permission proofs from the ordered module databases and query snapshot.
    #[must_use]
    pub fn with_vera_native_modules(
        mut self,
        databases: vera_backend::native::NativeStateSet,
        modules: SharedModuleState,
    ) -> Self {
        self.vera_native_modules = Some((databases, modules));
        self
    }

    /// Serve light blocks from durable history, including descendant certificates.
    #[must_use]
    pub fn with_vera_light_block_lookup(mut self, lookup: LightBlockLookup) -> Self {
        self.vera_light_block_lookup = Some(lookup);
        self
    }

    /// Serve ancestry proofs from durable history.
    #[must_use]
    pub fn with_vera_ancestry_proof_lookup(mut self, lookup: AncestryProofLookup) -> Self {
        self.vera_ancestry_proof_lookup = Some(lookup);
        self
    }

    /// Configure durable receipt evidence for cache misses.
    pub fn with_vera_receipt_proof_lookup(mut self, lookup: ReceiptProofLookup) -> Self {
        self.vera_receipt_proof_lookup = Some(lookup);
        self
    }

    /// Enable durable point reads for native receipts.
    pub fn with_vera_archive(mut self, archive: crate::ArchiveReader) -> Self {
        self.vera_archive = Some(archive);
        self
    }

    /// Set the light block index for `vera_getLightBlock` queries.
    #[must_use]
    pub fn with_vera_light_block_index(mut self, index: Arc<LightBlockIndex>) -> Self {
        self.vera_light_block_index = Some(index);
        self
    }

    /// Build the method table served by this node, without binding a listener.
    pub fn into_module(self) -> Result<jsonrpsee::RpcModule<()>, ServerError> {
        let node_state = Arc::new(self.state);
        let tx_submit = self.tx_submit;
        let state_provider = self.state_provider;
        let subscription_headers = self.subscription_headers;
        let vera_index = self.vera_index;
        let vera_modules = self.vera_modules;
        let vera_native_modules = self.vera_native_modules;
        let vera_light_block_index = self.vera_light_block_index;
        let vera_light_block_lookup = self.vera_light_block_lookup;
        let vera_ancestry_proof_lookup = self.vera_ancestry_proof_lookup;
        let vera_receipt_proof_lookup = self.vera_receipt_proof_lookup;
        let vera_archive = self.vera_archive;
        let extra_modules = self.extra_modules;

        let vera_api = {
            let mut api =
                VeraApiImpl::new(node_state, tx_submit).with_simulator(Arc::new(state_provider));
            if let (Some(idx), Some(mods)) = (vera_index, vera_modules) {
                api = api.with_index_and_modules(idx, mods);
            }
            if let Some((databases, modules)) = vera_native_modules {
                api = api.with_native_modules(databases, modules);
            }
            if let Some(archive) = vera_archive {
                api = api.with_archive(archive);
            }
            if let Some(lookup) = vera_receipt_proof_lookup {
                api = api.with_receipt_proof_lookup(lookup);
            }
            if let Some(lookup) = vera_light_block_lookup {
                api = api.with_light_block_lookup(lookup);
            }
            if let Some(lookup) = vera_ancestry_proof_lookup {
                api = api.with_ancestry_proof_lookup(lookup);
            }
            if let Some(lbi) = vera_light_block_index {
                api = api.with_light_block_index(lbi);
            }
            api
        };

        let mut module = jsonrpsee::RpcModule::new(());
        module.merge(vera_api.into_rpc())?;
        if let Some(headers) = subscription_headers {
            module.merge(HeaderSubscriptionApiImpl(headers).into_rpc())?;
        }
        for extra in extra_modules {
            module.merge(extra)?;
        }
        Ok(module)
    }

    /// Expose the method table to in-process callers only.
    pub fn into_local(self) -> Result<crate::LocalRpc, ServerError> {
        Ok(crate::LocalRpc::new(self.into_module()?))
    }

    /// Serve over the network and expose the same method table in-process.
    ///
    /// Without an inherited listener the configured address is bound before
    /// returning, so an address in use fails the start. Call from within the
    /// runtime that will serve the connections.
    pub fn start_with_local(
        self,
        listener: Option<TcpListener>,
    ) -> Result<(RpcServerHandle, crate::LocalRpc), ServerError> {
        let listener = match listener {
            Some(listener) => {
                let actual = listener.local_addr().map_err(ServerError::Bind)?;
                if actual != self.addr {
                    return Err(ServerError::Build(format!(
                        "listener address {actual} does not match configured {}",
                        self.addr
                    )));
                }
                listener
            }
            None => TcpListener::bind(self.addr).map_err(ServerError::Bind)?,
        };
        listener.set_nonblocking(true).map_err(ServerError::Bind)?;
        let max_connections = self.max_connections;
        let module = self.into_module()?;
        let local = crate::LocalRpc::new(module.clone());
        Ok((serve(max_connections, module, listener)?, local))
    }
}

fn serve(
    max_connections: u32,
    module: jsonrpsee::RpcModule<()>,
    listener: TcpListener,
) -> Result<RpcServerHandle, ServerError> {
    let addr = listener.local_addr().map_err(ServerError::Bind)?;
    let config = ServerConfig::builder()
        // Subscription acknowledgements echo the client's request id;
        // keeping the response budget above the request budget keeps
        // that echo from overflowing the response limit.
        .max_request_body_size(vera_domain::SUBMISSION_REQUEST_BYTES)
        .max_response_body_size(
            vera_permission::PERMISSION_RESPONSE_BYTES.max(vera_domain::RECEIPT_RESPONSE_BYTES)
                as u32,
        )
        .max_connections(max_connections)
        .set_batch_request_config(BatchRequestConfig::Limit(64))
        .max_subscriptions_per_connection(8)
        .set_message_buffer_capacity(8)
        .enable_ws_ping(
            PingConfig::default()
                .ping_interval(std::time::Duration::from_secs(30))
                .max_failures(2),
        )
        .build();
    #[cfg(not(feature = "nuclei-rpc"))]
    let server = Server::builder()
        .set_config(config)
        .build_from_tcp(listener)
        .map_err(|error| ServerError::Build(error.to_string()))?;
    #[cfg(feature = "nuclei-rpc")]
    let server = crate::nuclei_transport::Server::bind(addr, Some(listener), config)
        .map_err(|error| ServerError::Build(error.to_string()))?;

    info!(%addr, "JSON-RPC server started");
    Ok(RpcServerHandle {
        addr,
        server: server.start(module),
    })
}

/// A running RPC listener. Dropping the handle stops the server.
pub struct RpcServerHandle {
    addr: SocketAddr,
    server: ServerHandle,
}

impl std::fmt::Debug for RpcServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcServerHandle")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl RpcServerHandle {
    /// The bound address, which names the chosen port when port 0 was configured.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Wait until the server has stopped and its connections have drained.
    pub async fn stopped(self) {
        self.server.stopped().await;
    }

    /// Ask the server to stop accepting connections and drain.
    pub fn stop(&self) {
        // A server that already stopped needs no second signal.
        let _ = self.server.stop();
    }
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod listener_tests;
