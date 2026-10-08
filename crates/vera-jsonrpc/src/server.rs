//! HTTP and JSON-RPC server implementation.

use std::{
    net::{SocketAddr, TcpListener},
    sync::Arc,
};

use jsonrpsee_server::{BatchRequestConfig, PingConfig, Server, ServerConfig, ServerHandle};
use tokio::sync::broadcast;
use tracing::{error, info};

use vera_executor::{ModuleTrees, SharedModuleState};
use vera_indexer::{BlockIndex, LightBlockIndex};

use vera_domain::GossipHeader;

use crate::header_subscribe::{HeaderSubscriptionApiImpl, HeaderSubscriptionApiServer};

use crate::{
    eth::{
        EthApiImpl, EthApiServer, NetApiImpl, NetApiServer, TxSubmitCallback, Web3ApiImpl,
        Web3ApiServer,
    },
    eth_subscribe::{EthSubscriptionApiImpl, EthSubscriptionApiServer},
    state::NodeState,
    state_provider::{NoopStateProvider, StateProvider},
    types::{RpcBlock, RpcLog},
    vera_api::{LightBlockLookup, ReceiptProofLookup, VeraApiImpl, VeraApiServer},
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

/// Build a CORS layer from configuration.
/// RPC server for exposing node status via HTTP and Ethereum JSON-RPC.
pub struct RpcServer<S: StateProvider = NoopStateProvider> {
    state: NodeState,
    addr: SocketAddr,
    chain_id: u64,
    tx_submit: Option<TxSubmitCallback>,
    state_provider: S,
    max_connections: u32,
    subscription_heads: Option<broadcast::Sender<RpcBlock>>,
    subscription_logs: Option<broadcast::Sender<Vec<RpcLog>>>,
    subscription_headers: Option<broadcast::Sender<GossipHeader>>,
    extra_modules: Vec<jsonrpsee::RpcModule<()>>,
    vera_index: Option<Arc<BlockIndex>>,
    vera_modules: Option<SharedModuleState>,
    vera_module_trees: Option<ModuleTrees>,
    vera_native_modules: Option<(vera_backend::native::NativeStateSet, SharedModuleState)>,
    vera_light_block_index: Option<Arc<LightBlockIndex>>,
    vera_light_block_lookup: Option<LightBlockLookup>,
    vera_receipt_proof_lookup: Option<ReceiptProofLookup>,
    vera_archive: Option<crate::ArchiveReader>,
}

impl<S: StateProvider> std::fmt::Debug for RpcServer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcServer")
            .field("state", &self.state)
            .field("addr", &self.addr)
            .field("chain_id", &self.chain_id)
            .field("tx_submit", &self.tx_submit.is_some())
            .field("subscriptions", &self.subscription_heads.is_some())
            .finish()
    }
}

impl RpcServer<NoopStateProvider> {
    /// Create a new RPC server with default (noop) state provider.
    pub fn new(state: NodeState, addr: SocketAddr) -> Self {
        Self {
            state,
            addr,
            chain_id: 1,
            tx_submit: None,
            state_provider: NoopStateProvider,
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            vera_index: None,
            vera_modules: None,
            vera_module_trees: None,
            vera_native_modules: None,
            vera_light_block_index: None,
            vera_light_block_lookup: None,
            vera_receipt_proof_lookup: None,
            vera_archive: None,
        }
    }

    /// Create a new RPC server with chain ID.
    pub fn with_chain_id(state: NodeState, addr: SocketAddr, chain_id: u64) -> Self {
        Self {
            state,
            addr,
            chain_id,
            tx_submit: None,
            state_provider: NoopStateProvider,
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            vera_index: None,
            vera_modules: None,
            vera_module_trees: None,
            vera_native_modules: None,
            vera_light_block_index: None,
            vera_light_block_lookup: None,
            vera_receipt_proof_lookup: None,
            vera_archive: None,
        }
    }
}

impl<S: StateProvider + Clone + 'static> RpcServer<S> {
    /// Create a new RPC server with a custom state provider.
    pub fn with_state_provider(
        state: NodeState,
        addr: SocketAddr,
        chain_id: u64,
        state_provider: S,
    ) -> Self {
        Self {
            state,
            addr,
            chain_id,
            tx_submit: None,
            state_provider,
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            vera_index: None,
            vera_modules: None,
            vera_module_trees: None,
            vera_native_modules: None,
            vera_light_block_index: None,
            vera_light_block_lookup: None,
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

    /// Set subscription broadcast senders for `eth_subscribe` support.
    #[must_use]
    pub fn with_subscriptions(
        mut self,
        heads_tx: broadcast::Sender<RpcBlock>,
        logs_tx: broadcast::Sender<Vec<RpcLog>>,
    ) -> Self {
        self.subscription_heads = Some(heads_tx);
        self.subscription_logs = Some(logs_tx);
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

    /// Set JMT-backed module state trees for proof generation.
    #[must_use]
    pub fn with_vera_module_trees(mut self, trees: ModuleTrees) -> Self {
        self.vera_module_trees = Some(trees);
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

    /// Start the RPC server.
    ///
    /// This spawns background tasks for both HTTP and JSON-RPC servers and returns immediately.
    pub fn start(self) -> RpcServerHandle {
        self.start_inner(None)
    }

    /// Start with an already bound listener, without releasing and rebinding its port.
    pub fn start_with_listener(
        self,
        listener: TcpListener,
    ) -> Result<RpcServerHandle, ServerError> {
        let actual = listener.local_addr().map_err(ServerError::Bind)?;
        if actual != self.addr {
            return Err(ServerError::Build(format!(
                "listener address {actual} does not match configured {}",
                self.addr
            )));
        }
        listener.set_nonblocking(true).map_err(ServerError::Bind)?;
        Ok(self.start_inner(Some(listener)))
    }

    fn start_inner(self, listener: Option<TcpListener>) -> RpcServerHandle {
        let addr = self.addr;
        let node_state = Arc::new(self.state);
        let node_state_for_jsonrpc = Arc::clone(&node_state);
        let chain_id = self.chain_id;
        let tx_submit = self.tx_submit;
        let max_connections = self.max_connections;
        let state_provider = self.state_provider;
        let subscription_heads = self.subscription_heads;
        let subscription_logs = self.subscription_logs;
        let subscription_headers = self.subscription_headers;
        let vera_index = self.vera_index;
        let vera_modules = self.vera_modules;
        let vera_module_trees = self.vera_module_trees;
        let vera_native_modules = self.vera_native_modules;
        let vera_light_block_index = self.vera_light_block_index;
        let vera_light_block_lookup = self.vera_light_block_lookup;
        let vera_receipt_proof_lookup = self.vera_receipt_proof_lookup;
        let vera_archive = self.vera_archive;

        // Signal from the JSON-RPC task to the HTTP task indicating whether it
        // successfully bound the port. The HTTP status server waits for this
        // before attempting to bind, so there is no race condition.

        // JSON-RPC server serves eth_*, vera_*, net_*, web3_* methods over both
        // HTTP and WebSocket. It binds first and signals readiness to the HTTP task.
        let extra_modules = self.extra_modules;

        let jsonrpc_handle = tokio::spawn(async move {
            let config = ServerConfig::builder()
                // Subscription acknowledgements echo the client's request id;
                // keeping the response budget above the request budget keeps
                // that echo from overflowing the response limit.
                .max_request_body_size(vera_domain::SUBMISSION_REQUEST_BYTES)
                .max_response_body_size(
                    vera_permission::PERMISSION_RESPONSE_BYTES
                        .max(vera_domain::RECEIPT_RESPONSE_BYTES) as u32,
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
            let builder = Server::builder().set_config(config);
            let result = match listener {
                Some(listener) => builder.build_from_tcp(listener),
                None => builder.build(addr).await,
            };
            let server = match result {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "Failed to build JSON-RPC server");
                    return None;
                }
            };

            let eth_api = {
                let api = tx_submit.as_ref().map_or_else(
                    || EthApiImpl::new(chain_id, state_provider.clone()),
                    |submit| {
                        EthApiImpl::with_tx_submit(chain_id, state_provider.clone(), submit.clone())
                    },
                );
                api.with_node_state((*node_state_for_jsonrpc).clone())
            };
            let net_api = NetApiImpl::new(chain_id);
            let web3_api = Web3ApiImpl::new();
            let vera_api = {
                let mut api = VeraApiImpl::new(node_state_for_jsonrpc, tx_submit);
                if let (Some(idx), Some(mods)) = (vera_index, vera_modules) {
                    api = api.with_index_and_modules(idx, mods);
                }
                if let Some(trees) = vera_module_trees {
                    api = api.with_module_trees(trees);
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
                if let Some(lbi) = vera_light_block_index {
                    api = api.with_light_block_index(lbi);
                }
                api
            };

            let mut module = jsonrpsee::RpcModule::new(());
            if let Err(e) = module.merge(eth_api.into_rpc()) {
                error!(error = %e, "Failed to merge eth API");
                return None;
            }
            if let Err(e) = module.merge(net_api.into_rpc()) {
                error!(error = %e, "Failed to merge net API");
                return None;
            }
            if let Err(e) = module.merge(web3_api.into_rpc()) {
                error!(error = %e, "Failed to merge web3 API");
                return None;
            }
            if let Err(e) = module.merge(vera_api.into_rpc()) {
                error!(error = %e, "Failed to merge vera API");
                return None;
            }
            if let Some(headers) = subscription_headers.as_ref()
                && let Err(e) = module.merge(HeaderSubscriptionApiImpl(headers.clone()).into_rpc())
            {
                error!(error = %e, "Failed to merge header subscription API");
                return None;
            }
            if let (Some(heads_tx), Some(logs_tx)) = (subscription_heads, subscription_logs) {
                let mut sub_api = EthSubscriptionApiImpl::new(heads_tx, logs_tx);
                if let Some(headers_tx) = subscription_headers {
                    sub_api = sub_api.with_headers(headers_tx);
                }
                if let Err(e) = module.merge(sub_api.into_rpc()) {
                    error!(error = %e, "Failed to merge subscription API");
                    return None;
                }
            }
            for extra in extra_modules {
                if let Err(e) = module.merge(extra) {
                    error!(error = %e, "Failed to merge extra API module");
                    return None;
                }
            }

            info!(addr = %addr, "JSON-RPC server started");

            let handle = server.start(module);
            handle.stopped().await;
            Some(())
        });

        RpcServerHandle { jsonrpc_handle }
    }
}

/// Handle for managing the RPC server lifecycle.
pub struct RpcServerHandle {
    jsonrpc_handle: tokio::task::JoinHandle<Option<()>>,
}

impl std::fmt::Debug for RpcServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcServerHandle").finish_non_exhaustive()
    }
}

impl RpcServerHandle {
    /// Wait for the server to complete.
    pub async fn stopped(self) {
        let _ = self.jsonrpc_handle.await;
    }

    /// Abort the server.
    pub fn abort(self) {
        self.jsonrpc_handle.abort();
    }
}

/// Standalone JSON-RPC server without HTTP status endpoints.
pub struct JsonRpcServer<S: StateProvider = NoopStateProvider> {
    addr: SocketAddr,
    chain_id: u64,
    tx_submit: Option<TxSubmitCallback>,
    state_provider: S,
    node_state: Option<Arc<NodeState>>,
    max_connections: u32,
    subscription_heads: Option<broadcast::Sender<RpcBlock>>,
    subscription_logs: Option<broadcast::Sender<Vec<RpcLog>>>,
    subscription_headers: Option<broadcast::Sender<GossipHeader>>,
    extra_modules: Vec<jsonrpsee::RpcModule<()>>,
    vera_index: Option<Arc<BlockIndex>>,
    vera_modules: Option<SharedModuleState>,
    vera_module_trees: Option<ModuleTrees>,
    vera_native_modules: Option<(vera_backend::native::NativeStateSet, SharedModuleState)>,
    vera_light_block_index: Option<Arc<LightBlockIndex>>,
    vera_light_block_lookup: Option<LightBlockLookup>,
    vera_receipt_proof_lookup: Option<ReceiptProofLookup>,
    vera_archive: Option<crate::ArchiveReader>,
}

impl<S: StateProvider> std::fmt::Debug for JsonRpcServer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonRpcServer")
            .field("addr", &self.addr)
            .field("chain_id", &self.chain_id)
            .field("tx_submit", &self.tx_submit.is_some())
            .finish()
    }
}

impl JsonRpcServer<NoopStateProvider> {
    /// Create a new JSON-RPC server with default (noop) state provider.
    pub fn new(addr: SocketAddr, chain_id: u64) -> Self {
        Self {
            addr,
            chain_id,
            tx_submit: None,
            state_provider: NoopStateProvider,
            node_state: None,
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            vera_index: None,
            vera_modules: None,
            vera_module_trees: None,
            vera_native_modules: None,
            vera_light_block_index: None,
            vera_light_block_lookup: None,
            vera_receipt_proof_lookup: None,
            vera_archive: None,
        }
    }
}

impl<S: StateProvider + Clone + 'static> JsonRpcServer<S> {
    /// Create a new JSON-RPC server with a custom state provider.
    pub fn with_state_provider(addr: SocketAddr, chain_id: u64, state_provider: S) -> Self {
        Self {
            addr,
            chain_id,
            tx_submit: None,
            state_provider,
            node_state: None,
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            vera_index: None,
            vera_modules: None,
            vera_module_trees: None,
            vera_native_modules: None,
            vera_light_block_index: None,
            vera_light_block_lookup: None,
            vera_receipt_proof_lookup: None,
            vera_archive: None,
        }
    }

    /// Set the node state for vera API support.
    #[must_use]
    pub fn with_node_state(mut self, node_state: Arc<NodeState>) -> Self {
        self.node_state = Some(node_state);
        self
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

    /// Set subscription broadcast senders for `eth_subscribe` support.
    #[must_use]
    pub fn with_subscriptions(
        mut self,
        heads_tx: broadcast::Sender<RpcBlock>,
        logs_tx: broadcast::Sender<Vec<RpcLog>>,
    ) -> Self {
        self.subscription_heads = Some(heads_tx);
        self.subscription_logs = Some(logs_tx);
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

    /// Set JMT-backed module state trees for proof generation.
    #[must_use]
    pub fn with_vera_module_trees(mut self, trees: ModuleTrees) -> Self {
        self.vera_module_trees = Some(trees);
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

    /// Start the JSON-RPC server.
    ///
    /// Returns the server handle and the actual bound address (useful when binding to port 0).
    pub async fn start(self) -> Result<(ServerHandle, SocketAddr), ServerError> {
        let server = Server::builder()
            .set_config(
                ServerConfig::builder()
                    .max_request_body_size(vera_domain::SUBMISSION_REQUEST_BYTES)
                    .max_response_body_size(
                        vera_permission::PERMISSION_RESPONSE_BYTES
                            .max(vera_domain::RECEIPT_RESPONSE_BYTES)
                            as u32,
                    )
                    .max_connections(self.max_connections)
                    .set_batch_request_config(BatchRequestConfig::Limit(64))
                    .max_subscriptions_per_connection(8)
                    .set_message_buffer_capacity(8)
                    .build(),
            )
            .build(self.addr)
            .await
            .map_err(|e| ServerError::Build(e.to_string()))?;

        let local_addr = server
            .local_addr()
            .map_err(|e| ServerError::Build(e.to_string()))?;

        let eth_api = {
            let api = self.tx_submit.as_ref().map_or_else(
                || EthApiImpl::new(self.chain_id, self.state_provider.clone()),
                |submit| {
                    EthApiImpl::with_tx_submit(
                        self.chain_id,
                        self.state_provider.clone(),
                        submit.clone(),
                    )
                },
            );
            if let Some(ref ns) = self.node_state {
                api.with_node_state((**ns).clone())
            } else {
                api
            }
        };
        let net_api = NetApiImpl::new(self.chain_id);
        let web3_api = Web3ApiImpl::new();

        let mut module = jsonrpsee::RpcModule::new(());
        module.merge(eth_api.into_rpc())?;
        module.merge(net_api.into_rpc())?;
        module.merge(web3_api.into_rpc())?;
        if let Some(node_state) = self.node_state {
            let vera_api = {
                let mut api = VeraApiImpl::new(node_state, self.tx_submit);
                if let (Some(idx), Some(mods)) = (self.vera_index, self.vera_modules) {
                    api = api.with_index_and_modules(idx, mods);
                }
                if let Some(trees) = self.vera_module_trees {
                    api = api.with_module_trees(trees);
                }
                if let Some((databases, modules)) = self.vera_native_modules {
                    api = api.with_native_modules(databases, modules);
                }
                if let Some(archive) = self.vera_archive {
                    api = api.with_archive(archive);
                }
                if let Some(lookup) = self.vera_receipt_proof_lookup {
                    api = api.with_receipt_proof_lookup(lookup);
                }
                if let Some(lookup) = self.vera_light_block_lookup {
                    api = api.with_light_block_lookup(lookup);
                }
                if let Some(lbi) = self.vera_light_block_index {
                    api = api.with_light_block_index(lbi);
                }
                api
            };
            module.merge(vera_api.into_rpc())?;
        }
        if let Some(headers) = self.subscription_headers.as_ref() {
            module.merge(HeaderSubscriptionApiImpl(headers.clone()).into_rpc())?;
        }
        if let (Some(heads_tx), Some(logs_tx)) = (self.subscription_heads, self.subscription_logs) {
            let mut sub_api = EthSubscriptionApiImpl::new(heads_tx, logs_tx);
            if let Some(headers_tx) = self.subscription_headers {
                sub_api = sub_api.with_headers(headers_tx);
            }
            module.merge(sub_api.into_rpc())?;
        }
        for extra in self.extra_modules {
            module.merge(extra)?;
        }

        info!(addr = %local_addr, "Starting JSON-RPC server");

        Ok((server.start(module), local_addr))
    }
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod listener_tests;
