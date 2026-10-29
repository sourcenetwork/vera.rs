use std::{io, net::SocketAddr, time::Duration};

use jsonrpsee_server::{
    Methods, ServerConfig, ServerHandle, serve_with_graceful_shutdown, stop_channel,
};
use tokio::task::JoinSet;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, warn};

pub(crate) struct Server {
    listener: nuclei::net::TcpListener,
    config: ServerConfig,
}

impl Server {
    pub(crate) fn bind(
        addr: SocketAddr,
        listener: Option<std::net::TcpListener>,
        config: ServerConfig,
    ) -> io::Result<Self> {
        let listener = match listener {
            Some(listener) => listener,
            None => std::net::TcpListener::bind(addr)?,
        };
        Ok(Self {
            listener: nuclei::Handle::new(listener)?,
            config,
        })
    }

    pub(crate) fn start(self, methods: impl Into<Methods>) -> ServerHandle {
        let methods = methods.into();
        let (stop, handle) = stop_channel();
        let service_builder = jsonrpsee_server::Server::builder()
            .set_config(self.config)
            .to_service_builder();
        tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop.clone().shutdown() => break,
                    result = self.listener.accept() => match result {
                        Ok((socket, peer)) => {
                            if let Err(error) = socket.get_ref().set_nodelay(true) {
                                warn!(%peer, %error, "failed to configure RPC connection");
                                continue;
                            }
                            let service = service_builder.clone().build(methods.clone(), stop.clone());
                            let shutdown = stop.clone().shutdown();
                            connections.spawn(async move {
                                if let Err(error) = serve_with_graceful_shutdown(socket.compat(), service, shutdown).await {
                                    debug!(%peer, %error, "RPC connection stopped");
                                }
                            });
                        }
                        Err(error) => {
                            warn!(%error, "failed to accept RPC connection");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    },
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        if let Err(error) = result {
                            warn!(%error, "RPC connection task failed");
                        }
                    }
                }
            }
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    warn!(%error, "RPC connection task failed");
                }
            }
        });
        handle
    }
}

#[cfg(test)]
#[path = "nuclei_transport_tests.rs"]
mod tests;
