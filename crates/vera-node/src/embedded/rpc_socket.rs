//! The network RPC socket of an embedded node.

use std::net::{SocketAddr, TcpListener};

use super::EmbedError;

/// A bound RPC listener and the address the system gave it.
#[derive(Debug)]
pub(super) struct RpcSocket {
    listener: TcpListener,
    address: SocketAddr,
}

impl RpcSocket {
    /// Bind `address`; port 0 takes a port the system chooses.
    pub(super) fn bind(address: SocketAddr) -> Result<Self, EmbedError> {
        let bound = |source| EmbedError::RpcBind { address, source };
        let listener = TcpListener::bind(address).map_err(bound)?;
        let address = listener.local_addr().map_err(bound)?;
        Ok(Self { listener, address })
    }

    pub(super) const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The listener for the node to serve, keeping this handle bound.
    ///
    /// The kept handle holds the port while a node restarts in place, so the
    /// address stays the host's.
    pub(super) fn share(&self) -> Result<TcpListener, EmbedError> {
        self.listener
            .try_clone()
            .map_err(|source| EmbedError::RpcBind {
                address: self.address,
                source,
            })
    }
}
