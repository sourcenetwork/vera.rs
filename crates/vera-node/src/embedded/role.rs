//! What a device does in its account's deployment.

use std::net::SocketAddr;

use crate::DeviceKey;

/// The part an embedded node takes in the deployment it opens.
#[derive(Clone, Debug, Default)]
pub enum DeviceRole {
    /// The deployment's validator: it proposes and finalizes every block.
    #[default]
    Active,
    /// A follower of the active device. See [`Backup`].
    Backup(Box<Backup>),
}

/// What a backup needs to follow its account's deployment.
///
/// A backup holds the deployment's genesis record and none of its key
/// material. It verifies each finalized block against the consensus key the
/// record names, re-executes it, and serves reads and proofs from the result.
/// It proposes nothing, votes for nothing and refuses submissions.
#[derive(Clone, Debug)]
pub struct Backup {
    /// The deployment's genesis record, as [`crate::SoloDeployment::record`] returns it.
    pub record: Vec<u8>,
    /// Where the active device's consensus listener is reached.
    pub active: SocketAddr,
    /// This device's transport key, which the active device lists among its
    /// backups. `None` keeps one in `transport.key` in the data directory,
    /// created on first use.
    pub transport_key: Option<DeviceKey>,
}
