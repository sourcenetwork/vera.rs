//! The marshal mailbox type shared by the node's actors.

use commonware_consensus::marshal::{core::Mailbox, standard::Standard};

pub(crate) type VeraMarshal = Mailbox<vera_app::ConsensusScheme, Standard<vera_domain::Block>>;
