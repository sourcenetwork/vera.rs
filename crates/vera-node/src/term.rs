//! Switching the account's active device.
//!
//! Every device of an account holds the deployment's validator key, and one
//! of them is active. A term certificate moves that role to another device
//! and raises the term its blocks carry. See `docs/active-term.md`.

mod actor;
mod archive;
mod contest;
mod control;
#[cfg(feature = "fault-injection")]
pub(crate) mod fault;
mod floor;
mod gate;
mod journal;
mod kept;
mod probe;
mod record;
mod refusal;
mod reporter;
mod rewind;
mod seating;
mod switching;
mod wire;

pub(crate) use actor::{Parts, run};
pub(crate) use archive::{Archived, archived};
pub use contest::Contest;
pub use control::TermSeat;
pub(crate) use control::{Accept, TermControl};
#[cfg(test)]
pub(crate) use control::{Asked, Command};
pub(crate) use floor::seat;
pub(crate) use gate::WakeGate;
pub(crate) use journal::settle_role;
pub(crate) use probe::Probe;
pub(crate) use record::TermRecord;
pub use refusal::TermRefusal;
pub(crate) use reporter::{Applied, TermReporter};
pub(crate) use rewind::{acknowledge, discarded, resync_after, rewind};
pub(crate) use seating::{Role, settle as settle_seating};
pub use switching::{Device, Switching};

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_domain::PublicKey;

/// The identifier a term certificate names a device by: its transport key.
pub(crate) fn device_id(key: &PublicKey) -> B256 {
    B256::from_slice(key.encode().as_ref())
}
