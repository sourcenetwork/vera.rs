//! Separate retained-outcome budgets for short-lived and long-lived operation identities.

use vera_crypto::operation::{DEFAULT_OPERATION_LEAD, OperationId};

use super::operation::MAX_OPERATION_RECORD_BYTES;
use super::{AcpError, AcpModule, Result};
use crate::kv_store::ModuleKvStore as _;

/// Default encoded outcome budget of each class, adjustable through operator approvals.
pub const DEFAULT_OPERATION_BYTES: u64 = 64 << 20;

/// Which budget a retained outcome counts against, fixed when it is claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeClass {
    /// Claimed with at most the default 600-second lead remaining.
    Short,
    /// Claimed with more than the default lead remaining.
    Long,
}

impl OutcomeClass {
    /// Classify an identity claimed at `now` by the lead it still had.
    pub fn of(id: OperationId, now: u64) -> Self {
        if id.expires_at().saturating_sub(now) > DEFAULT_OPERATION_LEAD {
            Self::Long
        } else {
            Self::Short
        }
    }

    /// Native ACP key of this class's encoded-byte counter.
    pub const fn bytes_key(self) -> &'static [u8] {
        match self {
            Self::Short => b"operation-bytes/v1",
            Self::Long => b"operation-long-bytes/v1",
        }
    }

    /// Native ACP key of this class's operator-selected budget.
    pub const fn budget_key(self) -> &'static [u8] {
        match self {
            Self::Short => b"operation-budget/v1",
            Self::Long => b"operation-long-budget/v1",
        }
    }

    /// The byte recorded after the outcome key in the expiry index.
    pub(super) const fn tag(self) -> u8 {
        match self {
            Self::Short => 0,
            Self::Long => 1,
        }
    }

    pub(super) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::Short),
            1 => Ok(Self::Long),
            _ => Err(AcpError::State("invalid operation outcome class".into())),
        }
    }
}

impl AcpModule {
    /// Operator-selected budget of short-lived outcomes, or the default.
    pub fn operation_budget(&self) -> Result<u64> {
        self.class_budget(OutcomeClass::Short)
    }

    /// Operator-selected budget of long-lived outcomes, or the default.
    pub fn long_operation_budget(&self) -> Result<u64> {
        self.class_budget(OutcomeClass::Long)
    }

    pub(crate) fn set_operation_budget(&mut self, bytes: u64) -> Result<()> {
        self.set_class_budget(OutcomeClass::Short, bytes)
    }

    pub(crate) fn set_long_operation_budget(&mut self, bytes: u64) -> Result<()> {
        self.set_class_budget(OutcomeClass::Long, bytes)
    }

    /// Encoded bytes retained by outcomes of `class`.
    pub fn operation_bytes(&self, class: OutcomeClass) -> Result<u64> {
        decode(self.store.get_ref(class.bytes_key()), 0, "counter")
    }

    pub(super) fn class_budget(&self, class: OutcomeClass) -> Result<u64> {
        decode(
            self.store.get_ref(class.budget_key()),
            DEFAULT_OPERATION_BYTES,
            "budget",
        )
    }

    pub(super) fn set_class_budget(&mut self, class: OutcomeClass, bytes: u64) -> Result<()> {
        if bytes < MAX_OPERATION_RECORD_BYTES as u64 || bytes < self.operation_bytes(class)? {
            return Err(AcpError::State(
                "operation budget is below the record limit or retained usage".into(),
            ));
        }
        self.store
            .put(class.budget_key(), bytes.to_be_bytes().to_vec());
        Ok(())
    }
}

fn decode(bytes: Option<&[u8]>, default: u64, what: &str) -> Result<u64> {
    bytes.map_or(Ok(default), |bytes| {
        bytes
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| AcpError::State(format!("invalid operation storage {what}")))
    })
}
