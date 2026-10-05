use crate::ExecutionError;

/// Admit transactions by their full limit and account for their actual execution.
pub(super) struct BlockGasBudget {
    limit: u64,
    used: u64,
}

impl BlockGasBudget {
    pub(super) const fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    pub(super) const fn used(&self) -> u64 {
        self.used
    }

    pub(super) fn admit(&self, tx_limit: u64, building: bool) -> Result<bool, ExecutionError> {
        let remaining = self.limit.checked_sub(self.used).ok_or_else(|| {
            ExecutionError::BlockValidation("block gas accounting exceeds limit".into())
        })?;
        if tx_limit <= remaining {
            Ok(true)
        } else if building {
            Ok(false)
        } else {
            Err(ExecutionError::BlockValidation(format!(
                "transaction gas limit {tx_limit} exceeds remaining block gas {remaining}"
            )))
        }
    }

    pub(super) fn charge(&mut self, tx_limit: u64, used: u64) -> Result<(), ExecutionError> {
        if used > tx_limit {
            return Err(ExecutionError::BlockValidation(
                "transaction gas usage exceeds its limit".into(),
            ));
        }
        let total = self
            .used
            .checked_add(used)
            .filter(|total| *total <= self.limit)
            .ok_or_else(|| {
                ExecutionError::BlockValidation("block gas usage exceeds limit".into())
            })?;
        self.used = total;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_usage_cannot_overflow_or_change_the_budget() {
        let mut budget = BlockGasBudget::new(u64::MAX);
        budget.charge(u64::MAX, u64::MAX - 1).unwrap();
        assert!(budget.admit(1, false).unwrap());
        assert!(!budget.admit(2, true).unwrap());
        assert!(budget.admit(2, false).is_err());
        assert!(budget.charge(0, 1).is_err());
        assert!(budget.charge(2, 2).is_err());
        assert_eq!(budget.used(), u64::MAX - 1);
        budget.charge(1, 1).unwrap();
        assert_eq!(budget.used(), u64::MAX);
        assert!(!budget.admit(1, true).unwrap());
    }
}
