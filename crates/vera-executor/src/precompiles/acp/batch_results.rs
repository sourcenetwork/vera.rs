//! Shared accounting before retaining batch results or allocating wrapper encodings.

use alloy_primitives::Log;

use super::PrecompileError;

/// Reuse the request envelope allowance for cumulative encoded results and logs.
pub(super) const MAX_RESULT_BYTES: usize = vera_domain::MAX_TX_BYTES;
/// Fixed consensus charge for a log's address and vector/byte-buffer descriptors.
/// Do not use host-dependent `size_of` in execution accounting.
const LOG_OVERHEAD_BYTES: usize = 96;

pub(super) struct Budget {
    remaining: usize,
}

impl Budget {
    pub(super) const fn new() -> Self {
        Self {
            remaining: MAX_RESULT_BYTES,
        }
    }

    pub(super) fn begin_batch(&mut self, calls: usize) -> Result<(), PrecompileError> {
        // Return tuple offset + array length, then an offset and byte length per result.
        let bytes = calls
            .checked_mul(64)
            .and_then(|bytes| bytes.checked_add(64))
            .ok_or_else(limit)?;
        self.reserve(bytes)
    }

    pub(super) fn retain(&mut self, output: &[u8], logs: &[Log]) -> Result<(), PrecompileError> {
        let mut bytes = output.len().checked_add(31).ok_or_else(limit)? & !31;
        for log in logs {
            bytes = log
                .data
                .topics()
                .len()
                .checked_mul(32)
                .and_then(|size| size.checked_add(LOG_OVERHEAD_BYTES))
                .and_then(|size| size.checked_add(log.data.data.len()))
                .and_then(|size| size.checked_add(bytes))
                .ok_or_else(limit)?;
        }
        self.reserve(bytes)
    }

    pub(super) fn revert(&mut self, prefix: &str, output: &[u8]) -> Result<(), PrecompileError> {
        let bytes = output
            .utf8_chunks()
            .try_fold(prefix.len(), |bytes, chunk| {
                bytes
                    .checked_add(chunk.valid().len())
                    .and_then(|bytes| {
                        bytes.checked_add(if chunk.invalid().is_empty() { 0 } else { 3 })
                    })
                    .ok_or_else(limit)
            })?;
        self.reserve(
            bytes
                .checked_add(usize::from(!output.is_empty()) * 2)
                .ok_or_else(limit)?,
        )
    }

    fn reserve(&mut self, bytes: usize) -> Result<(), PrecompileError> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(limit)?;
        Ok(())
    }
}

fn limit() -> PrecompileError {
    PrecompileError::Fatal("ACP batch result byte limit exceeded".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::acp::IAcp;
    use alloy_primitives::{B256, Bytes};
    use alloy_sol_types::SolCall;

    #[test]
    fn exact_encoded_array_size_includes_offsets_lengths_and_padding() {
        let outputs: Vec<Bytes> = [0, 1, 31, 32, 33]
            .into_iter()
            .map(|length| vec![7; length].into())
            .collect();
        let encoded = IAcp::batchCallsCall::abi_encode_returns(&outputs);
        for allowance in [encoded.len(), encoded.len() - 1] {
            let mut budget = Budget {
                remaining: allowance,
            };
            budget.begin_batch(outputs.len()).unwrap();
            let result = outputs
                .iter()
                .try_for_each(|output| budget.retain(output, &[]));
            assert_eq!(result.is_ok(), allowance == encoded.len());
            if result.is_ok() {
                assert_eq!(budget.remaining, 0);
            }
        }
        assert!(Budget::new().begin_batch(usize::MAX).is_err());
    }

    #[test]
    fn result_budget_counts_log_structures_topics_and_data() {
        let log = Log::new_unchecked(Default::default(), vec![B256::ZERO; 2], vec![3; 17].into());
        let charge = 96 + 2 * 32 + 17;
        let mut exact = Budget { remaining: charge };
        exact.retain(&[], std::slice::from_ref(&log)).unwrap();
        assert_eq!(exact.remaining, 0);
        let mut over = Budget {
            remaining: charge - 1,
        };
        assert!(over.retain(&[], &[log]).is_err());
    }

    #[test]
    fn revert_formatting_checks_lossy_utf8_expansion_before_allocation() {
        let prefix = "batch call 1 reverted";
        let bytes = [b'x', 255, b'y', 255];
        let message = format!("{prefix}: {}", String::from_utf8_lossy(&bytes));
        let mut exact = Budget {
            remaining: message.len(),
        };
        exact.revert(prefix, &bytes).unwrap();
        assert_eq!(exact.remaining, 0);
        let mut over = Budget {
            remaining: message.len() - 1,
        };
        assert!(over.revert(prefix, &bytes).is_err());
    }
}
