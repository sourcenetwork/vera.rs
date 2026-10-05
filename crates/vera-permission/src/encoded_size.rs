use std::io::Write;

use serde::Serialize;

use crate::PermissionError;

/// Check serialized size without allocating another encoded copy.
/// Inputs must already have transport or structural bounds: counting visits the whole value.
pub fn encoded_size(value: &impl Serialize, maximum: usize) -> Result<usize, PermissionError> {
    struct Budget(Option<usize>);
    impl Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .and_then(|remaining| remaining.checked_sub(bytes.len()));
            // Hex formatters can retry failed writes; serde's Display adapter cannot.
            // Report exhaustion after serialization instead of returning a formatting error.
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut budget = Budget(Some(maximum));
    serde_json::to_writer(&mut budget, value).map_err(|_| PermissionError::Limit)?;
    budget
        .0
        .map(|remaining| maximum - remaining)
        .ok_or(PermissionError::Limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes};

    #[test]
    fn every_hex_and_escaped_string_cutoff_returns_a_limit_without_panicking() {
        let value = (
            B256::repeat_byte(0xab),
            Bytes::from(vec![0xcd; 37]),
            "quotes\" and \n",
        );
        let size = serde_json::to_vec(&value).unwrap().len();
        for maximum in 0..size {
            assert!(
                matches!(encoded_size(&value, maximum), Err(PermissionError::Limit)),
                "maximum={maximum}"
            );
        }
        assert_eq!(encoded_size(&value, size).unwrap(), size);
        assert_eq!(encoded_size(&value, usize::MAX).unwrap(), size);
    }
}
