//! Borrowed batch validation before ABI decoding allocates nested payloads.

use super::{IAcp, PrecompileError, SolCall, batch_error};

pub(super) const MAX_DEPTH: usize = 16;
pub(super) const MAX_CALLS: usize = 256;

pub(super) fn validate(input: &[u8]) -> Result<(), PrecompileError> {
    if input.len() > vera_domain::MAX_TX_BYTES {
        return Err(limit("calldata bytes"));
    }
    Budget {
        calls: MAX_CALLS,
        bytes: vera_domain::MAX_TX_BYTES,
    }
    .visit(input, 0)
}

struct Budget {
    calls: usize,
    bytes: usize,
}

impl Budget {
    fn visit(&mut self, input: &[u8], depth: usize) -> Result<(), PrecompileError> {
        self.calls = self
            .calls
            .checked_sub(1)
            .ok_or_else(|| limit("call count"))?;
        if !input.starts_with(&IAcp::batchCallsCall::SELECTOR) {
            return Ok(());
        }
        if depth == MAX_DEPTH {
            return Err(limit("depth"));
        }
        let body = &input[4..];
        let array = body.get(word(body, 0)?..).ok_or_else(invalid)?;
        let count = word(array, 0)?;
        if count > self.calls {
            return Err(limit("call count"));
        }
        // ABI array element offsets are relative to the word after its count.
        let elements = array.get(32..).ok_or_else(invalid)?;
        let head_bytes = count.checked_mul(32).ok_or_else(invalid)?;
        elements.get(..head_bytes).ok_or_else(invalid)?;
        for index in 0..count {
            self.child(elements, index, depth + 1)
                .map_err(|error| batch_error(index, error))?;
        }
        Ok(())
    }

    fn child(
        &mut self,
        elements: &[u8],
        index: usize,
        depth: usize,
    ) -> Result<(), PrecompileError> {
        let offset = word(elements, index.checked_mul(32).ok_or_else(invalid)?)?;
        let tail = elements.get(offset..).ok_or_else(invalid)?;
        let length = word(tail, 0)?;
        self.bytes = self
            .bytes
            .checked_sub(length)
            .ok_or_else(|| limit("decoded bytes"))?;
        let input = tail
            .get(32..)
            .and_then(|bytes| bytes.get(..length))
            .ok_or_else(invalid)?;
        // Each occurrence is copied by the decoder, even when offsets alias.
        self.visit(input, depth)
    }
}

fn word(input: &[u8], offset: usize) -> Result<usize, PrecompileError> {
    let end = offset.checked_add(32).ok_or_else(invalid)?;
    input
        .get(offset..end)
        .ok_or_else(invalid)?
        .iter()
        .try_fold(0usize, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(invalid)
        })
}

fn invalid() -> PrecompileError {
    PrecompileError::Other("invalid ACP batch ABI".into())
}

fn limit(resource: &str) -> PrecompileError {
    PrecompileError::Other(format!("ACP batch {resource} limit exceeded").into())
}
