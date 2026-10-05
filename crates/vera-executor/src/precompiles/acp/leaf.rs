//! Borrowed bounds for leaf string arrays before Alloy allocates owned values.

use super::{IAcp, PrecompileError, READ_GAS, SolCall, WRITE_GAS};
use vera_modules::acp::{MAX_REGISTRATION_OBJECTS, decision::MAX_ACCESS_OPERATIONS};

pub(super) fn required_gas(input: &[u8]) -> Option<u64> {
    if input.starts_with(&IAcp::checkAccessCall::SELECTOR) {
        Some(WRITE_GAS)
    } else if input.starts_with(&IAcp::verifyAccessRequestCall::SELECTOR)
        || input.starts_with(&IAcp::generateCommitmentCall::SELECTOR)
    {
        Some(READ_GAS)
    } else {
        None
    }
}

pub(super) fn validate(input: &[u8], remaining: &mut usize) -> Result<(), PrecompileError> {
    let (arrays, maximum) = if input.starts_with(&IAcp::generateCommitmentCall::SELECTOR) {
        (2, MAX_REGISTRATION_OBJECTS)
    } else if input.starts_with(&IAcp::checkAccessCall::SELECTOR)
        || input.starts_with(&IAcp::verifyAccessRequestCall::SELECTOR)
    {
        (3, MAX_ACCESS_OPERATIONS)
    } else {
        return Ok(());
    };
    let body = &input[4..];
    body.get(..(arrays + 2) * 32).ok_or_else(invalid)?;
    let mut heads: [&[u8]; 3] = [&[]; 3];
    let mut count = None;
    for (index, head) in heads[..arrays].iter_mut().enumerate() {
        let array = body
            .get(word(body, (index + 1) * 32)?..)
            .ok_or_else(invalid)?;
        let length = word(array, 0)?;
        if length > maximum {
            return Err(PrecompileError::Other(
                "ACP string-array count limit exceeded".into(),
            ));
        }
        if count.is_some_and(|expected| expected != length) {
            return Err(PrecompileError::Other("array length mismatch".into()));
        }
        count = Some(length);
        *head = array.get(32..).ok_or_else(invalid)?;
        head.get(..length.checked_mul(32).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
    }
    for head in &heads[..arrays] {
        for index in 0..count.unwrap_or(0) {
            string(head, index * 32, remaining)?;
        }
    }
    // The actor string is decoded independently even when it aliases an array tail.
    string(body, (arrays + 1) * 32, remaining)
}

fn string(input: &[u8], offset: usize, remaining: &mut usize) -> Result<(), PrecompileError> {
    let tail = input.get(word(input, offset)?..).ok_or_else(invalid)?;
    let length = word(tail, 0)?;
    let bytes = tail
        .get(32..)
        .and_then(|data| data.get(..length))
        .ok_or_else(invalid)?;
    charge(remaining, length)?;
    // Alloy uses from_utf8_lossy when detokenizing strings. Charge every occurrence
    // and the extra bytes of replacement characters, without allocating a String.
    for chunk in bytes.utf8_chunks() {
        if !chunk.invalid().is_empty() {
            charge(remaining, 3 - chunk.invalid().len())?;
        }
    }
    Ok(())
}

fn charge(remaining: &mut usize, bytes: usize) -> Result<(), PrecompileError> {
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or_else(|| PrecompileError::Other("ACP decoded bytes limit exceeded".into()))?;
    Ok(())
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
    PrecompileError::Other("invalid ACP string-array ABI".into())
}
