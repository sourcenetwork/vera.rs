//! Borrowed bounds for leaf dynamic values before Alloy allocates owned values.

use super::{IAcp, PrecompileError, READ_GAS, SolCall, WRITE_GAS};
use vera_modules::acp::{MAX_REGISTRATION_OBJECTS, decision::MAX_ACCESS_OPERATIONS};

pub(super) fn required_gas(input: &[u8]) -> Option<u64> {
    if let Some(selector) = input
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        && super::commands::handles(selector)
    {
        return Some(
            if selector == IAcp::checkManagementAuthorityCall::SELECTOR {
                READ_GAS
            } else {
                WRITE_GAS
            },
        );
    }
    if input.starts_with(&IAcp::checkAccessCall::SELECTOR)
        || input.starts_with(&IAcp::bearerCheckAccessCall::SELECTOR)
        || input.starts_with(&IAcp::createPolicyCall::SELECTOR)
        || input.starts_with(&IAcp::createPolicyWithOptionsCall::SELECTOR)
        || input.starts_with(&IAcp::bearerCreatePolicyCall::SELECTOR)
        || input.starts_with(&IAcp::editPolicyCall::SELECTOR)
        || input.starts_with(&IAcp::bearerEditPolicyCall::SELECTOR)
    {
        Some(WRITE_GAS)
    } else if input.starts_with(&IAcp::verifyAccessRequestCall::SELECTOR)
        || input.starts_with(&IAcp::generateCommitmentCall::SELECTOR)
        || input.starts_with(&IAcp::validatePolicyCall::SELECTOR)
    {
        Some(READ_GAS)
    } else {
        None
    }
}

pub(super) fn validate(input: &[u8], remaining: &mut usize) -> Result<(), PrecompileError> {
    if input.starts_with(&IAcp::createPolicyCall::SELECTOR)
        || input.starts_with(&IAcp::bearerCreatePolicyCall::SELECTOR)
        || input.starts_with(&IAcp::createPolicyWithOptionsCall::SELECTOR)
    {
        return policy_create(input, remaining);
    }
    if input.starts_with(&IAcp::editPolicyCall::SELECTOR)
        || input.starts_with(&IAcp::bearerEditPolicyCall::SELECTOR)
    {
        return policy_edit(input, remaining);
    }
    if input.starts_with(&IAcp::bearerCheckAccessCall::SELECTOR) {
        return bearer_access(input, remaining);
    }
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
    // Permission requests have their own bound, including repeated ABI tails.
    let allowance = if arrays == 3 {
        (*remaining).min(64 << 10)
    } else {
        *remaining
    };
    let mut fields_remaining = allowance;
    for head in &heads[..arrays] {
        for index in 0..count.unwrap_or(0) {
            string(head, index * 32, &mut fields_remaining)?;
        }
    }
    // The actor string is decoded independently even when it aliases an array tail.
    string(body, (arrays + 1) * 32, &mut fields_remaining)?;
    charge(remaining, allowance - fields_remaining)
}

fn bearer_access(input: &[u8], remaining: &mut usize) -> Result<(), PrecompileError> {
    let body = &input[4..];
    body.get(..3 * 32).ok_or_else(invalid)?;
    let request = bytes(body, 64)?;
    if request.len() > 64 << 10 {
        return Err(PrecompileError::Other(
            "access request exceeds byte limit".into(),
        ));
    }
    charge(remaining, request.len())?;
    let mut token_bytes = 16 * 1024;
    string(body, 0, &mut token_bytes)?;
    charge(remaining, 16 * 1024 - token_bytes)
}

fn policy_create(input: &[u8], remaining: &mut usize) -> Result<(), PrecompileError> {
    let bearer = input.starts_with(&IAcp::bearerCreatePolicyCall::SELECTOR);
    let options = input.starts_with(&IAcp::createPolicyWithOptionsCall::SELECTOR);
    let body = &input[4..];
    let fields = if bearer {
        3
    } else if options {
        1
    } else {
        2
    };
    body.get(..fields * 32).ok_or_else(invalid)?;
    let payload = bytes(body, if bearer { 32 } else { 0 })?;
    if !options && payload.len() > vera_modules::acp::MAX_POLICY_DEFINITION_BYTES {
        return Err(PrecompileError::Other(
            "policy definition exceeds 64 KiB".into(),
        ));
    }
    // Raw options JSON retains the transaction bound; semantic field limits are
    // applied after metered decode, so whitespace/escape spelling stays supported.
    charge(remaining, payload.len())?;
    if bearer {
        let mut token_bytes = 16 * 1024;
        string(body, 0, &mut token_bytes)?;
        charge(remaining, 16 * 1024 - token_bytes)?;
    }
    Ok(())
}

// Match the compiler/JWT hard limits before owned ABI decoding. These bounds
// remain separate from deterministic edit work accounting and YAML expansion limits.
fn policy_edit(input: &[u8], remaining: &mut usize) -> Result<(), PrecompileError> {
    let bearer = input.starts_with(&IAcp::bearerEditPolicyCall::SELECTOR);
    let body = &input[4..];
    let fields = if bearer { 4 } else { 3 };
    body.get(..fields * 32).ok_or_else(invalid)?;
    let policy = bytes(body, if bearer { 64 } else { 32 })?;
    if policy.len() > vera_modules::acp::MAX_POLICY_DEFINITION_BYTES {
        return Err(PrecompileError::Other(
            "policy definition exceeds 64 KiB".into(),
        ));
    }
    charge(remaining, policy.len())?;
    if bearer {
        // Include lossy UTF-8 expansion exactly as Alloy's String decoder does.
        let mut token_bytes = 16 * 1024;
        string(body, 0, &mut token_bytes)?;
        charge(remaining, 16 * 1024 - token_bytes)?;
    }
    Ok(())
}

pub(super) fn bytes(input: &[u8], offset: usize) -> Result<&[u8], PrecompileError> {
    let tail = input.get(word(input, offset)?..).ok_or_else(invalid)?;
    let length = word(tail, 0)?;
    tail.get(32..)
        .and_then(|data| data.get(..length))
        .ok_or_else(invalid)
}

fn string(input: &[u8], offset: usize, remaining: &mut usize) -> Result<(), PrecompileError> {
    let bytes = bytes(input, offset)?;
    let length = bytes.len();
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
