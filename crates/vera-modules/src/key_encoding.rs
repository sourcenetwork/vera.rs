//! Shared key encoding helpers used across module key builders.

/// Cosmos SDK-style length-prefix encoding: 1 byte length + raw bytes.
///
/// Matches Go `address.LengthPrefix`: empty input returns empty output
/// (no length byte prepended). Non-empty input returns `[len] + data`.
///
/// # Panics
///
/// Panics if `data.len() > 255`.
pub fn len_prefix(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    assert!(data.len() <= 255, "len_prefix: data exceeds 255 bytes");
    let mut out = Vec::with_capacity(1 + data.len());
    #[expect(clippy::cast_possible_truncation)]
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_prefix_basic() {
        let result = len_prefix(b"hello");
        assert_eq!(result[0], 5);
        assert_eq!(&result[1..], b"hello");
    }

    #[test]
    fn len_prefix_empty() {
        let result = len_prefix(b"");
        assert!(result.is_empty());
    }

    #[test]
    #[should_panic(expected = "len_prefix: data exceeds 255 bytes")]
    fn len_prefix_overflow() {
        len_prefix(&[0u8; 256]);
    }
}
