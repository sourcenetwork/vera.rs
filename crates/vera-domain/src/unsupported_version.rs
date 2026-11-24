//! Refusal of a versioned format written under a version this build does not read.

/// A versioned wire or state format carried a version other than the one this
/// build reads. The format is refused; its contents are never interpreted
/// under another version's rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unsupported {format} version {found}; this build reads version {supported}")]
pub struct UnsupportedVersion {
    /// The format whose version was read.
    pub format: &'static str,
    /// The version found in the encoding.
    pub found: u8,
    /// The version this build reads and writes.
    pub supported: u8,
}

impl UnsupportedVersion {
    /// Accept `found` only when it is the `supported` version of `format`.
    pub const fn check(format: &'static str, found: u8, supported: u8) -> Result<(), Self> {
        if found == supported {
            Ok(())
        } else {
            Err(Self {
                format,
                found,
                supported,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_supported_version_is_accepted() {
        assert_eq!(UnsupportedVersion::check("block format", 1, 1), Ok(()));
        for found in [0, 2, u8::MAX] {
            let error = UnsupportedVersion::check("block format", found, 1).unwrap_err();
            assert_eq!(error.found, found);
            assert_eq!(error.supported, 1);
            assert_eq!(
                error.to_string(),
                format!("unsupported block format version {found}; this build reads version 1")
            );
        }
    }
}
