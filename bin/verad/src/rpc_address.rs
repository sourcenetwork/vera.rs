use std::net::{AddrParseError, SocketAddr};

#[derive(Debug, thiserror::Error)]
pub(crate) enum RpcAddressError {
    #[error("invalid RPC listen address")]
    InvalidAddress(#[from] AddrParseError),
    #[error("validator index exceeds the default RPC port range")]
    ValidatorIndexOutOfRange,
}

pub(crate) fn resolve(
    configured: &str,
    override_port: Option<u16>,
) -> Result<SocketAddr, RpcAddressError> {
    let mut address: SocketAddr = configured.parse()?;
    if let Some(port) = override_port {
        address.set_port(port);
    }
    Ok(address)
}

pub(crate) fn validator_port(
    has_config_file: bool,
    override_port: Option<u16>,
    validator_index: usize,
) -> Result<Option<u16>, RpcAddressError> {
    if override_port.is_some() || has_config_file {
        return Ok(override_port);
    }
    u16::try_from(validator_index)
        .ok()
        .and_then(|index| 8545_u16.checked_add(index))
        .map(Some)
        .ok_or(RpcAddressError::ValidatorIndexOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_configuration_keeps_its_port_and_explicit_override_wins() {
        assert_eq!(validator_port(true, None, 3).unwrap(), None);
        assert_eq!(validator_port(true, Some(9000), 3).unwrap(), Some(9000));
        assert_eq!(validator_port(false, Some(9000), 3).unwrap(), Some(9000));
        assert_eq!(validator_port(false, None, 3).unwrap(), Some(8548));
    }

    #[test]
    fn validator_default_port_rejects_overflow_instead_of_wrapping() {
        assert_eq!(
            validator_port(false, None, usize::from(u16::MAX - 8545)).unwrap(),
            Some(u16::MAX)
        );
        for index in [usize::from(u16::MAX - 8545) + 1, usize::MAX] {
            assert!(matches!(
                validator_port(false, None, index),
                Err(RpcAddressError::ValidatorIndexOutOfRange)
            ));
        }
    }

    #[test]
    fn invalid_configured_addresses_never_fall_back_to_wildcard() {
        for address in ["", "localhost:9000", "127.0.0.1", "not-an-address"] {
            for port in [None, Some(8545)] {
                assert!(matches!(
                    resolve(address, port),
                    Err(RpcAddressError::InvalidAddress(_))
                ));
            }
        }
    }
}
