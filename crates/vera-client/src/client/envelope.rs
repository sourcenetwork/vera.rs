//! Single-pass decoding of a JSON-RPC response.

use serde::{Deserialize, Deserializer, de::DeserializeOwned};
use serde_json::{Value, value::RawValue};

use crate::error::ClientError;

#[derive(Deserialize)]
struct Envelope<'a> {
    jsonrpc: Option<Value>,
    id: Option<Value>,
    error: Option<Value>,
    #[serde(default, borrow, deserialize_with = "present")]
    result: Option<&'a RawValue>,
}

/// Keeps a `null` result distinct from a missing one: `null` is a valid `Option` result.
fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<&'de RawValue>, D::Error> {
    <&RawValue>::deserialize(deserializer).map(Some)
}

/// Bind the response to its request, then decode the result without an intermediate tree.
/// A `null` error member is treated as absent.
pub(super) fn decode<T: DeserializeOwned>(body: &[u8], id: u64) -> Result<T, ClientError> {
    let envelope: Envelope<'_> = serde_json::from_slice(body)?;
    if envelope.id.as_ref().and_then(Value::as_u64) != Some(id)
        || envelope.jsonrpc.as_ref().and_then(Value::as_str) != Some("2.0")
    {
        return Err(ClientError::InvalidResponse(
            "request ID or protocol version mismatch",
        ));
    }
    if let Some(error) = &envelope.error {
        return Err(ClientError::from_rpc(error));
    }
    let result = envelope.result.ok_or(ClientError::MissingResult)?;
    Ok(serde_json::from_str(result.get())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_result_is_a_value_and_a_missing_result_is_an_error() {
        let null = br#"{"jsonrpc":"2.0","id":7,"result":null}"#;
        assert_eq!(decode::<Option<u64>>(null, 7).unwrap(), None);
        let present = br#"{"jsonrpc":"2.0","id":7,"result":{"a":[1,2]},"error":null}"#;
        assert_eq!(
            decode::<Value>(present, 7).unwrap(),
            serde_json::json!({"a": [1, 2]})
        );
        let missing = br#"{"jsonrpc":"2.0","id":7}"#;
        assert!(matches!(
            decode::<Option<u64>>(missing, 7),
            Err(ClientError::MissingResult)
        ));
    }

    #[test]
    fn request_binding_is_checked_before_the_error_and_the_result() {
        for body in [
            r#"{"jsonrpc":"2.0","id":8,"result":"not a number"}"#,
            r#"{"jsonrpc":"2.0","id":"7","result":1}"#,
            r#"{"jsonrpc":"2.0","result":1}"#,
            r#"{"jsonrpc":2.0,"id":7,"result":1}"#,
            r#"{"id":7,"error":{"code":-32000,"message":"rejected"}}"#,
        ] {
            assert!(matches!(
                decode::<u64>(body.as_bytes(), 7),
                Err(ClientError::InvalidResponse(_))
            ));
        }
        let rejected =
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"rejected"},"result":1}"#;
        assert!(matches!(
            decode::<u64>(rejected, 7),
            Err(ClientError::Rpc { code: -32000, .. })
        ));
    }
}
