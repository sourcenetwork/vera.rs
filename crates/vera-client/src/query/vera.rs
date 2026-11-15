//! Vera read-only queries via `eth_call` to precompile `0x0812`.

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolCall;
use vera_modules::vera::abi::IVera;

use crate::client::{VERA_ADDRESS, VeraClient};
use crate::error::ClientError;

impl VeraClient {
    /// Look up a JWS token record by hash.
    pub async fn get_jws_token(&self, token_hash: &str) -> Result<(bool, Bytes), ClientError> {
        let calldata = IVera::getJWSTokenCall {
            tokenHash: token_hash.into(),
        }
        .abi_encode();
        let result = self.eth_call(VERA_ADDRESS, calldata.into()).await?;
        let decoded = IVera::getJWSTokenCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok((decoded.found, decoded.record))
    }

    /// Look up all JWS tokens issued by a DID.
    pub async fn get_jws_tokens_by_did(&self, did: &str) -> Result<Bytes, ClientError> {
        let calldata = IVera::getJWSTokensByDidCall { did: did.into() }.abi_encode();
        let result = self.eth_call(VERA_ADDRESS, calldata.into()).await?;
        let decoded = IVera::getJWSTokensByDidCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Look up all JWS tokens authorized for an account.
    pub async fn get_jws_tokens_by_account(&self, account: Address) -> Result<Bytes, ClientError> {
        let calldata = IVera::getJWSTokensByAccountCall { account }.abi_encode();
        let result = self.eth_call(VERA_ADDRESS, calldata.into()).await?;
        let decoded = IVera::getJWSTokensByAccountCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Look up recorded delegations bound to a submitting DID.
    pub async fn get_delegations_by_submitter(
        &self,
        submitter: &str,
    ) -> Result<Bytes, ClientError> {
        let calldata = IVera::getDelegationsBySubmitterCall {
            submitter: submitter.into(),
        }
        .abi_encode();
        let result = self.eth_call(VERA_ADDRESS, calldata.into()).await?;
        IVera::getDelegationsBySubmitterCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_jws_token_calldata_roundtrip() {
        let call = IVera::getJWSTokenCall {
            tokenHash: "abc123def456".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], <IVera::getJWSTokenCall as SolCall>::SELECTOR);
        let decoded = IVera::getJWSTokenCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.tokenHash, "abc123def456");
    }

    #[test]
    fn get_jws_tokens_by_did_calldata_roundtrip() {
        let call = IVera::getJWSTokensByDidCall {
            did: "did:key:z6Mk...".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IVera::getJWSTokensByDidCall as SolCall>::SELECTOR
        );
        let decoded = IVera::getJWSTokensByDidCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.did, "did:key:z6Mk...");
    }

    #[test]
    fn get_jws_tokens_by_account_calldata_roundtrip() {
        let account = Address::repeat_byte(0x42);
        let call = IVera::getJWSTokensByAccountCall { account };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IVera::getJWSTokensByAccountCall as SolCall>::SELECTOR
        );
        let decoded = IVera::getJWSTokensByAccountCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.account, account);
    }
}
