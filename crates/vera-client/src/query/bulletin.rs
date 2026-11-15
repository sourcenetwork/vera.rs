//! Bulletin read-only queries via `eth_call` to precompile `0x0811`.

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use vera_modules::bulletin::abi::IBulletin;

use crate::client::{BULLETIN_ADDRESS, VeraClient};
use crate::error::ClientError;

impl VeraClient {
    /// Fetch a post by namespace and post ID.
    pub async fn get_post(&self, namespace: &str, post_id: &str) -> Result<Bytes, ClientError> {
        let calldata = IBulletin::getPostCall {
            namespace: namespace.into(),
            postId: post_id.into(),
        }
        .abi_encode();
        let result = self.eth_call(BULLETIN_ADDRESS, calldata.into()).await?;
        let decoded = IBulletin::getPostCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Fetch a namespace by name.
    pub async fn get_namespace(&self, namespace: &str) -> Result<Bytes, ClientError> {
        let calldata = IBulletin::getNamespaceCall {
            namespace: namespace.into(),
        }
        .abi_encode();
        let result = self.eth_call(BULLETIN_ADDRESS, calldata.into()).await?;
        let decoded = IBulletin::getNamespaceCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// List all namespaces.
    pub async fn get_namespaces(&self) -> Result<Bytes, ClientError> {
        let calldata = IBulletin::getNamespacesCall {}.abi_encode();
        let result = self.eth_call(BULLETIN_ADDRESS, calldata.into()).await?;
        let decoded = IBulletin::getNamespacesCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// List collaborators for a namespace.
    pub async fn get_namespace_collaborators(&self, namespace: &str) -> Result<Bytes, ClientError> {
        let calldata = IBulletin::getNamespaceCollaboratorsCall {
            namespace: namespace.into(),
        }
        .abi_encode();
        let result = self.eth_call(BULLETIN_ADDRESS, calldata.into()).await?;
        let decoded = IBulletin::getNamespaceCollaboratorsCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// List posts in a namespace.
    pub async fn get_namespace_posts(&self, namespace: &str) -> Result<Bytes, ClientError> {
        let calldata = IBulletin::getNamespacePostsCall {
            namespace: namespace.into(),
        }
        .abi_encode();
        let result = self.eth_call(BULLETIN_ADDRESS, calldata.into()).await?;
        let decoded = IBulletin::getNamespacePostsCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// List all posts across all namespaces.
    pub async fn get_posts(&self) -> Result<Bytes, ClientError> {
        let calldata = IBulletin::getPostsCall {}.abi_encode();
        let result = self.eth_call(BULLETIN_ADDRESS, calldata.into()).await?;
        let decoded = IBulletin::getPostsCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Query posts matching a glob pattern within a namespace.
    pub async fn iterate_glob(&self, namespace: &str, glob: &str) -> Result<Bytes, ClientError> {
        let calldata = IBulletin::iterateGlobCall {
            namespace: namespace.into(),
            glob: glob.into(),
        }
        .abi_encode();
        let result = self.eth_call(BULLETIN_ADDRESS, calldata.into()).await?;
        let decoded = IBulletin::iterateGlobCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_post_calldata_roundtrip() {
        let call = IBulletin::getPostCall {
            namespace: "my-ns".into(),
            postId: "abc123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], <IBulletin::getPostCall as SolCall>::SELECTOR);
        let decoded = IBulletin::getPostCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.namespace, "my-ns");
        assert_eq!(decoded.postId, "abc123");
    }

    #[test]
    fn get_namespace_calldata_roundtrip() {
        let call = IBulletin::getNamespaceCall {
            namespace: "test-ns".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IBulletin::getNamespaceCall as SolCall>::SELECTOR
        );
        let decoded = IBulletin::getNamespaceCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.namespace, "test-ns");
    }

    #[test]
    fn get_namespaces_calldata_selector() {
        let calldata = IBulletin::getNamespacesCall {}.abi_encode();
        assert_eq!(calldata.len(), 4);
        assert_eq!(
            &calldata[..4],
            <IBulletin::getNamespacesCall as SolCall>::SELECTOR
        );
    }

    #[test]
    fn iterate_glob_calldata_roundtrip() {
        let call = IBulletin::iterateGlobCall {
            namespace: "ns".into(),
            glob: "dkg/*".into(),
        };
        let encoded = call.abi_encode();
        let decoded = IBulletin::iterateGlobCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.namespace, "ns");
        assert_eq!(decoded.glob, "dkg/*");
    }
}
