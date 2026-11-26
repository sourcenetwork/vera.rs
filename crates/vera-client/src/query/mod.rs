//! Typed queries: read-only module calls answered by `vera_call`.
//!
//! Every query in this module is UNAUTHENTICATED. The answer is the unproven
//! word of the node the client talks to about its own head revision: it
//! carries no finality certificate and no state proof. Use these queries for
//! display, convenience and tests, or against an in-process node the host
//! itself runs. Do not use them to grant access, to record a decision or to
//! act on behalf of another party.
//!
//! The verified readers are the authenticated path. Each returns evidence
//! checked against a consensus key the caller trusts:
//!
//! | Typed query | Verified equivalent |
//! |-------------|---------------------|
//! | `get_policy` | [`VeraClient::read_policy`] |
//! | `get_policies`, `get_policy_ids`, `get_policies_page`, `get_policy_catalogue` | [`VeraClient::read_policy_page`] |
//! | `has_relationship`, `get_object_registration` | [`VeraClient::read_current_record`] |
//! | `filter_relationships`, `get_relationships_page` | [`VeraClient::read_relationship_page`], [`VeraClient::read_current_policy_prefix_page`] |
//! | `verify_access_request`, `check_management_authority` | [`VeraClient::verify_current_access`] |
//! | `get_object_owner` | [`VeraClient::read_object_registration`] |
//! | `get_access_decision` | [`VeraClient::read_access_decision`] |
//! | `get_acp_params` | [`VeraClient::read_acp_parameters`] |
//! | `get_post` | [`VeraClient::read_bulletin_post`] |
//! | `get_namespace` | [`VeraClient::read_bulletin_namespace`] |
//! | `get_namespaces` | [`VeraClient::list_bulletin_namespaces`] |
//! | `get_namespace_collaborators` | [`VeraClient::list_bulletin_collaborators`], [`VeraClient::read_bulletin_collaborator`] |
//! | `get_namespace_posts`, `iterate_glob` | [`VeraClient::list_bulletin_posts`] |
//! | `get_posts` | [`VeraClient::read_current_prefix_page`] on the bulletin module |
//! | `get_jws_token` | [`VeraClient::read_token_record`] |
//! | `get_jws_tokens_by_did`, `get_jws_tokens_by_account`, `get_delegations_by_submitter` | [`VeraClient::read_current_prefix`] on the vera module with [`VeraClient::read_token_record`] |
//! | `administration` | [`VeraClient::read_administration`] |
//!
//! `validate_policy` has no verified RPC: parse a policy locally with acp-rs's
//! `acp::policy::compile_text`.

use alloy_primitives::{Address, Bytes};
use vera_domain::ViewCallResult;

use crate::client::VeraClient;
use crate::error::ClientError;

/// ACP queries (module `0x0810`).
pub(crate) mod acp;
/// Bulletin queries (module `0x0811`).
pub(crate) mod bulletin;
/// Vera queries (module `0x0812`).
pub(crate) mod vera;

mod acp_lifecycle;

impl VeraClient {
    /// Evaluate a signerless, read-only module call at the node's head
    /// revision (`vera_call`) and return its output.
    ///
    /// Unauthenticated: the output is the node's unproven answer. A refusal
    /// is returned as [`ClientError::Refused`] without a receipt.
    pub(crate) async fn view_call(
        &self,
        target: Address,
        calldata: Bytes,
    ) -> Result<Bytes, ClientError> {
        let result: ViewCallResult = self
            .rpc_call_typed("vera_call", serde_json::json!([target, calldata]))
            .await?;
        match result.refusal {
            Some(refusal) => Err(ClientError::Refused {
                refusal,
                receipt: None,
            }),
            None => Ok(result.output),
        }
    }
}
