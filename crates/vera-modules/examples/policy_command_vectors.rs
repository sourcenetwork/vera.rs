//! Emit cross-language fixtures for native gateway command commitments and call encoding.

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use serde_json::json;
use vera_modules::acp::{
    abi::IAcp,
    delegated_operation::DelegatedOperation,
    types::{Object, PolicyCmd},
};
use vera_zanzibar::{Relationship, Subject};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_id = "ab".repeat(32);
    let object = Object {
        resource: "file".into(),
        id: "report-雪<>&\u{2028}\u{2029}\n\"".into(),
    };
    let mut commands = vec![
        PolicyCmd::RegisterObject(object.clone()),
        PolicyCmd::ArchiveObject(object.clone()),
        PolicyCmd::UnarchiveObject(object.clone()),
    ];
    for subject in [
        Subject::entity(vera_identity::Did::new(format!(
            "did:opk:{}",
            "cd".repeat(32)
        ))?),
        Subject::entity(vera_identity::Did::new(
            "did:key:zExample\\u2028<>&\u{2028}",
        )?),
        Subject::entity_set("group", "staff-雪", "member"),
        Subject::typed_wildcard("user"),
        Subject::wildcard(),
    ] {
        let relationship = Relationship::new("file", object.id.clone(), "reader", subject);
        commands.push(PolicyCmd::SetRelationship(relationship.clone()));
        commands.push(PolicyCmd::DeleteRelationship(relationship));
    }
    let mut vectors = Vec::new();
    for command in commands {
        let encoded = serde_json::to_vec(&command)?;
        let operation = DelegatedOperation::PolicyCommand(&policy_id, &command);
        let call = IAcp::bearerPolicyCmdCall {
            bearerToken: "fixture-token".into(),
            policyId: B256::repeat_byte(0xab),
            cmd: encoded.clone().into(),
        };
        vectors.push(json!({
            "policy_id": policy_id,
            "command": String::from_utf8(encoded)?,
            "operation": serde_json::to_string(&operation)?,
            "digest": hex::encode(operation.digest()?),
            "token": "fixture-token",
            "call": hex::encode(call.abi_encode()),
        }));
    }
    println!("{}", serde_json::to_string_pretty(&vectors)?);
    Ok(())
}
