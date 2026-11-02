//! ACP module subcommands.

use std::path::PathBuf;

use alloy_primitives::FixedBytes;
use clap::Subcommand;

use super::context::ClientContext;

#[derive(Subcommand, Debug)]
pub(crate) enum AcpCommand {
    /// Create an ACP policy from YAML.
    CreatePolicy {
        /// Inline YAML policy string.
        #[arg(conflicts_with = "file")]
        yaml: Option<String>,
        /// Path to YAML policy file.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Fetch a policy by ID.
    GetPolicy {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
    },
    /// List all policy IDs.
    ListPolicies,
    /// Validate a policy without storing it.
    ValidatePolicy {
        /// Inline YAML policy string.
        #[arg(conflicts_with = "file")]
        yaml: Option<String>,
        /// Path to YAML policy file.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Register an object in a policy.
    RegisterObject {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
        /// Resource name.
        resource: String,
        /// Object ID.
        object_id: String,
    },
    /// Archive an object in a policy.
    ArchiveObject {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
        /// Resource name.
        resource: String,
        /// Object ID.
        object_id: String,
    },
    /// Get the owner of an object.
    GetObjectOwner {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
        /// Resource name.
        resource: String,
        /// Object ID.
        object_id: String,
    },
    /// Set a relationship in a policy.
    SetRelationship {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
        /// Resource name.
        resource: String,
        /// Object ID.
        object_id: String,
        /// Relation name.
        relation: String,
        /// Actor DID.
        actor: String,
    },
    /// Delete a relationship from a policy.
    DeleteRelationship {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
        /// Resource name.
        resource: String,
        /// Object ID.
        object_id: String,
        /// Relation name.
        relation: String,
        /// Actor DID.
        actor: String,
    },
    /// Check if a relationship exists (read-only).
    HasRelationship {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
        /// Resource name.
        resource: String,
        /// Object ID.
        object_id: String,
        /// Relation name.
        relation: String,
        /// Actor DID.
        actor: String,
    },
    /// Verify access (read-only, does not persist decision).
    VerifyAccess {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
        /// Resource name.
        resource: String,
        /// Object ID.
        object_id: String,
        /// Permission name.
        permission: String,
        /// Actor DID.
        actor: String,
    },
    /// Check access (persists a decision record on-chain).
    CheckAccess {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
        /// Resource name.
        resource: String,
        /// Object ID.
        object_id: String,
        /// Permission name.
        permission: String,
        /// Actor DID.
        actor: String,
    },
    /// Filter relationships matching a selector.
    FilterRelationships {
        /// Policy ID (hex, 32 bytes).
        policy_id: String,
        /// Resource name (empty string for wildcard).
        resource: String,
        /// Object ID (empty string for wildcard).
        object_id: String,
        /// Relation name (empty string for wildcard).
        relation: String,
        /// Actor DID (empty string for wildcard).
        actor: String,
    },
}

impl AcpCommand {
    #[allow(clippy::too_many_lines)]
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::CreatePolicy { yaml, file } => {
                let policy_bytes = read_policy_input(yaml, file)?;
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_create_policy(bls, &policy_bytes, 1)
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client.create_policy(&signer, &policy_bytes, 1).await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::GetPolicy { policy_id } => {
                let id = parse_policy_id(&policy_id)?;
                let data = ctx.client.get_policy(id).await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::ListPolicies => {
                let ids = ctx.client.get_policy_ids().await?;
                ctx.print_json(&ids)?;
            }
            Self::ValidatePolicy { yaml, file } => {
                let policy_bytes = read_policy_input(yaml, file)?;
                let (valid, reason) = ctx.client.validate_policy(&policy_bytes, 1).await?;
                ctx.print_json(&serde_json::json!({ "valid": valid, "reason": reason }))?;
            }
            Self::RegisterObject {
                policy_id,
                resource,
                object_id,
            } => {
                let id = parse_policy_id(&policy_id)?;
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_register_object(bls, id, &object_id, &resource)
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client
                        .register_object(&signer, id, &object_id, &resource)
                        .await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::ArchiveObject {
                policy_id,
                resource,
                object_id,
            } => {
                let id = parse_policy_id(&policy_id)?;
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_archive_object(bls, id, &object_id, &resource)
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client
                        .archive_object(&signer, id, &object_id, &resource)
                        .await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::GetObjectOwner {
                policy_id,
                resource,
                object_id,
            } => {
                let id = parse_policy_id(&policy_id)?;
                let (registered, record) = ctx
                    .client
                    .get_object_owner(id, &resource, &object_id)
                    .await?;
                let record_json = bytes_to_json(&record);
                ctx.print_json(
                    &serde_json::json!({ "registered": registered, "record": record_json }),
                )?;
            }
            Self::SetRelationship {
                policy_id,
                resource,
                object_id,
                relation,
                actor,
            } => {
                let id = parse_policy_id(&policy_id)?;
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_set_relationship(bls, id, &resource, &object_id, &relation, &actor)
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client
                        .set_relationship(&signer, id, &resource, &object_id, &relation, &actor)
                        .await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::DeleteRelationship {
                policy_id,
                resource,
                object_id,
                relation,
                actor,
            } => {
                let id = parse_policy_id(&policy_id)?;
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_delete_relationship(
                            bls, id, &resource, &object_id, &relation, &actor,
                        )
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client
                        .delete_relationship(&signer, id, &resource, &object_id, &relation, &actor)
                        .await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::HasRelationship {
                policy_id,
                resource,
                object_id,
                relation,
                actor,
            } => {
                let id = parse_policy_id(&policy_id)?;
                let has = ctx
                    .client
                    .has_relationship(id, &resource, &object_id, &relation, &actor)
                    .await?;
                ctx.print_json(&serde_json::json!({ "has_relationship": has }))?;
            }
            Self::VerifyAccess {
                policy_id,
                resource,
                object_id,
                permission,
                actor,
            } => {
                let id = parse_policy_id(&policy_id)?;
                let allowed = ctx
                    .client
                    .verify_access_request(
                        id,
                        vec![resource],
                        vec![object_id],
                        vec![permission],
                        &actor,
                    )
                    .await?;
                ctx.print_json(&serde_json::json!({ "allowed": allowed }))?;
            }
            Self::CheckAccess {
                policy_id,
                resource,
                object_id,
                permission,
                actor,
            } => {
                let id = parse_policy_id(&policy_id)?;
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_check_access(
                            bls,
                            id,
                            vec![resource],
                            vec![object_id],
                            vec![permission],
                            &actor,
                        )
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client
                        .check_access(
                            &signer,
                            id,
                            vec![resource],
                            vec![object_id],
                            vec![permission],
                            &actor,
                        )
                        .await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::FilterRelationships {
                policy_id,
                resource,
                object_id,
                relation,
                actor,
            } => {
                let id = parse_policy_id(&policy_id)?;
                let data = ctx
                    .client
                    .filter_relationships(id, &resource, &object_id, &relation, &actor)
                    .await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
        }
        Ok(())
    }
}

fn read_policy_input(yaml: Option<String>, file: Option<PathBuf>) -> eyre::Result<Vec<u8>> {
    match (yaml, file) {
        (Some(y), None) => Ok(y.into_bytes()),
        (None, Some(f)) => std::fs::read(&f)
            .map_err(|e| eyre::eyre!("failed to read policy file {}: {e}", f.display())),
        (None, None) => Err(eyre::eyre!("provide either a YAML string or --file PATH")),
        (Some(_), Some(_)) => Err(eyre::eyre!(
            "provide either a YAML string or --file, not both"
        )),
    }
}

fn parse_policy_id(hex: &str) -> eyre::Result<FixedBytes<32>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).map_err(|e| eyre::eyre!("invalid policy ID hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(eyre::eyre!(
            "policy ID must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(FixedBytes::from_slice(&bytes))
}

fn bytes_to_json(data: &[u8]) -> serde_json::Value {
    serde_json::from_slice(data)
        .unwrap_or_else(|_| serde_json::Value::String(format!("0x{}", hex::encode(data))))
}
