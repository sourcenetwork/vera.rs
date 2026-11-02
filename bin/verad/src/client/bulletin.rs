//! Bulletin module subcommands.

use clap::Subcommand;

use super::context::ClientContext;

#[derive(Subcommand, Debug)]
pub(crate) enum BulletinCommand {
    /// Register a new namespace.
    RegisterNamespace {
        /// Namespace name.
        namespace: String,
    },
    /// Fetch a namespace by name.
    GetNamespace {
        /// Namespace name.
        namespace: String,
    },
    /// List all namespaces.
    ListNamespaces,
    /// Add a collaborator to a namespace.
    AddCollaborator {
        /// Namespace name.
        namespace: String,
        /// Collaborator DID (e.g. did:key:zQ3s...).
        did: String,
    },
    /// Remove a collaborator from a namespace.
    RemoveCollaborator {
        /// Namespace name.
        namespace: String,
        /// Collaborator DID (e.g. did:key:zQ3s...).
        did: String,
    },
    /// List collaborators for a namespace.
    ListCollaborators {
        /// Namespace name.
        namespace: String,
    },
    /// Create a post in a namespace.
    CreatePost {
        /// Namespace name.
        namespace: String,
        /// Hex-encoded payload bytes.
        #[arg(long, default_value = "")]
        payload: String,
        /// Hex-encoded proof bytes.
        #[arg(long, default_value = "")]
        proof: String,
        /// Artifact string.
        #[arg(long, default_value = "")]
        artifact: String,
    },
    /// Fetch a post by namespace and post ID.
    GetPost {
        /// Namespace name.
        namespace: String,
        /// Post ID.
        post_id: String,
    },
    /// List posts (optionally filtered by namespace).
    ListPosts {
        /// Filter by namespace.
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Query posts matching a glob pattern.
    Glob {
        /// Namespace name.
        namespace: String,
        /// Glob pattern.
        pattern: String,
    },
}

impl BulletinCommand {
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::RegisterNamespace { namespace } => {
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_register_namespace(bls, &namespace)
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client.register_namespace(&signer, &namespace).await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::GetNamespace { namespace } => {
                let data = ctx.client.get_namespace(&namespace).await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::ListNamespaces => {
                let data = ctx.client.get_namespaces().await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::AddCollaborator { namespace, did } => {
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_add_collaborator(bls, &namespace, &did)
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client
                        .add_collaborator(&signer, &namespace, &did)
                        .await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::RemoveCollaborator { namespace, did } => {
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_remove_collaborator(bls, &namespace, &did)
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client
                        .remove_collaborator(&signer, &namespace, &did)
                        .await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::ListCollaborators { namespace } => {
                let data = ctx.client.get_namespace_collaborators(&namespace).await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::CreatePost {
                namespace,
                payload,
                proof,
                artifact,
            } => {
                let payload_bytes = parse_optional_hex(&payload)?;
                let proof_bytes = parse_optional_hex(&proof)?;
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client
                        .native_create_post(
                            bls,
                            &namespace,
                            &payload_bytes,
                            &proof_bytes,
                            &artifact,
                        )
                        .await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client
                        .create_post(&signer, &namespace, &payload_bytes, &proof_bytes, &artifact)
                        .await?
                };
                ctx.print_json(&receipt)?;
            }
            Self::GetPost { namespace, post_id } => {
                let data = ctx.client.get_post(&namespace, &post_id).await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::ListPosts { namespace } => {
                let data = if let Some(ns) = namespace {
                    ctx.client.get_namespace_posts(&ns).await?
                } else {
                    ctx.client.get_posts().await?
                };
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::Glob { namespace, pattern } => {
                let data = ctx.client.iterate_glob(&namespace, &pattern).await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
        }
        Ok(())
    }
}

fn parse_optional_hex(hex: &str) -> eyre::Result<Vec<u8>> {
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(hex).map_err(|e| eyre::eyre!("invalid hex: {e}"))
}

fn bytes_to_json(data: &[u8]) -> serde_json::Value {
    serde_json::from_slice(data)
        .unwrap_or_else(|_| serde_json::Value::String(format!("0x{}", hex::encode(data))))
}
