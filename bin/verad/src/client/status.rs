//! Status and chain info subcommands.

use clap::Subcommand;

use super::context::ClientContext;

#[derive(Subcommand, Debug)]
pub(crate) enum StatusCommand {
    /// Query node status (vera_nodeStatus).
    Status,
    /// Query chain ID (vera_nodeStatus).
    ChainId,
    /// Query the newest revision of the execution index (vera_nodeStatus).
    BlockNumber,
}

impl StatusCommand {
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::Status => {
                let status = ctx.client.node_status().await?;
                ctx.print_json(&status)?;
            }
            Self::ChainId => {
                let id = ctx.client.chain_id().await?;
                ctx.print_json(&serde_json::json!({ "chain_id": id }))?;
            }
            Self::BlockNumber => {
                let num = ctx.client.block_number().await?;
                ctx.print_json(&serde_json::json!({ "block_number": num }))?;
            }
        }
        Ok(())
    }
}
