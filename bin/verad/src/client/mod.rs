//! `verad client` — CLI for interacting with a running vera node.

mod acp;
mod bulletin;
mod chain_id;
mod context;
mod keys;
mod parse;
mod read_check;
mod status;
mod tx;
mod vera_mod;

use clap::{Args, Subcommand};

use self::context::ClientContext;

#[derive(Args, Debug)]
pub(crate) struct ClientArgs {
    /// JSON-RPC endpoint URL.
    #[arg(
        long,
        env = "VERA_RPC_URL",
        default_value = "http://localhost:8545",
        global = true
    )]
    url: String,

    /// Hex secp256k1 private key for EVM transaction signing.
    #[arg(long, env = "VERA_KEY", global = true)]
    key: Option<String>,

    /// Hex BLS12-381 private key for native transaction signing.
    #[arg(long, env = "VERA_BLS_KEY", global = true)]
    bls_key: Option<String>,

    /// Target chain ID; the same as the top-level --chain-id. Without either
    /// flag the client uses VERA_CHAIN_ID, then 9001.
    #[arg(long, global = true)]
    client_chain_id: Option<u64>,

    /// Output compact single-line JSON instead of pretty-printed.
    #[arg(long, global = true)]
    compact: bool,

    #[command(subcommand)]
    command: ClientCommand,
}

#[derive(Subcommand, Debug)]
enum ClientCommand {
    /// Verify a native policy read against independently selected trust, checkpoint and age.
    CheckRead(read_check::ReadCheckArgs),
    #[command(flatten)]
    Status(status::StatusCommand),

    /// Transaction operations (receipt, send).
    #[command(subcommand)]
    Tx(tx::TxCommand),

    /// ACP (Access Control Policy) operations.
    #[command(subcommand)]
    Acp(acp::AcpCommand),

    /// Bulletin board operations.
    #[command(subcommand)]
    Bulletin(bulletin::BulletinCommand),

    /// Vera module operations (chain config, JWS tokens).
    #[command(subcommand)]
    Vera(vera_mod::VeraCommand),

    /// Key management utilities.
    #[command(subcommand)]
    Keys(keys::KeysCommand),
}

impl ClientArgs {
    /// Run the command; `chain_id` is the top-level `--chain-id`.
    pub(crate) fn run(self, chain_id: Option<u64>) -> eyre::Result<()> {
        let environment = std::env::var(chain_id::ENVIRONMENT).ok();
        let chain_id = chain_id::resolve(self.client_chain_id, chain_id, environment.as_deref())?;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(self.run_async(chain_id))
    }

    async fn run_async(self, chain_id: u64) -> eyre::Result<()> {
        let ctx = ClientContext::new(
            &self.url,
            self.key.as_deref(),
            self.bls_key.as_deref(),
            chain_id,
            self.compact,
        )?;

        match self.command {
            ClientCommand::CheckRead(args) => {
                let report = args.run(&ctx.client).await?;
                ctx.print_json(&report)
            }
            ClientCommand::Status(cmd) => cmd.run(&ctx).await,
            ClientCommand::Tx(cmd) => cmd.run(&ctx).await,
            ClientCommand::Acp(cmd) => cmd.run(&ctx).await,
            ClientCommand::Bulletin(cmd) => cmd.run(&ctx).await,
            ClientCommand::Vera(cmd) => cmd.run(&ctx).await,
            ClientCommand::Keys(cmd) => cmd.run(&ctx).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Commands};

    fn client(arguments: &[&str]) -> ClientArgs {
        match Cli::try_parse_from(arguments).unwrap().command.unwrap() {
            Commands::Client(args) => args,
            other => panic!("expected a client command, got {other:?}"),
        }
    }

    #[test]
    fn status_commands_keep_their_top_level_names() {
        for arguments in [
            vec!["verad", "client", "status"],
            vec!["verad", "client", "chain-id"],
            vec!["verad", "client", "block-number"],
            vec!["verad", "client", "balance", "0x00"],
        ] {
            assert!(matches!(
                client(&arguments).command,
                ClientCommand::Status(_)
            ));
        }
    }

    #[test]
    fn client_chain_id_is_unset_unless_its_flag_is_given() {
        assert_eq!(client(&["verad", "client", "status"]).client_chain_id, None);
        assert_eq!(
            client(&["verad", "client", "--chain-id", "1234", "status"]).client_chain_id,
            None
        );
        assert_eq!(
            client(&["verad", "client", "status", "--client-chain-id", "42"]).client_chain_id,
            Some(42)
        );
    }
}
