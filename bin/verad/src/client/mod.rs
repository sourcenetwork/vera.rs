//! `verad client` — CLI for interacting with a running vera node.

mod acp;
mod bulletin;
mod context;
mod keys;
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

    /// Target chain ID.
    #[arg(long, env = "VERA_CHAIN_ID", default_value = "9001", global = true)]
    client_chain_id: u64,

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
    /// Query node status (vera_nodeStatus).
    Status,
    /// Query chain ID (eth_chainId).
    ChainId,
    /// Query latest block number (eth_blockNumber).
    BlockNumber,
    /// Query balance of an address (eth_getBalance).
    Balance {
        /// Ethereum address (hex, 0x-prefixed).
        address: String,
    },

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
    pub(crate) fn run(self) -> eyre::Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(self.run_async())
    }

    async fn run_async(self) -> eyre::Result<()> {
        let ctx = ClientContext::new(
            &self.url,
            self.key.as_deref(),
            self.bls_key.as_deref(),
            self.client_chain_id,
            self.compact,
        )?;

        match self.command {
            ClientCommand::CheckRead(args) => {
                let report = args.run(&ctx.client).await?;
                ctx.print_json(&report)
            }
            ClientCommand::Status => status::StatusCommand::Status.run(&ctx).await,
            ClientCommand::ChainId => status::StatusCommand::ChainId.run(&ctx).await,
            ClientCommand::BlockNumber => status::StatusCommand::BlockNumber.run(&ctx).await,
            ClientCommand::Balance { address } => {
                status::StatusCommand::Balance { address }.run(&ctx).await
            }
            ClientCommand::Tx(cmd) => cmd.run(&ctx).await,
            ClientCommand::Acp(cmd) => cmd.run(&ctx).await,
            ClientCommand::Bulletin(cmd) => cmd.run(&ctx).await,
            ClientCommand::Vera(cmd) => cmd.run(&ctx).await,
            ClientCommand::Keys(cmd) => cmd.run(&ctx).await,
        }
    }
}
