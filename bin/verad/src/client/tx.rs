//! Transaction subcommands (receipt, send-raw, send-native).

use clap::Subcommand;

use super::{context::ClientContext, parse};

#[derive(Subcommand, Debug)]
pub(crate) enum TxCommand {
    /// Fetch an EVM transaction receipt.
    Receipt {
        /// Transaction hash (hex, 0x-prefixed).
        hash: String,
    },
    /// Fetch a native (BLS) transaction receipt.
    NativeReceipt {
        /// Transaction hash (hex, 0x-prefixed).
        hash: String,
    },
    /// Submit a raw signed EVM transaction.
    SendRaw {
        /// Hex-encoded signed transaction bytes.
        raw_tx: String,
    },
    /// Submit a raw signed native BLS transaction.
    SendNative {
        /// Hex-encoded signed native transaction bytes.
        raw_tx: String,
    },
}

impl TxCommand {
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::Receipt { hash } => {
                let tx_hash = parse::b256(&hash)?;
                let receipt = ctx.client.get_transaction_receipt(tx_hash).await?;
                ctx.print_json(&receipt)?;
            }
            Self::NativeReceipt { hash } => {
                let tx_hash = parse::b256(&hash)?;
                let receipt = ctx.client.get_native_receipt(tx_hash).await?;
                ctx.print_json(&receipt)?;
            }
            Self::SendRaw { raw_tx } => {
                let bytes = parse::hex_bytes(&raw_tx)?;
                let tx_hash = ctx.client.send_raw_transaction(&bytes).await?;
                ctx.print_json(&serde_json::json!({ "tx_hash": format!("{tx_hash:?}") }))?;
            }
            Self::SendNative { raw_tx } => {
                let bytes = parse::hex_bytes(&raw_tx)?;
                let tx_hash = ctx.client.send_native_tx(&bytes).await?;
                ctx.print_json(&serde_json::json!({ "tx_hash": format!("{tx_hash:?}") }))?;
            }
        }
        Ok(())
    }
}
