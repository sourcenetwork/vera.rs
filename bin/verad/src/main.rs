//! verad — SourceHub validator node.

#![recursion_limit = "256"]

use clap::Parser;
use tracing_subscriber::prelude::*;

mod cli;
mod client;
mod rpc_address;
mod testnet;

fn main() -> eyre::Result<()> {
    vera_cli::Backtracing::enable();
    vera_cli::SigsegvHandler::install();

    let span_events = if std::env::var("VERA_TRACE_SPANS").as_deref() == Ok("1") {
        tracing_subscriber::fmt::format::FmtSpan::CLOSE
    } else {
        tracing_subscriber::fmt::format::FmtSpan::NONE
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_span_events(span_events))
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    cli::Cli::parse().run()
}
