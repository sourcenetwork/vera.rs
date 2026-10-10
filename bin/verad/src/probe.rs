use std::{io::Write, path::PathBuf, time::Duration};

use vera_client::{ReadinessError, VeraClient};
use vera_genesis::{VeraGenesis, VeraGenesisError};

#[derive(clap::Args, Debug)]
pub(crate) struct ProbeArgs {
    /// JSON-RPC endpoint to observe.
    #[arg(long)]
    url: String,
    /// Independently provisioned genesis containing the deployment's consensus key.
    #[arg(long)]
    genesis: PathBuf,
    /// Minimum finalized checkpoint required by the operator.
    #[arg(long)]
    minimum_height: u64,
    /// Maximum age of each certified revision timestamp, in seconds.
    #[arg(long, default_value_t = 30)]
    max_age_seconds: u64,
    /// Deadline for the entire observation, in seconds.
    #[arg(long, default_value_t = 10)]
    timeout_seconds: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProbeError {
    #[error("cannot load the provisioned consensus configuration")]
    Genesis(#[from] VeraGenesisError),
    #[error("genesis does not contain epoch-0 consensus material")]
    MissingTrust,
    #[error(transparent)]
    Readiness(#[from] ReadinessError),
    #[error("cannot create probe runtime or write its result")]
    Io(#[from] std::io::Error),
    #[error("cannot serialize the readiness result")]
    Json(#[from] serde_json::Error),
}

impl ProbeArgs {
    pub(crate) fn run(&self) -> Result<(), ProbeError> {
        let genesis = VeraGenesis::load(&self.genesis)?;
        let epoch = genesis
            .decode_epoch_info()?
            .ok_or(ProbeError::MissingTrust)?;
        let trusted = *epoch.output.public().public();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let client = VeraClient::new(&self.url);
        let result = runtime.block_on(client.verify_readiness(
            &trusted,
            self.minimum_height,
            Duration::from_secs(self.max_age_seconds),
            Duration::from_secs(self.timeout_seconds),
        ))?;
        let mut output = std::io::stdout().lock();
        serde_json::to_writer(&mut output, &result)?;
        writeln!(output)?;
        Ok(())
    }
}
