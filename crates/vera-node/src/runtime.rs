use commonware_runtime::tokio;

/// Configure the node runtime.
pub fn configure_storage_buffers(runtime: tokio::Config) -> tokio::Config {
    runtime
}
