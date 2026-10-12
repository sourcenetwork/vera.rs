//! Bounded RPC readiness checks for managed test clusters.

use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 8 * 1024;

/// Readiness failures without endpoint or remote error text.
#[derive(Debug, thiserror::Error)]
pub enum HealthCheckError {
    /// The local HTTP client could not be initialized.
    #[error("could not initialize the RPC readiness client")]
    Client(#[from] reqwest::Error),
    /// The listed member positions did not answer before the shared deadline.
    #[error("RPC readiness timed out after {timeout:?} for members {unavailable_nodes:?}")]
    Timeout {
        /// Configured total wait.
        timeout: Duration,
        /// Positions in the supplied endpoint list.
        unavailable_nodes: Vec<usize>,
    },
}

impl HealthCheckError {
    /// Member positions that did not return a valid readiness response.
    pub fn unavailable_nodes(&self) -> Option<&[usize]> {
        match self {
            Self::Timeout {
                unavailable_nodes, ..
            } => Some(unavailable_nodes),
            Self::Client(_) => None,
        }
    }
}

/// Polling interval and total readiness deadline.
#[derive(Clone, Debug)]
pub struct HealthCheckConfig {
    /// Interval between readiness rounds.
    pub poll_interval: Duration,
    /// Shared deadline for all member checks.
    pub timeout: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(50),
            timeout: Duration::from_secs(5),
        }
    }
}

fn valid_response(body: &[u8]) -> bool {
    let Ok(response) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    response["jsonrpc"] == "2.0"
        && response["id"] == 1
        && response["error"].is_null()
        && response["result"]
            .as_str()
            .and_then(|id| id.strip_prefix("0x"))
            .is_some_and(|id| {
                !id.is_empty()
                    && id.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && u64::from_str_radix(id, 16).is_ok()
            })
}

async fn check_node_health(client: &reqwest::Client, url: &str) -> bool {
    let request = serde_json::json!({
        "jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1
    });
    let Ok(mut response) = client.post(url).json(&request).send().await else {
        return false;
    };
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return false;
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if chunk.len() <= MAX_RESPONSE_BYTES - body.len() => {
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return valid_response(&body),
            _ => return false,
        }
    }
}

/// Wait for every member to return a valid RPC response within one shared deadline.
pub async fn wait_all_healthy(
    rpc_urls: &[String],
    config: &HealthCheckConfig,
) -> Result<(), HealthCheckError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;
    let deadline = tokio::time::Instant::now() + config.timeout;
    loop {
        let mut checks = tokio::task::JoinSet::new();
        for (member, url) in rpc_urls.iter().enumerate() {
            let client = client.clone();
            let url = url.clone();
            checks.spawn(async move {
                let ready = tokio::time::timeout_at(deadline, check_node_health(&client, &url))
                    .await
                    .unwrap_or(false);
                (member, ready)
            });
        }
        let mut ready = vec![false; rpc_urls.len()];
        while let Some(result) = checks.join_next().await {
            if let Ok((member, available)) = result {
                ready[member] = available;
            }
        }
        let unavailable_nodes = ready
            .into_iter()
            .enumerate()
            .filter_map(|(member, available)| (!available).then_some(member))
            .collect::<Vec<_>>();
        if unavailable_nodes.is_empty() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(HealthCheckError::Timeout {
                timeout: config.timeout,
                unavailable_nodes,
            });
        }
        tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + config.poll_interval))
            .await;
    }
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
