//! Host load and the served node's CPU time.

use super::*;

pub(super) fn load_average() -> f64 {
    let output = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

/// Waits for the host's one-minute load to fall under the limit within the shared budget.
pub(super) async fn quiet_host(budget: &mut Duration) -> f64 {
    let limit: f64 = std::env::var("READ_MAX_LOAD").map_or(8.0, |value| value.parse().unwrap());
    loop {
        let load = load_average();
        if load < limit || budget.is_zero() {
            return load;
        }
        let pause = Duration::from_secs(5).min(*budget);
        tokio::time::sleep(pause).await;
        *budget -= pause;
    }
}

/// Process CPU time in seconds, user plus system, as `ps` reports it.
pub(super) fn cpu_seconds(pid: u32) -> f64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    text.trim().split(':').fold(0.0, |total, part| {
        total * 60.0 + part.parse::<f64>().unwrap()
    })
}
