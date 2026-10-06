//! Local mixed-policy workload; see docs/mixed-policy-workload.md.

#[path = "mixed_policy_workload/fixture.rs"]
mod fixture;
#[path = "mixed_policy_workload/io.rs"]
mod io;
#[path = "operation_baseline/resources.rs"]
mod resources;
#[path = "mixed_policy_workload/workflow.rs"]
mod workflow;

use std::{path::PathBuf, process::ExitCode, sync::Arc, time::Duration};

use alloy_sol_types::SolCall;
use serde_json::json;
use tokio::{task::JoinSet, time::Instant};
use vera_client::{BlsSigner, VeraClient};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::acp::abi::IAcp;

use fixture::{DEPLOYMENT, Graph, POLICY};
use io::{Counts, Evidence, Failure, Result};
use workflow::{Completed, GRANTED, REVOKED, Scenario};

struct Config {
    count: usize,
    rate: usize,
    outstanding: usize,
    deadline: Duration,
    binary: PathBuf,
}
impl Config {
    fn read() -> Result<Self> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.len() > 4 {
            return Err(Failure::new(
                "configuration",
                "usage: mixed_policy_workload [workflows=16] [arrivals/sec=2] [outstanding=8] [deadline-seconds=900]",
            ));
        }
        let parse = |index: usize, default: usize, maximum: usize| -> Result<usize> {
            let value = args
                .get(index)
                .map_or(Ok(default), |v: &String| v.parse::<usize>())
                .map_err(|e| Failure::new("configuration", e.to_string()))?;
            if !(1..=maximum).contains(&value) {
                return Err(Failure::new(
                    "configuration",
                    format!("argument {index} must be within 1..={maximum}"),
                ));
            }
            Ok(value)
        };
        if std::env::var("VERA_E2E_KEEP").as_deref() != Ok("1") {
            return Err(Failure::new(
                "configuration",
                "set VERA_E2E_KEEP=1 to retain failure evidence",
            ));
        }
        let binary = std::env::var_os("VERAD_BINARY")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && p.is_file())
            .ok_or_else(|| {
                Failure::new(
                    "configuration",
                    "VERAD_BINARY must name the staged release daemon",
                )
            })?;
        Ok(Self {
            count: parse(0, 16, 2048)?,
            rate: parse(1, 2, 100)?,
            outstanding: parse(2, 8, 64)?,
            deadline: Duration::from_secs(parse(3, 900, 86400)? as u64),
            binary,
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let counts = Arc::new(Counts::default());
    let result = match Config::read() {
        Err(error) => Err(error),
        Ok(config) => {
            let deadline = config.deadline;
            tokio::time::timeout(deadline, run(config, counts.clone()))
                .await
                .unwrap_or_else(|_| {
                    Err(Failure::new(
                        "deadline",
                        format!(
                            "whole-run deadline {deadline:?} elapsed; unfinished submissions remain unresolved"
                        ),
                    ))
                })
        }
    };
    println!(
        "{}",
        json!({"kind":"result", "success":result.is_ok(), "counts":counts.json(),
        "failure_kind":result.as_ref().err().map(|e|e.kind),"error":result.as_ref().err().map(|e|&e.message)})
    );
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn run(config: Config, counts: Arc<Counts>) -> Result<()> {
    let restart_deadline = Duration::from_secs(30) + vera_e2e::readiness_deadline();
    println!(
        "{}",
        json!({"kind":"configuration", "schema_version":1, "workflows":config.count,
        "scheduled_arrivals_per_second":config.rate, "maximum_outstanding_workflows":config.outstanding,
        "whole_run_deadline_seconds":config.deadline.as_secs(), "request_deadline_seconds":30, "workflow_deadline_seconds":120,
        "validators":4,"epoch_revisions":192,"timing":"normal","pipelined":true,
        "debug_assertions":cfg!(debug_assertions),
        "verification_concurrency_per_replica":workflow::VERIFICATION_CONCURRENCY,
        "startup_readiness_seconds":30, "restart_readiness_seconds":restart_deadline.as_secs_f64(),
        "daemon":config.binary,"objects_per_workflow":4,"readers":2,"outsiders":1})
    );
    let trusted = *KeySet::builder()
        .seed(DEPLOYMENT)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let mut cluster = TestCluster::builder()
        .binary(&config.binary)
        .nodes(4)
        .seed(DEPLOYMENT)
        .chain_id(DEPLOYMENT)
        .preset(ConsensusPreset::Normal)
        .genesis(
            GenesisBuilder::devnet()
                .blocks_per_epoch(192)
                .simplex(Default::default()),
        )
        .build()
        .await
        .map_err(|e| Failure::new("startup", e.to_string()))?;
    println!(
        "{}",
        json!({"kind":"artifacts", "node_directories":(0..4).map(|i|&cluster.node(i).data_dir).collect::<Vec<_>>()})
    );
    cluster
        .wait_ready(Duration::from_secs(30))
        .await
        .map_err(|e| Failure::new("startup", e.to_string()))?;
    let client = Arc::new(VeraClient::new(cluster.node(0).rpc_url()));
    let evidence = Evidence { trusted, counts };
    let policy_owner = BlsSigner::new(100_000u64.into(), DEPLOYMENT).unwrap();
    evidence
        .submit(
            &client,
            &policy_owner,
            IAcp::createPolicyCall {
                policy: POLICY.as_bytes().to_vec().into(),
                marshalType: 1,
            }
            .abi_encode()
            .into(),
            1,
            "policy_setup",
            None,
        )
        .await?;
    let ids = client
        .get_policy_ids()
        .await
        .map_err(|e| Failure::new("setup", e.to_string()))?;
    if ids.len() != 1 {
        return Err(Failure::new("setup", "expected exactly one shared policy"));
    }
    let policy_text = ids[0].clone();
    let policy = policy_text
        .parse()
        .map_err(|e| Failure::new("setup", format!("{e}")))?;
    let readers = [200_000u64, 200_001, 200_002].map(|key| {
        BlsSigner::new(key.into(), DEPLOYMENT)
            .unwrap()
            .did()
            .to_string()
    });
    let scenario = Arc::new(Scenario {
        policy,
        policy_text,
        readers,
        evidence,
    });
    resources::storage(&cluster, "before_workload").await;
    let (stop, sampler) = resources::start(&cluster);
    let measured = measured(&config, &scenario, &client).await;
    let _ = stop.send(());
    sampler
        .await
        .map_err(|e| Failure::new("sampling", e.to_string()))?;
    let completed = measured?;
    resources::storage(&cluster, "after_workload").await;
    let clients: Vec<_> = cluster.rpc_urls().iter().map(VeraClient::new).collect();
    let mut minimum = completed
        .iter()
        .map(|v| v.minimum)
        .max()
        .ok_or_else(|| Failure::new("verification", "no workflows completed"))?;
    workflow::verify_replicas(
        &scenario,
        &clients,
        &completed,
        minimum,
        GRANTED,
        "after_workload",
    )
    .await?;
    for (phase, definition) in [
        ("remove_member", fixture::without_member()),
        ("reintroduce_member", POLICY.to_string()),
    ] {
        minimum = scenario
            .evidence
            .submit(
                &client,
                &policy_owner,
                IAcp::editPolicyCall {
                    policyId: policy,
                    policy: definition.into_bytes().into(),
                    marshalType: 1,
                }
                .abi_encode()
                .into(),
                1,
                phase,
                None,
            )
            .await?;
        workflow::verify_replicas(&scenario, &clients, &completed, minimum, REVOKED, phase).await?;
    }
    for flow in &completed {
        let calls = flow.graph.grants(policy, &scenario.readers);
        let mutations = calls.len();
        minimum = scenario
            .evidence
            .submit(
                &client,
                &flow.graph.owner,
                IAcp::batchCallsCall { calls }.abi_encode().into(),
                mutations,
                "restore_current_grants",
                Some(flow.graph.index),
            )
            .await?;
    }
    workflow::verify_replicas(
        &scenario,
        &clients,
        &completed,
        minimum,
        GRANTED,
        "after_explicit_regrant",
    )
    .await?;
    cluster.kill_node(3);
    let restart = Instant::now();
    cluster
        .restart_node(3)
        .map_err(|e| Failure::new("restart", e.to_string()))?;
    cluster
        .wait_ready(restart_deadline)
        .await
        .map_err(|e| Failure::new("restart", e.to_string()))?;
    let recovered_clients: Vec<_> = cluster.rpc_urls().iter().map(VeraClient::new).collect();
    workflow::verify_replicas(
        &scenario,
        &recovered_clients,
        &completed,
        minimum,
        GRANTED,
        "after_hard_restart",
    )
    .await?;
    println!(
        "{}",
        json!({"kind":"restart", "replica":3,"verified_workflows":completed.len(),
        "minimum_revision":minimum,"elapsed_ms":restart.elapsed().as_secs_f64()*1000.0})
    );
    resources::storage(&cluster, "after_verification").await;
    Ok(())
}

async fn measured(
    config: &Config,
    scenario: &Arc<Scenario>,
    client: &Arc<VeraClient>,
) -> Result<Vec<Completed>> {
    let started = Instant::now();
    let before = scenario.evidence.counts.json();
    let mut tasks = JoinSet::new();
    let mut completed = Vec::with_capacity(config.count);
    let mut failures = Vec::new();
    for index in 0..config.count {
        while tasks.len() >= config.outstanding {
            collect(
                tasks.join_next().await.unwrap(),
                &mut completed,
                &mut failures,
            );
        }
        let scheduled = started + Duration::from_secs_f64(index as f64 / config.rate as f64);
        tokio::time::sleep_until(scheduled).await;
        let scenario = scenario.clone();
        let client = client.clone();
        tasks.spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(120),
                workflow::run(Graph::new(index), scenario, client, scheduled),
            )
            .await
            .unwrap_or_else(|_| {
                Err(Failure::new(
                    "deadline",
                    format!(
                        "workflow {index} exceeded 120 seconds; pending submission remains unresolved"
                    ),
                ))
            })
        });
    }
    while let Some(result) = tasks.join_next().await {
        collect(result, &mut completed, &mut failures);
    }
    println!(
        "{}",
        json!({"kind":"workload_summary", "scheduled_workflows":config.count,
        "completed_workflows":completed.len(),"failed_workflows":failures.len(),
        "elapsed_seconds":started.elapsed().as_secs_f64(),"counts_before":before,
        "counts_after":scenario.evidence.counts.json(),"failures":failures.iter().map(|e|json!({"kind":e.kind,"error":e.message})).collect::<Vec<_>>()})
    );
    if let Some(error) = failures.into_iter().next() {
        return Err(error);
    }
    if completed.len() != config.count {
        return Err(Failure::new("verification", "workflow count differs"));
    }
    completed.sort_unstable_by_key(|v| v.graph.index);
    Ok(completed)
}

fn collect(
    result: std::result::Result<Result<Completed>, tokio::task::JoinError>,
    completed: &mut Vec<Completed>,
    failures: &mut Vec<Failure>,
) {
    match result {
        Ok(Ok(value)) => completed.push(value),
        Ok(Err(error)) => failures.push(error),
        Err(error) => failures.push(Failure::new("worker", error.to_string())),
    }
}
