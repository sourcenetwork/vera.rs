use std::sync::Arc;

use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use futures::{StreamExt, stream};
use serde_json::json;
use tokio::time::Instant;
use vera_client::VeraClient;
use vera_modules::acp::abi::IAcp;

use super::{
    fixture::Graph,
    io::{Evidence, Result},
};

pub(super) const VERIFICATION_CONCURRENCY: usize = 8;

pub(super) struct Scenario {
    pub(super) policy: B256,
    pub(super) policy_text: String,
    pub(super) readers: [String; 3],
    pub(super) evidence: Evidence,
}

#[derive(Clone, Copy)]
pub(super) struct Expected {
    pub(super) members: [bool; 2],
    pub(super) blocked_first: bool,
}
pub(super) const GRANTED: Expected = Expected {
    members: [true, true],
    blocked_first: false,
};
pub(super) const REVOKED: Expected = Expected {
    members: [false, false],
    blocked_first: false,
};

impl Scenario {
    pub(super) async fn check(
        &self,
        client: &VeraClient,
        graph: &Graph,
        minimum: u64,
        expected: Expected,
        owners: bool,
    ) -> Result<usize> {
        let mut checked = 0;
        for object in &graph.objects {
            for (index, actor) in self.readers.iter().enumerate() {
                let allowed = index < 2
                    && expected.members[index]
                    && !(index == 0 && expected.blocked_first && object.resource == "document");
                self.evidence
                    .permission(client, &self.policy_text, object, actor, allowed, minimum)
                    .await?;
                checked += 1;
            }
            if owners {
                self.evidence
                    .owner(
                        client,
                        &self.policy_text,
                        object,
                        graph.owner.did(),
                        minimum,
                    )
                    .await?;
            }
        }
        Ok(checked)
    }
}

pub(super) struct Completed {
    pub(super) graph: Graph,
    pub(super) minimum: u64,
}

pub(super) async fn run(
    graph: Graph,
    scenario: Arc<Scenario>,
    client: Arc<VeraClient>,
    scheduled: Instant,
) -> Result<Completed> {
    let started = Instant::now();
    let index = graph.index;
    let phases = [
        (
            "initial_grants",
            graph.registrations(scenario.policy, &scenario.readers),
            GRANTED,
        ),
        (
            "member_revoke",
            vec![graph.member(scenario.policy, &scenario.readers[0], true)],
            Expected {
                members: [false, true],
                blocked_first: false,
            },
        ),
        (
            "member_regrant",
            vec![graph.member(scenario.policy, &scenario.readers[0], false)],
            GRANTED,
        ),
        (
            "blocked_deny",
            vec![graph.blocked(scenario.policy, &scenario.readers[0], false)],
            Expected {
                blocked_first: true,
                ..GRANTED
            },
        ),
        (
            "unblock",
            vec![graph.blocked(scenario.policy, &scenario.readers[0], true)],
            GRANTED,
        ),
    ];
    let mut minimum = 0;
    for (phase, calls, expected) in phases {
        let phase_started = Instant::now();
        let mutations = calls.len();
        let calldata = if mutations == 1 {
            calls.into_iter().next().unwrap()
        } else {
            IAcp::batchCallsCall { calls }.abi_encode().into()
        };
        let result = async {
            minimum = scenario
                .evidence
                .submit(
                    &client,
                    &graph.owner,
                    calldata,
                    mutations,
                    phase,
                    Some(index),
                )
                .await?;
            scenario
                .check(&client, &graph, minimum, expected, false)
                .await
        }
        .await;
        println!(
            "{}",
            json!({"kind":"workflow_phase", "workflow":index, "phase":phase,
            "minimum_revision":minimum, "permission_checks":result.as_ref().ok(),
            "elapsed_ms":phase_started.elapsed().as_secs_f64()*1000.0,
            "failure_kind":result.as_ref().err().map(|e|e.kind), "error":result.as_ref().err().map(|e|&e.message)})
        );
        result?;
    }
    println!(
        "{}",
        json!({"kind":"workflow_completed", "workflow":index,
        "schedule_lag_ms":(started-scheduled).as_secs_f64()*1000.0,
        "elapsed_ms":started.elapsed().as_secs_f64()*1000.0,
        "scheduled_to_complete_ms":scheduled.elapsed().as_secs_f64()*1000.0,
        "finalized_revision":minimum})
    );
    Ok(Completed { graph, minimum })
}

pub(super) async fn verify_replicas(
    scenario: &Scenario,
    clients: &[VeraClient],
    completed: &[Completed],
    minimum: u64,
    expected: Expected,
    phase: &str,
) -> Result<()> {
    let started = Instant::now();
    let mut checks = 0;
    for (replica, client) in clients.iter().enumerate() {
        let mut verified = stream::iter(completed).map(|flow| async move {
            let result = scenario
                .check(client, &flow.graph, minimum, expected, true)
                .await;
            println!(
                "{}",
                json!({"kind":"replica_check", "phase":phase, "replica":replica,
                "workflow":flow.graph.index, "minimum_revision":minimum,
                "permission_checks":result.as_ref().ok(), "owner_checks": result.as_ref().ok().map(|_|4),
                "failure_kind":result.as_ref().err().map(|e|e.kind), "error":result.as_ref().err().map(|e|&e.message)})
            );
            result
        }).buffer_unordered(VERIFICATION_CONCURRENCY);
        while let Some(result) = verified.next().await {
            checks += result?;
        }
    }
    println!(
        "{}",
        json!({"kind":"replica_verification", "phase":phase, "replicas":clients.len(),
        "workflows":completed.len(), "permission_checks":checks, "minimum_revision":minimum,
        "verification_concurrency_per_replica":VERIFICATION_CONCURRENCY,
        "elapsed_ms":started.elapsed().as_secs_f64()*1000.0})
    );
    Ok(())
}
