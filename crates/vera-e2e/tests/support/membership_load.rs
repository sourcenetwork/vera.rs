use super::{deadline, receipt};
use alloy_primitives::B256;
use std::time::Duration;
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
};
use vera_client::{
    AccessRequest, Actor, BlsSigner, Object, Operation, PERMISSION_LIMITS, VeraClient,
};
use vera_domain::ConsensusPublicKey;

const POLICY: &[u8] = b"name: membership_load\nresources:\n  - name: document\n    relations:\n      - name: reader\n    permissions:\n      - name: read\n        expr: reader\n";

pub(super) struct Load {
    stop: watch::Sender<Option<u64>>,
    task: Option<JoinHandle<(u64, u64)>>,
    policy: String,
    request: AccessRequest,
    trusted: ConsensusPublicKey,
    first: u64,
}

impl Load {
    pub(super) async fn start(
        endpoint: String,
        deployment: u64,
        trusted: ConsensusPublicKey,
    ) -> Self {
        let client = VeraClient::new(endpoint);
        let owner = BlsSigner::new(73u64.into(), deployment).unwrap();
        let reader = BlsSigner::new(74u64.into(), deployment).unwrap();
        let before = client.get_policy_ids().await.unwrap();
        let created = client
            .native_create_policy(&owner, POLICY, 1)
            .await
            .unwrap();
        receipt(&client, created.transaction_hash, &trusted).await;
        let policies: Vec<_> = client
            .get_policy_ids()
            .await
            .unwrap()
            .into_iter()
            .filter(|id| !before.contains(id))
            .collect();
        assert_eq!(policies.len(), 1);
        let policy = policies[0].clone();
        let policy_id: B256 = policy.parse().unwrap();
        let registered = client
            .native_register_object(&owner, policy_id, "report", "document")
            .await
            .unwrap();
        receipt(&client, registered.transaction_hash, &trusted).await;
        let request = AccessRequest {
            actor: Actor(reader.did().parse().unwrap()),
            operations: vec![Operation {
                object: Object {
                    resource: "document".into(),
                    id: "report".into(),
                },
                permission: "read".into(),
            }],
        };
        let (stop, target) = watch::channel(None::<u64>);
        let (ready, started) = oneshot::channel();
        let task_policy = policy.clone();
        let task_request = request.clone();
        let task = tokio::spawn(async move {
            let mut ready = Some(ready);
            let mut cycles = 0;
            loop {
                let final_minimum = *target.borrow();
                for allowed in [true, false] {
                    let outcome = if allowed {
                        client
                            .native_set_relationship(
                                &owner,
                                policy_id,
                                "document",
                                "report",
                                "reader",
                                reader.did(),
                            )
                            .await
                    } else {
                        client
                            .native_delete_relationship(
                                &owner,
                                policy_id,
                                "document",
                                "report",
                                "reader",
                                reader.did(),
                            )
                            .await
                    }
                    .unwrap();
                    let height = receipt(&client, outcome.transaction_hash, &trusted).await;
                    let (_, observed) = client
                        .verify_current_access(
                            &task_policy,
                            &task_request,
                            height,
                            &trusted,
                            PERMISSION_LIMITS,
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        observed, allowed,
                        "grant/revocation during membership changes"
                    );
                    if !allowed {
                        cycles += 1;
                        if let Some(ready) = ready.take() {
                            ready.send(height).unwrap();
                        }
                        if let Some(minimum) = final_minimum {
                            assert!(
                                height > minimum,
                                "load must continue past the last membership write"
                            );
                            return (cycles, height);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        let mut load = Self {
            stop,
            task: Some(task),
            policy,
            request,
            trusted,
            first: 0,
        };
        load.first = tokio::time::timeout(deadline(), started)
            .await
            .unwrap()
            .unwrap();
        load
    }

    pub(super) async fn finish(mut self, admitted: u64, final_write: u64, endpoints: &[String]) {
        assert!(self.first < admitted, "load must precede admission");
        self.stop.send(Some(final_write)).unwrap();
        let (cycles, last) = tokio::time::timeout(deadline(), self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap();
        self.task.take();
        assert!(cycles >= 2);
        for endpoint in endpoints {
            let client = VeraClient::new(endpoint);
            tokio::time::timeout(deadline(), async {
                while client.block_number().await.unwrap() < last {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .unwrap();
            let (_, allowed) = client
                .verify_current_access(
                    &self.policy,
                    &self.request,
                    last,
                    &self.trusted,
                    PERMISSION_LIMITS,
                )
                .await
                .unwrap();
            assert!(!allowed, "active replicas must retain the final revocation");
        }
        eprintln!(
            "native membership load cycles={cycles} first={} last={last} verified_replicas={}",
            self.first,
            endpoints.len()
        );
    }
}

impl Drop for Load {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
