use super::*;
use std::time::Duration;
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use vera_modules::acp::{delegated_operation::DelegatedOperation, operation::OperationRecord};

pub(super) async fn publication(cluster: &TestCluster, minimum: u64) {
    let clients: Vec<_> = cluster
        .rpc_urls()
        .into_iter()
        .map(VeraClient::new)
        .collect();
    let mut observed = vec![String::from("not polled"); clients.len()];
    let ready = tokio::time::timeout(vera_e2e::readiness_deadline(), async {
        loop {
            let mut ready = true;
            for (index, client) in clients.iter().enumerate() {
                let height = client.block_number().await;
                ready &= matches!(&height, Ok(height) if *height >= minimum);
                observed[index] = format!("node {index}: {height:?}");
            }
            if ready {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        ready.is_ok(),
        "publication of fixed revision {minimum} failed: {observed:?}"
    );
}

pub(super) async fn submit(
    cluster: &TestCluster,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: impl SolCall,
) -> vera_client::TransactionReceipt {
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    let receipt = client
        .wait_for_receipt(
            id,
            vera_e2e::RECEIPT_POLL_INTERVAL,
            vera_e2e::RECEIPT_POLL_ATTEMPTS,
        )
        .await
        .unwrap();
    assert_eq!(receipt.status, 1, "transaction {id} reverted");
    publication(cluster, receipt.block_number + 2).await;
    // Poll only publication. Evidence is requested and verified once on each member.
    for index in 0..cluster.node_count() {
        let replica = VeraClient::new(cluster.node(index).rpc_url());
        let response = replica
            .read_receipt(id, trusted)
            .await
            .unwrap()
            .expect("published certified receipt");
        let certified = response.verify(id, trusted).unwrap();
        assert!(
            certified.success(),
            "node {index}: certified transaction failed"
        );
        assert_eq!(certified.tx_hash, receipt.transaction_hash);
        assert_eq!(response.revision.height, receipt.block_number);
    }
    receipt
}

pub(super) fn command(token: &str, policy: B256, command: &PolicyCmd) -> IAcp::bearerPolicyCmdCall {
    IAcp::bearerPolicyCmdCall {
        bearerToken: token.into(),
        policyId: policy,
        cmd: serde_json::to_vec(command).unwrap().into(),
    }
}

pub(super) struct Controller {
    pub key: k256::ecdsa::SigningKey,
    pub actor: String,
    pub token: String,
    pub issued: u64,
    pub expires: u64,
    pub genesis: [u8; 32],
}

impl Controller {
    pub(super) async fn archive(
        &self,
        cluster: &TestCluster,
        worker: &BlsSigner,
        trusted: &ConsensusPublicKey,
        policy: &str,
        tag: u8,
        expected: u64,
    ) -> u64 {
        let command = PolicyCmd::ArchiveObject(Object {
            resource: "file".into(),
            id: "report".into(),
        });
        let digest = DelegatedOperation::PolicyCommand(policy, &command)
            .digest()
            .unwrap();
        let mut id = [tag; 32];
        id[..8].copy_from_slice(&self.expires.to_be_bytes());
        let id = OperationId(id);
        let claims = JwtClaims {
            iss: self.actor.clone(),
            sub: worker.did().into(),
            exp: self.expires,
            aud: format!("vera:{DEPLOYMENT}"),
            scope: DelegationScope::PolicyCommands,
            iat: self.issued,
            nbf: self.issued,
            relay: None,
            request: Some(OperationClaim {
                id,
                digest,
                genesis_id: self.genesis,
            }),
        };
        let token = vera_client::create_operation_token(&self.key, &claims).unwrap();
        let receipt = submit(
            cluster,
            worker,
            trusted,
            self::command(&token, policy.parse().unwrap(), &command),
        )
        .await;
        let key = vera_modules::acp::operation::operation_key(&self.actor, id).unwrap();
        for index in 0..cluster.node_count() {
            let replica = VeraClient::new(cluster.node(index).rpc_url());
            let response = replica
                .read_current_record(
                    ModuleId::Acp,
                    &key,
                    receipt.block_number,
                    trusted,
                    RECORD_PROOF_BYTES,
                )
                .await
                .unwrap();
            let outcome: OperationRecord = serde_json::from_slice(
                response
                    .record
                    .value
                    .as_ref()
                    .expect("retained archive result"),
            )
            .unwrap();
            assert_eq!(outcome.id, id);
            assert_eq!(outcome.digest, digest);
            assert_eq!(outcome.actor, self.actor);
            assert_eq!(outcome.worker, worker.did());
            assert_eq!(outcome.submission, receipt.transaction_hash.0);
            assert_eq!(outcome.revision.block_height, receipt.block_number);
            let result: PolicyCmdResult = serde_json::from_value(outcome.result).unwrap();
            assert!(
                matches!(result, PolicyCmdResult::ArchiveObject { found: true, relationships_removed } if relationships_removed == expected),
                "node {index}: archive must remove exactly {expected}, got {result:?}"
            );
        }
        receipt.block_number
    }
}

pub(super) struct Expected<'a> {
    pub allowed: bool,
    pub owned: bool,
    pub incarnation: u64,
    pub rows: usize,
    pub incoming: &'a RelationshipRecord,
}

pub(super) async fn check_members(
    cluster: &TestCluster,
    policy: &str,
    owner: &str,
    reader: &str,
    minimum: u64,
    trusted: &ConsensusPublicKey,
    expected: Expected<'_>,
) {
    publication(cluster, minimum).await;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let owner_prefix = vera_client::object_owner_prefix(policy, &object).unwrap();
    for index in 0..cluster.node_count() {
        let client = VeraClient::new(cluster.node(index).rpc_url());
        for target in ["report", "child"] {
            let request = AccessRequest {
                actor: Actor(reader.parse().unwrap()),
                operations: vec![Operation {
                    object: Object {
                        resource: "file".into(),
                        id: target.into(),
                    },
                    permission: "read".into(),
                }],
            };
            let (_, allowed) = client
                .verify_current_access(policy, &request, minimum, trusted, PERMISSION_LIMITS)
                .await
                .unwrap();
            assert_eq!(
                allowed, expected.allowed,
                "node {index}, {target}: reader permission"
            );
        }
        let owner_request = AccessRequest {
            actor: Actor(owner.parse().unwrap()),
            operations: vec![Operation {
                object: object.clone(),
                permission: "read".into(),
            }],
        };
        let (_, allowed) = client
            .verify_current_access(policy, &owner_request, minimum, trusted, PERMISSION_LIMITS)
            .await
            .unwrap();
        assert_eq!(allowed, expected.owned, "node {index}: owner permission");
        let ownership = client
            .read_current_policy_prefix(policy, &owner_prefix, minimum, trusted, RECORD_PROOF_BYTES)
            .await
            .unwrap();
        assert_eq!(
            ownership
                .verify_object_owner(policy, &object, minimum, trusted)
                .unwrap(),
            expected.owned.then(|| Actor(owner.parse().unwrap())),
            "node {index}: certified owner"
        );
        let state = client
            .read_current_record(
                ModuleId::Acp,
                &object_state::key(policy, "file", "report"),
                minimum,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await
            .unwrap();
        let incarnation = state
            .record
            .value
            .as_deref()
            .map(|value| object_state::decode(value))
            .transpose()
            .unwrap()
            .unwrap_or(0);
        assert_eq!(
            incarnation, expected.incarnation,
            "node {index}: object incarnation"
        );
        let page = client
            .read_relationship_page(policy.parse().unwrap(), None, 16, minimum, trusted)
            .await
            .unwrap();
        assert!(
            page.continuation.is_none(),
            "small fixture must fit one physical page"
        );
        assert_eq!(
            page.records.len(),
            expected.rows,
            "node {index}: current rows"
        );
        let incoming = page
            .records
            .iter()
            .find(|row| row.relationship == expected.incoming.relationship)
            .expect("incoming userset must remain");
        assert_eq!(
            serde_json::to_value(incoming).unwrap(),
            serde_json::to_value(expected.incoming).unwrap(),
            "node {index}: incoming userset changed"
        );
        for row in page.records.iter().filter(|row| {
            row.relationship.object_id == "report" && row.relationship.relation != "owner"
        }) {
            assert_eq!(row.incarnation, expected.incarnation);
        }
    }
}

pub(super) async fn old_rows_absent(
    cluster: &TestCluster,
    rows: &[RelationshipRecord],
    minimum: u64,
    trusted: &ConsensusPublicKey,
) {
    publication(cluster, minimum).await;
    for index in 0..cluster.node_count() {
        let client = VeraClient::new(cluster.node(index).rpc_url());
        for row in rows {
            let key = keys::relationship_generation_key(
                &row.policy_id,
                row.generations,
                &keys::relationship_storage_key(&row.relationship, row.incarnation),
            );
            let response = client
                .read_current_record(ModuleId::Acp, &key, minimum, trusted, RECORD_PROOF_BYTES)
                .await
                .unwrap();
            assert!(
                response.record.value.is_none(),
                "node {index}: old incarnation row survived cleanup"
            );
        }
    }
}
