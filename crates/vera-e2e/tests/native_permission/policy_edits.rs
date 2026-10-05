use super::*;

const OWNER_ONLY: &str = "name: native-permissions
resources:
  - name: document
    permissions:
      - name: read
        expr: owner
";

pub(super) async fn exercise(
    cluster: &mut TestCluster,
    policy: &str,
    owner: &BlsSigner,
    request: &AccessRequest,
    trusted: &ConsensusPublicKey,
) {
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let mut minimum = 0;
    for definition in [OWNER_ONLY, POLICY] {
        minimum = submit(
            &client,
            owner,
            IAcp::editPolicyCall {
                policyId: policy.parse().unwrap(),
                policy: definition.as_bytes().to_vec().into(),
                marshalType: 1,
            },
        )
        .await;
        for index in 0..cluster.node_count() {
            let replica = VeraClient::new(cluster.node(index).rpc_url());
            let (_, allowed) = replica
                .verify_current_access(policy, request, minimum, trusted, PERMISSION_LIMITS)
                .await
                .unwrap();
            assert!(!allowed, "node {index} must not reuse removed grants");
            let object = &request.operations[0].object;
            let ownership = replica
                .read_current_policy_prefix(
                    policy,
                    &vera_client::object_owner_prefix(policy, object).unwrap(),
                    minimum,
                    trusted,
                    RECORD_PROOF_BYTES,
                )
                .await
                .unwrap();
            assert_eq!(
                ownership
                    .verify_object_owner(policy, object, minimum, trusted)
                    .unwrap()
                    .unwrap()
                    .0
                    .as_str(),
                owner.did()
            );
        }
    }
    cluster.restart_node(0).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let restarted = VeraClient::new(cluster.node(0).rpc_url());
    let (_, allowed) = restarted
        .verify_current_access(policy, request, minimum, trusted, PERMISSION_LIMITS)
        .await
        .unwrap();
    assert!(!allowed, "restart must preserve grant invalidation");
    let granted = submit(
        &restarted,
        owner,
        IAcp::setRelationshipCall {
            policyId: policy.parse().unwrap(),
            resource: "document".into(),
            objectId: "report".into(),
            relation: "reader".into(),
            actor: READER.into(),
        },
    )
    .await;
    for index in 0..cluster.node_count() {
        let replica = VeraClient::new(cluster.node(index).rpc_url());
        let (_, allowed) = replica
            .verify_current_access(policy, request, granted, trusted, PERMISSION_LIMITS)
            .await
            .unwrap();
        assert!(allowed, "node {index} must use the newly granted relation");
    }
}
