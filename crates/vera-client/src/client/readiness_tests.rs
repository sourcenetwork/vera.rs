use std::time::Duration;

use alloy_primitives::B256;
use serde_json::json;
use vera_domain::testing::TestDeployment;

use super::VeraClient;
use super::stub::{Reply, Stub};

fn head(height: u64) -> Reply {
    Reply::Result(json!({
        "chainId": 1, "validatorIndex": 0, "uptimeSecs": 1,
        "finalizedCount": 0, "proposedCount": 0, "headHeight": height,
    }))
}

fn pending(height: u64) -> Reply {
    Reply::Error(json!({
        "code": -32006,
        "message": format!("finalization certificate not found for height {height} within retained proof limits"),
        "data": {"retryable": true, "height": height},
    }))
}

/// A node publishes a revision before a descendant's certificate finalizes
/// it, so readiness waits out pending finality instead of failing.
#[tokio::test]
async fn readiness_waits_for_pending_finality_within_its_deadline() {
    let deployment = TestDeployment::new(3);
    let light = |height| {
        let block = deployment.block(height, B256::repeat_byte(1), 0, B256::ZERO);
        Reply::Result(serde_json::to_value(deployment.light_block(&block)).unwrap())
    };
    let stub = Stub::serve(vec![
        head(5),
        pending(5),
        light(5),
        head(6),
        pending(6),
        light(6),
    ]);
    let client = VeraClient::new(stub.url.clone());
    let readiness = client
        .verify_readiness(
            &deployment.key(),
            5,
            Duration::from_secs(u64::from(u32::MAX)),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!((readiness.initial_height, readiness.height), (5, 6));
    let methods: Vec<_> = stub
        .requests()
        .into_iter()
        .map(|request| request["method"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        methods,
        [
            "vera_nodeStatus",
            "vera_getLightBlock",
            "vera_getLightBlock",
            "vera_nodeStatus",
            "vera_getLightBlock",
            "vera_getLightBlock",
        ]
    );
}

#[tokio::test]
async fn readiness_gives_up_on_pending_finality_at_its_deadline() {
    let deployment = TestDeployment::new(3);
    let stub = Stub::serve(vec![head(5), pending(5)]);
    let client = VeraClient::new(stub.url.clone());
    let result = client
        .verify_readiness(
            &deployment.key(),
            5,
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .await;
    assert!(matches!(result, Err(crate::ReadinessError::Deadline)));
    stub.requests();
}
