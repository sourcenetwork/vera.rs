//! One actor key in every accepted spelling, for certified permission reads.

use vera_client::{AccessRequest, Actor, PERMISSION_LIMITS, VeraClient};

/// One secp256k1 key: its canonical DID, then its uncompressed Base58BTC,
/// compressed Base64URL and uncompressed Base64URL spellings.
pub(super) const ACTOR: [&str; 4] = [
    "did:key:zQ3shkpqZaRR4P8KsTE1vXHRtjAAjKPfHFeu5B8vmPnW79A51",
    "did:key:z7r8oqKHB4AwqvHNsPgHdGic7GYAWgVjrWsKwwazb9epJXZ3wBwVMJd5xrWTvrmDBFLJ1RZAx13earK9RyJzj8nqWbvG6",
    "did:key:u5wEDW-XpR4IJZ0qW5g8fA39hdlQP0AH6HWRpR3DFancJxCw",
    "did:key:u5wEEW-XpR4IJZ0qW5g8fA39hdlQP0AH6HWRpR3DFancJxCwDWojDhD2_ixDVLMceJszhceGqHjL44ZPJ9qa9jwe4vw",
];

pub(super) fn respelled(request: &AccessRequest, spelling: &str) -> AccessRequest {
    AccessRequest {
        actor: Actor(spelling.parse().unwrap()),
        ..request.clone()
    }
}

/// Every spelling of the actor gets one certified decision at `revision`.
pub(super) async fn every_spelling(
    client: &VeraClient,
    policy: &str,
    request: &AccessRequest,
    revision: &vera_domain::LightBlock,
    trusted: &vera_domain::ConsensusPublicKey,
    expected: bool,
) {
    for spelling in ACTOR {
        let request = respelled(request, spelling);
        let at = client.verify_access_at(policy, &request, revision, trusted, PERMISSION_LIMITS);
        assert_eq!(at.await.unwrap(), expected);
        let (current, allowed) = client
            .verify_current_access(
                policy,
                &request,
                revision.height,
                trusted,
                PERMISSION_LIMITS,
            )
            .await
            .unwrap();
        assert_eq!((current.height, allowed), (revision.height, expected));
    }
}
