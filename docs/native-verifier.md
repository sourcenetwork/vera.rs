# Native client proof verification

`vera-verifier` exposes receipt, current-record, live object-owner, permission and stored access-decision
verification through the C interface in `crates/vera-verifier/include/vera_verifier.h`. It calls the same
`ReceiptResponse::verify`, `RecordResponse::verify`,
`PolicyPrefixResponse::verify_object_owner` and `PermissionResponse::verify`
implementations as Rust clients. Build the shared library with `cargo build -p vera-verifier`.

Each call takes UTF-8 JSON bytes, without a terminating NUL. The caller keeps
the input alive until `vera_verify` returns and releases the returned buffer
exactly once with `vera_buffer_free`. The returned length is authoritative;
the output is not NUL-terminated. Input is limited to `MAX_REQUEST_BYTES`
(`RECEIPT_RESPONSE_BYTES + 4 * MAX_KEY_BYTES + 4096`). Receipt decoding also
enforces the light-block transaction count limit.

Receipt request:

```json
{"kind":"receipt","trusted_key":"<96-byte hex key>","submission":"0x<32-byte ID>","proof":{}}
```

`proof` is the unmodified `vera_getReceiptProof` result. Success returns
`{"result":{"height":0,"timestamp":0,"submission":"0x...","success":true,"logs":[]}}`
with actual verified values. A successful verification can report an unsuccessful
operation. A missing RPC receipt is not proof of rejection.

Current-record request:

```json
{"kind":"record","trusted_key":"<96-byte hex key>","module":"acp","key":"0x<key bytes>","minimum_height":1,"proof":{}}
```

`proof` is the `vera_getCurrentRecordProof` result. Modules are `acp`, `bulletin`,
`vera` and `native_nonce`. Success returns
`{"result":{"height":0,"timestamp":0,"value":"0x..."}}`; certified absence
returns a null value. The requested module, key and minimum height are verified.
Applications must also bind record contents to their operation and apply any
required freshness policy. Inclusion alone does not authorize an operation.

Current object-owner request:

```json
{"kind":"object_owner","trusted_key":"<96-byte hex key>","policy_id":"<policy ID>","object":{"resource":"document","id":"report"},"minimum_height":1,"proof":{}}
```

`proof` is the `vera_getCurrentPolicyPrefixProof` result for the policy and
`object_owner_prefix(policy_id, object)`. The verifier derives the prefix again,
authenticates the active policy and complete ownership coverage at the same
revision, and returns `{"result":{"height":0,"timestamp":0,"owner":"did:..."}}` with
verified values. An absent policy, missing ownership or archived ownership returns
a null owner. Raw prefix responses without a policy witness are rejected. Invalid
owner records or multiple live owners fail verification. This describes live
registration; it does not return an archived owner as a current registration.
Minimum height bounds the accepted revision. Callers remain responsible for any
additional freshness requirement.

Policy relationship page requests use `kind: "policy_prefix_page"`, with
`trusted_key`, `policy_id`, `request`, `minimum_height` and `proof`. The request is
an ACP `PrefixPageRequest`; proof is the unmodified
`vera_getCurrentPolicyPrefixPageProof` result. Success returns `height`,
`timestamp`, `policy_exists`, `entries` and `continuation`. A certified absent
policy returns `policy_exists: false`, empty entries and no continuation. The raw
`prefix_page` request remains a physical storage read. See
[permission proofs](permission-proofs.md#native-prefix-and-owner-reads) for bounds
and the fresh-state relationship namespace.

Current permission request:

```json
{"kind":"permission","trusted_key":"<96-byte hex key>","policy_id":"<policy ID>","request":{"operations":[{"object":{"resource":"document","id":"report"},"permission":"read"}],"actor":"did:..."},"minimum_height":1,"proof":{}}
```

`proof` is the `vera_getCurrentPermissionProof` result. The verifier authenticates
its revision and evidence, then evaluates the request with the shared ACP engine
and `PERMISSION_LIMITS`. Success returns
`{"result":{"height":0,"timestamp":0,"allowed":false}}` with verified values.
Every requested operation must be allowed. A denial is a valid result; incomplete
or invalid evidence is an error. The result describes the queried revision and
does not create a stored access decision or ticket.

Stored access-decision requests use the same certified record response:

```json
{"kind":"access_decision","trusted_key":"<96-byte hex key>","deployment_id":9063,"decision_id":"<64 lowercase hex characters>","minimum_height":1,"proof":{}}
```

The verifier authenticates `access_decision/<decision_id>` and binds the decision
ID to its deployment, policy, submitting worker and sequence, target actor and
ordered operations. It checks issuance and returns `record` containing `decision`
and `expires_at_revision`, plus the certified `height` and `timestamp`. Absence
returns a null record. Expired records remain readable; this result is issuance
metadata and does not establish current permission.

Caller-bound recovery uses `kind: "decision_outcome"` with `operation` containing
`deployment_id`, `caller`, `operation_id` (32-byte hex), `policy_id` and `request`
(the same ordered actor/operations format as permission verification). It also
requires `trusted_key`, `minimum_height` and `proof`. The verifier derives the
caller operation key and checks the exact operation digest, original worker,
submission, issuance revision and decision identity. The returned `outcome`
contains `decision`, `expires_at_revision`, `submission` and `revision`; absence
returns null. Recovery preserves the original expiry, including when the decision
has expired. The caller operation record has its own bounded retention deadline.

Malformed or invalid evidence returns `{"error":"..."}` with no result. Only
the result returned by this interface is authenticated. Consensus trust must
come from independent provisioning, never from the response being verified.

Consumers link dynamically against `libvera_verifier` and ship the matching
library and header from the same revision. Dynamic linking keeps the library's
native crypto dependencies separate from a consumer's own copies. On macOS the
install name is `@rpath/libvera_verifier.dylib`; the consumer supplies its runtime
search path. Linux uses `libvera_verifier.so` and the platform loader search path.

The ignored `vera-e2e` test `native_go_client` runs a prebuilt Trust API test binary
from `TRUST_NATIVE_TEST_BINARY`. It checks independent Go/Rust signing and
operation commitments, concurrent provider-owned policy creation, receipt and
record verification, object registration/archive/reactivation, altered owner
evidence, direct/group/wildcard permission grants and revocation, and revoked
relay authority after node restart. The current owner verifier rejects changed policy/object selection, minimum revision, consensus
trust, proof roots, witnesses and revision metadata.

The `native_go_gateway_verifies_pipelined_vera` case additionally requires
`TRUST_NATIVE_GATEWAY_TEST_BINARY`, built from Trust's `cmd/trust-api` package
with `vera_native` and CGo. It enables native-only pipelined consensus and runs
the gateway workflow before restart, after restart, and after relay revocation.
The gateway binary is mandatory for this case; the client-only cases remain
available separately. Both Go binaries must link the matching shared verifier.

```sh
TRUST_NATIVE_TEST_BINARY=/path/to/trust-native.test \
TRUST_NATIVE_GATEWAY_TEST_BINARY=/path/to/trust-gateway.test \
VERAD_BINARY=/path/to/verad \
cargo test --frozen -p vera-e2e --test native_go_client \
  native_go_gateway_verifies_pipelined_vera -- --ignored --exact --nocapture
```
