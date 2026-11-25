# Policy IDs

A policy ID is derived from the policy, its creator and a nonce the creator
chooses, so separate deployments that seed the same definition under different
keys get different IDs without coordinating.
`vera_modules::acp::policy_id::{policy_hash, policy_id}` implements it as
`acp::ppp::{policy_hash, policy_id}` do, and reproduces acp's
`conformance/vectors/policy-id.json`.

```text
policy id   = lowercase_hex(SHA-256(
                "acp/policy-id/v2" || policy hash (32 bytes) || nonce (32 bytes)
                || u64be(len(creator)) || creator))
policy hash = acp::ppp::policy_hash(processed policy)    ("acp/policy-hash/v1", 32 bytes)
```

- **Creator**: the policy owner's canonical DID
  (`vera_crypto::actor::canonical_did`), so every spelling of a secp256k1 key
  gives one ID. For delegated and relay creation it is the actor, not the
  worker that signed the submission.
- **Nonce**: 32 bytes, `bytes32 nonce` in `createPolicy` and
  `bearerCreatePolicy`, `nonce` (64 hex characters) in the
  `createPolicyWithOptions` request. A host seeding policies deterministically
  uses a fixed nonce per policy; zeroes are fine because the creator already
  separates hosts.
- **Policy hash**: acp's content hash of the processed policy, which covers
  the name, description, `meta`, specification, the actor's doc, every
  resource, relation (docs, `manages`, `types`), permission (docs, expression)
  and collection `create` rule. acp encodes resources, relations and
  permissions in name order, and `manages`, `types` and the operands of `+`
  and `&` as sets, so declaration order and YAML formatting do not change it. This is not the hash of the retired vendored engine: a policy
  stored by it does not reproduce its ID here.

Creating the same definition, nonce and creator twice is refused with
`PolicyAlreadyExists` (refusal kind `AlreadyExists`); the stored policy is
kept. A deleted policy's ID is refused until its cleanup finishes; after that
the same triple creates a new, empty policy under the same ID.

The stored record keeps `nonce` and `policy_hash` (the hash at creation; edits
keep the ID, the nonce and the hash), so a verifier recomputes the ID from the
record and its owner. Restoration rejects a record whose ID does not.

`AcpModule::predict_policy_id` and `vera_client::predict_policy_id` give the
ID before the policy exists. Genesis `policies` are owned by
`vera_modules::acp::GENESIS_POLICY_CREATOR` and carry a nonce each;
`placed_policies` and `SoloGenesis::policies` name owner and nonce.
