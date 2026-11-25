# Simulated calls

A node answers two methods by executing a module call against its committed
state and discarding every effect: `vera_call` and `vera_simulateNativeCall`. None of them writes state, takes a sequence or
enters a revision, and none of their answers is evidence. A caller that needs
an authenticated answer reads a certified record, prefix or permission proof
instead ([permission-proofs.md](permission-proofs.md)).

## Context

A simulated call observes the deployment and the node's head revision:

| Value | Source |
| --- | --- |
| Block height and time | The newest revision in the node's execution index |
| Deployment ID | The deployment's chain ID |
| Genesis record | The genesis identifier administrative approvals are bound to |
| Membership limit | The active-committee capacity derived from the epoch and term lengths |
| Module state | A snapshot of the committed module values taken when the call starts |

Time-dependent module paths, such as token validity and expiry, are evaluated
at the head revision's time. A request executed later runs in a later revision, so a
simulated success does not guarantee that a submission succeeds.

The height, time and module snapshot are read together when the call starts
executing, after any wait for an execution slot, so a call that queued observes
the head at the moment it runs. Module values and the execution index are
published separately as a revision finalizes; a call that starts between the
two can observe one revision's values at the adjacent revision's height and
time.

While the node's head is still genesis, before the first revision is
finalized, the height is zero. Policy commands and policy creation are refused
there, as `invalid policy command execution context` and `invalid policy
creation context`: the records they write are bound to the revision that
executes them, no request executes in genesis, and the modules reject a zero
height rather than store a record that names it. Dry runs of those calls
succeed once the first revision is indexed. Queries are not affected.

## `vera_call`

Evaluates one module call without a signer and returns what the module
answered.

```json
{
  "method": "vera_call",
  "params": ["0x0000000000000000000000000000000000000810", "0x..."]
}
```

| Result field | Meaning |
| --- | --- |
| `output` | Return data of a call that ran to completion; empty when refused |
| `refusal` | Why the module refused the call: `module`, `kind` and `message`; absent when it ran to completion |
| `blockNumber`, `timestamp` | The head revision the call was evaluated at |

The call carries no signer, so module queries answer and every method that
needs an authenticated caller is refused as `unauthenticated` with
`module call requires an authenticated caller`. To learn what an actor's module
write would do, use `vera_simulateNativeCall`. The target must be a module
address and the calldata at most what a native request may carry; a request
outside these bounds fails with -32602 before it takes a slot.

The Rust client's typed queries (`get_policy`, `has_relationship`,
`verify_access_request`, `get_post`, `get_jws_token` and the rest of
`vera_client`'s query helpers) are this method. Their documentation names the
verified reader that answers the same question with evidence.

## When an unauthenticated read is acceptable

**`vera_call` and `vera_simulateNativeCall` are unauthenticated.** The answer is
the word of the node that served it about its own head revision. It carries no
finalization certificate and no state proof, the node checks nothing about the
caller, and a node that is behind, on a discarded fork or dishonest answers
just as readily.

Acceptable:

- a host reading the embedded node it runs itself, in-process through
  `LocalRpc`, where the node is the host's own state;
- convenience and display queries, where a wrong answer misleads a view and
  grants nothing;
- tests and tooling.

Not acceptable:

- anything that grants or denies access, including answering another party's
  access question;
- anything recorded as a decision or acted on for another party;
- any check a later write relies on.

Those read certified evidence against a consensus key the caller trusts:
`VeraClient::verify_current_access` for a permission, `read_current_record`,
`read_current_prefix` and their typed forms for state
([permission-proofs.md](permission-proofs.md)). Nothing in Vera's own services
decides access or records a decision from either method.

## `vera_simulateNativeCall`

Dry-runs one native module call as a named acting DID, without a signature.

```json
{
  "method": "vera_simulateNativeCall",
  "params": [{
    "signer": "did:key:z6DtQ...",
    "target": "0x0000000000000000000000000000000000000810",
    "calldata": "0x..."
  }]
}
```

| Result field | Meaning |
| --- | --- |
| `success` | Whether the module call ran to completion |
| `refusal` | Why it was refused, as a receipt would record it: `module`, `kind` and `message` (see [receipt commitments](receipt-commitments.md#refusals)); absent on success |
| `gasUsed` | Gas a receipt would record. A refused call records what it used, at least 5,000; an exhausted allowance records the whole 1,000,000 |
| `output` | Return data of a successful call |
| `logs` | Events a successful call would emit: `address`, `topics`, `data` |
| `blockNumber`, `timestamp` | The head revision the call was evaluated at |

**The method is unauthenticated.** The node checks neither that the caller
controls the signer DID nor anything else about the caller. The result answers
what that DID could do at the head revision. It authorizes nothing and must
not be treated as an access decision: use `vera_getCurrentPermissionProof` and
`VeraClient::verify_current_access` for that. Anyone who can reach the RPC
listener can simulate as any DID, against the same committed module state
that module queries read.

The call runs through the same module dispatch as an executed native request,
with these differences:

- No signature or sequence is checked. The call observes the signer's next
  sequence from committed state.
- The submission identifier is 32 zero bytes, so identifiers a module derives
  from the submission differ from those of a real request.
- A secp256k1 signer named in any accepted spelling acts as its canonical DID,
  as the executor derives it from a key.
- A fault of the node's own state fails the method with an execution error
  instead of a result.

Requests are bounded like a native submission. The signer must be a supported
DID of at most 256 bytes, the target one of the four module addresses, and the
calldata at most the 12 MiB + 4 KiB a native request may carry; the request
body shares the submission body limit. A request outside these bounds, or with
an unknown field, fails with -32602 before it takes a simulation slot.

The Rust client exposes the method as `VeraClient::simulate_native_call`.

## Admission

The two methods share one set of slots per node. Executions run on the
blocking pool against the module snapshot, so they hold neither an async
worker nor the lock finalization publishes under. Four run at a time and up to
64 more wait at most two seconds for a slot. A caller beyond the 64, or one
whose wait expires, receives -32002 with `retryable: true`. A slot stays taken
until its execution ends, even if the caller disconnects. The Rust client
reports the refusal as `ResourceBusy` and does not retry it.
