# Anchored policy snapshots

One deployment (the *anchoring* deployment, S) records the newest finalized
revision of other deployments (D). D's owner captures one of its policies at a
revision, anchors that revision in S, and hands out the result as a snapshot.
Anyone may hold and relay a snapshot. A reader that trusts only S's consensus
key verifies it and answers access questions from it while D is offline.

A snapshot is as good as its anchor: it shows the policy at the anchored
revision, and nothing later. A reader learns that D changed the policy only by
learning of a newer anchor.

## Identity of a deployment

S knows a deployment only by its consensus key, the BLS group key every one of
its finalization certificates verifies against. Resharing keeps the key, so
one key covers every epoch and S follows no epoch changes.

```
deployment = SHA-256("vera/anchor/deployment/v1\0" || canonical consensus key)
```

There is no registration step. The first anchor of a key creates the
deployment's record. Because the identifier is derived from the key, nobody can
record revisions under another deployment's identifier with keys of their own,
and recording a revision under someone else's key requires that deployment's
own certificate.

## Anchors

An anchor is a native request (or an EVM call) to the anchor precompile at
`0x0814`:

```solidity
function anchorRevision(
    bytes consensusKey, bytes block, bytes[] descendants,
    bytes finalization, bytes epochMaterial
) external returns (bytes record);
event RevisionAnchored(bytes32 indexed deployment, uint64 sequence, uint64 height, bytes32 blockHash);
```

The byte fields are those of D's `LightBlock` for the revision, decoded from
hex (`LightBlock::artifacts`). Anyone may submit one: the request's authority is
D's certificate, not its signer, so D's owner, S's operator or a relay can post
it. S's executor verifies the submission and `VeraModule::record_anchor`
records it:

1. The artifacts together are at most 256 KiB (`MAX_ANCHOR_ARTIFACT_BYTES`).
2. The key decodes, and `vera_domain::verify_finalized_artifacts` verifies the
   block, any descendants, and the threshold certificate against it, exactly as
   a light block is verified. Every validator of S checks the pairing.
3. The block's height is above the deployment's latest anchor, and its term is
   not below the latest anchor's. Resubmitting the latest anchored block
   succeeds without changing anything or emitting an event.
4. S stores the new record, numbered one above the previous anchor.

Steps 1 and 2 run in `vera-executor`, which holds the consensus types; the
module receives the verified block's fields as a `VerifiedRevision` and the
key's canonical encoding. `vera-modules` keeps no Commonware dependency, so
clients that encode module calls do not build the consensus stack.

A refused anchor has a failed receipt from module `anchor` (code 5): kind
`invalid_proof` when the revision is not finalized under the key, `not_newer`
(code 20) when it is not above the latest anchor or is in a lower term,
`argument_out_of_bounds` for oversized artifacts and `undecodable_input` for a
key that does not decode. An anchor costs 250,000 gas.

### The record

The record is a constant-size JSON value in S's identity (`vera`) partition at
`"anchor/v1/" || hex(deployment)`:

| Field | Meaning |
|---|---|
| `deployment` | The identifier above |
| `consensus_key` | D's canonical consensus key |
| `sequence` | How many anchors D has; 1 for the first |
| `height`, `block_hash`, `term`, `timestamp` | The anchored block |
| `module_state_root` | The anchored block's native module root |
| `anchored_at` | Height of S's revision that recorded it |

Only the latest anchor is kept. Sequence numbers and heights only increase, so
a reader that holds two records of one deployment can tell which is newer.
`AnchorRecord::decode` refuses a record that does not name the deployment its
key belongs to or whose key is not 96 bytes long; a reader decodes the key
itself when it verifies a revision against it.

### Reading the latest anchor

The record is an ordinary native record: `vera_getCurrentRecordProof` returns
it, or its absence, with S's light block, and
`VeraClient::read_latest_anchor(deployment, minimum, s_key)` verifies it. The
proof is a Merkle path in one partition plus S's light block.

### Conflicting histories

A single-validator deployment whose key runs on two devices can finalize two
blocks at one height. The first one anchored at a height wins: another block at
that height, or at any height up to the latest anchor, is refused. S does not
check that a later anchor descends from the previous one: blocks carry no
accumulator of their ancestors, and a chain of headers between two anchors is
unbounded. A second history that branched below the latest anchor can still be
anchored at a greater height in the same or a later term. Readers who need more
compare the anchored block with the term certificate D's operators issued (see
[terms](active-term.md)).

## Snapshots

`vera_getCurrentPolicySnapshot(policy, minimum_height)` returns a
`PolicySnapshotResponse`: the current finalized revision as a light block and,
captured under the four partition read locks at that revision:

- the policy record (`policy/objs/<policy>`) or its absence, and
- complete-prefix proofs of the three ACP prefixes the evaluator reads for the
  policy: its relationships (`relationship/v5/<policy>/`), relationship indexes
  (`relation_state/<policy>/`) and object incarnations
  (`object_state/<policy>/`).

The prefixes share one budget of 4,096 records and 1 MiB of keys and values,
and the proofs 4 MiB; a larger policy is refused with the request limit error.
The policy identifier is a 64-character lowercase hex string. The record carries
its creator's nonce and creation hash, and verification checks that the
identifier derives from them and the record's owner
([policy-ids.md](policy-ids.md)), so a snapshot shows who created the policy.

An `AnchoredSnapshot` (in `vera-client`) is that response plus the anchor's
evidence from S:

```json
{"policy": "<id>", "revision": <D's LightBlock>, "proof": <PolicySnapshotProof>, "anchor": <S's RecordResponse>}
```

It is self-contained JSON, at most `ANCHORED_SNAPSHOT_BYTES`. D's revision is
held to the anchor limit of 256 KiB, the policy evidence to 4 MiB, and the
anchor evidence to S's record-response limit, which includes S's whole block.

### Publishing

`VeraClient::publish_policy_snapshot`, called on D with a client of S:

1. captures the policy at D's current revision and verifies it against D's key;
2. anchors that same revision in S and waits for the certified receipt;
3. reads the latest anchor from S at or after the receipt's revision;
4. assembles and verifies the snapshot.

A deployment that prunes history can publish, because the revision captured is
the current one. A refusal of step 2 (`AnchoringError::Refused`) means another
anchor at or above that revision landed first; publishing again captures and
anchors a newer revision. An anchor that lands between steps 2 and 3 makes step
4 fail with `NotAnchored`, and publishing again succeeds.

## Verification

`AnchoredSnapshot::verify(deployment, policy, s_key, minimum_anchor_revision)`
needs no contact with D or S:

1. The anchor evidence verifies against S's key at a revision at or above the
   caller's minimum, and its record is D's latest anchor at that revision.
2. D's light block verifies against the consensus key in the anchor record, and
   its height, block identifier and module root are the anchored ones.
3. The policy record and the three complete prefixes verify against that
   module root.

`VerifiedSnapshot` carries the anchor (with its `sequence`), the height and
time of S's revision it was read at, and the policy state.
`VerifiedSnapshot::check(request)` evaluates an access request with the shared
ACP evaluator, the same one current permission evidence replays; a read outside
the snapshot is an error, never a denial.

### Freshness

A verified snapshot says what the policy was at the anchored revision and that
S held that revision as D's latest anchor at S's stated revision. A reader:

- keeps the highest anchor `sequence` it has verified for D, and refuses a
  snapshot below it: `VerifiedSnapshot::ensure_current(&latest)` returns
  `Stale` when `latest` is newer, and `Conflict` if S ever shows two records
  with one sequence;
- asks S for the latest anchor (`read_latest_anchor`) whenever it is online,
  with its last-seen S height as the minimum;
- decides how old an anchor it accepts offline, from the anchor's `timestamp`
  and the S revision's timestamp.

Offline, a reader cannot know whether D has anchored since, whether D revoked
something without anchoring, or whether D's key is also running elsewhere. A
snapshot never reflects changes D has not anchored.

## RPC and client calls

| Call | Where | Purpose |
|---|---|---|
| `vera_getCurrentPolicySnapshot` / `capture_policy_snapshot` | D | Policy state at the current revision |
| `vera_sendNativeTx` to `0x0814` / `submit_anchor`, `await_anchor` | S | Anchor a revision |
| `vera_getCurrentRecordProof` / `read_latest_anchor` | S | Latest anchor with proof |
| `publish_policy_snapshot` | D and S | The three steps above |
| `AnchoredSnapshot::decode`, `verify`; `VerifiedSnapshot::check`, `ensure_current` | Anywhere | Relay, verify and evaluate |

## What changed in consensus

No partition, block field or commitment changed. Anchor records live in the
existing identity partition under their own prefix, so the module state root,
the four native log targets and the receipt commitment keep their structure.
Execution accepts a fifth native target address (`0x0814`), and receipts can
name refusal module code 5 and refusal kind code 20; both are committed through
the receipt commitment, so every validator must run a release that knows them.

## Limits

- Ancestry between anchors is not checked (see above).
- The anchor evidence carries S's whole block, so a snapshot is as large as S's
  block at the revision it was read at.
- Only one policy per snapshot, at most 4,096 records.
- Nobody pays for anchors beyond gas; S's admission controls who can submit.
- Only the latest anchor is stored, so older anchors cannot be proven later.
- A snapshot is not imported into the reader's own deployment.
