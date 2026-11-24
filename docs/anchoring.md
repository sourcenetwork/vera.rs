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
deployment's record and is the block its chain of anchors starts at. Because the identifier is derived from the key, nobody can
record revisions under another deployment's identifier with keys of their own,
and recording a revision under someone else's key requires that deployment's
own certificate.

## Anchors

An anchor is a native request to the anchor module at
`0x0814`:

```solidity
function anchorRevision(
    bytes consensusKey, bytes block, bytes[] descendants,
    bytes finalization, bytes epochMaterial, bytes ancestryProof
) external returns (bytes record);
event RevisionAnchored(bytes32 indexed deployment, uint64 sequence, uint64 height, bytes32 blockHash);
```

The byte fields are those of D's `LightBlock` for the revision, decoded from
hex (`LightBlock::artifacts`), and `ancestryProof` is the encoding of an
`AncestryProof` that D's latest anchor is an ancestor of the revision; it is
empty for D's first anchor. D's node gives the proof
(`vera_getAncestryProof`, `VeraClient::anchor_proof`). Anyone may submit an
anchor: the request's authority is D's certificate, not its signer, so D's
owner, S's operator or a relay can post it. S's executor verifies the
submission and `VeraModule::record_anchor` records it:

1. The artifacts together are at most 256 KiB (`MAX_ANCHOR_ARTIFACT_BYTES`).
2. The key decodes, and `vera_domain::verify_finalized_artifacts` verifies the
   block, any descendants, and the threshold certificate against it, exactly as
   a light block is verified. Every validator of S checks the pairing.
3. The block's height is above the deployment's latest anchor, and its term is
   not below the latest anchor's. Resubmitting the latest anchored block
   succeeds without changing anything or emitting an event.
4. The proof shows that the latest anchored block is the block's ancestor at
   the anchored height (`Block::has_ancestor`, against the ancestry the block
   itself carries; see
   [receipt-commitments.md](receipt-commitments.md#ancestry)). The first anchor
   of a deployment has no anchor to extend and starts its chain.
5. S stores the new record, numbered one above the previous anchor.

Steps 1, 2 and the proof check of step 4 run in `vera-executor`, which holds
the consensus types; the module receives the verified block's fields and the
ancestor the proof established as a `VerifiedRevision`, and the key's
canonical encoding. `vera-modules` keeps no Commonware dependency, so clients
that encode module calls do not build the consensus stack.

A refused anchor has a failed receipt from module `anchor` (code 5): kind
`invalid_proof` when the revision is not finalized under the key, `not_newer`
(code 20) when it is not above the latest anchor or is in a lower term,
`not_descendant` (code 21) when it is above the latest anchor and not shown to
descend from it, `argument_out_of_bounds` for oversized artifacts and
`undecodable_input` for a key that does not decode. An anchor costs 250,000
gas, and so does one refused after its artifacts decoded: every validator
verified it.

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

### One chain per deployment

Every anchor after the first descends from the one before, so a deployment's
anchors are blocks of one history in increasing height, and S's revisions
order them in time.

The proof is checked against the ancestry the anchored block commits to, and
that block is certified by D's key. A deployment whose validators follow the
protocol cannot produce a certified block with a false ancestry: every voter
recomputes it from the parent. A holder of a single-validator deployment's
key who signs arbitrary blocks can claim any ancestry; what S guarantees then
is that each anchored block *commits* to every earlier anchor, so the anchors
remain one chain of commitments, and the honest history, which does not
contain the forged block, is refused from then on and shows up as a fork.

### Forks

A single-validator deployment whose key runs on two devices can finalize two
histories. Only one of them extends the latest anchor. A block of the other
is refused as an anchor, and anyone holding it can record it as evidence:

```solidity
function reportFork(
    bytes consensusKey, bytes block, bytes[] descendants,
    bytes finalization, bytes epochMaterial, bytes32 ancestor, bytes ancestryProof
) external returns (bytes record);
event ForkReported(bytes32 indexed deployment, uint64 sequence, bytes32 anchoredBlock, uint64 height, bytes32 blockHash);
```

The block must be finalized under the key and conflict with the latest anchor:
either it is another block at the anchored height, or it lies above it and
`ancestryProof` shows that its ancestor at the anchored height is `ancestor`,
a block other than the anchored one. A block below the latest anchor, a block
that descends from it, and a block without the proof are refused with
`invalid_proof`; a deployment without an anchor with `not_found`; a block
already recorded with `already_exists`. The call costs what an anchor costs. A
refused anchor leaves no state behind, which is why the evidence is its own
call.

The record is JSON at `"anchor-fork/v1/" || hex(deployment) || "/" ||
hex(blockHash)` in the identity partition:

| Field | Meaning |
|---|---|
| `deployment` | The deployment's identifier |
| `sequence`, `anchored_height`, `anchored_block` | The anchor the block conflicts with |
| `height`, `block_hash`, `term` | The conflicting block |
| `ancestor` | The conflicting block's ancestor at the anchored height; the block itself at that height |
| `reported_at` | Height of S's revision that recorded it |

`VeraClient::report_fork`, called on the device that holds the other history,
builds the report, and `VeraClient::read_forks(deployment, minimum, s_key)`
reads every fork of a deployment as one complete-prefix proof, so a reader
that trusts only S's key learns that D's key finalized two histories and which
blocks they are. A fork record does not move the latest anchor or stop later
anchors.

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

Before step 2 it reads D's latest anchor from S and asks D's node for the
proof that the anchor is an ancestor of the captured revision. D's node builds
it from retained history, so a deployment that prunes history publishes as
long as it still holds its latest anchored revision and at most 65,536
revisions lie between the two. A refusal of step 2
(`AnchoringError::Refused`) with `not_newer` means another anchor at or above
that revision landed first, and publishing again captures and anchors a newer
revision; with `not_descendant` it means the latest anchor belongs to another
device's history. An anchor that lands between steps 2 and 3 makes step
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
| `vera_getAncestryProof` / `ancestry_proof`, `anchor_proof` | D | Proof that the latest anchor is an ancestor |
| `vera_sendNativeTx` to `0x0814` / `submit_anchor`, `await_anchor` | S | Anchor a revision |
| `vera_sendNativeTx` to `0x0814` / `report_fork`; `read_forks` | D and S; S | Record and read a fork |
| `vera_getCurrentRecordProof` / `read_latest_anchor` | S | Latest anchor with proof |
| `publish_policy_snapshot` | D and S | The three steps above |
| `AnchoredSnapshot::decode`, `verify`; `VerifiedSnapshot::check`, `ensure_current` | Anywhere | Relay, verify and evaluate |

## What changed in consensus

Blocks carry their ancestry, which raised the block format to 2
([receipt-commitments.md](receipt-commitments.md#format-versions)): a
deployment and the deployment that anchors it run releases of the same block
format, because S decodes D's block. Anchor and fork records live in the
existing identity partition under their own prefixes, so the module state
root, the four native log targets and the receipt commitment keep their
structure. Receipts can name refusal module code 5 and refusal kinds 20 and
21; both are committed through the receipt commitment, so every validator
must run a release that knows them.

## Limits

- A key holder that signs arbitrary blocks can forge an ancestry (see above);
  S then holds a chain of commitments and the honest history is a fork.
- A proof needs D's records from the latest anchor on. A device whose history
  floor is above the latest anchor, or more than 65,536 revisions past it,
  cannot extend it.
- S decodes one block format. Accepting an older or newer format of D would
  be a second decoder in `vera_domain::light_block::decode_block`, selected by
  the block's first byte.
- The anchor evidence carries S's whole block, so a snapshot is as large as S's
  block at the revision it was read at.
- Only one policy per snapshot, at most 4,096 records.
- Nobody pays for anchors beyond gas; S's admission controls who can submit.
- Only the latest anchor is stored, so older anchors cannot be proven later.
- A snapshot is not imported into the reader's own deployment.
