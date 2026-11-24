# Anchored deployments and policy snapshots

One deployment (the *anchoring* deployment, S) keeps an ordered, authenticated
record of other deployments (D): each D's finalized revisions as one chain,
the device switches its operators certified, and the forks its key produced.
D's owner captures one of its policies at a revision, anchors that revision in
S, and hands out the result as a snapshot. Anyone may hold and relay a
snapshot. A reader that trusts only S's consensus key verifies it and answers
access questions from it while D is offline.

A snapshot is as good as its anchor: it shows the policy at the anchored
revision, and nothing later. A reader learns that D changed the policy only by
learning of a newer anchor, and that a device switch voided the anchored
revision only by reading D's terms.

## Identity and registration

S names a deployment by its consensus key, the BLS group key every one of its
finalization certificates verifies against. Resharing keeps the key, so one key
covers every epoch and S follows no epoch changes.

```
deployment = SHA-256("vera/anchor/deployment/v1\0" || canonical consensus key)
```

S's operators register a deployment before anything of it is anchored, with an
[administrative request](consensus-membership.md#operator-keys) carrying
`RegisterDeployment`:

| Field | Meaning |
|---|---|
| `consensus_key` | D's consensus key, 96 bytes in lowercase hexadecimal |
| `genesis_id` | Identifier of D's genesis block, which D's term certificates name |
| `operators` | D's operator policy, which approves D's term certificates |

The registration is stored as JSON at `"anchor-deployment/v1/" ||
hex(deployment)` in S's identity (`vera`) partition, with the block time it was
first registered at and the term certified last.
`VeraClient::read_registered_deployment` reads it with proof. S does not prove
the three fields against each other: its operators' approval is the authority
for them. Registering the same key again replaces the operator policy, which
is how S learns that D rotated its operators; another genesis block for a
registered key is refused.

### Submitters

Anchors, fork reports and term changes are native requests, and S's operators
decide which signers may send them. `SetAnchorSubmitter` grants one native
signer (the `did:key` of its BLS key: D's owner, a device, or a relay) the
right to submit for one registered deployment, `quota` times a day;
`RevokeAnchorSubmitter` removes it. The grant is JSON at
`"anchor-submitter/v1/" || hex(deployment) || "/" || did`, with the day (days
since the Unix epoch by S's block time) and the submissions counted on it.

- A node admits an anchor request to its pool only when committed state holds
  a grant of the signer for the deployment the request names, with quota left
  today by the node's clock after the signer's anchor requests for that
  deployment already in the pool are counted. Other requests are refused with
  the reason, and a pending one is dropped when its grant goes.
- Execution checks the same against block time and counts the submission,
  whether it is then recorded or refused: a refusal rolls the module back, and
  the executor counts it afterwards. A signer without a grant is refused with
  `unauthorized`, one past its quota with `work_limit_exceeded`, and a
  deployment that is not registered with `not_found`.
- Every submission costs 250,000 gas, and so does one refused after its
  arguments decoded, whichever check refused it: a refusal for the
  registration, the grant or the quota comes before the artifacts are
  verified, and costs the same so that no refusal is a cheaper probe.

## Anchors

An anchor is a native request to the anchor module at `0x0814`:

```solidity
function anchorRevision(
    bytes32 deployment, bytes block, bytes[] descendants,
    bytes finalization, bytes epochMaterial, bytes ancestryProof
) external returns (bytes record);
event RevisionAnchored(bytes32 indexed deployment, uint64 sequence, uint64 height, bytes32 blockHash);
```

The byte fields are those of D's `LightBlock` for the revision, decoded from
hex (`LightBlock::artifacts`), and `ancestryProof` is the encoding of an
`AncestryProof` that the tip of D's chain of anchors is an ancestor of the
revision; it is empty for D's first anchor. D's node gives the proof
(`vera_getAncestryProof`, `VeraClient::anchor_proof`). What is recorded rests
on D's certificate, not on the signer. S's executor verifies the submission
and `VeraModule::record_anchor` records it:

1. The artifacts together are at most 256 KiB (`MAX_ANCHOR_ARTIFACT_BYTES`).
2. `vera_domain::verify_finalized_artifacts` verifies the block, any
   descendants, and the threshold certificate against the registered key,
   exactly as a light block is verified. Every validator of S checks the
   pairing.
3. The block's height is above the tip. Resubmitting the latest anchored block
   succeeds without changing anything or emitting an event.
4. The block is in the term certified last (see [terms](#terms)): 0 until D's
   operators certify one.
5. The proof shows that the tip is the block's ancestor at the tip's height
   (`Block::has_ancestor`, against the ancestry the block itself carries; see
   [receipt-commitments.md](receipt-commitments.md#ancestry)). The tip is the
   latest anchor recorded in the current term, or else that term's cut. The
   first anchor of a deployment in term 0 has no tip and starts the chain.
6. S stores the new record, numbered one above the previous anchor.

Steps 1, 2 and the proof check of step 5 run in `vera-executor`, which holds
the consensus types; the module receives the verified block's fields and the
ancestor the proof established as a `VerifiedRevision`. `vera-modules` keeps
no Commonware dependency, so clients that encode module calls do not build
the consensus stack.

A refused anchor has a failed receipt from module `anchor` (code 5):

| Kind | When |
|---|---|
| `invalid_proof` | The revision is not finalized under the registered key |
| `not_newer` (20) | It is not above the tip, or it is above the cut in a term below the certified one |
| `not_descendant` (21) | It is above the tip and not shown to descend from it |
| `unauthorized` | It is in a term above the certified one, or the signer has no grant |
| `not_found`, `work_limit_exceeded` | The deployment is not registered; the signer's quota is used |
| `argument_out_of_bounds` | The artifacts are oversized |

### The records

The latest anchor is a constant-size JSON value at `"anchor/v1/" ||
hex(deployment)`:

| Field | Meaning |
|---|---|
| `deployment` | The identifier above |
| `consensus_key` | D's canonical consensus key |
| `sequence` | How many anchors D has; 1 for the first |
| `height`, `block_hash`, `term`, `timestamp` | The anchored block |
| `module_state_root` | The anchored block's native module root |
| `anchored_at` | Height of S's revision that recorded it |

`AnchorRecord::decode` refuses a record that does not name the deployment its
key belongs to or whose key is not 96 bytes long; a reader decodes the key
itself when it verifies a revision against it. `vera_getCurrentRecordProof`
returns the record, or its absence, with S's light block, and
`VeraClient::read_latest_anchor(deployment, minimum, s_key)` verifies it.

Every anchor also stays in D's history, the same fields without the key, at
`"anchor/v1/" || hex(deployment) || "/" || sequence` with the sequence as 16
lowercase hexadecimal digits, so the entries of a deployment are adjacent and
in order. `VeraClient::read_anchor_history(deployment, from, limit, minimum,
s_key)` reads up to 128 consecutive entries as one certified prefix page and
returns the sequence the next page starts at; the page's proof shows no entry
between them. This is how a reader that trusts only S's key walks the versions
of D's policies in order and dates each by S's revision (`anchored_at`).

History is never pruned. An entry is about 0.5 KiB of key and value in S's
identity partition, and, like every native record, in the memory of every node
of S. A million anchors are about 0.5 GiB; the submitters' quotas bound the
rate at which they accrue.

### One chain per deployment

Within a term every anchor descends from the one before, so a deployment's
anchors are blocks of one history in increasing height, and S's revisions
order them in time. A new term continues the chain from its cut.

The proof is checked against the ancestry the anchored block commits to, and
that block is certified by D's key. A deployment whose validators follow the
protocol cannot produce a certified block with a false ancestry: every voter
recomputes it from the parent. A holder of a single-validator deployment's
key who signs arbitrary blocks can claim any ancestry; what S guarantees then
is that each anchored block *commits* to every earlier anchor of its term, so
the anchors remain one chain of commitments, and the honest history, which
does not contain the forged block, is refused from then on and shows up as a
fork. D's operators end that with a term certificate whose cut is below the
forged anchor.

The first anchor is not proven against the registered genesis block. A proof
of the genesis block needs every record since it, which a device that prunes
history no longer has. The registration is what binds the key to the genesis
block.

## Terms

A `TermCertificate` moves D's active role to another device and names the cut,
the block the new term builds on; blocks above it in a lower term are void
([active-term.md](active-term.md)). S takes no block's term at face value:

```solidity
function changeTerm(bytes32 deployment, bytes certificate) external returns (bytes record);
event TermChanged(bytes32 indexed deployment, uint64 term, uint64 cutHeight, bytes32 cutBlock, uint64 sequence);
```

`certificate` is the JSON certificate, at most 32 KiB. The executor verifies
it with `TermCertificate::verify` against the registered genesis block and
operator policy, and `VeraModule::record_term` records it when its term is
above the one recorded last. A certificate that does not verify is refused
with `invalid_proof`, a term that is not newer with `not_newer`. Terms may
skip numbers: S holds only the certificates it was given.

The record is JSON at `"anchor-term/v1/" || hex(deployment) || "/" || term`
(16 hexadecimal digits):

| Field | Meaning |
|---|---|
| `deployment`, `term`, `holder` | The term and the device active in it |
| `cut_height`, `cut_block` | The block the term builds on |
| `sequence` | Sequence of D's latest anchor when the term was recorded; 0 without one |
| `recorded_at` | Height of S's revision that recorded it |

From then on:

- An anchor above the cut must carry the term. A block of a later term is
  refused until its certificate is recorded, so whoever holds D's key cannot
  shut out lower-term anchors by minting a high-term block.
- The tip is the cut, so the term's first anchor proves the cut is its
  ancestor, and anchors at or below the cut are refused. S does not check
  that the cut descends from the anchors below it: D's operators certified
  the cut, and a device that took over may hold no history from before it.
  Linearity is proven within each term and certified across a switch.
- Anchors recorded before the term that the cut does not keep are superseded:
  those above the cut, and one at the cut's height that is another block
  (`TermRecord::supersedes`). Their entries stay in the history, and the
  latest anchor record is not rewritten; a reader derives which are void from
  the term records.

`VeraClient::submit_term_change` submits a certificate.
`read_anchor_terms(deployment, from, limit, minimum, s_key)` reads up to 128
consecutive terms from term `from` as one certified prefix page and returns
the term the next page starts at, like `read_anchor_history`, and
`read_anchor_terms_above(deployment, term, minimum, s_key)` reads every term
above `term` page by page. Term records never change once recorded, so pages
read at increasing revisions together hold every term up to the last one.
`read_anchor_lineage` returns the latest anchor with the term certified last,
whose `Lineage::tip` is what the next anchor must descend from. It reads three
records with proof however many terms there are: the registration, whose
`term` names the term certified last, that term's record and the latest
anchor.

A device that cannot prove the tip, because its history starts above it or
more than 65,536 revisions past it, continues the chain by renewing its term:
a certificate naming the device itself with a cut it holds
([active-term.md](active-term.md)).

## Forks

A single-validator deployment whose key runs on two devices can finalize two
histories. Only one of them extends the tip. A block of the other is refused
as an anchor, and anyone with a grant can record it as evidence:

```solidity
function reportFork(
    bytes32 deployment, bytes block, bytes[] descendants,
    bytes finalization, bytes epochMaterial, bytes32 ancestor, bytes ancestryProof
) external returns (bytes record);
event ForkReported(bytes32 indexed deployment, uint64 sequence, bytes32 anchoredBlock, uint64 height, bytes32 blockHash);
```

The block must be finalized under the registered key and conflict with the
tip: either it is another block at the tip's height, or it lies above it and
`ancestryProof` shows that its ancestor at that height is `ancestor`, a block
other than the tip. A block below the tip, a block that descends from it, a
block without the proof, and a block the certified term voids are refused with
`invalid_proof`; a block of a term above the certified one with
`unauthorized`, as an anchor is, until that term's certificate is recorded and
says whether the block is a switch of the active device or a fork; a
deployment without a tip with `not_found`; a block already recorded with
`already_exists`. A refused anchor leaves no state behind, which
is why the evidence is its own call.

The record is JSON at `"anchor-fork/v1/" || hex(deployment) || "/" ||
hex(blockHash)`:

| Field | Meaning |
|---|---|
| `deployment` | The deployment's identifier |
| `sequence` | Sequence of D's latest anchor when the fork was reported |
| `anchored_height`, `anchored_block` | The tip the block conflicts with |
| `height`, `block_hash`, `term` | The conflicting block |
| `ancestor` | The conflicting block's ancestor at the tip's height; the block itself at that height |
| `reported_at` | Height of S's revision that recorded it |

`VeraClient::report_fork`, called on the device that holds the other history,
builds the report, and `VeraClient::read_forks(deployment, from, limit,
minimum, s_key)` reads up to 128 forks of a deployment, ordered by the
conflicting block's identifier from `from` (zero for the first page), as one
certified prefix page with the identifier the next page starts at, so a reader
that trusts only S's key learns that D's key finalized two histories and which
blocks they are. A fork record does not move the tip or stop later anchors.

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
2. reads where D's anchors stand in S and asks D's node for the proof that the
   tip is an ancestor of the captured revision;
3. anchors that revision in S and waits for the certified receipt;
4. reads the latest anchor from S at or after the receipt's revision;
5. assembles and verifies the snapshot.

D's node builds the proof from retained history, so a deployment that prunes
history publishes as long as it still holds the tip's revision and at most
65,536 revisions lie between the two. A refusal of step 3
(`AnchoringError::Refused`) with `not_newer` means another anchor at or above
that revision landed first, and publishing again captures and anchors a newer
revision; with `not_descendant` it means the tip belongs to another device's
history; with `unauthorized` that S holds no certificate of the device's term,
or no grant of the submitter. An anchor that lands between steps 3 and 4 makes
step 5 fail with `NotAnchored`, and publishing again succeeds.

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
- reads D's terms above the snapshot anchor's own term
  (`read_anchor_terms_above(deployment, anchor.term, ...)`; a term at or
  below it was recorded before the anchor and cannot void it) and refuses a
  snapshot whose anchor one of them voided:
  `VerifiedSnapshot::ensure_kept(&terms)` returns `Superseded` with the term.
  The latest anchor record itself can be a superseded one until the new term's
  first anchor lands, so a reader checks both;
- asks S for the latest anchor and the terms (`read_latest_anchor`,
  `read_anchor_terms_above`) whenever it is online, with its last-seen S height as
  the minimum;
- decides how old an anchor it accepts offline, from the anchor's `timestamp`
  and the S revision's timestamp.

Offline, a reader cannot know whether D has anchored since, whether D revoked
something without anchoring, whether D switched devices, or whether D's key is
also running elsewhere. A snapshot never reflects changes D has not anchored.

## RPC and client calls

| Call | Where | Purpose |
|---|---|---|
| `vera_sendNativeTx` to `0x0812` / `native_apply_administration` | S | Register a deployment; grant or revoke a submitter |
| `read_registered_deployment`, `read_anchor_submitter` | S | Registration and grant with proof |
| `vera_getCurrentPolicySnapshot` / `capture_policy_snapshot` | D | Policy state at the current revision |
| `vera_getAncestryProof` / `ancestry_proof`, `anchor_proof` | D | Proof that the tip is an ancestor |
| `vera_sendNativeTx` to `0x0814` / `submit_anchor`, `await_anchor` | S | Anchor a revision |
| `vera_sendNativeTx` to `0x0814` / `submit_term_change` | S | Record a certified term |
| `vera_sendNativeTx` to `0x0814` / `report_fork` | D and S | Record a fork |
| `vera_getCurrentRecordProof` / `read_latest_anchor` | S | Latest anchor with proof |
| `vera_getCurrentPrefixPageProof` / `read_anchor_history` | S | A page of anchors in order |
| `vera_getCurrentPrefixPageProof` / `read_anchor_terms`, `read_anchor_terms_above`, `read_forks` | S | Pages of terms and forks with proof |
| `vera_getCurrentRecordProof` / `read_anchor_lineage` | S | Tip: registration, certified term and latest anchor with proof |
| `publish_policy_snapshot` | D and S | The five steps above |
| `AnchoredSnapshot::decode`, `verify`; `VerifiedSnapshot::check`, `ensure_current`, `ensure_kept` | Anywhere | Relay, verify and evaluate |

## What changed in consensus

Blocks carry their ancestry, which raised the block format to 2
([receipt-commitments.md](receipt-commitments.md#format-versions)): a
deployment and the deployment that anchors it run releases of the same block
format, because S decodes D's block. Anchor, history, term, fork, registration
and submitter records live in the existing identity partition under their own
prefixes, so the module state root, the four native log targets and the
receipt commitment keep their structure. Administrative requests gained three
commands. Receipts can name refusal module code 5 and refusal kinds 20 and 21;
both are committed through the receipt commitment, so every validator must run
a release that knows them.

## Limits

- A key holder that signs arbitrary blocks can forge an ancestry (see above);
  S then holds a chain of commitments and the honest history is a fork until
  D's operators certify a term below the forged anchor.
- Continuity across a term change, and the binding of a key to its genesis
  block and operator policy, rest on operators' approvals, not on proofs.
- A proof needs D's records from the tip on. A device whose history floor is
  above the tip, or more than 65,536 revisions past it, renews its term to go
  on.
- S learns a rotation of D's operators from S's own operators, not from D's
  anchored state.
- S decodes one block format. Accepting an older or newer format of D would
  be a second decoder in `vera_domain::light_block::decode_block`, selected by
  the block's first byte; nothing activates a format in protocol.
- History, terms and forks are never pruned (see above for the size). Every
  read of them is a page or a single record, so no read stops working as they
  grow.
- The anchor evidence carries S's whole block, so a snapshot is as large as S's
  block at the revision it was read at.
- Only one policy per snapshot, at most 4,096 records.
- A snapshot is not imported into the reader's own deployment.
