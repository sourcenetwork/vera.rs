# Execution receipt commitments

Native revisions include `Block::receipt_commitment`, a Keccak-256 commitment to
the ordered execution receipts and execution gas limit. Proposal verification
re-executes the operations and requires the same commitment. A block does not
decode without one.

`vera_executor::receipt_commitment` computes the commitment without constructing
an intermediate receipt buffer. Its input encoding is:

| Field | Encoding |
|---|---|
| Domain | Literal bytes `vera/receipts/v3` |
| Execution gas limit | Big-endian u64 |
| Receipt count | Big-endian u64 |
| Each receipt | Fields below, in execution order |

Each receipt contributes:

| Field | Encoding |
|---|---|
| Operation hash | 32 bytes |
| Gas used | Big-endian u64 |
| Cumulative gas used | Big-endian u64 |
| Success | One byte, 0 or 1 |
| Refusal presence | One byte, 0 or 1 |
| Refusal | Module code (one byte) and kind code (one byte), only when present |
| Log count | Big-endian u64 |
| Each log | Address (20 bytes), topic count (big-endian u64), ordered topics (32 bytes each), data length (big-endian u64), data bytes |

The commitment binds ordering, collection boundaries and every field retained by
the finalized execution history except a refusal's message. The canonical revision digest binds it to the
operations, parent and resulting state. A certificate authenticating that digest
therefore also authenticates the receipt commitment. Verifying downloaded
receipts requires recomputing the commitment against an independently verified
revision; existing receipt RPC responses do not perform that verification.

## Refusals

A native request a module refuses has a failed receipt naming why: the module it
was addressed to, a refusal kind and the module's message. A successful receipt
carries no refusal; verification rejects a successful receipt that names one.

The module and kind are committed. The message is not: it is the module's
error text, which embeds parser and library wording (for example a YAML
parser's position report) that can change between releases without changing
what was refused. Committing it would make validators running two releases
disagree on receipts. The message is at most 1,024 bytes, cut at a character
boundary; decoders reject a longer one. It is reported by the node that
executed or imported the receipt, so a light client can rely on the kind and
show the message as that node's explanation.

| Module | Code |
|---|---|
| `acp` | 1 |
| `bulletin` | 2 |
| `vera` | 3 |
| `validator_registry` | 4 |
| `anchor` | 5 |

| Kind | Code | Raised for |
|---|---|---|
| `unknown_selector` | 1 | Calldata naming no method, or shorter than a selector |
| `undecodable_input` | 2 | ABI, UTF-8, JSON or DID decoding of the calldata or an argument |
| `argument_out_of_bounds` | 3 | Size and count limits on arguments, including Bulletin field sizes |
| `invalid_argument` | 4 | A decoded argument the module cannot accept, such as an invalid access request, subject, namespace or membership address |
| `invalid_policy` | 5 | A policy definition the parser or validator refuses |
| `unauthenticated` | 6 | A method needing a signer called without one |
| `unauthorized` | 7 | `Unauthorized` errors of every module and Bulletin's non-collaborator |
| `invalid_token` | 8 | Invalid bearer tokens and JWS, or a token already invalidated |
| `invalid_proof` | 9 | An ACP proof, or an anchored revision's finality, that does not verify |
| `not_found` | 10 | A missing policy, commitment, namespace, post, collaborator, token or validator |
| `object_not_registered` | 11 | An ACP object that is not registered |
| `already_exists` | 12 | An existing object, namespace, post, collaborator, validator or consensus key |
| `expired` | 13 | An expired registrations commitment |
| `membership_constraint` | 14 | A membership change leaving no active member or exceeding the limit or epoch capacity |
| `work_limit_exceeded` | 15 | Module limits not drawn from the gas allowance: Bulletin's query limit and the ACP batch result budget |
| `storage_bounds` | 16 | A successful call whose records exceed the native storage bounds |
| `out_of_gas` | 17 | A call that exhausted its allowance, including ACP work allowances carved from it |
| `state_error` | 18 | Module state the call needed could not be used (`State` errors) |
| `module_failed` | 19 | A module panic |
| `not_newer` | 20 | An anchor at or below the height of the deployment's latest anchor, or in a lower term |

The kind follows from the module error's variant, so every node classifies a
refusal the same way. Codes outside these tables do not decode. Faults of the
node's own state still fail the block instead of producing a receipt.

A refusal is charged the gas the call reported, and at least 5,000, the base
charge of a module write; methods with fixed charges report no usage of their
own when they refuse. `out_of_gas` and `module_failed` are charged the whole
1,000,000 allowance. See [execution limits](execution-limits.md).

## History

History checks the commitment before appending a record and again before
publishing that record to query indexes during recovery. A changed receipt or
execution limit fails recovery. Record decoding also checks receipt count and
rejects malformed or trailing log bytes. The bounded peer transport below applies
the same checks. Snapshot startup coordinates this import with storage recovery
before accepting requests; see `snapshot-recovery.md`.

## Staging retained history

`FinalizedHistory::record_chunk` copies at most 64 KiB from a pinned Regolith
snapshot into a response and reports the full record length and offset. The
caller must bound record assembly before allocating for the advertised length.
The native node serves these chunks on authenticated peer channel 13 using
Commonware's resolver. Each request is produced on the blocking pool, two at a
time per node; a request arriving while both are busy is dropped, which the
importer sees as a failed fetch and retries. The four most recent finality
proofs are kept, within one proof response's byte limit, so the chunks of a
proof are sliced from one assembly. Pinned reads avoid copying the
entire stored value into a Rust buffer; Regolith's own resource use still applies.

`begin_import` verifies the selected revision against the caller's independent
consensus key and persists that selection. Records arrive in descending height
order. `import_record` checks each canonical revision against the expected parent
hash, verifies its receipt commitment and finality proof, and requires the chain
to connect to the destination's committed prefix. Finality uses the consensus key
persisted by `begin_import`; proof-supplied keys cannot replace that trust.
`HistoryLimits` bounds assembled bytes and the aggregate log count before decoding their fields. Operation counts obey the
existing revision codec bounds. Limits are caller-selected; no default import
workload or capacity is implied.

`HistoryPeer::import_next_from` fetches one required record from a caller-selected
current group member. It checks chunk framing, offsets, advertised size, stable
record length and the assembly budget, then passes the complete record through
the ancestry, receipt and finality verifier. It also transfers the existing
`LightBlock` JSON proof under its 70 MiB plus 64 KiB response bound. Invalid
records or proofs leave the durable cursor unchanged; the caller can try another peer. Commonware supplies request IDs,
targeted retries and cancellation. Dropping the import future cancels its active
fetch. The caller's timeout covers the asynchronous transfer; synchronous decode
and storage work can outlast it.

The client issues one chunk request at a time and holds at most one assembled
record and one bounded finality response. The producer slices chunks from its
four cached proofs instead of rebuilding a proof per chunk. The 17-byte request
key contains a resource kind (0 for execution record, 1 for finality proof),
height and offset; the latter two are big-endian u64 values. This replaces the
previous 16-byte record-only protocol. Individual chunks receive no positive
authenticity score because only the completed record can establish receipt
integrity. Malformed framing is
reported to the resolver as invalid. The underlying network limits messages to
4 MiB; the history response payload is at most 64 KiB plus 16 bytes for length
and offset. Aggregate peer traffic and storage work still require load testing.

Each accepted record, its verified finalization evidence and the next expected
ancestor are persisted in one synced write batch. Evidence is deduplicated by
certified height. Canonical descendants beyond the import anchor are retained
only for proofs; they do not advance the execution head or expose their receipts.
Appending execution at those heights must match the retained canonical bytes.
Proof material is stored with its certificate, independently of the membership
index; membership still comes from authenticated configuration and history.
`import_anchor` and `import_next` expose restart progress. Replayed,
out-of-order, incomplete and altered records fail without advancing that cursor.
The final record advances the durable history head, but the import marker still
blocks normal appends, chunk serving and light-client proof serving.

The caller must keep admission and query publication stopped, recover application
state at the selected revision, and call `recover` with that same anchor. Recovery
rejects unfinished imports and other anchors before indexing records. Its final
durable batch removes the marker. This is the history-side handoff; the running
node drives this handoff before synchronized databases reach the processor.

Starting an import marks the history store as imported in the same batch as the
import marker; recovery of an imported store keeps the blocks its certificates
need above the recovery anchor. A later authenticated selection can restart the
descending cursor while retaining the original committed-prefix boundary.
Record bytes remain unchanged. Any other store format is refused.

## Canonical block encoding

A block encodes, in order: the format version byte, consensus context, parent,
height, timestamp, term, module state root, requests, the optional DKG payload,
the four native storage targets and the 32-byte receipt commitment. Every field
is required, there is one encoding per format version, and a truncated block is
rejected. The block identifier hashes the whole encoding, so it covers the
version.

Native genesis uses the empty receipt list with gas limit zero because genesis
has no executed operations. Startup rejects a persisted genesis whose receipt
commitment is not that value and preserves its files. Releases start with
fresh state.

## Format versions

Each format below names its version, and a reader refuses a version it does not
implement with a typed error. No reader interprets bytes under another
version's rules, and none falls back to a default.

| Format | Marker | Current | Refusal |
|--------|--------|---------|---------|
| Block encoding | First byte, `vera_domain::BLOCK_FORMAT_VERSION` | 1 | `UnsupportedVersion`, the source of the codec error |
| State layout | First byte of `native-genesis.bin` and `native-genesis.intent`, `vera_backend::native::STATE_LAYOUT_VERSION` | 1 | `UnsupportedVersion`; the marker and journals are left unchanged |
| Native request | First byte, `vera_domain::NATIVE_TX_TYPE` | `0x45` | `NativeTxDecodeError::UnsupportedType` |
| Receipt commitment | Hash domain | `vera/receipts/v3` | Re-execution and history reject the block's commitment |
| Genesis fingerprint | Hash domain | `vera/native-genesis/v3` | The genesis record does not match the node's configuration |
| Finalized history | `format` key | 1 (appended), 3 (imported) | `UnsupportedHistoryFormat` |
| Module records | Key namespace, such as `relationship/v5/` | Per record family | A key outside the namespace is not read |

Light blocks, history records, block backfill and snapshot handoffs carry
encoded blocks and take the block's version with them. A finality certificate
signs the block identifier, so it binds the version as well.

State layout 1 is four ordered current-QMDB partitions, `acp`, `bulletin`,
`vera` and `nonces`, sealed into each block in that order. The genesis
fingerprint hashes the layout version between its domain and the serialized
configuration; the genesis block names the fingerprint as its parent, so the
layout is part of the deployment identity and of every block identifier.

The request type fixes a native request's signing scheme and field layout. The
type byte leads both the wire encoding and the signed bytes, so a signature
under one type does not verify under another.

### Adding a component

A release that adds an execution path, state or block fields takes new
versions; releases start with fresh state, so no reader of an earlier version
is kept.

- A block that gains, loses or reorders a field raises `BLOCK_FORMAT_VERSION`.
- A partition set that changes raises `STATE_LAYOUT_VERSION` and names the new
  set where the constant is defined. Each partition has its own journals under
  `vera-native-<name>` and its own state-transfer channel, and its
  operation-log target joins the block's targets, which raises the block
  version too.
- A second signing scheme or request layout takes its own request type byte
  beside `0x45`.
- Receipt fields that change take the next `vera/receipts/v<n>` domain.
- A record whose encoding changes takes the next key namespace of its family.

Modules keep their addresses and call encodings. A new execution shim decodes
its own request form and calls the same `module.method(args)` as the native
shim; module logic and module state do not change with the shim.
