# Execution receipt commitments

Native revisions include `Block::receipt_commitment`, a Keccak-256 commitment to
the ordered execution receipts and execution gas limit. Proposal verification
re-executes the operations and requires the same commitment. Missing commitments
are rejected by the native application and native checkpoint verifier.

`vera_executor::receipt_commitment` computes the commitment without constructing
an intermediate receipt buffer. Its input encoding is:

| Field | Encoding |
|---|---|
| Domain | Literal bytes `vera/receipts/v1` |
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
| Contract address presence | One byte, 0 or 1 |
| Contract address | 20 bytes, only when present |
| Log count | Big-endian u64 |
| Each log | Address (20 bytes), topic count (big-endian u64), ordered topics (32 bytes each), data length (big-endian u64), data bytes |

The commitment binds ordering, collection boundaries and every field retained by
the finalized execution history. The canonical revision digest binds it to the
operations, parent and resulting state. A certificate authenticating that digest
therefore also authenticates the receipt commitment. Verifying downloaded
receipts requires recomputing the commitment against an independently verified
revision; existing receipt RPC responses do not perform that verification.

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
The native node serves these chunks on authenticated peer channel 16 using
Commonware's resolver. Pinned reads avoid copying the
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
record and one bounded finality response. The producer shares one cached proof
across resolver requests to avoid rebuilding it per chunk. The 17-byte request
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

Starting an import upgrades the history metadata format to 3 in the same batch
as the import marker. A later authenticated selection can restart the descending
cursor while retaining the original committed-prefix boundary. Older binaries
reject that format rather than treating an
unfinished import as an execution suffix to discard. Record bytes remain
unchanged. Format 1 and completed format 2 histories remain readable; unfinished
format 2 imports require the previous binary to complete recovery before upgrade.
The new importer cannot resume them without the missing persisted trust and
finality evidence.

## Canonical encoding and existing data

Commitment tag 3 encodes the optional DKG payload, optional four native storage
targets, 32-byte receipt commitment and existing execution storage targets.
Tags 0, 1 and 2 preserve their previous bytes and remain decodable. Tag 3 adds
33 bytes to a revision that already has native targets. Unknown tags and
truncated encodings are rejected.

Fresh native genesis uses the empty receipt list with gas limit zero because
genesis has no executed operations. Native startup rejects a persisted genesis
with missing or invalid receipt commitments and preserves its files. Releases
start with fresh state; incompatible development history is unsupported.
Legacy library execution and history can still read revisions without native
targets or receipt commitments, but those receipts have no authenticated
commitment.
