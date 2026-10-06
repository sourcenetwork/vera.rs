# Threshold-service rings

A ring starts with an ACP-authorized creation request. The actor must have
`create_ring` on `ring_policy/<policy_id>`. Creation registers the corresponding
`ring/<ring_id>` ACP object for that actor and stores the pending ring atomically.
All committee and reporting-backup node keys must already be registered.

`RingConfig::id` binds the initial deployment state, creator and complete creation
configuration, including a caller-generated nonce. Node and relay sets must be
sorted and unique. Reporting settings are explicit; `ReportingConfig::default`
uses one demerit per report, a daily reset and a kick threshold of three. Ring
configuration retains these settings for the reporting service.

| Current state | Authorized action | Result |
|---|---|---|
| Absent | Actor with ACP creation permission | Pending ring and registered ACP object |
| Pending | First confirmation from a participant | Record that participant's public-key declaration |
| Pending | All participants confirm the same key | Active ring |
| Pending | Different participant confirms a conflicting key | Terminal conflict record |
| Pending | Creator or participant cancels | Terminal cancellation record |
| Active, cancelled or conflicting | Fresh-DKG confirmation/cancellation | Rejected |

Duplicate confirmations are rejected before checking for a conflicting key, so a
participant cannot reverse its own accepted declaration to abort the ring. Every
participant must confirm; the configured cryptographic threshold does not replace
this fresh-DKG unanimity rule. Confirmation also checks the node controller's
current allowed-policy/ring set. Participant cancellation remains available if
the controller withdraws that permission.

Cancelled and conflicting records remain stored. Their identifiers cannot be
reused, preventing old signed confirmations from applying to a recreated ring.
Creation retries with the same authenticated operation identity return the
original recorded outcome; read the ring again to obtain its current state.

## Native client

Use `vera_client::rings::encode_ring_command` with an `orbis:ring` delegation for
creation, administration or creator cancellation. Delegations use the existing expiry,
revocation, relay authorization and optional exact-operation binding checks.
`DelegatedOperation::RingCommand` supplies the digest for a relay assertion or
operation-bound delegation. Failed admission, including outcome-storage budget
exhaustion, rolls back both Vera and ACP changes.

Participants use `sign_ring_participant_request` and
`encode_ring_participant_request`. These signatures bind the deployment root and
ID, ring, node identity, command and expiry. A controller or submission worker
cannot confirm using the node's authority. Public-key declarations use lowercase
hex; the ring lifecycle records participant agreement on those bytes. It does
not validate a DKG transcript or select a threshold cryptographic scheme.

Pass the encoded command to `NativeWorker::prepare(VERA_ADDRESS, calldata)` before
submission. Recover the exact pending bytes after interruption and acknowledge
only a verified receipt. `read_threshold_ring` verifies inclusion or absence
against caller-provisioned consensus trust and a minimum revision, then validates
the record's identity, configuration and state. Callers enforce their freshness
requirements.

Requests are limited to 48 KiB; records to 128 KiB; each node/relay set to 256
entries; public-key declarations to 8 KiB of hex. The refresh interval must be at
least one day. Reporting counters and thresholds must be positive.

## Administration

`RingCommand::Update` requires ACP `update_ring` permission on `ring/<ring_id>`
and the current `expected_sequence`. Every ring mutation increments this sequence,
including writes within one finalized revision. An outdated command fails without
changing either the ring or delegation outcome storage. Creation parameters remain
immutable, so administrative changes preserve the ring identifier.

Active rings support refresh-interval changes, reporting configuration, scheduled
upgrades and resharing announcements. Upgrades must increase the version and allow
at least 600 seconds before activation. Consumers can resolve the effective version
at a certified timestamp; later service updates materialize an activated upgrade.
Cancellation requires an upgrade whose activation time has not arrived.

Relay additions/removals also work while fresh DKG is pending. Creation with relays
disabled is permanent. Reporting backup nodes and resharing target nodes must be
registered and their controllers must permit the ring or its policy. A resharing
announcement records the target committee and threshold while the current committee
continues serving; a second announcement is rejected while one is pending.

## Resharing finalization

`RingRecord::reshare_signing_bytes` builds the existing Orbis protobuf signing
document from the current committee, pending target, policy, relay set and ring
sequence. Its deployment namespace is `vera:<deployment_id>:<deployment_root_hex>`.
The sequence advances for every administrative mutation, so even changes to
settings omitted from the protobuf projection invalidate previous signatures.

Submit the aggregate signature with `encode_ring_reshare` through the durable
worker. The service verifies either `bls12_381_g1_pk_g2_sig_aug_v1` or
`jubjub_frost` against the existing ring key, then rechecks target controllers'
current permission. It atomically replaces the committee/threshold, clears the
pending target and advances the sequence. The ring identifier and public key
remain unchanged. Replays, changed targets and outdated sequences are rejected.

Jubjub rings require fresh key generation. Decaf keys and signatures are not
Jubjub-compatible; there is no legacy scheme alias, decoder or key conversion.

This verifies threshold authorization for finalization; it does not verify the
underlying resharing transcript or guarantee participants retained their shares.
## Fault reports

`encode_ring_report` prepares a threshold-signed report for durable submission.
The native JSON envelope calls its namespace `deployment`; signing bytes retain
the existing Orbis format. The service checks current ring state, protocol version
at observation time, declared committee membership and the accused node's current
registered endpoint. Reporting requires a threshold of at least two that can be
met while excluding the accused.

Offline, unauthorized-request and all existing cryptographic fault evidence kinds
are supported. Evidence must match the envelope's deployment, ring, state, session,
accused and timestamp. The threshold signature attests to the off-service evidence
checks; admission independently enforces structure, bounds and state bindings.
It does not repeat PRE proof, signature-share or transport-signature verification.

Accepted reports add configured demerits, with lazy window resets and saturating
counters. Crossing the kick threshold selects the first eligible backup in the
canonical list and announces a reshare; the serving committee stays unchanged
until threshold-authorized finalization. Existing pending reshares are preserved.

Each ring retains at most 4,096 session deduplication records. Accepted records
expire after 120 seconds; admission removes at most 64 indexed expired records
plus an expired record for the submitted session. A canonical report has one
deterministic session key, so exact and varied-artifact retries both deduplicate.
Ring, score and retention changes are committed together. Failed admission leaves
all three unchanged. Demerit records use `reports::demerits_key` for certified
record queries.

Module-level evidence bounds preserve the existing per-field limits, with a
3 MiB payload and 12 MiB JSON ceiling. Signed submissions allow 12 MiB plus
4 KiB for the authorization envelope. Workers persist that same bounded request
for retries. Admission rejects oversized requests before signature verification
and caps pending request bytes at 64 MiB across at most 4,096 entries.

Proposals contain at most 256 operations and 16 MiB of encoded operation data.
The complete block limit is 17 MiB, including epoch material. RPC, gossip, block
backfill and standalone verification share these limits. Finality evidence allows
35 MiB of combined decoded artifacts, sufficient for two maximum-size blocks and
certificate material; longer ancestry can still exhaust that bounded budget.
These are safety bounds, not measured throughput or latency targets.

The 256-operation limit requires updated nodes and standalone verifiers. Older
builds capped at 64 reject larger revisions; upgrade the entire member group and
verified consumers before using this protocol limit. Previously valid revisions
remain within the new bounds.

Encrypted document and signing-derivation registration is described in [threshold objects](threshold-objects.md). This API does not import
existing rings or choose an encrypted-record migration policy.


### Threshold signature suites

BLS reshare finalization and fault reports require
`bls12_381_g1_pk_g2_sig_aug_v1`, matching Orbis's augmented BLS signer. Verification
uses the compressed ring public key as the message prefix and the AUG domain.
Basic NUL scheme identifiers and signatures are rejected; there is no fallback
verifier. Jubjub FROST uses `jubjub_frost` and Orbis's Jubjub challenge transcript.

Vera and Orbis must use matching builds. BLS ring IDs and public keys retain their
encoding. Native threshold services target a fresh deployment; no legacy
threshold-signature compatibility or history migration is provided.
