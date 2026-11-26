# Consensus membership

Consensus membership changes are native signed submissions to the validator
registry, authorized by ACP. A rejected command consumes its submission sequence
and leaves membership unchanged. A member record that does not read back aborts
proposal execution; it cannot become a certified rejection or leave a partial
member entry.

The registry holds at most 64 entries, matching the current protocol's DKG
participant bound. Inactive entries count toward that limit. A consensus public
key can belong to only one registered entry, including inactive entries. See
[validator records](#validator-records) for the stored form.

The active committee is also bounded by the configured epoch length. Commonware
requires its dealer quorum to fit between the dealing phase and the final epoch
artifact. The inclusion window must offer each dealer a proposing term because
a proposer supplies only its own log. For an epoch length `B` and term length `L`, the window has
`S = B - floor(B / 2) - 1` blocks and permits at most `ceil(S / L)` members,
capped at 64. This assumes contiguous successful views and ready dealer logs.
Skipped terms or delayed dealing can still fail a ceremony; the previous voting
committee and shares remain effective until resharing succeeds. Additions and reactivations that exceed this capacity
are rejected during command execution. Inactive entries do not use active
committee capacity. Startup rejects a genesis committee that exceeds it.

Removing or deactivating the last active participant is rejected. Inactive
entries may still be removed.

Operators first approve `InitializeMembershipPolicy` using the configured
approval quorum. That ACP policy controls `manage` on the `registry` resource's
`registry` object. Membership requests require that permission for the native
signer's DID. Registration, status changes and removal use the same permission
check. An independent native worker can submit the operator approvals; those
approvals bind the deployment root, administrative sequence, expiry and command.

Execution records the active roster at the last revision of each epoch `e` for
selection in epoch `e + 3`. Commonware reads that immutable record while preparing
the end of epoch `e + 1`, which gives every replica the same finalized cutoff.
Changes after the cutoff enter a later selection. Genesis supplies the initial
lookahead through epoch 2. A selected roster does not guarantee admission:
the corresponding resharing ceremony must also succeed.
The roster selected for ceremony `e + 3` can first supply voting material in
`e + 4`. A valid certificate from an earlier epoch, or one carrying forward a
previous ceremony's output, does not prove that a registry change took effect.

The `validator_epoch_transition` fixture derives this earliest epoch from the
membership receipt and waits for certified material containing the complete new
roster and a changed polynomial. Its bounded wait still fails if resharing never
succeeds. Failed extended CI runs retain the test's observed heights, epochs, and
roster status together with node stdout/stderr logs; generated keys and state
files are excluded from the artifact.

These records participate in the native state commitment, proposal verification,
recovery and state synchronization. The provider reads them under the committed
module lock and retains no separate epoch cache. Live state retains three recent
rosters. Older selections are read from their finalized epoch artifacts in the
existing history store, including after restart. A missing or inconsistent
historical artifact is an error; it never substitutes a newer roster. This bounds
live roster records without adding another historical index. General finalized
history retention is separate.

This changes execution commitments at epoch boundaries and requires a fresh
deployment; it is not a rolling upgrade for existing data.

Membership writes use `VALIDATOR_REGISTRY_ADDRESS` with the request bindings in
`vera_modules::validator_registry::abi`. Persist the signed submission before sending, retain its identifier,
and use `read_receipt` with independently provisioned consensus trust to verify
the result. A successful receipt records the registry update. The effective
committee changes after successful distributed resharing, so inspect verified
revision evidence and its `EpochMaterial.participants` before treating admission
as complete.

For an incoming process:

1. Provision the same deployment genesis and an independent participant identity.
2. Include that public identity and its reachable route in the incoming process's
   peer configuration, with existing members as bootstrappers.
3. Start with an empty threshold-secret store. The process initially verifies
   consensus evidence using the public genesis material.
4. Submit the authorized membership registration and wait for its certified result.
5. Wait for verified evidence that includes the incoming identity in the effective
   committee. The new share is received through resharing and persisted locally.

The consensus public key remains stable through this transition. The public
sharing polynomial changes. A member's service address and its consensus identity
remain distinct configuration values.

The `native_membership` process fixture starts four members, admits a fifth with
no initial share, verifies its new committee evidence, and stops an original
member. A subsequent native write finalizes with the incoming member needed for
quorum. It then kills and restarts the admitted process using its persisted share,
deactivates and removes the unavailable original member, and verifies the reduced
committee under the same consensus identity. Finalization continues after a
second original process stops. The pipelined variant uses 192-block epochs with
16-view terms and repeats the same effective-membership, polynomial-change,
restart and required-quorum assertions. Interruption during the admission ceremony,
power-loss behavior and broader network/storage faults require additional
qualification.

```sh
VERAD_BINARY=/path/to/verad cargo test -p vera-e2e --test native_membership
```

### Validator records

The registry (module address `0x0813`) keeps one record per member in the vera
module's partition under `registry/member/<20-byte address>`: the Ed25519
consensus key, the socket address peers dial (at most 64 bytes), whether the
member is active, the admission that created the record, and the sequence its
next address update must carry. Every admission, a genesis member or an
`addValidator`, takes the next number from a count under `registry/admissions`
that removal never lowers. Genesis seeds the records from `validators` in the
order listed; reads return members in address order. A
record that does not decode is a fault of the node and fails the block that
reads it.

`addValidator`, `removeValidator` and `setValidatorStatus` require the
submitting signer to hold `manage` on the `registry/registry` object of the
membership policy operators selected. The registry holds at most 64 members,
keeps at least one active, admits no more active members than an epoch has
leader terms for, and never registers one consensus key twice, including the
key of an inactive member.

A validator moves its own network address without that permission.
`updateP2PAddress(validator, p2pAddr, sequence, signature)` carries the Ed25519
signature of the member's consensus key over

```
keccak256("vera/registry/p2p-address/v1" || genesis id || validator address
          || admission (u64, big endian) || sequence (u64, big endian)
          || new address bytes)
```

Any native signer may submit it. The sequence must equal the record's and then
advances, so a signature applies once, and the genesis record identifier keeps
it to one deployment. Removing a member deletes its record and admitting it
again starts the sequence at zero under a new admission, so no signature made
before the removal applies to the new record. `vera_client::ValidatorAddressUpdate::sign` builds it from
the 32-byte secret in the validator's key file and the record's admission and
sequence, which `getValidator` returns. An inactive member may still
update its address.

### Operator keys

An operator policy is a threshold and a list of keys in ascending string order
without duplicates. Each key has exactly one entry form:

| Key type | Entry | Approval signature |
|---|---|---|
| secp256k1 | 66 lowercase hexadecimal characters of the compressed key | ECDSA over the signing digest as the prehash, low `s` |
| Ed25519 | its `did:key` | strict Ed25519 over the 32 digest bytes as the message |
| P-256 | its `did:key` (compressed point) | ECDSA over the signing digest as the prehash, low `s` |

A secp256k1 key written as a `did:key` is rejected, so a key cannot be listed
twice. `AdministrativeRequest::signing_digest` is the one definition of what
every operator signs, and an approval is a signer index with 64 signature bytes
in lowercase hexadecimal. A hardware-held P-256 key signs the supplied digest
directly; `external_approval` and `external_der_approval` in `vera-client` turn
a signature made outside the library, raw or ASN.1 DER, into an approval after
checking it against the policy entry. The threshold applies to the whole list;
no key counts for more than one approval.

A P-256 operator may instead approve with a passkey: an assertion whose
challenge is the signing digest, carried in the approval's `webauthn` member
beside the same raw low-S signature ([passkeys.md](passkeys.md)).
`webauthn_approval` in `vera-client` builds one from the authenticator data,
client data JSON and DER signature a platform authenticator returns. An
assertion requires user verification and proves only that the key's holder
signed: it carries no attestation, custody belongs to the platform account
that syncs the key, and the credential must be dedicated to Vera approvals,
since a credential that also signs server-chosen challenges lets that server
obtain an approval of any digest.

`VeraClient::read_administration` verifies the current operator configuration and
next administrative sequence against independently configured consensus trust.
It returns the selected revision, timestamp and decoded state, or certified
absence if administration is not initialized. Decoding rejects malformed operator
policies and incomplete or trailing record bytes. Use a minimum revision from a
certified administrative receipt to observe its resulting configuration.

The existing `administration` convenience method does not authenticate its RPC
response. Use the certified read when selecting an operator policy or checking
rotation recovery. A certified operator configuration does not grant authority to
an unlisted signer; execution still requires the configured approval threshold.

`VeraClient::read_acp_parameters` authenticates the ACP parameter record separately
from operator configuration. Its value is absent until parameters are explicitly
stored; execution then uses `AcpParams::default()`. Malformed stored bytes are
errors and never select defaults. Parameter-dependent registration commitments
also reject malformed configuration before changing state. After an approved
parameter update, use its certified revision as the minimum for the read.


## Pipelined consensus

Every deployment runs Simplex with stable leader terms and optimistic
validation. Genesis states the parameters; omitting `simplex` selects the values
below, and omitting `blocks_per_epoch` selects 192:

```json
"blocks_per_epoch": 192,
"simplex": {
  "term_length": 16,
  "optimistic_views": 4,
  "stall_timeout_ms": 5000
}
```

This configuration permits up to six active members. An epoch too short for the
genesis committee, such as 20 blocks for four members with 16-view terms, is
rejected at startup. The test harness generator also uses 192 unless a test
states another length. Longer terms or larger
committees require longer epochs. These settings prevent deterministic capacity
starvation; they do not guarantee resharing under arbitrary network schedules.

One leader serves each term. Commonware may propose and validate up to the
configured optimistic distance before receiving the preceding notarizations.
Native proposals collect requests for at most one quarter of the local leader
timeout, capped at 100 milliseconds; batches reaching the request-count limit proceed
immediately. Empty
proposals remain possible after this deadline so DKG and idle progress continue.
Certification, finalization and durable publication still require their normal
evidence. A stalled term is abandoned through Commonware's nullification path.

Terms must contain 2–64 views. Optimistic lookahead may be zero to disable
optimism, or at most 16 views and strictly less than the term length. The stall
timeout must be 1–60000 milliseconds. All parameters are included in the genesis
fingerprint, which the genesis block names as its parent. Changing parameters
requires a new deployment; restarting against different parameters is rejected.

Deployments accept native signed requests only. Other bytes are refused at
admission, and a proposal that carries any is invalid. Blocks carry
no consensus randomness. Threshold signatures and DKG/resharing remain enabled.
