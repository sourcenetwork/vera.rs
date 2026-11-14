# Finality proofs

`vera_getLightBlock(height)` returns the requested revision with evidence that
it is finalized. Verify it with `vera_domain::verify_light_block` and the
consensus public key from authenticated deployment configuration.
A request served from the finalization cache holds one of the eight shared
proof slots while the response is assembled; a request served from durable
history holds a history-read slot instead. Either returns a retryable -32002
when its slots are occupied.

A revision can finalize through a descendant without receiving its own direct
certificate. The response then includes `descendants`: canonical encoded
blocks in ascending height order, starting immediately after the requested
revision and ending at the certified block. The `finalization` and
`epoch_material` fields describe that last block. When the requested revision
has a direct certificate, `descendants` is omitted.

All displayed fields, including `height`, `epoch`, `timestamp` and state roots,
describe the requested revision. Verification checks those fields against its
canonical bytes, follows contiguous heights and parent hashes, and verifies
the final descendant's threshold certificate against the configured key. It
returns the requested revision's roots. A newer descendant does not refresh
the requested revision's timestamp or change which state a record proof must
authenticate.

Commonware can re-propose an epoch's final revision in a later view. Its
certificate signs the same canonical digest while its proposal view and parent
view advance. The verifier accepts this when the certified revision carries
next-epoch information, the certificate stays in the same epoch, and the parent
view lies between the original view (inclusive) and the certificate view
(exclusive). Threshold signature verification remains mandatory. This applies
to both direct proofs and the last descendant; consumers need the updated
shared verifier to accept these certificates.

The node serves direct certificates from its existing index. It assembles
indirect proofs from one snapshot of its durable finalized history, using
the first retained direct certificate within the proof limits, and
does not copy canonical history into an additional memory index. History
reads run outside the asynchronous RPC worker. Missing history, inconsistent
ancestry, unavailable epoch material and excessive proofs return errors.

Imported history retains verified certificates with their verifier material.
These artifacts can serve proofs without the destination's previous consensus
archive. A descendant beyond the recovered execution head may complete a proof,
but cannot be queried as an executed revision until execution reaches it. Peer
verifier material does not establish consensus membership.

The shared limits are 64 descendants and 35 MiB of combined decoded block,
certificate and epoch-material bytes. The JSON response limit is 70 MiB plus
64 KiB for hex encoding and metadata. JSON decoding enforces the descendant
count while reading the list. These are per-proof limits; they do not
establish aggregate server memory or sustainable serving capacity.

Direct proof responses retain their existing JSON shape. Consumers must use
the updated shared verifier to accept descendant proofs. Historical record
and permission evidence remains subject to its own retention and freshness
rules; a retained finality proof does not imply that all state at that revision
is still queryable.
