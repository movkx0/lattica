# C045 fixed root-artifact header and typed packet probes

This isolated subtree is a prerequisite for the private root-transport action.
It activates no driver, CLI, production acceptance, proof dispatch or network
format. It allocates no packet, proof, key, registry, decoder or verifier. Its
six authored tests use deliberately invalid synthetic bodies and establish no
cryptographic relation. Compilation and execution belong to the coordinator.

## Ownership and API

C owns only `header.rs` and `header/{probes.rs,tests.rs,BOUNDS.md}`. A owns the
original-ledger admission and source/header/memory census. B owns the consuming
same-Component action and sealed retained-output adapter. The coordinator owns
ancestor module wiring and any later driver. These files require those separate
reviews and grant no dispatch permission by themselves.

`RootHeaderValues` is a Copy borrowed value view containing height, exactly46
public values and exactly64 cap roots of four field words each. It is explicitly
not an authority token. Before constructing it, B must check the actual retained
root against its own Parent3 retirement, same source/request/ledger, trusted
spec, first38 source-derived public values, actual supported height and exact
cap content/capacity. A retains the source expectation independently of bytes.
Pointers and Rust object identities are never serialized into the packet.

`encode_header(values, inner_bytes, output)` takes an exactly2480-byte mutable
prefix borrowed from an already admitted packet. It validates the fixed profile,
height and complete packet size before writing. `inner_bytes` includes the inner
registered codec's8-byte magic. The encoder never touches the packet body.

`validate_packet(packet, expected)` validates fixed syntax, canonical words and
exact expected height/public/cap equality. Its `HeaderCheckedPacket::inner()`
returns only borrowed inner bytes. No key is reconstructed from the packet and
no source/request/transaction authority arises from that return value. B uses its
actual retained verifier and original public values after all46 words match.

`probe_packet(original, scratch, expected)` accepts the immutable used prefix of
packet one and the already admitted capacity of packet two. It mutates only the
second packet. The report is fixed diagnostics, non-Copy/non-Clone, and contains
no bytes, proof, key, reservation or reference. B's returned report owner must
retain A's original reservations through the last borrowed diagnostic use.

## Exact versioned wire prefix

All integers are fixed-width little endian; no varints, serde or dynamic length
containers occur in this outer prefix. Its size is2480 bytes:

| Byte interval | Contents |
| --- | --- |
| 0..8 | magic `LRCART01` |
| 8..24 | local format domain `RC_SHAKE_ROOT_V1` |
| 24..26 | u16 format version1 |
| 26..28 | u16 header bytes2480 |
| 28..30 | u16 public count46 |
| 30..32 | u16 cap root count64 |
| 32..40 | u64 registered codec revision2 |
| 40..48 | u64 inner length including inner magic |
| 48..56 | u64 row height, one of2^3 through2^20 |
| 56..64 | u64 source-only scope constant1 |
| 64..432 | all46 canonical Goldilocks public words |
| 432..2480 |64 cap roots, four canonical Goldilocks words each |

The format domain is a parser discriminator, not a new cryptographic transcript
domain or security construction. The inner magic must remain `LBV2RP02`.
The local wide codec revision, eight-byte field size, Goldilocks modulus and
unchanged2MiB packet limit are checked. A separately checks the full faithful
profile and all18 transport/CPU envelopes; the header cannot select parameters.

Public words0..8 carry the contract profile. Words8..16 carry the source's
context label;16..28 carry statement/input/output commitments;28..34 carry
kind/request/first/count/total/level;34..38 carry the descriptor commitment.
The remaining eight endpoint words also compare exactly to the actual root.
Exact equality of these values is component-source binding only. It does not
authenticate a MatRiCT transaction, an obligation manifest or transaction
context. `transaction_context_authenticated` must stay false, as must complete
workflow and production acceptance. A scope value asking for more is refused.

## Complete packet and memory limits

The entire outer prefix plus registered inner encoding fits inside the existing
2MiB ceiling. No2480-byte extension beyond that ceiling is allowed. Before
Attempt, A must check `HEADER_BYTES + case.encoded_inner_bytes + 1 <= PACKET_LIMIT`
for every one of18 heights. The extra byte is for a trailing-data probe inside
packet two's same2MiB capacity; it does not enlarge either packet allowance.
The header helper independently checks actual used lengths on every operation.

A must retain both full packet capacities, the original proof/key/runtime and
all existing Component owners,64MiB cumulative decoder/canonical storage, fixed
decoded-proof storage, all-height CPU verifier lifecycle and fixed source/header/
codec/action/report/caller/forwarding storage before native dispatch. Header
helpers only borrow those buffers. They allocate no vectors or strings, emit no
diagnostics, run no decoder/verifier and accept no callback. No reservation is
released or recycled by this module. Driver printing still needs separate
admission; neither the header nor its result carries a driver allowance.

Source-fixed helper storage includes value/checked-packet views and Results,
HeaderRefusal, HeaderProbeReport and HeaderProbeError/Results, four-entry u16 and
u64 encode arrays, four-entry u16 validation array, two/four/seven-entry negative
case arrays, eight prefix lengths, their complete IntoIter types, public/cap
slice iterators and enumerate frames, ranges, scalar/word byte arrays and array
construction closure captures. A must include all of these and caller frames,
not only the report's layout. There is no recursive data traversal or unbounded
list. Each loop has a source-fixed maximum, and checked counters bound reports.

Test reservations precede every fixture and packet. A separate test-only
2MiB+1-byte synthetic vector exercises refusal of an oversized outer packet;
it never reaches a decoder or runtime and does not increase the runtime packet
cap. The remaining tests use fixed arrays. Requested test storage and fixed
frames are held through payload destruction and final ledger-zero checks.
These source claims do not establish process RSS, allocator behavior or physical
worker/GPU fit, and are not substitutes for the coordinator's terminal audits.

## Negative observations and refusal classification

Successful probe diagnostics contain two positive header checks and exactly:

-24 syntax refusals: magic, domain, format/header/public/cap versions/counts,
  codec revision, source-only scope, three invalid inner lengths, two invalid
  heights, eight short prefixes, one missing byte, one extra byte and inner magic;
-46 distinct canonical public mismatches, including every profile/context/spec/
  endpoint field;
-256 distinct canonical cap-word mismatches;
-one different but supported height;
-302 noncanonical field refusals, one for every public or cap word.

The total629 negative observations are outer syntax/equality checks, not
cryptographic mutation rejections. Each case must yield its exact typed local
HeaderRefusal; acceptance or a different error fails the action. Missing data,
wrong counts and oversized declarations are refused before any inner decode.
The original packet and actual proof are never mutated. Scratch is restored on
success; on an error only disposable scratch may remain changed. No restoration
or whole-owner unwinding claim is made for a failed helper. There is no retry.

No arbitrary corrupted inner body is decoded in this helper. The core API's
generic postcard failures remain unclassified, including A046's one-byte-short
storage test. They cannot count as a valid cryptographic mutation, budget-only
refusal or complete artifact acceptance. B's positive bounded decode, exact
complete-packet reencoding and numerical CPU verification are separate actions.
These header probes add no raw-proof, interior-boundary or transaction-context
coverage, no asynchronous/unwind qualification, no complete workflow and no
performance claim. Existing resource, thread, row and cryptographic limits stay
unchanged.
