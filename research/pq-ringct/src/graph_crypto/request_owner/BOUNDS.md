# Immutable SHAKE request storage

`ShakeRequestPlan` derives a source-storage reservation before copying an input
or constructing a partition. It borrows the exact source bytes immutably and
stores fixed profile/operation/subrequest/output metadata plus the existing
Policy. It validates lengths and index arithmetic, maximum batch sizes and the
unchanged 8 GiB child-estimate ceiling. No caller can attach a token to a
previously allocated Request, substitute a different input during construction,
extract the owned Request, or obtain a mutable borrow of it.

The additive [`graph request collection`](../request_collection/BOUNDS.md) shares
the same allocation-free geometry through `source_geometry`. This helper accepts
length/identity/policy metadata and returns fixed requirements only. It creates
no owner or dispatch token. The single-request `new` path still fixes the actual
immutable byte borrow, and its construction and storage formula are unchanged.
The collection separately admits its own serialization buffer before producing
those borrowed bytes; standalone callers still need enclosing source admission.
The extraction was included in the audited 46-pass ownership regression suite
and two ignored collection qualifications, including unchanged full-graph
reference equivalence. Their receipts and allocation evidence are recorded in
the [collection qualification results](../request_collection/BOUNDS.md#audited-qualification-results).

`construct` accepts only its exact categories/bytes in the same ledger, within
the existing 32 GiB host and 8 GiB device worker ceilings. It then copies the
input and calls the unchanged `Request::new`. The returned `ReservedShakeRequest`
destroys the full Request before its reservation. Its shared `request()` borrow
keeps that reservation alive while native/compiler owners borrow the Request,
including the execution adapter's synchronous actual phase-cleanup call.

The original source bytes, their serialization and surrounding graph/fixture
storage already exist before this planner; they are separate enclosing terms.
No graph/manifest authentication, native producer admission, dispatch permit,
recursive proof ownership or GPU fallback is supplied here. AES construction and
the baseline request path are unchanged. Paired runtime dispatch stays disabled.

## Source-derived request bound

Qualification pins the existing Rust 1.96 release x86_64 implementation. Planning
uses only checked fixed-size arithmetic and allocates no heap. It mirrors the
source constructor's existing pre-dispatch choice of maximum batch size; it does
not change that choice or retry a dispatched proof.

For a full absorb or squeeze range of length `n` and power-of-two maximum `m`,
the current greedy partition emits `n / m + popcount(n % m)` segments. Add the
mandatory singleton padding segment and, where present, the odd squeezing tail.
The largest native segment's unchanged `estimate` formula determines whether
the existing constructor keeps that attempt or halves `m`. `m <= 64` gives at
most seven attempts. This use of the existing heuristic reproduces partition
selection; it is not a native proving-memory bound.

For each attempt with `s` segments, independently sum
`4 * max(s, 8) * size_of::<ShakeSegmentAir>()` and
`4 * max(s, 8) * size_of::<SegmentInfo>()`. These terms cover all cumulative
RawVec allocation requests, minimum capacities, replaced buffers and spare
backing for the source partition's push loop and Result/collect metadata loop.
All attempts are summed, so rejected partitions and old/new allocation overlap
remain covered even though those buffers are normally destroyed between
attempts. The final reservation is retained unchanged, without shrinking it to
observed capacity.

| Category | Owned charge |
| --- | --- |
| CompilerInputs | Exact byte length of the new `to_vec` input copy |
| RegisteredMetadata | All cumulative partition and SegmentInfo Vec requests, original constructor-error allowance, and fixed plan/owner/Request headers |

The source constructor's error paths contain only fixed literals and Debug
formatting of the closed SHAKE Error or standard TryFromIntError types. The
longest enumerated text is the existing smallest-segment budget error.
`4 * max(longest_text_length, 8) + 2 * size_of::<String>()` covers its String
growth/copy bookkeeping. One error ends construction. The original String is
explicitly dropped while the reservation is still held; only an inline Error
enum escapes. The closed error-source list is in `error_text_bound`; a future
constructor or formatter change requires renewed source review/qualification.

Source success checks compare actual segment count, total coverage, descriptor
and largest segment to the precomputed plan before returning the owner. These
are consistency checks after a preceding reservation, never retroactive memory
admission. Allocator overhead, OS stacks and preexisting enclosing state remain
separate from these requested-storage counters.

## Qualification

Authored focused tests compare the unchanged constructor's exact segment
metadata, AIR geometry and cache identity across empty input/output, boundaries,
absorption/padding/squeezing, and batch maxima 1/8/64. They check owned payload
independence, retained charge through native/compiler borrows, refusal under the
existing worker budget, identity/length/policy rejection, foreign/mixed/short
tokens, and final cleanup after all seven constructor attempts fail.

An ignored test under `native-verification-allocation-audit`, explicitly enabled
with `LATTICA_REQUEST_OWNER_QUALIFICATION=1`, observes all process allocation
requests in serialized planning/construction. Planning and rejected-token paths
must allocate zero bytes; varied successful growth cases and the original error
path must fit the preceding source bound. The existing generic planner observer
retains its historical native-verification log prefix; no proof verification is
claimed by this request-construction check.

On 2026-10-24 the coordinator qualified the frozen combined A+B source serially.
`allowance-ab-ownership-tests-1` passed 40 focused tests with four ignored,
including the four request-owner tests. The explicitly enabled
`allowance-ab-native-ownership-tests-2` then passed both ignored qualifications:
this allocation observer and the actual-context fresh native pair/odd-tail test.
The observer recorded zero allocation requests in planning and rejected-token
paths. Successful construction and the injected original-constructor failure
stayed within their preceding source bounds:

| Construction case | Observed requested bytes | Pre-admitted source bound |
| --- | ---: | ---: |
| Empty input/output | 416 | 4,340 |
| 137-byte input/output | 553 | 4,477 |
| 65 rate blocks, output with a trailing byte | 112,424 | 125,916 |
| 4,096 rate blocks plus 17 input bytes | 3,935,409 | 3,945,157 |
| Original-constructor failure after seven partition attempts | 59,237 | 73,084 |

The actual-context test kept this request charge alive through three fresh CPU
native children, pair and odd-tail compilation, and actual phase cleanup. Each
output drop left only the request charge; dropping the request owner and retiring
the context left zero ledger storage. This is small-fixture lifetime evidence,
not admission for the original borrowed input, enclosing graph or native proof
production scratch.

The coordinator audited terminal/reaped status, frozen/current source manifests,
executable identity and raw logs before permitting documentation changes. The
ignored job took 130.31840506198932 guard seconds including build, peaked at
2,247,233,536 process bytes, and used the existing 8 GiB process cap, 6 GiB high
watermark and zero swap. These are correctness-job measurements. Full receipt
identities, the preserved initial command-line failure, and compiler geometry
are recorded in the
[`owned SHAKE qualification`](../../component_tree/owned_shake/BOUNDS.md#combined-request-and-actual-phase-qualification).
No outer proof, GPU work, complete-workflow timing or runtime admission was
established; paired production remains disabled.
