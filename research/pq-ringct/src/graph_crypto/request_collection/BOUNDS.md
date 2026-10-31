# Immutable collection of the graph's three SHAKE requests

`GraphShakeCollectionPlan` covers exactly one ordered `ParametersPp`, `HashAlpha`
and `HashX` request from an immutable `UnprovedRelationGraph`. It derives their
actual operation indices, serialized lengths, partitions and request recipes
before allocating any owned data. AES requests, other graph obligations and
the existing baseline `Plan` are unchanged. This is an additive CPU-reference
source owner; `Singleton` remains the default and paired runtime dispatch stays
disabled.

The source graph/fixture, decoded transaction, graph-plan metadata and their
original construction allocations already exist. **This collection does not
admit or own those enclosing `E_graph` terms.** Its source borrow prevents
replacement or mutation while its plan/owner is live, but does not establish
that the graph has a storage reservation. Authentication of the supplied profile,
graph manifest, statement and operation/source joins is also a separate required
obligation. Exact pointer/profile checks are identity checks, not cryptographic
acceptance.

## Fixed recipe before allocation

Planning uses a three-entry stack array and checked scalar arithmetic. It scans
all graph operations, rejecting missing, repeated or reordered SHAKE kinds.
The graph's opaque IDs are read only through its own accessors. Setup seed must
match the graph; each transcript has 1 through 256 parts, matching the existing
`TranscriptAir` limit. A byte part contributes 32 bytes. A canonical Q/QHAT
polynomial contributes `4 * 256` bytes; every coefficient must fit the named
modulus and u32 before serialization can begin. Signed/mismatched polynomial
values, unsupported policies, index/size overflow and excessive child estimates
fail with inline error enums. No AIR, source-root vector, manifest or inventory
hash is constructed in planning.

The narrow `ShakeRequestPlan::source_geometry` helper shares the unchanged
single-request recipe. It returns only fixed geometry/requirements; it cannot
construct an owner, attach a token to a raw Request, or authorize proof dispatch.
The real `ShakeRequestPlan` is still formed from exact immutable serialized bytes
and validates the same recipe before copying them.

| Component | Preceding charge |
| --- | --- |
| Three complete request owners | Sum of their exact `source_geometry` recipes, including input copies, all partition attempts, original constructor diagnostics and fixed headers |
| Serialization buffer | Largest of the three derived input lengths, charged as CompilerInputs |
| Serializer fixed storage | Vec header, SHAKE256 state/reader sizes, 49-byte setup frame, 32-byte digest and 4-byte LE word, charged as CompilerInputs |
| Collection metadata | Fixed plan, final owner and partial-construction array sizes, charged as RegisteredMetadata |

One exact same-ledger reservation covers the entire recipe atomically before
any serialization or request allocation. The combined worker ceilings remain
32 GiB host and 8 GiB device, with the existing 8 GiB native child-estimate cap.
No caller quota, generic callback or raw Request attachment can replace the
recipe. Insufficient allowance is rejected by the ledger before construction;
foreign, short, mixed or oversized reservations are refused before allocation.

`Vec::with_capacity(maximum_input_length)` requests the serialization backing
once. The buffer is cleared and reused between the three requests. Every append
checks the predetermined length and existing capacity before writing; it cannot
grow the buffer. There is overlap between this buffer and all completed request
payload copies. The complete three-request reservation plus this one temporary
buffer accounts for that overlap, even while the current request's partition
constructor runs. All original single-request growth/error terms remain intact.
Observed capacities never expand a budget.

These counters describe requested backing plus conservative fixed bookkeeping,
not physical RSS. Allocator metadata/alignment, compiler-generated stack spills,
OS thread stacks and the preexisting ledger/control blocks require separate
enclosing allowance and process guards. Charging named fixed serializer values
does not establish a bound for the complete call stack.

The closed serializer writes each Bytes32 part verbatim and every canonical
coefficient in LE-u32 order. It creates no intermediate kind/value/root/word
vectors. The ParametersPp encoding is the existing domain string followed by
the SHAKE256 digest of the fixed 49-byte setup frame and the exact context bytes.
SHAKE state and output use fixed stack arrays. This public CPU preprocessing
does not produce a fresh GPU-work receipt or implement a GPU-required fallback.
The output bytes are compared with the existing reference serializers in tests.

## Ownership and failure cleanup

The plan pins the graph and profile; construction accepts no replacement source,
profile, entries or serializer. Each returned request is a `ReservedShakeRequest`
with its original exact recipe. `request_for` returns a shared borrow only for
the same graph pointer and profile. Request indices and the complete ordered
three-entry inventory are derived from the actual source graph, never supplied
at construction or lookup. There is no mutable borrow, Clone or raw extraction.

Construction declares reservations before their dependent locals. On a late
failure, the serialization buffer and any completed request owners die before
collection/temporary reservations. Each child owner destroys its Request before
its own token. On success, the buffer is explicitly destroyed before temporary
storage is released; final request owners precede collection metadata in the
returned struct. Drop or unwind releases the complete retained collection.
Only bounded inline errors escape.

A request borrow from the collection can feed the existing native-owner and
`GroupCompilePlan` APIs. Their request lifetimes keep this collection alive,
including through the existing execution adapter's synchronous actual cleanup.
This adds no new execution entry, generic phase split or native production
permit. The actual phase adapter still admits its own compiler/output/verifier
requirements while the entire collection remains charged. Native proving scratch,
backend/report/error transients, recursive proof/frontier storage, enclosing graph
ownership and final transaction closure remain separate prerequisites.

## Qualification

Authored focused tests compare both public setup seeds and batch maxima 1/8/64
against the existing reference serializers, exact payloads, first/last cache
identities, operation indices and native partitions. The graph hints deliberately
use repeated fixed polynomials: their HashAlpha/HashX byte lengths are the full
230,496/16,416 profile, but they are not a valid transaction or proof. Other tests
cover missing/repeated/reordered operations, transcript limits, setup mismatch,
noncanonical/wrong-kind values, checked arithmetic, exact/foreign/short/oversized
tokens, insufficient allowance, graph/profile lookup mismatch, native/compiler
borrows, late construction refusal after one request exists, and owner unwind.

The ignored allocation test requires `native-verification-allocation-audit` and
`LATTICA_SHAKE_COLLECTION_QUALIFICATION=1` under the coordinator's serialized
process guard. It requires zero heap requests during planning and wrong-token
refusal, and checks all successful/partial-failure construction allocation
requests against the complete preceding recipe. Source fixture creation and the
independent reference serializer are outside that observed/admitted scope. The
generic observer's historical native-verification prefix does not mean this
collection test verified a proof.

A second ignored test, `full_graph_collection_matches_unchanged_seven_request_plan`,
requires `native-matrict` and the same explicit qualification environment. It
uses the existing full public graph fixture and unchanged `Plan::new`, selects
its three SHAKE requests, and compares all payload bytes, request/profile/operation
identities, native segment geometry and every segment cache identity. The shared
fixture can load the existing public archive; source fixture creation, manifest
validation and the reference plan remain outside collection admission and inside
the coordinator's process guard. This adds no production acceptance path.

## Audited qualification results

The coordinator qualified the frozen source serially on 2026-10-24 with Rust
1.96 release and `recursive-wide,native-matrict,native-verification-allocation-audit`.
Both jobs used two build/Rayon threads, one test thread, an 8 GiB process cap,
6 GiB high watermark and zero swap. Terminal/reaped status, frozen/current source
manifests, executable identity and raw logs all passed audit before documentation
thaw. Peer and coordinator source reviews found no blocker for this ownership
scope. Rust source remained unchanged after qualification.

| Correctness job | Result | Guard seconds including build | Peak process bytes |
| --- | --- | ---: | ---: |
| `wireopt-b-ownership-tests-1` | 46 passed, 6 ignored | 76.21927784499712 | 1,505,062,912 |
| `wireopt-b-collection-qualification-1` | 2 passed | 2.083719836024102 | 182,317,056 |

The normal suite includes six new collection tests plus the existing request,
native/compiler owner, report and lifecycle regressions. The explicitly enabled
ignored run passed the allocation observer and full-graph reference comparison.
At the current default maximum of eight SHAKE permutations per native segment,
the full fixture and unchanged seven-request `Plan::new` agreed on all three
selected payloads, identities, segment geometry and every segment cache key:

| SHAKE request | Input bytes | Native segments in the request partition |
| --- | ---: | ---: |
| ParametersPp | 109 | 1 |
| HashAlpha | 230,496 | 214 |
| HashX | 16,416 | 17 |

The total is 232 native segments in the existing partition. This is reference
planning evidence, not 232 newly generated STARK proofs or a recursive-proof
speedup measurement. The full graph/source fixture and reference plan remained
outside collection admission and inside the process guard.

All observed allocation requests fit the preceding collection bound:

| Allocation case | Observed requested bytes | Pre-admitted bound |
| --- | ---: | ---: |
| Requested batch maximum 1 | 929,709 | 1,244,606 |
| Requested batch maximum 8 | 537,005 | 584,830 |
| Requested batch maximum 64, existing child-budget selection unchanged | 587,757 | 677,598 |
| Late failure after ParametersPp construction | 231,021 | 584,830 |

Planning, graph/profile lookup rejection and wrong-token refusal each recorded
zero heap requests. Successful output destruction and partial-failure cleanup
left zero collection ledger storage. Requested maximum 64 still follows the
existing pre-dispatch budget selection; no dispatched proof was retried. The
observer reports cumulative allocation requests, not process RSS or additional
memory allowance.

Receipt and raw-log SHA256 identities are preserved with the campaign evidence:

| Job | JSON receipt | Raw log |
| --- | --- | --- |
| Focused ownership suite | `3443ee09473e2b78a4d9dab7b7e77694a7549c9b019255ad43dd5a2c231b3ee5` | `2fb3d971342980c77015b90bd579ec0066c7eae50562d3ffe7a3c3f66d780dec` |
| Ignored collection qualifications | `1ea75c39c728f7b1204997e7dd5b154fe4463340f60d2ab51e8614f95bccf94d` | `3824a9870adbdb77fe29604cf7a687ebffd1b375755788e79ce853be6c7314d7` |

These are correctness-job measurements. No SHAKE native proof, outer proof, GPU
execution, complete-workflow timing or performance promotion was established.
Production gates, cryptographic parameters and all resource allowances remain
unchanged; enclosing graph/source ownership is still a separate prerequisite.
