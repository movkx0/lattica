# Selected R4 diagnostic row screen

This test-only module attempts complete row closure for one persisted public
MatRiCT fixture. It neither proves a transaction nor issues a dispatch permit.
PairedV1 continues to refuse before execution. A successful fixture screen would
not qualify a fresh request, runtime storage ownership, or workflow throughput.

## Provenance and accounting scope

The enclosing serialized harness loads an existing, bounded public fixture with
`allow_create=false`, independently verifies its native proof, and lowers one
immutable graph. Its private input constructor derives the registered shape,
algebra plan, graph tree, crypto plan and auxiliary factory together from that
same graph. No constructor accepts independently built plans. The result borrows
the complete private input owner and exact immutable Request slice; it cannot
outlive them or be transferred to a different input owner. No unsafe or
self-referential ownership is used.

Existing fixture decode, native verification, graph lowering and public
plan/witness-hint setup run in the enclosing diagnostic harness. Their memory
and time are explicitly outside this compiler-screen accounting. No statement
here establishes source-derived admission for those earlier stages. The harness
still needs the coordinator's OS guard, zero swap and serialized execution.

The sole fixture is the campaign copy
`fixtures/diagnostic-context71-setup29.json`, 833617 bytes, context `[71;32]`,
setup `[29;32]`. The file is SHA3-256 checked before and after loading against
`0f2a2e44d7bff5597b3fc6f21ce4dfb8716201cdc0f2e32471ccda213e2d08b2`.
Its coordinator-pinned SHA-256 is
`b78c234c604cdbc2e44925715f6c900a739e24408223df60ab6a9b1846d5898a`.
The report distinguishes the verified SHA3 digest and pinned SHA-256 identity.
This is an older research fixture, not an accepted N3/N4 benchmark transaction.

## Exact configuration and coverage

The screen requires the unchanged 1048576 row ceiling, serial SHAKE and AES,
Branches composition, 24 GiB native allowance, 32 GiB outer allowance, and
64 MiB proof-cache entry limit. Both source-owned crypto policy and supplied
pipeline policy must have AES64, SHAKE32, Estimated admission and 24 GiB child
allowance. `GraphProofPlan` retains its exact immutable `ResourceLimits`; all
five fields must equal algebra64/NTT32/Mul32/cells2^27/24 GiB, and its native
host allowance must still equal 24 GiB.

Every native segment descriptor is compiled separately. Singleton and PairedV1
wrapper schedules feed the same binary carry topology used by RequestProver;
all spans must remain adjacent and cover exactly the source request's native
units. Every request and auxiliary child is consumed exactly once by its graph
consumer or producer branch. Duplicate, omitted or missing consumption refuses.
The graph plan's exact operation batches must match the algebra plan in order.
All source/algebra cores, branches, graph leaves and adjacent graph parents are
then closed before the actual binary N3/N4 final aggregation shapes.

Four registered public widths enumerate all 18 configured power-of-two child
heights. Their independent operation-class maxima are conservative envelopes,
not an assumption that compiler size is monotone in height. A source-derived
upper bound above the configured ceiling refuses with the stage, ordinal,
span and row bounds. That refusal does not prove that a different optimized
implementation could not fit. There is no silent fallback or proof retry.

## Planner-owned metadata before allocation

Let Q be crypto Request count, S the sum of all native segment counts, A the
auxiliary Request count, L the graph leaf count, and B the producer-branch count.
All sums and products are checked before allocation. The per-layout report
capacity N is `2*S + 2*L + B`: each request contributes at most twice its native
segments, every graph contributes at most twice its leaves, and each producer
branch contributes one node. Exact counts may be smaller.

Each fixed source capacity below receives a factor of two for allocation
capacity/temporary movement. No vector is pushed beyond its fixed capacity.

| Planner backing | Logical simultaneous entries |
| --- | ---: |
| Both layout RowBound vectors | 2*N |
| Crypto core outer Vec headers | Q |
| All crypto OperationCounts inner vectors | S |
| Auxiliary OperationCounts vector | A |
| Graph Option<OperationCounts> vector | L |
| Both layout request-root Node vectors | 2*Q |
| Current and next adjacent graph generations | at most 2*L |
| Complete-consumption bool vectors | Q+A |

The current graph generation remains owned by its IntoIter while its successor
is allocated. They fit `L+ceil(L/2) <= 2*L`; layouts are closed sequentially.
The reservation also includes the inline result, NativeCores and Descendants
objects plus 16 KiB for the fixed carry array, Vec headers, closures, scalar
scratch and bounded error strings. All planner metadata must fit 4 MiB before
the first compiler or metadata Vec is created. Every core separately admits
its 2 GiB builder and 512 MiB auxiliary planning allowances; no proof or compiler
program survives a core call.

## Bounded reporting and measurement labels

Reporting uses one fixed 16 KiB stack byte array and seven fixed optional
stage-maxima references. It creates no JSON Value tree, BTreeMap or report Vec.
Checked formatting refuses to grow the buffer. The logical output bound is
8192 bytes: fewer than 3000 bytes of fixed labels/flags/identities, at most
seven 256-byte stage objects, and fewer than forty 20-digit numeric fields.
Elapsed time is finite, nonnegative, below 10^12 seconds and printed with six
fractional digits. A single buffer is reused for both layout records.

Elapsed time is captured once immediately after both layouts close, before
report construction or output. Both records therefore carry the same combined
layout compiler-screen duration. Native/recursive totals are scheduled
invocations; N3/N4 totals are fixture estimates. They are not measured proof
counts, per-layout speed comparisons, GPU timings, or workflow speedups.
