# Native graph preparation staging inventory

This source census follows the actual GPU constructor. It is not a total byte
bound, preallocation lease or dispatch authority. It identifies allocations that
must be reserved before construction, including allocations made before the
existing per-operation admission checks. No CPU witness fallback is proposed.

## Entry and retained inputs

`execution/preparation.rs::with_witness_preparation` releases prepared state,
borrows the registration registry mutably to serialize preparation, and calls
`native_gpu::with_operations`. The latter constructs Capabilities, Run,
DeviceSession, a full managed ProofCapacity, and a borrowed OperationContext.
The callback constructs the entire CommittedBackend and returns the graph.
Graph and decoded input capacities are explicitly outside the existing numeric
operation allowance. The Session/capacity guard ends before the returned graph
is later consumed. It is therefore not the graph's ownership reservation.

OperationContext itself is inline: borrowed Session/Run, host allowance and one
Cell<bool>. Raw arithmetic/crypto execute through a poison guard. Catching a
failure cannot restore that context. CommittedBackend moves its first error
String into its poisoned state and skips later callbacks without cloning that
diagnostic. Original diagnostic creation remains outside the input/output
operation models.

## Research adapter storage before operation dispatch

| Actual adapter | Owned storage and lifetime |
| --- | --- |
| Graph canonical arithmetic | ArithmeticOperationSpec's four-word metadata Vec and an exact raw input Vec; at most 512 input and 256 output words for whole polynomials, two/one for scalar calls |
| Signed scalar arithmetic | Four-word metadata Vec; raw operand arrays are inline; one output word |
| Signed-to-canonical polynomial conversion | Four-word metadata Vec and at most 256 copied raw words; returned256-word Vec coexists until conversion to the fixed array |
| NttAir raw operation, count 1 | 768 entries of `[u64;4]` plus inline 64-word permutation; spec metadata grows from 4 to 3076 to 3140 logical words, then steps retire;256-word raw input;256 output words and shaped result coexist after raw input retires |
| MulAir raw operation, count 1 | 1024 entries of `[u64;2]`; spec metadata grows from 4 to 2052 logical words, then terms retire;512-word raw input;256 output words and shaped result coexist after raw input retires |
| Automorphism | Inline 256 source and 256 factor words; spec metadata grows from 4 to 260 to 516 logical words;256 output words converted into a fixed array |
| Node commitments | RawNode is an inline 256-word scrubbed array for signed/byte conversion; public root/status readback is five inline words |

The NTT/Mul AIR constructors hold only modulus/count/height scalars. Their dense
periodic-column builders are not called by `evaluate_gpu_operations`.
`gpu_operation_schedule`/`gpu_operation_terms` allocate before the existing
`ctx.admit_arithmetic_operation` call. A genuine preconstruction reservation must
cover those earlier allocations as well as metadata growth overlap. The pinned
metadata growth upper bounds follow RawVec and are source-derived; they must not
be replaced by only the final Vec length.

## Core arithmetic operation staging

`native_gpu/operations_arithmetic.rs::staging_bytes` includes raw input words,
raw output words, actual metadata capacity and status/work-item words, and
rejects above 64 MiB. This is a per-operation component check after spec creation.

`engine/device/operations_arithmetic.rs::research_arithmetic_output` additionally
constructs a four-entry MatrixSpec Vec, a MemoryPlan, four SecretAllocation
owners (input, metadata, output, status), an invalid-status Vec, compute kernel
builder/event wrappers, fences, and the returned output Vec. The plans precede
GPU buffers, and status is checked before reading the result. Status and result
Vecs coexist. Device wrappers have Arc/lease/runtime referents outside their
inline struct sizes. Every source-owned wrapper and all shared engine objects
need their real retained owners charged; the 64 MiB component check alone does
not supply that charge.

## Raw primitive construction and crypto

Parameters run three AES streams of 30592, 13464, 186160 bytes, followed by uniform
outputs 7168, 3040, 37120 u64 words respectively. The retained matrix shapes are
28,12,145 raw polynomial arrays. `polynomials(words)` copies into arrays while
the input word Vec is live; regrouping into rows then copies those arrays again
while the intermediate Vec lives. Mat2 fills a new 4 × 3 matrix from an IntoIter;
the iterator's backing survives until the cursor is dropped. Native matrices
coexist with their symbolic conversions until the backend parameter method ends.

SampleG uses 4788 AES bytes and 1024 coefficient words, twice sequentially.
ExpandAlpha uses 2572 AES bytes and 512 coefficient words, then 127 bytes for a
256-word sparse output. HashAlpha serializes 230496 bytes and returns 32 bytes.
HashX serializes 16416 bytes, returns 137 bytes and produces 256 sparse words.
Setup and parameter-binding byte buffers also grow. These owners coexist with
the graph, imported references, parameters and generic intermediate Vecs.

`operations_crypto::host_bytes(input, output)` checks
`input +16*(output+1)+80KiB`. `pq_raw_crypto::RawPlan` repeats that check and
builds four inline specs. Device buffer lengths are input bytes expanded to
words, five geometry words, an AES table of 16896 words (or one scratch word),
and output+1 words. The four SecretAllocation owners scrub independently.
Input upload uses an inline 2048-word staging array. AES launches two kernels;
other raw operations launch one. EventBatch uses the engine's bounded inline
64-event collection, not a per-operation heap Vec, but compute/event backend
wrappers and engine ownership still need a runtime bound.

Readback reserves exactly output+1 u64 slots, validates the final status, then
pops it. **The returned Vec retains output+1 capacity.** Byte conversion keeps
that raw-word allocation while allocating the Vec<u8>; uniform conversion moves
the existing Vec without shrinking; sparse conversion copies into a fixed
array before its RawWords scrubbed owner drops. Owned Vec-to-Vec transformations
in the research adapter may preserve their source allocation through in-place
collection, so logical result element counts alone do not bound capacity.

The fixed primitive schedules make the largest raw AES byte conversion component
check `32 + 16*(186160+1)+81920 =3060528` bytes. This number is a component formula,
not an additional worker allowance or a complete constructor plan. Counts and
intermediate lifetimes must still be incorporated into one preceding ledger
reservation with the retained owners.

## Run, reporting, error and cleanup referents still open

Capabilities::cpu initially collects the arithmetic-stage vector, and `scoped`
uses retain: reducing it to WitnessTrace does not shrink the original capacity.
Run holds Arc<Mutex<State>> with observation/component Vecs. Native operations
only use WitnessTrace/OpenCl and no component scopes, but the first observation
push still has Vec minimum capacity. `finish` builds missing/unaccounted/component
vectors, clones Capabilities, and moves observations to Report. Run::Drop also
clones Capabilities and publishes a failure report on early exit. Optional
publication serializes into a String. Those owners and failure paths must remain
leased through report return/destruction; merely observing one final report
entry does not bound their creation.

DeviceSession retains Arc<Session>, JobLease and transcript HostQuota. Its
ProofCapacity retains a capacity Lease, optional WalletDevicePlan and another
JobLease reference. Shared engine program/kernel caches, allocation accounting,
retained event wrappers and backend driver state have additional referents.
The existing context reserve remains 4 GiB and managed limit 8 GiB; this inventory
does not enlarge or replace them.

The current OpenCL/CUDA wrappers convert backend errors with `to_string()`.
Their maximum owned diagnostic length is not established here. The backend
moves the first String without copying it, but the live outer entry still
formats a failure prefix. Without a bounded diagnostic owner or an
established upstream length bound, no complete error-path host reservation can
be issued. This is a concrete missing source referent, not permission to insert
an arbitrary safety margin.

Raw operations use queue fences before readback and SecretAllocation cleanup on
partial allocation or kernel failure. An eventual constructor owner must retain
its host and device/runtime claims until all fences, partial buffers, event
records, reports and backend/import containers have retired. The graph claim
then moves with the original graph into downstream consumers. The existing
callback return, metadata admission and B013/B014 census objects do not establish
that lifetime, so the complete producer remains unavailable.

## Graph payload lifetime qualification

The private test-only `gpu::lower_owned_on_gpu` wrapper now carries a real
`source_graph::PendingGraph` through `with_witness_preparation` and drops the
returned report before releasing graph growth storage. The original graph and
decoded input reservations remain with the returned immutable owner. This
closes that graph-payload transfer in the qualification path only. The other
adapter, memo, runtime, report/error and cleanup referents in this inventory
are still separate obligations; no complete producer is enabled.
