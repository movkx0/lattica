# Required phase storage: source audit and unresolved admission

This is a rejecting audit, not dispatch authority. The accounting and lifecycle
prerequisites at `fcb34a6d7e141df604fe5626289d3b9b72a0c19c` accept caller-supplied
`Requirements`; they do not derive a complete workflow bound. The baseline
methods remain unchanged and do not use those prerequisites. No paired runtime
is enabled by this document. Complete selected-R4 native, consumer, ancestor,
and final-aggregation row closure must pass first, within 1,048,576 rows.

All additions, multiplications, and subtractions below must be checked before
allocation. A missing bound, unsupported source shape, or underflow rejects the
whole configuration before proof dispatch. Post-allocation capacity checks can
detect drift but cannot authorize the preceding allocation.

## Unchanged envelope and owners

The worker host allowance is 32 GiB, the native allowance 24 GiB, and managed
device allowance 8 GiB. The existing 4 GiB GPU context reserve is outside that
managed allowance. The process cap remains 47 GiB, with zero swap and unchanged
thread and row limits. These are ceilings, not additional storage granted to
each owner. Heap-request accounting is not a proof of RSS or driver storage.

Use these symbols for requested storage:

| Symbol | Owner |
| --- | --- |
| `E` | Enclosing live worker data, including registry, graph/fixture/request data and bounded persistent diagnostics |
| `L` | All retained proofs, registered keys, frontier nodes, manifests and report snapshots outside the active phase |
| `C` | Enforced program-construction quota, retained conservatively until its compiler/program owner is destroyed |
| `A` | Source-derived compiler auxiliaries outside `C` |
| `O` | Output storage reserved before production, including native or recursive proof backing |
| `R` | Live typed reports, composition state, serialized reports and diagnostic temporaries outside other proven reservations |
| `B` | Active backend host envelope passed to an existing bounded backend |
| `V` | Independent-verifier scratch, configuration, public copies and bounded error formatting |

`E`, `L`, `O`, and `R` must describe simultaneous owners, not only logical
payload lengths. Include containers, spare capacities, Arc allocations and
replacement overlap where their source allocates them. A retained output's
reservation must move with it and release only after its payload is destroyed.

The registry can conservatively contribute **64 MiB once** to `E`. That existing
combined limit includes verifier metadata, identity-receipt backing and the
bounded registration telemetry backing/report reservation. Its **1 MiB receipt
sublimit is inside 64 MiB**. Caller-owned keys, retained report snapshots, the
active prover, independent verification scratch, allocator/driver overhead and
general diagnostics are explicitly excluded. See
[`execution.rs`](src/execution.rs), `PUBLIC_METADATA_LIMIT_BYTES`,
`Registry::metadata`, and `ProvingContext::report`.

Prepared state is cleared before and after the future bounded phase. Its
currently unknown footprint must never be represented as zero while it is
still live. There is no idle prepared-state retention in this proposal.

## Conservative phase equations

For each phase, require the complete host sum to fit 32 GiB before dispatch:

| Phase | Conservative host requirement |
| --- | --- |
| Native production | `E + L + O_native + R + B_native` |
| Native independent verification | `E + L + O_native + R + V_native` |
| Recursive compilation | `E + L + C + A + R` |
| Registered proving and its admitted verification | `E + L + C_owner + A_owner + O_recursive + R + B_registered` |
| Carry-stack or final graph merge | The corresponding compilation/proving equation with every still-live sibling and completed graph in `L` |

The native sublimit also remains enforced. Conservatively charge all native
proof owners and native phase-specific helpers outside `B_native` against that
24 GiB declaration, and reduce `B_native` accordingly. Do not treat the current
context check `B_native <= context.host_bytes()` as enforcement of the separate
native sublimit.

Each GPU backend phase reserves the full **8 GiB managed device allowance once**
in `PhaseScratch`, with retained device storage zero only after actual cleanup.
The backend engine's live allocations and workspaces are inside that capacity;
do not add another 8 GiB for them. CPU compilation/verification does not itself
grant device capacity. Any GPU endpoint preparation used by compilation must
be admitted explicitly as a GPU phase or included in its complete phase bound.

Keep the compiler/program owner charged while passing only the remaining host
allowance to the registered backend. This intentionally duplicates the Program
source contribution also present in the backend's reservation. The overlap is
conservative, not transferable credit. Do not implement complex ownership
reclassification merely to recover it. If this duplicate accounting does not
fit, refuse unless a separately reviewed exact ownership model is justified by
an actually admissible selected-R4 shape.

## Existing registered backend partition

[`with_registered_shared_with_host_budget`](src/execution.rs) already takes a
smaller nonzero host allowance, requires `GpuRequired`, and evicts preparation
admitted under an earlier allowance. Its backend uses
`H = min(passed_budget, resident_pcs::host_output_budget())` before preprocessing.

In
[`gpu_backend/resources.rs`](../../lattica-prover-p3/src/block_v2/machine/gpu_backend/resources.rs),
`Bounds::reservation(1)` derives its own source/compiler/staging reservation.
Writing `input_bytes`, `sample_bytes`, and `trace_bytes` for its checked source
terms, its staging and transient terms are:

```text
input_staging = 3 * input_bytes + 8
staging = max(input_staging, sample_bytes, 2 * trace_bytes)
transient = max(compiler_host_bytes + staging,
                program_host_bytes + input_staging)
```

The reservation also includes retained Program source, compact compiler
schedule, lookup graphs, PCS metadata, the 1 MiB helper allowance, typed-recursive
session storage, engine retained host storage, public-hash storage, symbolic
workspace and the registered native-verifier lifecycle component. Its own
`partition_host(H)` requires that complete reservation to fit and then gives
`H - reservation.host_bytes > 0` to PCS. Those internals are already inside
`B_registered = H`; adding them again as backend internals is unnecessary.
Backend admission still has to prove the requested PCS work fits the remainder.

`program_host_bytes` is the maximum of actual retained source and the
construction request peak. The retained-source census covers Program Arc
storage, operation/row/reference capacities, SelectHint arrays and per-row
instruction arrays. That census occurs after construction; the prior owner
still requires its enforced construction and auxiliary reservations.

The registered independent verifier has a source-audited 257 MiB lifecycle
component included above. It includes a 64 MiB admitted proof-backing ceiling
and bounded metadata/numerical/configuration/public/error storage. This applies
to the registered batch verifier, not arbitrary native AIR verification. Its
source explicitly excludes caller caches, stacks, callbacks, allocator/OS/driver
overhead and diagnostic I/O. See
[`verification_lifetimes.rs`](../../lattica-prover-p3/src/block_v2/machine/backend/verification_lifetimes.rs)
and
[`verification_call.rs`](../../lattica-prover-p3/src/block_v2/machine/backend/verification_call.rs).

## Compiler and native backend boundaries

`ConstructionLimits::max_requested_program_bytes` covers builder interning,
operation growth overlap, compaction and final packing. It explicitly excludes
caller-owned child proofs, `ProofInputs` backing, returned wire arrays, folding
scratch and allocator overhead. Its bounded `ProofInputs` implementation keeps
each old/new value array within the input limit and checks exact requested
capacity. Thus `2 * input_limit * size_of::<Val>()` bounds simultaneous value
backing, while cumulative returned-wire backing needs a separate
`input_limit * size_of::<Wire>()` contribution. Closed compiler adapters must
also derive AIR-owned descriptor/periodic tables, callback expression/variable
arrays, symbolic workspace/retained graphs, private-template construction
overlap and helper arrays. These are terms in `A`, not evidence that arbitrary
AIR callbacks fit.

The native GPU research entry point subtracts two public-value backings and
two Vec headers before giving the remainder to its `Prepared` compiler/PCS
path. It reserves engine capacity before trace generation. This does not cover
caller-owned graph/raw inputs, retained sibling proofs or the caller's later
independent verification. See
[`native_gpu/research.rs`](../../lattica-prover-p3/src/block_v2/native_gpu/research.rs).

## Remaining blockers to complete Required values

1. **Complete live graph and fixture ownership.** The selected workload still
   needs a prior source bound for request/graph/fixture storage, all carry-stack
   owners, compiled nodes and graph children retained through ordered N3/N4
   aggregation. A post-owned census or `estimated_prover_bytes` heuristic is
   insufficient.
2. **Native independent-verifier admission.** The baseline
   [`graph_crypto/factory.rs`](src/graph_crypto/factory.rs) calls
   `p3_uni_stark::verify` directly. It has no preceding complete scratch
   reservation. Agent C's separate bounded native-verifier adapter is intended
   for a future paired producer only; this audit does not claim it is integrated
   or qualified. Do not substitute the registered verifier's 257 MiB component
   for a source bound on this different upstream verifier.
3. **Report ownership and serialization.** The typed stage domain has 19 stages
   and six backends, hence at most 114 distinct observations; composition allows
   at most 16 child slots. In the closed current constructors, capability stages
   are at most 16, or 17 with the debug audit. These are logical counts, not a
   complete preceding byte reservation. `Run::finish` simultaneously owns the
   original and cloned capabilities, missing/unaccounted vectors, missing child
   IDs, the report and possibly parent composition state. `publish` may allocate
   JSON text. Context reports and diagnostics create or clone `serde_json::Value`
   trees and retained snapshots outside the metadata allowance. Derive every
   backing and static/string-size envelope from the pinned source, or stream
   through a bounded writer before admitting the phase. A later `capacity()`
   measurement cannot close this gap.
4. **Failure and diagnostic ownership.** Diagnostics retain at most 32 events
   and truncate the displayed message to 2048 characters, but that does not
   bound the original backend error String, cloned device/identity Values,
   artifact paths or JSON temporaries. The phase lifecycle now returns fixed
   cleanup stage codes; backend formatting and diagnostics still need preceding
   bounds. Preserve required error evidence within an admitted bounded path.
5. **Actual lifetimes and exclusive dispatch.** The current phase capability
   cannot prove arbitrary caller locals have dropped and baseline methods can
   bypass it. Future typed producer/compiler/prover adapters must own payloads,
   move reservations with outputs, enforce the native sublimit, forbid dispatch
   outside the admitted phase, and drop all temporary owners before releasing
   scratch. The lifecycle releases prepared state and drains the queue; failure
   or abandonment retains the reservation and poisons the scope. Recovery
   retires the context rather than permitting another proof.
6. **Source/toolchain and process limits.** The numerical/source bounds are for
   pinned release x86_64 code. Debug callbacks, changed dependencies, arbitrary
   tracing subscribers, allocator overhead, thread stacks, GPU context/driver
   storage and OS/process accounting need their existing enclosing admission
   and guard limits. The 47 GiB process guard is not a replacement for complete
   pre-dispatch payload requirements.

Until every relevant term is supplied and reviewed, the result is
**Required bytes unknown: refuse before dispatch**. The lifecycle's focused
tests and this source audit do not establish runtime admission, complete row
closure, a fresh workflow measurement or a performance improvement.
