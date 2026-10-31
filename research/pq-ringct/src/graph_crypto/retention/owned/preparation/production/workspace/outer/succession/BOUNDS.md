# Original HashX outer succession

This opt-in continuation extends A040's first outer leaf to a fixed nine-phase
HashX component schedule. It grants no complete-request, transaction or final
aggregate dispatch authority. Existing first-only APIs and production Singleton
selection retain their behavior.

The exact order is `L0, L1, P0, L2, L3, P1, P2, L4, P3`. Leaves cover native
permutation spans `[0,32)`, `[32,64)`, `[64,96)`, `[96,120)`, `[120,122)`.
`P0 = L0 + L1`, `P1 = L2 + L3`, `P2 = P0 + P1`, and `P3 = P2 + L4`.
The eight queued plans are consequently `[L1, P0, L2, L3, P1, P2, L4, P3]`.
No assumption that all leaves execute before all parents is made.

## Pre-native closure

`PendingNativeHashx::with_outer_sequence` installs the ordinary bridge if absent
and reserves an independent complete sequence claim before actual preparation
derives immutable PCS capacity. Every B source, compiler, input, output, report,
verification and caller requirement must separately be held before that point.
The new sequence claim never replaces any B claim or admits its source payload.

After original preparation, `PreissuedHashxOuter::with_successors` consumes the
pending sequence ticket and all eight source-issued backend plans exactly once.
The core checks every original footprint against the same startup and PCS bytes,
and rechecks each captured execution selection before allocating the queue.
Its `Vec<Option<PreissuedOuterBackend>>` uses fallible exact-capacity reservation
and requires length and capacity eight. The full backing remains allocated
until queue destruction, even after entries become empty.

The immutable ticket borrow remains alive throughout all ten native attempts.
Sequence-enabled native entry refuses missing, pending, replaced or detached
queue state before native zero. A first-only ticket cannot acquire successors.
Every queued plan must match the original native attempt's private `Rc` identity,
startup requirements, PCS bytes and original ledger. There is no post-native
binding, append, replacement, replan, fallback or readmission path.

## Exact retirement and successor consumption

The opaque original scratch gains an execution ordinal initialized to zero.
The private queue checks its entire prefix is empty, its remaining suffix full,
and its next ordinal agrees with that same original scratch. A successor call
consumes the queue and scratch and permits exactly the next stored plan. After
the ninth outer phase no successor remains. Refusal consumes the complete owner
and grants no retry.

The research continuation requires `RetiredHashxOuterOriginals` returned from
the same actual `ActiveHashxOuter::finish`. It restores that actual sealed
retired runtime through the existing private outer-startup adapter. Startup,
PCS, native wrapper, preparation and verifier claims remain their original
owners; no token is extracted or admitted. Full ledger snapshots must remain
unchanged through binding/restoration, and exact preflight precedes startup.
All compiler, Program, public and witness borrows disappear at actual finish.

Core binding checks only lifecycle/order/source-plan conformance. An actual
runtime can retire after a failed proof. **B must authenticate the preceding
successful proof and the exact next leaf/parent compiler source before every
successor call.** An execution ordinal or retirement receipt is never proof
success or source-authentication evidence. This capsule supplies neither B's
full-sequence source factory nor its parent acceptance gates.

## Ownership and census

`Ready` stores the full queue before its independent original reservation.
Prepared, active and retired phase owners keep runtime/backend/scratch payloads
before that queue claim. The local bound-successor owner similarly stores the
bound backend before the queue so a restoration or preflight failure destroys
payloads before their reservation. The actual active Session remains first in
drop order. Original bridge and native bookkeeping claims stay live through all
their support payloads and compiler-free retirement.

The independent sequence requirement includes full exact queue backing, eight
copies of the incoming/moved backend array and its owning iterator, complete
core/research owners, results, tuples, scratch, source/selection, original
startup restoration and preflight frames. It independently covers the retained
`Rc` allocation/control block and bounded diagnostics. No move elision, inlining
or shared-allocation credit is taken. Existing B source/planning claims remain
additive. The sequence uses no unbounded growth or late quota admission.

Default proof behavior is unchanged, but larger owner layouts and small new
entry-check frames increase the source accounting of existing paths. A043's
shared wrapper formula and original bookkeeping see those new layouts as well.
All immutable PCS/source feasibility values must therefore be recomputed; older
larger capacities are invalid. The unchanged limits are 8 GiB managed device,
4 GiB context reserve, 32 GiB worker host, 24 GiB native host, 47 GiB process,
zero swap, existing row/thread limits, FreshOnly and GpuRequired.

## Qualification scope

Authored focused checks cover exact next-step boundaries and refusal of skipped,
duplicate, reversed and exhausted steps; missing/short/foreign sequence claims;
actual pending-source bridge/queue preclaim; repeated opt-in refusal; and release
after one-byte-short sequence admission. They fabricate no runtime, backend,
proof or successful continuation. Source inspection and isolated rustfmt are
the only author validation; the coordinator owns all builds and execution.

No complete source/parent closure, device fit, complete workflow, timing,
speedup, artifact round-trip or security-adoption claim follows from this
capsule. Full B orchestration and genuine focused GPU/CPU verification remain
required before this opt-in research continuation can be exercised or promoted.
