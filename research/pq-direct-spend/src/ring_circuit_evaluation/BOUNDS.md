# Host constraint evaluation admission

## Current backend selection and admission

`EvaluationBackend::Trace` (`trace`) remains the default. The opt-in
`EvaluationBackend::ConstraintsOnly` (`constraints-only`) executes the same
ordered operation evaluator and drops its wire values without materializing a
machine trace. Neither backend generates or independently verifies a proof.
The existing `evaluation_footprint`, `plan_evaluation`, and direct
`evaluate_with_host_allowance` entrypoints preserve the trace default.

`plan_evaluation_with_backend` consumes the exact immutable compiled owner and
seals the selected backend with its source-derived footprint. The owner cannot
be replaced or extracted. The returned footprint is a descriptive copy;
editing its backend, geometry, or required bytes cannot alter execution or
admission. No execution allocation occurs while planning. Execution checks the
sealed whole-live requirement and the 32 GiB worker maximum before creating
wire values, an Arc, or a trace.

Both backends retain these existing requirements:

- Canonical compiler limits and actual program capacity within its selected
  allowance, actual wire and padded row ceilings, and actual witness capacity
  within its fixed allowance.
- Full retained program capacity, including its conservative future Arc charge,
  the unchanged 128 MiB witness and 16 MiB auxiliary allowances, and one field
  value per wire in the live-storage sum.
- Checked byte arithmetic and enclosing fixture/process accounting separate
  from the worker diagnostic. These bounds describe requested storage, not RSS.

For `trace`, the sum additionally includes
`program.height() * WIDTH * size_of::<Val>()`. For `constraints-only`,
`trace_bytes` is zero and that is the only term removed. Wire values are dropped
before return on success and failure. The candidate creates no trace or Arc,
but does not reclaim their absence by changing other allowances or ceilings.

The equivalence claim is limited to successful `ProgramBuilder::finish` owners
and valid subsequent padding. Both diagnostics call the exact same evaluator;
finalization makes later trace serialization infallible apart from allocation.
See the source argument, operation coverage, lifetime analysis, and limits in
[`host_evaluation/BOUNDS.md`](../../../../lattica-prover-p3/src/block_v2/machine/program/host_evaluation/BOUNDS.md).
This is not an AIR or proof soundness claim and gives no complete-workflow result.

The `ring_circuit::evaluation::tests` filter has ten focused tests, including
exact/short/oversized admission, immutable-owner/backend binding, preserved
compiler/wire/row ceilings, equal rejection of invalid inputs, and different
fresh values for the same public program shape. The core differential filter
is intended for both narrow and wide layouts. Current validation outcomes are
recorded by the coordinator; no candidate timing is inferred from fewer bytes.

## Measured host diagnostics, 2026-10-25 UTC

The coordinator's guarded core filters passed five tests in each of the narrow
and wide layouts. The combined research check passed 79 library, three CLI,
and eight relation tests (90 passed, five optional tests ignored), including
the ten evaluator tests and six independently authored range audits. These are
host diagnostic correctness results, not proof or independent AIR verification.

Agent A independently audited six evaluation-only and six combined run
receipts/logs, recomputing every measurement and median below from their raw
JSON events. Each experiment used three matched alternating pairs in the order
baseline/candidate, candidate/baseline, baseline/candidate. All twelve receipts
and raw log digests matched, all 1,309 source-input digests were unchanged, and
the recorded post-run executable digest matched the current executable:
`dc7084fa9e9e538ef86d7cfb0f8246dbe8319dcd5fa04989233cdff4e63180b4`.
Terminal success, stopped/reaped subprocesses, zero swap, unchanged resource
limits, and nonoverlapping runs were verified.

All runs explicitly selected `8g` compiler memory, `16m` wires, CPU-required
execution, and two worker threads. Each guarded job had a 16 GiB hard memory
limit and 14 GiB high watermark. Evaluation admission retained the unchanged
32 GiB worker maximum. The baseline representation was
`fused-ternary-ntt-v1` with `trace`; evaluation-only changed just the diagnostic
backend to `constraints-only`.

| Evaluation-only median | Trace | Constraints-only |
| --- | ---: | ---: |
| Complete compiler diagnostic, seconds | 2.299231888 | 2.155173436 |
| Host constraint check, seconds | 0.180931132 | 0.040281352 |
| Compiler, seconds | 2.098791647 | 2.094623752 |
| Wires | 8,012,253 | 8,012,253 |
| Active / padded rows | 1,276,409 / 2,097,152 | 1,276,409 / 2,097,152 |
| Retained program bytes | 930,640,144 | 930,640,144 |
| Admitted evaluation bytes | 2,722,791,416 | 1,145,733,112 |
| Trace bytes | 1,577,058,304 | 0 |

The complete compiler diagnostic median was 6.27% lower and the host check
median 77.74% lower. Requested evaluation storage fell by exactly the omitted
1,577,058,304-byte trace term; program, witness, auxiliary and wire charges
were unchanged. Median guarded-job `MemoryPeak` was 1,992,769,536 bytes for
trace and 1,763,926,016 bytes for constraints-only. This observed job peak and
the requested evaluation bound measure different quantities.

The combined experiment additionally selected `fused-ternary-ranges-v1`.
Its effect includes both the smaller compiled relation and the changed host
diagnostic; it cannot be attributed to the evaluator alone.

| Combined median | Prior representation + trace | Range reuse + constraints-only |
| --- | ---: | ---: |
| Complete compiler diagnostic, seconds | 2.306050042 | 1.955442390 |
| Host constraint check, seconds | 0.180972804 | 0.032157331 |
| Compiler, seconds | 2.104910301 | 1.906497123 |
| Wires | 8,012,253 | 6,114,044 |
| Active / padded rows | 1,276,409 / 2,097,152 | 925,151 / 1,048,576 |
| Witness hint values | 60,030 | 59,822 |
| Retained program bytes | 930,640,144 | 675,761,592 |
| Admitted evaluation bytes | 2,722,791,416 | 875,668,888 |

The combined complete compiler diagnostic median was 15.20% lower. Median
guarded-job `MemoryPeak` was 1,992,364,032 versus 1,192,755,200 bytes. Admission
limits did not increase in either experiment.

The total diagnostic timer includes fixture construction, planning, compilation,
host checking and destruction, as confirmed by its
`includes_fixture_planning_and_drop` event. It excludes the Cargo launch/build
wrapper. In particular, the first evaluation baseline's guarded job also built
the executable; its outer wall time is not a matched proving benchmark. Every
screen reported `cryptographic_proof_started=false`. There was no GPU proof,
independent proof verification, recursive graph, artifact round trip, or
complete RingCT workflow. These results do not satisfy complete-workflow
promotion gates; both diagnostic and range selections remain opt-in research.

Evidence labels are `rowopt-evaluation-pair-{1,2,3}-{baseline,candidate}` and
`rowopt-combined-pair-{1,2,3}-{baseline,candidate}` under the campaign's
`integration/.tools/pq-opencl-opt/runs/`. The independent twelve-receipt audit
JSON has SHA256
`d2b1bda6f32b4241813a74a12ce6aeb4c23c0616c1c120361d02e40627c4ff71`.
The coordinator owns final evidence packaging and subsequent workflow audits.

## Historical trace diagnostic and measurements

The remaining notes preserve the prior trace-only implementation's accounting
and measured evidence. They do not describe a constraints-only measurement.
That diagnostic executes the compiled relation and materializes its machine
trace. It is neither proof generation nor independent cryptographic verification.
It grants no GPU or production runtime authority. The existing unbounded legacy
`evaluate` method is unchanged; the explicit CLI option uses the sealed
`EvaluationPlan` path described below.

Before evaluation, derive the whole simultaneous requested-storage footprint
from the immutable compiled owner: retained program storage, fixed 128 MiB
witness allowance, fixed 16 MiB auxiliary allowance, `wire_count * sizeof(Val)`,
and `padded_rows * machine::WIDTH * sizeof(Val)`. All arithmetic is checked and
the total must be representable by usize. The supplied host allowance must fit
the unchanged 32 GiB worker maximum and cover that entire footprint. Callers
cannot substitute a precomputed footprint or caller-selected program.

`Program::retained_host_bytes` exposes the existing core source-storage recipe.
It counts the future `Arc<Program>` layout, operation/row/reference capacities,
nested `SelectHint` entry/bit capacities, and each packed row's index capacity.
It includes spare capacity and performs checked arithmetic without scratch
allocation on success. It reads this exact immutable program; neither manifest
length nor caller-supplied counts can reconstruct or replace these capacities.
The query returns a description, not an allocation or execution permit.

The compiler has already admitted construction, compaction and row packing under
the selected compiler allowance. At evaluation time its interning tables and
construction scratch are gone. The retained bound must still fit that selected
allowance, independently of the whole-live evaluation check. Descriptive limits
must equal the canonical closed profile, actual wires/rows must respect it, and
the retained witness capacity must fit its unchanged fixed allowance. There is
no fallback to larger limits.

The retained-storage query scans operations and rows. `plan_evaluation(self)`
performs that scan once and moves the exact immutable owner and computed
description into an `EvaluationPlan`. This plan has no Clone, mutable access or
owner extraction. Its `footprint()` returns a descriptive copy; callers cannot
substitute that copy or another program during execution. The plan's
`evaluate_with_host_allowance` checks the whole-live bound before creating the
Arc or trace. The original convenience method delegates through the same path.
This allows reporting a refused footprint without scanning again or treating a
caller-supplied footprint as authority. A standalone `evaluation_footprint`
query remains descriptive only.

The source recipe is `machine/program.rs::Program::evaluate`, which allocates
one value per wire, and `machine/air.rs::MachineAir::trace`, which retains those
values while allocating the full row-major trace. The immutable program and
witness overlap both. The complete witness and auxiliary allowances remain in
the sum. Only the program term changes from the selected construction ceiling to
its retained bound; the compiler's diagnostic peak does not authorize storage.
Reports now distinguish `selected_program_allowance_bytes` from
`retained_program_bytes`. The former replaces the old ambiguous
`retained_program_allowance_bytes` field. Reducing this reservation does not
remove a program allocation or establish a reduction in physical memory use.

The auxiliary allowance covers fixed bookkeeping, fixed public values, trace
loop temporaries and the reads/writes vectors (at most eight Wire entries each
in the pinned source), plus closed error text. It also covers the pinned x86_64
scalar Poseidon2 constructor's 688-byte round-constant heap transient:
`(2 * 4 * 8 + 22) * sizeof(Goldilocks)` in p3-goldilocks 0.6.1
`default_goldilocks_poseidon2_8`. The constructor moves these vectors into its
layers; sequential scalar permutations retain only one set at a time. This
transient remains within the unchanged 16 MiB auxiliary allowance.
This is a live requested-storage bound, not cumulative allocation volume or
process RSS. Enclosing statement/fixture, allocator overhead, runtime and OS
stacks remain outside this owner. The serialized process guard still enforces
its separate maximum and zero swap; successful logical admission is not a
measurement of physical peak usage.

The full trace dies before returning the summary. An unsatisfied equation
returns an error; no cryptographic receipt is emitted. Focused tests cover an
exact allowance boundary, one-byte-short and oversized refusal, retained storage
independent of the chosen compiler allowance, the independent compiler ceiling,
altered descriptive limits, checked overflow, and an actual larger program with
stale small-owner summary counters, altered report copies and insufficient
foreign allowance. They also retain successful execution and reject witnesses
that fail constraints. Core tests cover spare capacities and nested hint storage.

## Coordinator qualification

The coordinator's serialized focused evaluation run passed all five tests, and
the core retained-source test passed. The combined direct-spend suite passed
56 tests with 3 ignored, including these five admission tests and all eight
independent NTT audits. Terminal, source, executable and log audits passed. The
audit author ran no builds or tests.

The complete `fused-public-linear-v1` relation reported 4379757128 retained
program bytes and a whole-live evaluation bound of 11125435768 bytes. Previously
the selected 24 GiB program ceiling produced a bound of 32515482416 bytes for
that same relation. The revised `fused-public-ntt-v1` relation reported 1503289944
retained program bytes and a whole-live evaluation bound of 3332911096 bytes.
Both completed host constraint evaluation in all three matched repetitions.

The first reduction removes unused reservation headroom; it does not shrink the
same program or establish a change in physical memory use or execution time.
The NTT representation changes the compiled relation and has separately observed
guarded job peaks recorded in `NTT_AUDIT.md`. Selected program ceilings, fixed
witness/auxiliary allowances,
32 GiB worker cap, process guards and zero-swap requirement remain unchanged.
No cryptographic proof, recursive graph closure or complete-workflow result
follows from these admission and host-evaluation checks.
