# RingCT preprocessing

RingCT registrations hash their program identities on the CPU. Preprocessing
commitments and proof generation retain their GPU-required policy; independent
verification runs on the CPU. This work belongs to the recursive proof workflow,
not native RingCT transaction construction. Shared prover GPU identity APIs are
unchanged for other callers.

Source metadata planning is CPU work. Full-workflow entries default to
`--planning-cache geometry-v1` and `--metadata-cpu-workers auto`. The latter is
independent of identity hashing and allows up to 16 allowed physical cores for
uncached registered height enumeration and native descriptor cohorts. Use `--planning-cache off` and workers
`1` to measure fresh serial planning. Ordered CLI options are case/layout/seed/context,
identity workers, metadata workers, planning cache, then host profile.

A 64-entry geometry cache (1 MiB), 256-entry native bounds cache (1 MiB), and
64 KiB planning-scope reservation fit within the unchanged 64 MiB metadata
allowance. They retain only numerical bounds, clear on scope exit/unwind, and
never cache failed computations. Native keys include every closed descriptor
field, including setup seeds, counters, moduli, linear-map coefficients and
derived limits, plus source, profile and construction allowances. Preflight
still precedes every native cache lookup. No proof, witness, manifest,
registration or memory-admission token is cached.

Registered and native numeric compilation uses normal constant folding,
interning and wire/input checks without retaining instructions, hint payloads,
packed rows, dummy proof templates or input-value buffers. Geometry-only inputs
are fresh unknown wires and are accepted exclusively by the non-proving numeric
sink. Real proof compilation retains its value and shape checks. The native
manifest API remains available for reference checks.

Each registered envelope prepares its symbolic constraints and lookups once.
Height workers borrow that immutable graph; this reuse is restricted to the
source-audited MachineAir whose symbolic relation depends on public width.
Native numeric compilation similarly prepares its own symbolic graph once.
The original compiler-plus-auxiliary reservation remains held throughout.
Registered heights run largest first on a bounded queue and borrow one immutable
symbolic graph. Native descriptors also run largest estimated public work first;
each admitted worker prepares and lowers its own graph.
An idle worker takes another admitted job without waiting for the whole batch.
Results retain their original order, and failures publish no partial cohort.

Each CPU phase uses fixed scoped worker threads and fixed queue/result slots.
Native ready windows hold up to 64 admitted requests while execution remains
capped at 16 workers. This lets threads and compiler backing serve more jobs
before joining. Cleared compiler backing can cross windows only while an
actual supplemental ledger claim covers its complete retained capacity.
Metadata worker placement spreads allowed physical cores across their L3 cache groups;
failed pinning is reported and leaves the inherited allowed affinity intact.
Job signals target one worker, and completions wake the coordinator separately.
Automatic native concurrency uses the available physical cores, up to sixteen;
explicit requests remain subject to the same live memory admission.
Compiler interning tables store checked nonzero 32-bit encodings of wire
references internally. The zero niche removes slot tags/padding where possible;
wire zero remains valid and out-of-range wires retain their validation errors.
Instructions, public wire APIs, manifests, randomized hashing and full-key
comparison retain their existing behavior.
Numeric compiler interning tables can retain their allocated capacity between
jobs on the same worker. The next builder clears old keys and charges the full
retained capacity before use; a smaller cap evicts backing that cannot fit.
Registered-height compiler caps remain reserved throughout their worker scope.
Native workers receive compiler growth grants only for active jobs. Completed
jobs report the exact retained map capacities; idle workers are charged for
those buffers. Under admission pressure the owning idle worker drops its buffers
before the coordinator reclaims their bytes. Preparation scratch is dropped
before the pool joins. A workflow planning session can retain cleared compiler
backing across windows under its supplemental claim; excess backing is dropped
by its owning worker. This does not reuse proofs, witnesses, programs, or
completed identities. Reported compiler allocation peaks can vary with
retained scratch; mathematical operation, wire, input and row counts must match.

Registered-height admission retains its 128 MiB scheduling floor. The initial
native heuristic uses public-geometry compiler caps of 48, 80, 112 or 128 MiB;
exact-geometry history can raise a grant within the original cap. These are
heuristics: every allocation enforces its cap. Only byte-cap refusals permit a
retry. Native retries increase the failed job's cap within the same pool when
possible; reducing pool width first drains and joins every owner. Registered
retries reduce the worker ceiling. Other errors
remain fatal. Workers receiving the full original cap, including inline fallback,
use fresh storage so retained scratch cannot introduce a new full-cap refusal.

Native preparation first reserves its full symbolic construction allowance.
After preparation retires, cumulative normalization allocation accounting bounds
the retained graph, and actual owned vector capacities bound periodic columns.
Borrowed AES columns are charged once. This releases unused construction
allowance without using RSS as allocation authority. Admission still includes
preparation overlap, retained graphs, helpers, compiler caps, 2 MiB stacks and
bounded thread/TLS overhead, and the existing 1 MiB coordinator allowance.
The original per-job source bounds and process memory limits are unchanged.
Native admission includes the complete existing live set and the larger of a
job's preparation phase or its graph plus compiler grant, since that job's two
phases do not overlap. The coordinator drains all available completions before
dispatching another graph. Active compiler counts exclude buffer-maintenance jobs;
reports also expose drained completions, admission stalls, trimmed bytes, idle
retained bytes and extra phase reservations.

Native callers holding an authenticated scratch reservation automatically
request a separate planning-phase claim from the same workflow ledger. This is
the only ledger-backed planning policy; there is no memory-mode selector. The supplement is at
most 1 GiB and targets a total 3 GiB native planning allowance. It never increases
an individual compiler cap, the ledger's host limit, or the process limit. If
capacity is unavailable, the same scheduler uses the bytes already reserved. Cache-only and small
cohorts, and worker ceilings of eight or fewer, acquire no supplement. The claim
outlives all cohort workers. A planning session can split off only the exact
claim needed for cleared compiler backing between windows. The remainder is
released on return, and session destruction drops backing before its claim.
The original scratch reservation always remains borrowed.
Callers without a ledger can authorize only the bytes in their existing source
reservation; they use the same scheduler and live-storage accounting.
Caller control-frame accounting uses the shared ready-window size, including
the larger fixed request and result arrays.

The standard release x86_64 profile can load generated numerical rows for public
widths 25/28/38/46 at every power-of-two height from 8 through 2^20. Tables require
matching compiled source digest, proof profile, geometry signature, compiler
limits and row-content checksum. Auxiliary admission still runs. Other profiles,
limits and stale tables use the ordinary bounded compiler. Table reduction
includes every height; it does not assume counts increase with height. Table
storage is included in the existing geometry-cache reservation.

`tools/generate_metadata_tables.py --record PATH` generates rows only from a
passed guarded metadata qualification with matching source inventory, build
record and raw-log hashes. `--check` checks reproduction. The build digest
covers both supported Cargo lockfiles and excludes the generated data file to
avoid circular invalidation. Rebuild
and run the same qualification again to check every populated row and the
complete table envelopes against fresh compilation before using the artifact.

Reports include `metadata_cpu`, `metadata_planning` (workers, shared preparation,
compiler jobs/retries, admitted bytes and times), `source_geometry_cache`
(including table hits), and `native_metadata_cache`. A table-only registered
plan legitimately reports zero compiler jobs. Summed worker time overlaps wall
time. The dedicated `--metadata-cpu-qualification` guard runs only the ignored
`block_v2::machine::verifier::batch::shape::metadata_planning::tests::metadata_cpu_worker_qualification`
test. It checks all 72 shapes against full compilation, measures cold/warm
planning at worker ceilings 1/2/4/8/16, and verifies populated tables. It retains
the existing memory caps and Rayon setting while allowing 1600% CPU with
physical-core affinity. These measurements do not establish transaction or
complete recursive-workflow speedups. Metadata GPU execution remains deferred.

Native metadata now has a separate source-qualified table of 159 exact descriptors
across 13 families. Its rows include numerical counts and compiler peaks, with
exact canonical descriptor digests, source/profile/content checks and the same
standard construction limits. Unknown descriptors and stale tables compile as
usual. The immutable linear-map descriptor hashes all normalized coefficients,
constants, polynomial kinds and derived bounds once during construction; warm
keys stream that digest instead of formatting the coefficient arrays. Workflow
source fingerprints use the existing v1 framing but are computed at build time.

Native cohorts preflight and deduplicate descriptors, check tables on the
coordinator, then split the maximum original planner reservation among joined
misses. They are used by paired source inspection and the selected layout's
native-core planning. Every worker retains its own bounded symbolic preparation.
AES jobs can share their source-audited fixed periodic columns; their constraints
still depend on counters and segment positions and are not shared. No partial
cohort is published on failure. Cache `planning_ns` counts cohort wall time once. Queue telemetry includes
`threads_spawned`, `queue_refills`, `workspace_reuses`, `coordinator_wait_ns`,
and, for native jobs, `preparation_ns` and `retained_worker_bytes_peak`.
The CPU worker efficiency implementation and component measurements are recorded
in `../../docs/evidence/ringct-cpu-worker-efficiency-2026-11-01.json`.

`--native-metadata-profile` accepts only the ignored
`component_tree::native_shape::profiling::tests::native_metadata_profile` test
under `research-compile-large`, with the exact build receipt. It profiles all 159
descriptors, compares both the original 39-case set and the complete catalogue
at workers 1/2/4/8/16 with serial counts, and checks populated
tables without transactions, witnesses, proofs or GPU work. The native table
generator is `tools/generate_native_metadata_tables.py --record PATH`; regenerate,
rebuild and rerun the profile before treating new rows as qualified. Both
generated numeric data files are excluded from the native source digest to avoid
circular invalidation. Everything else in its compiler source inventory remains
bound. Measurements are recorded in
`../../docs/evidence/ringct-native-metadata-2026-10-31.json`.

Use `--identity-cpu-workers auto|INTEGER` with `pq-ringct-full-workflow`. `auto`
selects up to 16 allowed physical cores. Explicit integers from 1 through 16 are
ceilings. The scheduler limits each independent sibling cohort to its available
programs and admitted storage; a singleton runs inline. Dependent parents use
the complete CPU streaming hash. There is no RingCT GPU identity selector or
identity-result cache.

The hash is unchanged: domain, complete field count, manifest, compiler
fingerprint, profile fields, actual preprocessing cap, and final zero padding
match the slice reference. A prefix keeps its partial rate block. Its opaque,
single-use token binds the workflow, job, original immutable program and exact
metadata. Fresh registration validates these bindings and appends fresh cap
roots. Blocks within one sponge remain sequential.

The coordinator prepares symbolic metadata under the original GPU epoch, then
retires that epoch before starting CPU workers. Scoped workers have 2 MiB stacks
and bounded input/result storage. They join before GPU registration or proof
work begins. Failure, cancellation and panic paths join outstanding workers
before releasing their owners. Original compiler reservations remain charged;
fingerprints, prefix states, stacks and reports have additional explicit bounds.
A cohort that cannot admit even one job is refused.

The guarded full workflow and dedicated CPU qualification use a 1600% CPU quota
and one allowed logical CPU per physical core. The runner records and checks
actual process affinity. Proof-host `RAYON_NUM_THREADS` remains 8. Other guard
profiles retain their existing quotas. Standard limits remain 32 GiB worker
host, 47 GiB process maximum, 45 GiB high watermark, 49 GiB fresh available RAM,
zero swap, 8 GiB managed device storage plus the existing 4 GiB context reserve.
Native PCS keeps its 24 GiB allowance and 8 GiB host-backed trees. Complete
workflow admission remains mandatory and can refuse even a locally valid cohort.

Build with `--features full-workflow-experiment`. The retired
`identity-batch-experiment` feature is no longer needed. Use the serialized
`tools/opencl_private_spend_validate.py` runner for builds and execution. Its
`--identity-cpu-qualification` flag accepts only the ignored test
`identity_preprocessing_screen::cpu_recursive_identity_worker_qualification`,
under the `full` profile, `--expect-tests`, and an exact build label. That test
uses 17 actual recursive verifier programs, widths 1/2/4/8/16, partial tails,
matching identities and fresh proofs with independent CPU verification.
The v2 qualification separately reports `full_batches_hash_ns` for the first
16 programs and `tail_hash_ns` for the final program at every width, with their
sum in `total_hash_ns`. Compare these hash times across widths; `component_ns`
also includes GPU registration and proof work. A
16-worker result requires observed concurrency of 16, not just a requested cap.

GPU preprocessing, CPU prefix work, CPU finalization and GPU proof reports are
separate. `worker_elapsed_ns` sums per-worker durations; `hash_wall_ns` measures
cohort wall time. They overlap and must not be added together. Complete cases
use `lattica-research-ringct-complete-case-v2`; CPU prefixes use
`identity-cpu-prefix-v1`. The strict GPU validator remains unchanged. A separate
CPU validator reconciles exact registration order and one-time token use.

`tools/owned_preprocessing_campaign.py` provides CPU presets 1/2/4/8/16 and
optional geometry-cache combinations. These identity comparisons explicitly
hold metadata workers at `auto`; changing that setting requires a separate
metadata comparison. Source-only admission is a prerequisite,
not a completed-workflow result. `tools/owned_workflow_benchmark.py` compares
fresh N3/N4 cases under the same CPU, memory and device limits; component times,
refusals, timeouts and partial runs cannot establish a whole-workflow speedup.

Historical GPU-prefix evidence in `../../docs/evidence/` remains audit-only.
`tools/identity_preprocessing_receipts.py` still reads those old receipts, while
new complete cases require CPU identity reports. Existing lookup-table compiler
constant optimizations and their parity evidence are preserved.

### CPU worker scaling comparison

The first CPU-only perf comparison on the 16-core Ryzen 9 5900XT measured three
cold runs per worker ceiling, with metadata tables disabled. Median times were:

| Workload | Workers | Before | After |
| --- | ---: | ---: | ---: |
| Registered shapes (72) | 4 | 3.497 s | 2.548 s |
| Registered shapes (72) | 8 | 3.021 s | 1.948 s |
| Registered shapes (72) | 16 | 2.882 s | 1.629 s |
| Native descriptors (159) | 4 | 17.033 s | 13.874 s |
| Native descriptors (159) | 8 | 14.641 s | 8.513 s |
| Native descriptors (159) | 16 | 15.293 s | 13.550 s |

Sixteen active native workers were observed within the unchanged original
reservation: the campaign's maximum accounted reservation was 2.383 GiB.
Larger descriptors still reduce concurrency; a worker ceiling is not a promise
that every job can run simultaneously. Eight native workers used 1.589 GiB at
peak and finished faster in that implementation. It initially selected eight
automatic native workers; the follow-up below removes the idle-cap bottleneck
and supersedes that default. Registered planning retains its physical-core
ceiling up to sixteen. All byte-cap admission and retry checks remain in force.

A separate two-repeat placement comparison at eight and sixteen workers favored
spreading physical cores across cache groups overall. Pinning stays inside the
process's inherited allowed CPU set and happens before worker scratch allocation.
These results qualify this host and cold metadata planning; they do not measure
transaction creation, recursive proving, GPU execution, or warm table lookup.
Generic perf cache counters indicate fewer misses per instruction but do not
isolate memory bandwidth or a particular cache level.

Use the serialized validation guard with `--profile research-compile-large`,
`--cpu-scaling-profile registered` (or `native`), `--cpu-scaling-workers 4|8|12|16`,
`--cpu-scaling-placement scheduler|packed|spread`, `--expect-tests`, and the exact
matching build label. It accepts only the corresponding ignored `scaling` test
with `--exact --ignored --test-threads=1 --nocapture`; `/usr/bin/perf` is hashed
and runs under the same guard. Hardware counters cover the complete test process.
Worker scheduling counts come from `getrusage(RUSAGE_THREAD)` and
`/proc/thread-self/sched`, because user-only perf scheduling events can report
misleading zeros when kernel events are unavailable. Initial pinning migrations
are included. Records and validation details are indexed in the
[CPU scaling evidence](../../docs/evidence/ringct-cpu-scaling-2026-11-01.json).

The native follow-up measured three fresh runs per configuration after adding
active-job compiler grants, complete live-job admission, prompt completion
draining, denser map slots with pressure-driven trimming, and a separately owned
phase supplement. The same 159 descriptors ran with tables disabled:

| Native workers | Fresh baseline | Automatic phase allowance |
| --- | ---: | ---: |
| 8 | 8.443 s | 7.903 s (no extra claim) |
| 12 | Not measured | 6.091 s |
| 16 | 12.346 s | 6.050 s |

At sixteen workers the scheduler now sustains sixteen active compilers
in all three catalogue windows; the baseline fell to four in the final window.
Median wall time drops 51.0%, and sixteen workers finish 23.5% sooner than eight
with the new scheduler. Automatic native planning therefore uses up to sixteen
physical cores. This trades more total CPU work for less elapsed time.

The original source allowance is at most 2.385 GiB. The automatic phase allowance
reserved up to 3 GiB, used at most 2.695 GiB of accounted live storage, and had a
1.965 GiB observed cgroup peak. Development comparisons without the supplement
are preserved in the evidence; they did not establish a consistent throughput
benefit from the additional memory itself. These memory figures describe this
metadata-only workload; they exclude
transaction generation and proof work. Source accounting, rather than observed
RSS, remains the authority for admission.

The exact native scaling guard always exercises the automatic phase allowance.
Its receipts require a bounded ledger peak and
retirement of every claim. Numerical results, retry/failure joining, retained-map
accounting and ledger ownership are covered by focused tests. The comparison,
source hashes and final qualification records are indexed in
[native worker evidence](../../docs/evidence/ringct-native-workers-2026-11-01.json).

### Native compiler and preparation efficiency

The follow-up collects bounded user-space cycle samples with
`--cpu-scaling-callgraph` on the exact native catalogue. Sampling records are
separate from the repeated `perf stat` timing comparisons. Optimized release
symbols identify hot functions; incomplete DWARF caller unwinding means these
records do not support precise inclusive or source-line attribution.

Commitment-verifier emission shares compiler-proven operand facts across scalar
lanes and paired FRI selections. Dense periodic evaluation adds each base-field
coefficient to the first extension limb, avoiding redundant zero interning and
add-zero lookups. Both paths preserve the original instruction sequence and
ordinary folding, interning, wire validation and memory admission.

Compiler tables use separately charged control bytes to filter full-key probes
and clear retained tables without rewriting their payload arrays. Randomized
hashing and full-key equality remain authoritative. Growth charges both old and
new arrays; stale vacant probes remain bound to a table identity and generation.

Native workers prepare their own graphs. Admission reserves the larger of the
preparation and compilation phases, including any retained compiler backing.
After preparation scratch and excess backing have been dropped, a bounded queue
notification publishes the retained graph census and returns those temporary
credits. This notification does not retire the job or free its worker slot.

The scheduler favors compatible public layouts, leaves growth room when reusing
nearly full backing from a different layout, and retries byte-cap refusals within
the same pool. Completed jobs remain complete. Only a grant that cannot coexist
with the current pool's stacks requires joining owners and reducing pool width.
The automatic ledger-backed memory allowance remains the sole implementation.

`preparation_ns` now sums worker preparation time, and job durations include that
preparation. Coordinator waiting is not worker idle time. The source-bound
[compiler efficiency evidence](../../docs/evidence/ringct-cpu-hotspots-2026-11-01.json)
records the comparisons, numeric parity and memory accounting. These are cold
metadata-planning measurements, not transaction-generation or proof timings.


### Native compiler bookkeeping and planning reuse

The next pass probes eight control bytes together after a small first-slot
lookup, with exact full-key comparison and the same randomized hasher. Fixed
compiler tuple keys are encoded in one hasher write without changing their
storage layout or public wire representation. Map growth still reserves both
old and new arrays before allocation.

Cubic multiplication reuses compiler-proven operand facts across its folding
paths. An exact bitmap skips negative constant-map lookups for nonconstant
wires. The bitmap contains only public wire identities, and its retained
capacity and old/new growth overlap count against the existing compiler cap.
Numeric operation counting uses fixed opcode-specific read/write lists while
preserving wire validation, overflow checks and mathematical counts.

Workflow planning sessions retain only cleared compiler backing across native
windows, covered by an actual split of the supplemental PhaseScratch claim.
Workers retire excess backing before joining. Original scratch remains borrowed;
foreign ledgers and small cohorts discard saved backing. The final planning
handoff drops saved buffers and their claims before taking the runtime ledger
census. The automatic 3 GiB phase target and 1 GiB supplement ceiling are unchanged.

A bounded history orders jobs using measured durations and public geometry.
Exact geometry supplies capacity hints; related shapes of the same native AIR
width supply time estimates only. Every allocation still enforces its existing
cap. Reports add `restored_workspaces` and `cost_hint_jobs`; maintenance jobs
include explicit buffer transfers, and trimmed bytes are cumulative.

Three paired cold runs per worker count, alternating old/new order on the
Ryzen 9 5900XT, measured the full 159-descriptor native catalogue with numeric
tables disabled. Timings include final buffer cleanup; cycle samples were
collected separately.

| Native workers | Previous median | Updated median | Elapsed reduction | CPU-time reduction |
|---:|---:|---:|---:|---:|
| 8 | 5.965 s | 5.592 s | 6.3% | 6.3% |
| 12 | 5.095 s | 4.766 s | 6.5% | 7.1% |
| 16 | 4.655 s | 4.325 s | 7.1% | 10.8% |

All requested worker counts were reached in every window, with no byte-cap
retries. The planning allowance remained 2.385 GiB at eight workers and 3 GiB
at twelve and sixteen. Median instruction counts fell 31.5–37.0%. The extra
constant bitmap adds 4–256 KiB to the fresh registered compiler peaks measured
across the 72 registered shapes; generated bounds include those bytes.

Validation passed 130 focused Rust tests, all 72 registered and 159 native
numeric cases, both regenerated-table checks, the release all-target build
check and 58 validation-tool tests. Mathematical counts match the previous
implementation. The source hashes, all paired samples and bounded cycle
reports are recorded in the [bookkeeping evidence](../../docs/evidence/ringct-cpu-bookkeeping-2026-11-01.json).
These measurements cover cold CPU metadata planning; recursive proofs were
not generated and complete transaction/proof throughput was not measured.

### Complete N3 metadata stage: lookup coverage and memory admission

The next pass completes the metadata stage within the existing 32 GiB worker,
24 GiB native and 8 GiB device limits. Reservation-slot selection minimizes
additional growth among compatible idle slots. Parent plans use authenticated
child heights. Retained program, proof-input and identity-prefix bounds now
describe the objects that survive construction; temporary construction and
vector-growth overlap remain charged to phase scratch, with capacity checks
before scratch is released. Frozen owner tables charge their payload backing
once, and sequential forwarding frames retain a shared scratch allowance.

Native lookup tables now contain 304 independently qualified descriptors,
including 120 SHAKE and 25 additional affine recipes observed in N3. The static
table limit is 512 rows; the LRU remains 256 entries, with a 2 MiB allowance for
the cache and bounded descriptor inventory. Lookup diagnostics distinguish
memory hits, table hits and cold compilation, including explicit fallback
reasons. Existing GPU preparation batches signed subtraction for `f0` and
reuses scope-owned public NTT/multiplication layouts. Owner validation and
failure poisoning remain enforced. The GPU metadata compiler port is deferred.

Three fresh processes per metadata worker count replayed the same verified
public N3 fixture on a Ryzen 9 5900XT. CPU identity hashing kept its existing
automatic concurrency and 16-core affinity throughout; only metadata workers
varied. The timing includes startup, graph construction, source preparation,
producer metadata constructors, and final schedule/memory closure. It excludes
fixture loading/verification, native input generation, runtime preissue and
recursive proofs.

| Metadata workers | Baseline attempt median | Completed metadata median | Elapsed reduction |
|---:|---:|---:|---:|
| 1 | 40.146 s | 20.867 s | 48.0% |
| 8 | 32.913 s | 20.346 s | 38.2% |
| 16 | 33.122 s | 20.362 s | 38.5% |

Every baseline attempt stopped at `CombinedAdmission`; those times are not
successful complete-stage measurements. All nine optimized runs completed
metadata, as did a separately generated heldout fixture in 20.254 s. Both
fixtures serialize only public seeds, context, statements and native proofs,
and verify the native proofs on load. Replay is deterministic; their original
native generation used fresh private randomness. Metadata-only runs retain
incomplete owners until isolated process teardown and issue no workflow
completion receipt.

Native cold compilation fell from 158/585 requests (27.01%) to 13/585 (2.22%).
Memory hits remained 400; table hits increased from 27 to 172. The LRU miss
rate therefore remains 31.62%: most misses now resolve through the static table.
These are software descriptor-cache rates, not hardware cache counters.
Registered lookups had zero cold compilation misses, and neither cache evicted
entries in any N3 replay. Counts were identical across repeats and the heldout
fixture. The remaining native cold descriptors are five AES, two transcript,
one statement and five linear-map shapes.

At sixteen workers, median metadata-constructor time fell from 14.679 s to
4.052 s, and graph construction from 12.245 s to 10.047 s. Source preparation
remained about 5.954 s. The latter two phases explain most remaining latency;
eight and sixteen metadata workers finish at essentially the same time after
the lookup improvements. The comparison combines the changes and does not
isolate the speedup of each optimization.

The baseline reservation census required 36.112 GiB of host capacity, exceeding
the worker allowance by 4.112 GiB. The corrected census passes at 32 GiB. Its
outer-backend residual intentionally fills the remaining allowance, so this
figure is a future reservation bound, not measured RSS or evidence of spare
runtime capacity. No memory ceiling was raised.

Validation passed 99 research correctness tests, 11 core correctness tests,
the final table-use test, real GPU arithmetic/failure parity, all 304 native
and 72 registered numeric qualification cases, both generated-table checks,
80 Python validation tests, and the release all-target check. The ten optimized
metadata runs generated zero recursive proofs. Runtime proving performance
and full workflow retirement remain outside this measurement.

Use the serialized validation guard with `--metadata-stage-profile`,
`--metadata-workers 1|8|16`, and `--metadata-fixture-in` pointing to the captured
public fixture. The exact ignored test is
`spend_pipeline::full_workflow::driver::metadata_profile::tests::complete_n3_metadata_stage`.
The guard pins the fixture digest and rejects incomplete metadata or proof
receipts. Per-run timings, hashes, source/build provenance, memory diagnostics
and validation records are in the
[complete metadata optimization evidence](../../docs/evidence/ringct-metadata-optimization-2026-11-01.json).

### Scope reuse and complete N3 lookup coverage (2026-11-02)

Source preparation now transfers its graph registration into the tree plan and
reuses statement/manifest bindings and crypto input plans within one immutable
preparation scope. The bindings borrow the exact graph, tree and operation
context; source-byte equality checks and failed-scope rejection remain active.
Standalone constructors retain their original validation paths.

Existing GPU operations now reuse eight bounded scratch buffers and three kernel
handles within that scope. Four fixed slots retain exact public NTT/multiplication
metadata. Operations outside the workspace capacities use the existing GPU path.
Used buffer prefixes are scrubbed before reuse, all buffers are scrubbed at scope
exit, and arithmetic status is checked before downloading output. The workspace
is charged alongside transient fallback operations. No new GPU kernels or GPU
metadata compiler were introduced; identity hashing remains on CPU.

The native lookup catalog grew from 304 to 317 qualified descriptors, covering
the remaining five AES, two transcript, one statement and five linear-map shapes
observed in the N3 fixture. Public recipe capture deduplicates before allocation
and has a 32 KiB heap cap inside the existing 2 MiB cache/inventory allowance.
All 317 native descriptors and 72 registered shapes were qualified at
1, 2, 4, 8 and 16 workers, and both generated tables pass reproduction checks.

Three paired fresh-process comparisons per configuration replayed the same
verified public fixtures, alternating baseline/candidate order. Both versions
complete the metadata stage. Detailed diagnostic instrumentation was disabled
for these comparisons.

| Metadata workers / fixture | Baseline median | Updated median | Elapsed reduction |
|---|---:|---:|---:|
| 1 / baseline N3 | 20.857 s | 14.585 s | 30.1% |
| 8 / baseline N3 | 20.332 s | 14.602 s | 28.2% |
| 16 / baseline N3 | 20.394 s | 14.629 s | 28.3% |
| 16 / held-out N3 | 20.430 s | 14.627 s | 28.4% |

At 16 workers, median graph construction fell from 10.066 to 6.805 seconds,
source preparation from 5.952 to 4.078 seconds, and metadata constructors from
4.071 to 3.429 seconds. The 15% improvement target at 16 workers and the
no-regression checks at 1 and 8 workers passed. These times include metadata
startup and final schedule/memory closure, exclude fixture loading/verification
and native input generation, and stop before runtime preissue or recursive
proving. They do not measure full transaction or proof throughput.

Every optimized replay had 400 native memory hits, 185 table hits and zero cold
compilations across 585 requests, versus 13 cold compilations in the baseline.
The native LRU miss rate remains 31.62%; all those misses now resolve through
the table for these fixtures. Registered requests remain 962 memory hits and
9 table hits, with zero cold compilations. Neither cache evicted entries during
any of the 24 complete-stage comparisons. These are software descriptor-cache
rates, not hardware cache counters, and zero cold misses is specific to the
measured N3 configuration.

The optional `--metadata-preparation-detail` flag records bounded operation and
phase summaries and requires all 27 raw preparation scopes to complete. A
bindings-only diagnostic measured source preparation at 4.087 seconds before
GPU workspace reuse. Comparing its graph phase with the final diagnostic,
GPU allocations fell from 55,224 to 252 and allocation time from 2.691 to
0.013 seconds. Nested operation metrics overlap and must not be added together.
The intermediate diagnostic had stale lookup tables, so its total time is not
a performance comparison; these phase observations are not independent
whole-stage ablations.

The 32 GiB worker, 24 GiB native and 8 GiB device limits remain unchanged.
All complete-stage memory plans have zero shortfall. Their outer residual still
fills the remaining reservation allowance, so the reservation total is not RSS.
Incomplete case owners remain retained until isolated process teardown, and
the runs issue no workflow completion receipt or recursive proof.

Validation includes four real GPU parity/failure tests (including full graph
parity against CPU), 12 core resource tests, 81 Python tests, all numeric
qualifications, generated-table checks, table-use validation, and a release
all-target check. The broader research suite passed 102 checks and exposed an
old hard-coded scratch assertion; that assertion was updated to include the
funded host/device workspace and passed its focused rerun.

Baseline and candidate sources are preserved locally in
`.tools/metadata-latency-baseline` and `.tools/metadata-latency-candidate-source`.
Per-run timings, phase diagnostics, fixtures, build/source hashes, validation
records and acceptance gates are recorded in
[metadata latency evidence](../../docs/evidence/ringct-metadata-latency-2026-11-02.json).

### Batched commitments and endpoint reuse (2026-11-02)

Graph preparation now defers node commitments until its private graph is
complete, then hashes homogeneous batches of up to 64 Q, QHAT, signed, or byte
nodes. Coefficient-major packing lets adjacent GPU work items read adjacent
coefficients. Each node keeps its original domain, framing, and sponge state.
An unfinished or failed graph cannot be returned to a caller.

Source preparation computes the seven crypto requests' input/output endpoints
once per transaction. Auxiliary requests reuse those exact hashes and consume
the temporary output streams. Endpoint facts become available to subsequent
constructors only after the source GPU scope completes successfully. The
existing request identity, full graph context, ledger, scratch admission, and
one-shot publication checks still apply. All 21 AES/SHAKE constructors in N3
adopt these request-owned facts.

Independent affine, crypto, and auxiliary field commitments use bounded batches
of at most 64 streams and 131,072 packed words. Each stream retains its serial
sponge recurrence and 4,096-word tile order. Larger streams use the existing
bounded scalar GPU path. The workspace still has eight GPU buffers and now has
five kernel handles. Batch packing, temporary outputs, pending result frames,
and retained facts are charged before execution. Status checks precede root
readback; GPU buffers and packed host words retain their cleanup paths. Identity
hashing remains on CPU, and the GPU metadata compiler port remains deferred.

Three alternating baseline/candidate pairs per configuration replayed the same
verified public fixtures in fresh processes. Detailed instrumentation was
disabled for these 24 comparisons. The baseline contains all priorities from
the preceding scope-reuse pass.

| Metadata workers / fixture | Previous median | Updated median | Elapsed reduction |
|---|---:|---:|---:|
| 1 / baseline N3 | 14.553 s | 7.414 s | 49.1% |
| 8 / baseline N3 | 14.570 s | 7.421 s | 49.1% |
| 16 / baseline N3 | 14.567 s | 7.418 s | 49.1% |
| 16 / held-out N3 | 14.592 s | 7.407 s | 49.2% |

These measurements include metadata startup and schedule/memory closure,
exclude fixture loading/verification and native input generation, and stop
before runtime preissue or recursive proof generation. The 25% reduction target
at 16 workers passed, as did the no-regression checks at 1 and 8 workers.

At 16 workers, median graph construction fell from 6.793 to 1.309 seconds and
constructors from 3.396 to 1.787 seconds. Source preparation changed from 4.046
to 3.985 seconds and is now the largest phase. Long field-hash streams retain a
serial dependency; increasing metadata workers has little effect on this phase.

Single instrumented ablations using the final binary measured 14.497 seconds
with all three optimizations disabled, 9.061 with node batching alone, 12.989
with endpoint reuse alone, 14.463 with field batching alone, and 7.447 with all
three enabled. These are diagnostic samples with overlapping effects. Field
batching alone showed little standalone elapsed improvement. Across the
combined diagnostic, 5,334 logical node hashes used 93 GPU events instead of
5,334. Field hashes changed from 189 logical commitments and 411 GPU events to
168 commitments and 147 events. Node device time fell from 5.328 to 0.098
seconds; field device time fell from 3.878 to 2.213 seconds.

All 24 comparisons had 400 native memory hits and 185 native table hits across
585 requests, plus 962 registered memory hits and 9 table hits across 971
requests. Cold compiler misses and evictions were zero. Native LRU misses are
still 31.62%; every observed miss resolves through the descriptor table. These
are software cache rates for the measured N3 configurations. Both catalogs
were requalified at 1, 2, 4, 8, and 16 workers: 317 native descriptors and 72
registered shapes. Both generated tables pass reproduction checks.

Validation passed 109 CPU regression tests, 6 GPU parity/failure tests, 12 core
resource tests, and 82 Python guard/validator tests. Coverage includes complete
graph parity, endpoint/public-root parity, invalid inputs in different batch
positions, empty and oversized streams, poisoned scopes, pending graph
publication, and cleanup after errors and panics. Every complete-stage memory
plan had zero shortfall under the unchanged 32 GiB worker, 24 GiB native, and
8 GiB device limits. Reserved memory still includes the existing outer residual
and is not an RSS measurement.

For diagnostics, `--metadata-preparation-detail` now accepts version-2 counters
with logical hashes separate from calls and device events. The test-only
`--metadata-hash-variant reference|nodes|endpoints|fields|all` selector supports
the ablations above. Validation requires all 6 raw scopes with endpoint reuse,
or all 27 without it, and checks complete logical hash and adoption counts.
Production enables the qualified optimizations and exposes no selector.

The frozen sources are in `.tools/metadata-hash-baseline` and
`.tools/metadata-hash-candidate-source`. Per-run timings, source/build hashes,
fixtures, diagnostics, memory plans, and acceptance results are saved in
[batched metadata evidence](../../docs/evidence/ringct-metadata-hash-batches-2026-11-02.json).

## Structural reuse, numeric verifier plans, and vector arithmetic (2026-11-02)

This pass implements the three priorities following the hash-batching results
above. All previous hash optimizations remain enabled.

An internal `PreparedGraphStructure` borrows the immutable graph and collects
exact registration words, source counts, the registration label, and the
structural digest in one canonical traversal. Algebra planning, tree planning,
and manifest preparation reuse those facts. The tree shares the registration
through an `Arc`; prepared bindings require that same registration allocation.
Ordinary entry points retain their exact shape checks. The two hash domains,
graph labels, expression order, and public roots remain unchanged.

Each prepared graph now owns a fixed 64-entry numeric verifier-plan cache for
NTT, multiplication, and permutation descriptors. Keys compare the complete
typed descriptor, family, numeric source identity, and profile. Only successful
numeric plans are retained. A full cache uses the admitted uncached recorder;
failed recordings are never cached. Source ownership, exact reservations,
private buffers, runtime recording, and `same_census` checks remain in place.
Linear-map verification is unchanged.

Two canonical formulas, the four-pair adjustment, and inverse challenge now
use existing vector GPU arithmetic. Intermediate values are recorded in the
original coefficient-major expression order, including constant folding and
signed bounds. Default backend hooks preserve the scalar formulas. GPU errors
poison preparation without a CPU fallback. No new GPU kernel was added.

Three alternating fresh-process pairs per configuration produced these medians:

| Metadata workers / fixture | Previous median | Updated median | Elapsed reduction |
|---|---:|---:|---:|
| 1 / baseline N3 | 7.337 s | 4.959 s | 32.4% |
| 8 / baseline N3 | 7.345 s | 4.963 s | 32.4% |
| 16 / baseline N3 | 7.345 s | 4.968 s | 32.4% |
| 16 / held-out N3 | 7.351 s | 4.969 s | 32.4% |

These are complete metadata-stage times for three transactions, including
startup and schedule/memory closure. Fixture loading/verification and native
input generation are excluded. Recursive proof generation and runtime preissue
remain disabled. The target of at least 20% improvement and at most 5.93 seconds
at 16 workers passed, as did the 3% regression limits for the other configurations.

At 16 workers, median graph construction fell from 1.310 to 0.746 seconds,
source preparation from 3.933 to 2.884 seconds, and constructors from 1.770 to
1.008 seconds. Native constructors account for 0.519 seconds of the updated
constructor phase. Phase medians are computed independently.

Separate instrumented single-run ablations use the same final binary:

| Enabled in this pass | Complete stage | Structural traversals | Verifier recordings | Arithmetic GPU events |
|---|---:|---:|---:|---:|
| Baseline | 7.397 s | 18 | 81 | 11,082 |
| Structural reuse | 6.317 s | 3 | 81 | 11,082 |
| Verifier reuse | 6.608 s | 18 | 39 | 11,082 |
| Vector arithmetic | 6.812 s | 18 | 81 | 3,900 |
| All three | 4.973 s | 3 | 39 | 3,900 |

The combined diagnostic eliminated six full inventories and nine repeated
exact comparisons from the prepared path. The verifier cache served 42 hits
and performed 39 first recordings, with no overflow. Arithmetic GPU events
fell by 7,182, matching the planned reduction. These diagnostic effects overlap
and should not be added. Source preparation remains the largest phase; field
commitments still take about 2.21 seconds in the instrumented run. The GPU
metadata compiler port and cooperative hash kernels remain deferred.

All 24 comparisons had zero cold descriptor compilations, zero descriptor-cache
evictions, and zero memory shortfall. The native descriptor cache still has
400 memory hits and 185 table hits across 585 requests; the registered cache
has 962 memory hits and nine table hits across 971 requests. These descriptor
statistics are separate from numeric verifier-plan recordings. Both catalogs
were requalified at 1, 2, 4, 8, and 16 workers: 317 native descriptors and 72
registered shapes. Both generated tables reproduce exactly.

The original admission census includes the fixed verifier cache, shared
registration allocation, vector recipe frames, and bounded profiling records.
Retained host accounting increased by 59,088 bytes across N3. The 32 GiB worker,
24 GiB native, and 8 GiB device limits remain unchanged. Reservation accounting
includes the existing outer residual and is not an RSS measurement.

Validation passed 134 CPU regression tests, six real GPU parity/failure tests,
12 core descriptor/resource tests, 84 Python tests, and the release all-target
compilation check. Coverage includes exact hash framing, graph/binding parity,
constant folding, foreign operands and registrations, cache key/source/profile
separation, failed recordings, full-cache fallback, and poisoned GPU scopes.
The first GPU test attempt refused an incompatible guard allowance before
execution; the corrected 8 GiB smoke profile passed all six tests.

The test-only selector is
`--metadata-reuse-variant baseline|structure|verifier|arithmetic|all`.
`--metadata-preparation-detail` also reports a bounded arithmetic opcode/width
histogram. Production enables all three optimizations and exposes no selector.
CPU identity hashing remains unchanged.

Frozen sources are in `.tools/metadata-reuse-baseline` and
`.tools/metadata-reuse-candidate-source`. Timings, ablations, memory plans,
fixture/source/build hashes, and acceptance checks are saved in
[metadata reuse evidence](../../docs/evidence/ringct-metadata-reuse-2026-11-02.json).
This documentation and evidence were added after the measured source snapshot.

## Cooperative field hashing, buffered encoding, and case-wide verifier reuse (2026-11-02)

This pass implements the next three priorities against commit `b19e96d`. All
previous hash batching, structural reuse, and vector arithmetic remain enabled.

Raw field commitments now use one eight-lane GPU workgroup per stream, with one
Poseidon state word per lane. They reuse the existing register-shuffle helpers
and immutable round constants. Workspace creation selects this path on NVIDIA
SM 7 or newer with 32-thread warps; other devices and oversized single streams
retain the scalar GPU path. The scalar reference retains its original batch
launch layout. Initial states, canonicalization, rate-four padding, ordered
4096-word tiles, and the 64-stream / 131072-word batch limits are unchanged.
Canonical validation is collective, so every lane follows the same error path
before any shuffle-dependent hashing. An execution error poisons the scope;
the existing queue fences and scrubbing remain in force.

Registration encoding uses a four-word expression buffer, reuses node and
operation scratch, and reserves shape storage from the already admitted census.
That census is an upper bound, not an expected exact length. An overrun is
refused before the shape vector can grow beyond it. An 8 KiB buffer combines
structural LE-u64 hash updates; it flushes before witness-only roots and hash
finalization. Exact words, both inventory hash domains, and registration labels
remain identical. Ordinary public shape validation remains exact.

The 64-entry numeric verifier cache now belongs to `SourcePlanningPlan`, shared
by all transactions in one N3/N4 case. The graph-local version exists only in
tests as an independent reference. Keys still include the full typed NTT, Mul,
or permutation descriptor, numeric source identity, and profile. Source and
ownership validation, exact reservations, runtime recording, and `same_census`
checks remain per request. Failed recordings are uncached, a full cache uses
the original recorder without eviction, and linear maps are unchanged. Inline
cache ownership, lookup frames, the encoder buffer, and reporting storage are
included in admission before allocation. CPU identity hashing is unchanged;
numeric metadata compilation remains on CPU.

Three alternating fresh-process pairs per configuration produced these complete
N3 metadata-stage medians on the Ryzen 9 5900XT / RTX 5080:

| Metadata workers / fixture | Frozen baseline | Updated median | Elapsed reduction |
|---|---:|---:|---:|
| 1 / baseline N3 | 4.928 s | 3.365 s | 31.7% |
| 8 / baseline N3 | 4.927 s | 3.370 s | 31.6% |
| 16 / baseline N3 | 4.915 s | 3.388 s | 31.1% |
| 16 / held-out N3 | 4.875 s | 3.420 s | 29.8% |

These timings include startup and metadata schedule/memory closure for three
transactions. They exclude fixture loading/verification and native input
generation, and stop before recursive proof generation and runtime preissue.
The target of at least 20% improvement and at most 3.97 seconds at 16 workers
passed. All other configurations passed the 3% regression limit. At 16 workers,
source preparation fell from 2.877 to 1.538 seconds; native constructors now
account for 0.346 seconds. Phase medians are calculated independently.

Separate instrumented single-process ablations used the final binary:

| Enabled in this pass | Complete stage | Field GPU time | Expression allocations | Shape allocations | Verifier recordings |
|---|---:|---:|---:|---:|---:|
| Baseline | 5.005 s | 2.207 s | 1,515,483 | 69 | 39 |
| Cooperative field hashing | 3.853 s | 0.994 s | 1,515,483 | 69 | 39 |
| Buffered encoding | 4.795 s | 2.207 s | 0 | 3 | 39 |
| Case-wide verifier cache | 4.816 s | 2.207 s | 1,515,483 | 69 | 13 |
| All three | 3.441 s | 0.994 s | 0 | 3 | 13 |

The combined run used 147 cooperative field-kernel events and zero scalar field
kernel events. Field commitments retained zero GPU allocations during execution.
Verifier reuse served 68 hits from 81 requests, versus 42 hits previously, with
no overflow. Shape allocation counts include initial backing and growth; the
optimized path makes one admitted allocation per graph. These diagnostic
single-run effects overlap and are not additive.

All 24 paired runs had zero cold descriptor compilations, descriptor-cache
evictions, and memory shortfall. The native descriptor cache still served 400
memory hits and 185 table hits from 585 requests; the registered cache served
962 memory hits and nine table hits from 971 requests. These software descriptor
caches are separate from the numeric verifier cache. The worker/native/device
limits remain 32/24/8 GiB. All 317 native descriptors and 72 registered shapes
were requalified at 1, 2, 4, 8, and 16 workers, with matching counts and exactly
reproducible generated tables.

Validation passed 137 CPU regression tests, seven GPU parity/failure tests,
12 core resource/descriptor tests, one shared public-hash GPU parity test,
85 Python tests, and a release all-target compilation check. Coverage includes
CPU/scalar/cooperative roots at tile boundaries, invalid fields in every lane,
unequal and empty streams, scope poisoning and cleanup, all expression variants,
buffer flushes before witness roots, shape-capacity refusal, concurrent cache
misses, source/profile/key separation, and isolation between case owners.

The new test-only selector is
`--metadata-next-variant baseline|field_hash|encoding|case_cache|all`.
Both older selectors stay `all` throughout these comparisons. Detail reports
include `field_kernels` in scalar/cooperative order and `next_counters` in
expression allocations, shape allocations, case hits, case recordings order.
Production enables the qualified optimizations without an environment selector.

Frozen sources are in `.tools/metadata-cooperative-baseline` and
`.tools/metadata-cooperative-candidate-source`. Per-run source/build hashes,
fixtures, timings, ablations, memory plans, and acceptance checks are in
[cooperative metadata evidence](../../docs/evidence/ringct-metadata-cooperative-2026-11-02.json).
This documentation and evidence were added after the measured source snapshot.
