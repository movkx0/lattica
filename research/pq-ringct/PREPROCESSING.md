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
the coordinator prepares the next graph while workers lower earlier graphs.
An idle worker takes another admitted job without waiting for the whole batch.
Results retain their original order, and failures publish no partial cohort.

Each CPU phase uses fixed scoped worker threads and fixed queue/result slots.
Native ready windows hold up to 64 admitted requests while execution remains
capped at 16 workers. This lets threads and compiler backing serve more jobs
before joining, without retaining them outside the original reservation.
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
before the coordinator reclaims their bytes. All scratch is dropped before
the pool joins. This does not reuse proofs, witnesses, programs,
or completed identities. Reported compiler allocation peaks can vary with
retained scratch; mathematical operation, wire, input and row counts must match.

Registered-height admission retains its 128 MiB scheduling floor. Native jobs
start with public-geometry compiler caps of 48, 80, 112 or 128 MiB. These are
heuristics: every allocation enforces its cap. Only byte-cap refusals permit a
retry, after draining and joining all workers; native retries increase the
failed job's cap, and registered retries reduce the worker ceiling. Other errors
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
preparing another graph. Active compiler counts exclude buffer-maintenance jobs;
reports also expose drained completions, admission stalls, trimmed bytes, idle
retained bytes and extra phase reservations.

Native callers holding an authenticated scratch reservation automatically
request a separate planning-phase claim from the same workflow ledger. This is
the only ledger-backed planning policy; there is no memory-mode selector. The supplement is at
most 1 GiB and targets a total 3 GiB native planning allowance. It never increases
an individual compiler cap, the ledger's host limit, or the process limit. If
capacity is unavailable, the same scheduler uses the bytes already reserved. Cache-only and small
cohorts, and worker ceilings of eight or fewer, acquire no supplement. The claim
outlives all cohort workers and is released before returning to the caller.
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
