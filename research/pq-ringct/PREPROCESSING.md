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
Preparation uses that reservation before workers start; concurrent execution
charges shared symbolic backing once, each worker's returned wires/helpers and
compiler cap, a 2 MiB stack plus bounded thread/TLS overhead, and the existing
1 MiB coordinator allowance. The returned source bound is unchanged.

Worker admission selects the largest fitting width whose compiler share is at
least 128 MiB for registered heights or 256 MiB for native descriptors. These
minimums are scheduling heuristics, not memory grants or
claimed source bound. Actual allocations still enforce their caps. Reduced
compiler byte-limit refusals join all workers before retrying at lower width;
other failures remain errors. Inline fallback uses the original cap. Neither
measured RSS nor unused external allowances authorize additional workers.

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

Native metadata now has a separate source-qualified table of 39 exact descriptors
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
cohort is published on failure. Cache `planning_ns` counts cohort wall time once.

`--native-metadata-profile` accepts only the ignored
`component_tree::native_shape::profiling::tests::native_metadata_profile` test
under `research-compile-large`, with the exact build receipt. It profiles all 39
descriptors, compares workers 1/2/4/8/16 with serial counts, and checks populated
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
matching identities and fresh proofs with independent CPU verification. A
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
