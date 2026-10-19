# CUDA GPU prover implementation plan

Build a native CUDA backend for Lattica's existing prover, then optimize the
dominant arithmetic and command-submission costs. Keep the current proof
formats, verification rules, security parameters, and worker resource limits.
The initial targets are Linux workers on Tesla V100 and desktop RTX 5080, with
the same job interface usable by a future distributed worker pool.

This plan is based on `ec1c93700d9f3755446ba143501efb136294729e`, pulled into
`main` from `origin/main` on 2026-10-18. The pull includes the V100 benchmark
harness and the query reconstruction optimization. CUDA implementation is in
progress.

## Current checkpoint

The opt-in `gpu-cuda` feature provides an experimental Linux transport: explicit
device selection, shared OpenCL/CUDA leases, bounded allocations, private-buffer
cleanup, NVRTC compilation, kernel launches and completion events. Native CUDA
now implements base/quadratic/cubic field arithmetic, tiled coset transforms,
query reconstruction from device prefixes, Poseidon2 commitments, and resident
quadratic/cubic quotient evaluation with partitioned prefix reconstruction.
Resident Poseidon2 transcripts now support observation, sampling, bounded
snapshots and deterministic grinding. An explicit CUDA challenger adapter
produces a mixed proof accepted by the unchanged CPU verifier; it does not
select CUDA for the other proving stages.
Native scalar kernels derive challenge powers, lookup bus prefixes/pairs,
next-row points and coset shifts. The CUDA lookup adapter samples alpha/beta
directly into device storage, then derives per-instance challenge pairs without
host readback. It shares the bounded bus mapping and domain metadata with OpenCL.
Native LogUp witness generation now consumes those resident challenge pairs,
main/preprocessed traces and public values. Expression evaluation, denominator
inversion, fractions and hierarchical prefix scans run on CUDA; the permutation
trace and terminal sum stay resident. Only an eight-byte validity status is
read back. The lookup compiler, integer kernels and memory planner are shared
with OpenCL.
Native ChaCha20 sampling now imports a seed and cursor, generates ordered
Goldilocks samples on CUDA, and supplies fresh salt matrices to commitments.
It shares byte admission with OpenCL. An explicit proof RNG adapter retires
every stream in a failed proof group. Bounded private salt recipes now support
CUDA regeneration, commitments and requested query rows without changing the
active RNG cursor. Native trace/preprocessing hiding and quotient
randomization now generate bounded LDE column tiles from resident random
samples. Shared protocol geometry preserves the existing OpenCL behavior.
Hidden LDE tiles now stream into mixed-height MMCS commitments. Only low-coset
evaluation prefixes, Merkle nodes and private salt recipes remain resident;
requested rows are reconstructed and salted on CUDA. Native out-of-domain
evaluation now consumes resident challenge points, and column-compressed opening
reductions produce resident FRI inputs. Native FRI folding, salted layer queries
and final-polynomial extraction are implemented. Native FRI protocol orchestration
now generates authenticated proofs accepted by the unchanged CPU FRI verifier.
The native hiding PCS opening wrapper evaluates each matrix once, observes
resident claims before sampling alpha, reduces them on CUDA, and returns the
existing public/masking opening and authenticated FRI proof format. Native
randomization-polynomial commitments sample their original rows and masking
columns directly, preserving the upstream polynomial degree. Native single-AIR
STARK orchestration now consumes resident traces and public values, with static
periodic columns, and returns the existing proof encoding. Both pinned field
profiles and real JoinSplit/HTLC AIRs pass the unchanged CPU verifier. Native
wallet generation now also constructs JoinSplit and HTLC traces/public values
from raw witness packets and feeds them directly into this prover. The existing
stage ledger now binds observed CUDA completions to each wallet proof attempt,
covering all fourteen arithmetic stages in the single-wallet protocol. Typed
JoinSplit and HTLC preparation binds the actual AIR and runtime; each proof uses
fresh private randomness and finalizes its report before returning its artifact.
Native recursive-machine execution now also constructs witness traces and
deterministic preprocessing from immutable public program metadata and raw
inputs. Dependency waves, base/cubic arithmetic, Poseidon2 traces and execution
checks run on CUDA. Generated traces, preprocessing and public values feed the
native lookup stage directly. Native machine batch-STARK orchestration now
connects these stages to the hiding PCS, preserving the upstream transcript and
proof encoding. Real JoinSplit verifier programs also pass independent CPU
verification against CPU-rebuilt preprocessing commitments. Production wrapper
and merge programs, public routing and recursive workers remain outstanding.
Public preprocessing now survives failed private proof attempts on a healthy
runtime. Each salt replay uses an isolated temporary consumer; failed private
randomness still retires across every alias. The public path accepts only
deterministic machine preprocessing and the production fixed public seed.
Native registered-machine handles now authenticate preparation against a caller's
approved cap and public program schema. Setup and proof components have separate
CUDA inventories and complete execution receipts; cached setup records provenance
without replaying device observations. Production request routing is still absent.

Registered proofs now admit their complete device allocation schedule before
importing private seeds. The planner uses the public program and existing
component geometry, including retained FRI layers during initial commitment
queries. It checks managed bytes, individual allocations, allocation counts,
random-stream slots and known host payloads under the runtime's submission
scope. Borrowed source capacities are charged during preparation and proving.
Source construction before entry, production request routing and worker-level
process accounting remain separate integration work.

An explicit CUDA public-arithmetic context now supports recursive statements and
registry compilation: protocol hashes, summary validation, compiler constants,
constant folding and symbolic AIR preparation. Its statement and registry child
components bind actual completions to their own inventories. CPU/OpenCL defaults
are unchanged. Connecting these components to registered wrapper/merge proving,
the typed-session cache and worker admission is still outstanding.

Commitment fragments preserve padding-free absorption across column boundaries;
fresh salts remain explicit caller inputs. Merkle nodes stay on the GPU, with bounded cap and
path reads that preserve query order and duplicates. Matrix geometry, immutable
roots and the query memory planner are shared with OpenCL. Intermediate
polynomials remain on the device; explicit transfer counters check this boundary.
The public AIR compiler and its 64-instruction specialization/liveness pass are
shared between OpenCL and CUDA. CUDA prepares immutable public program handles;
unsupported specialization shapes retain GPU interpretation. Current/next rows,
alpha powers, selectors, constraints and vanishing-polynomial division execute
on CUDA, with only a public domain-validity word read back per evaluation.

Wallet requests and recursive proofs are not yet routed through CUDA. Cached
twiddle tuning, backend integration, complete proof-stage coverage, controller
admission and pool integration remain outstanding. Prepared quotient handles
support reuse without retaining witnesses or sampled parameters. A bounded
public program cache now supports repeated preparation within an evaluator;
disk and cross-worker caches remain absent. Use the existing OpenCL backend
for complete proof benchmarks at this checkpoint.

Install the pinned development components with
`python3 lattica-prover-p3/scripts/setup-cuda-toolchain.py --prefix .tools/cuda-12.9.1`.
This leaves the system driver unchanged. From the prover crate, build with
`cargo test --locked --no-default-features --features gpu-cuda,block-v2-capacity-128 --lib cuda_compute:: --no-run`.
Run the resulting test executable in a bounded 3 GiB, four-thread, zero-swap
service with `LD_LIBRARY_PATH` pointing to the toolchain's `lib` directory and
`LATTICA_GPU_DEVICE_UUID` selecting the device. The filter
`cuda_compute:: --include-ignored --skip benchmark --skip recursive_tests --test-threads=1` covers arithmetic, transforms,
query reconstruction, salted commitments, quotient evaluation, host limits and device lifecycle
checks. The separate
`gpu_matrix:: --test-threads=1` filter checks shared roots and planner boundaries.
These tests do not establish a complete CUDA prover or transaction throughput.

The [2026-10-18 algebra qualification](evidence/cuda-algebra-2026-10-18.json)
passed 15 CUDA host/device tests and four shared planner/root tests on the desktop
RTX 5080. Compute Sanitizer reported zero memory errors and leaks across 14 tests;
the deliberate missing-kernel test passed outside memcheck. Transform/query race
and synchronization checks also passed. OpenCL regression coverage passed 144
host tests and six device tests. CPU-only and aarch64 Apple Metal library builds
checked successfully. NVRTC compiled the field and transform kernels for both
Volta and Blackwell; V100 CUDA execution and Metal execution remain untested.
The evidence records source and executable hashes for the implementation under
test, including its uncommitted source files at qualification time.

The [commitment qualification](evidence/cuda-commitments-2026-10-18.json) adds
independent CPU oracles for Poseidon2, salted leaves, partial-rate absorption,
Merkle caps and paths, plus bounded readback and allocation rejection tests.
All 22 CUDA tests and four shared planner tests passed on the RTX 5080.
Memory, race and synchronization checks passed across 21 tests; the intentional
missing-kernel API-error test passed outside the sanitizer runs. CPU-only,
OpenCL, Apple Metal cross-compilation and standalone CUDA builds also passed.
The new tests exposed a default-stream ordering gap: legacy clears and copies
could return before the nonblocking compute stream consumed their results.
Explicit completion now precedes compute and private-buffer retirement, with
a larger-buffer regression covering initialization, uploads and device copies.
These correctness results do not qualify complete CUDA proofs or performance.

The [quotient qualification](evidence/cuda-quotient-2026-10-18.json) passed all
30 CUDA host/device tests, four shared planner tests, 33 OpenCL host tests and
two OpenCL device comparisons. The CUDA comparisons cover both field extensions,
mixed physical row orders, 16,384-row tile boundaries, generic fallback and
specialized register reuse. The real machine AIR with LogUp matched the upstream
CPU Batch-STARK quotient evaluator. Quotient outputs were consumed by CUDA
commitments before any polynomial readback. Compute Sanitizer found zero memory
errors, leaks, race hazards or synchronization errors across 29 tests; the
intentional missing-kernel test passed separately. CPU/OpenCL libraries, Apple
Metal cross-compilation and standalone CUDA builds passed. Public programs have
a 16 MiB per-entry and 64 MiB aggregate retained host allowance, with at most 32
live prepared handles per runtime. The first OpenCL device check required a
retry with `LATTICA_V2_GPU_RETAIN_TREES=1`; that setup failure is retained in the
evidence. V100 execution and complete CUDA proofs remain unqualified.

The [OpenCL comparison at `bce8830`](evidence/gpu-tuning-rtx5080-2026-10-18.json)
completed 56 four-entry trials with full stage coverage and independent CPU root
audits. Event batching reduced median aggregation time from 23.892 to 23.402
seconds (2.05%); combined tuning increased it by 25.82%. Optional candidates
remain disabled by default while wider-workload qualification is outstanding.

The [partition qualification](evidence/cuda-partition-2026-10-18.json) covers
whole-operation byte admission and reconstruction of up to 256 component cosets.
Main, preprocessing and permutation prefixes may have different heights and row
orders. A single coset aliases compatible inputs; larger domains expand one
component at a time and scatter into a resident quotient. Only public domain
status and component shifts are downloaded. A 64-column case whose full main
LDE needs a 4 MiB allocation succeeds with a 2 MiB managed budget and a 512 KiB
allocation ceiling, including a resident commitment checked against the CPU.
This remains an experimental primitive, not an integrated CUDA prover.

The opt-in `cuda_partitioned_quotient_benchmark` test compares materialized and
partitioned cubic quotient evaluation on the same inputs. Set
`LATTICA_CUDA_PARTITION_BENCHMARK=1` and run that test with `--ignored
--test-threads=1 --nocapture` in the bounded CUDA service described above. It
reports cold preparation separately, then two warmups and five alternating pairs
for each case, with an independent CPU audit of every output. The benchmark
prints its build profile; debug-host timings are exploratory and do not qualify
production performance. It does not measure recursive proofs or transactions.

The [post-push microbenchmark at `968e403`](evidence/cuda-partition-benchmark-2026-10-18.json)
completed 20 measured samples and eight warmups, all independently CPU-audited.
With 16 cosets, median materialized/partitioned times were 1.09/13.32 ms; with
256 cosets, they were 1.04/175.41 ms. The measured command counts grew from 21
to 285 and 4,349, respectively. Partition byte plans required about 1.27 MiB and
263 KiB including retained inputs and public code; the full main LDE alone needs
4 MiB. These are small synthetic AIR workloads using debug host orchestration.
They demonstrate a memory/latency tradeoff, not a proving speedup. Future CUDA
backend admission should favor materialization when it fits. Adaptive component
sizes and scratch/command reuse need qualification before partitioning is used
as a performance optimization.

The [program-cache qualification](evidence/cuda-cache-2026-10-18.json) covers
public AIR reuse across proof attempts. `prepare_cached(profile, program, mode)`
keys the entire bytecode/layout, profile, specialization policy, generator and
kernel sources, compiler options, target, driver API and the loaded NVRTC library
instance. This identity is intentionally local to one evaluator/process; disk
or distributed reuse will need toolchain binary hashes including NVRTC builtins.
The default cache holds at most eight entries, 32 MiB of retained public host
storage and 8 MiB of device IR buffers, reduced for smaller runtime allowances.
These are additional cache ceilings within the existing runtime budgets, not
extra memory reservations. Native modules remain subject to the runtime module
limit and its separate context allowance.

Concurrent preparation of the same program compiles one copy. Cache hits allocate no device buffers and issue no uploads or GPU launches. Eviction plans all required releases before
retiring the least recently used unpinned entries; impossible requests preserve
existing entries. Active handles retain their allocations and host charges after
cache retirement, and failed runtimes reject hits as well as misses. Public
metadata includes hit, miss, eviction and retained-byte counters. Cache tables
and handle overhead are conservatively charged with retained programs. The real
machine AIR/LogUp oracle now exercises this cached preparation path. This is a
correctness/resource checkpoint; no complete-proof speedup is claimed.

The [transcript qualification](evidence/cuda-transcript-2026-10-18.json) passed
50 native CUDA tests, five challenger tests and four shared planner tests.
Memory, race and synchronization checks passed across 49 native tests and three
challenger device tests per tool. Three OpenCL challenger device tests and the
existing CPU/OpenCL/Metal build and quotient regression checks also passed.
The device owns the duplex state; public sampling can read back bounded values,
while resident samples feed native commitments without host transfers. Shared
family retirement prevents continuation after a failed or abandoned attempt.
Whole-operation admission covers grinding scratch before state mutation, and
each grinding batch downloads only two public status words. Zero-bit grinding
does not change state; zero-bit sampling still consumes a sample.

The integration test preserves the production hiding PCS, security parameters
and Postcard format, verifies using the original CPU proof type, and rejects
altered public inputs. Only its challenger runs on CUDA. Randomness/hiding,
witness/preprocessing/lookup evaluation, openings/FRI/final
polynomials, complete PCS/backend selection, stage receipts, worker admission
and pool integration remain outstanding. This checkpoint does not establish
complete CUDA proving or transaction throughput.

The opt-in `cuda_transcript_primitive_benchmark` test measures public and
resident observation/sampling plus bounded grinding at 0, 8, 16 and 20 bits.
Set `LATTICA_CUDA_TRANSCRIPT_BENCHMARK=1` and run that filter with `--ignored
--test-threads=1 --nocapture` using the bounded CUDA test process above. It emits
two warmups and five measurements for each case, auditing every sample against
the unchanged CPU challenger. Kernel preparation, resident input uploads and
CPU audits are outside operation timing; the public case includes its transfers.
Resident result readback and cleanup follow timing. The ordinary debug test
build measures debug host orchestration with NVRTC-compiled kernels, not release
proof throughput. Command and byte counters accompany every measurement.

The [post-push transcript benchmark at `a02373b`](evidence/cuda-transcript-benchmark-2026-10-18.json)
completed 40 measurements and 16 warmups on the desktop RTX 5080; every sample
passed its CPU audit. Observing 64 fields and sampling 32 took a median
0.374 ms with resident buffers and 0.411 ms through the public host API.
The 1,024-field/256-sample case took 4.712/4.767 ms. Resident cases issued no
transfers within timing, but their input upload and audit readback were outside
that region. Grinding medians were 0.212, 0.342 and 3.163 ms at 8, 16 and 20 bits;
the 20-bit samples ranged from 0.344 to 9.914 ms as witness positions varied.
These measurements establish primitive costs under debug host orchestration,
not CPU/GPU proof speedups or complete transaction throughput.

The [scalar qualification](evidence/cuda-scalars-2026-10-18.json) passed 56 native
CUDA tests, nine challenger tests, four shared planner tests and the OpenCL
scalar/lookup/quotient regressions. Memory, race and synchronization checks passed
across 55 native tests and all nine challenger tests per tool. CPU/OpenCL library,
Apple Metal cross-compilation and standalone CUDA checks also passed. Three
streaming tests preserved the existing lookup metadata allocation accounting.

CUDA now derives base/quadratic/cubic powers, lookup bus prefixes and mapped
challenge pairs, next-row points and domain shifts. Prepared lookup work admits
its output, public ID map and upcoming sample before consuming the transcript.
Empty lookup batches consume no samples. A test chains the resident challenge
pairs and quotient alpha into specialized quotient evaluation and a Merkle
commitment, then checks both against independent CPU oracles. Before that audit,
the chain uploads one public bus ID and downloads only the quotient-domain
validity word. Scalar failures and unwinds retire the shared transcript family.
This establishes native stage composition, not complete CUDA proof construction;
the default backend, proof profile and worker admission remain unchanged.

The [randomness qualification](evidence/cuda-random-2026-10-18.json) passed 33
checks, including 64 native CUDA tests, nine challenger tests and three proof
RNG tests. Memory, race and synchronization checks passed across 63 native tests
and both adapters; the deliberate missing-kernel test ran separately. Six
OpenCL sampler/planner host tests, six sampler device tests and the existing
proof RNG, scalar, quotient and streaming regressions passed. CPU/OpenCL library,
Apple Metal cross-compilation and standalone CUDA checks also passed. Native
sampling matches `rand_chacha` at odd offsets, counter and batch boundaries;
dense rejection preserves order. A failed proof retires all stream aliases,
and fresh salt matrices feed CPU-audited CUDA commitments without sample
transfers. At that checkpoint, complete hiding PCS and salt replay remained
unimplemented. The final streaming test build needed a 6 GiB host cap; GPU
checks retained the 3 GiB cap.

The opt-in `cuda_random_primitive_benchmark` compares CUDA field expansion with
CPU expansion plus upload, producing identical device-resident outputs. Set
`LATTICA_CUDA_RANDOM_BENCHMARK=1` and run that filter with `--ignored
--test-threads=1 --nocapture` in the bounded CUDA test service. Four request sizes
from 256 to 1,048,593 fields each receive two warmups and five alternating pairs;
every result is independently CPU-audited. Timing includes allocation, expansion,
transfers and temporary-buffer cleanup, but excludes engine/seed preparation,
result readback and result cleanup. The build profile and transfer counters are
printed. Debug-host measurements do not establish production proof throughput.

The [post-push sampler benchmark at `9329a9c`](evidence/cuda-random-benchmark-2026-10-18.json)
completed 40 measurements and 16 warmups, with every output CPU-audited. Median
CUDA times were 0.154, 0.159, 0.179 and 0.357 ms for 256, 4,096, 65,536 and
1,048,593 fields. CPU generation plus upload took 0.087, 1.039, 16.246 and
258.909 ms in the same debug-host build. The CPU code is unoptimized, so these
figures do not establish an optimized CPU/GPU speedup. CUDA uploaded no samples;
its only downloads were one 8-byte status word per batch. Complete proof and
transaction throughput remain unmeasured for the native backend.

Native private salt replay now captures exact start/end positions under the
active cursor lock. Preparing up to 256 recipes retains no sample matrices;
each recipe occupies a slot within the existing 4,096-state engine allowance.
Regeneration uses an independent local cursor and the original private key.
Runtime ownership, stream retirement and rejection boundaries remain checked.
The commitment consumer admits both sampling and hashing peaks before replay;
the query consumer gathers only requested physical rows, preserving order and
duplicates. Requested rows and public status words are the only downloads.
Canonical salt recipes bind to the input's public coset through a metadata-only
view, preserving their values on shifted domains.
Failures or unwinds after private work retire the whole proof RNG family,
including recipes that escaped the adapter. Complete hiding PCS, polynomial
randomization and remaining proof-stage integration are still outstanding.

The [salt replay qualification](evidence/cuda-salt-replay-2026-10-18.json)
passed 34 checks, including 73 native CUDA tests, nine challenger tests and four
proof RNG tests. Memory, race and synchronization checks passed across 72 native
tests and both adapters; the deliberate missing-kernel test ran separately.
CPU oracles cover shifts 1, 7 and 13, all three field extensions, concurrent
replay, stream exhaustion, query block boundaries and the 4,096-query limit.
Three OpenCL replay device tests and the existing sampler, quotient, scalar,
streaming and cross-platform build checks also passed. No complete native CUDA
proof or throughput qualification is implied.

Native polynomial hiding now interleaves trace/random rows and zero-padded
preprocessing on CUDA, then generates LDE column tiles on the generator coset.
Quotient hiding preserves the CPU draw order, normalizes each partition on the
device, and balances the final mask across the complete uniform partition.
Prepared inputs admit sampling and LDE storage peaks before random draws;
multiple quotient sample requests hold one cursor lock. Consumer errors and
unwinds retire the shared RNG family. Coefficients have a distinct internal
type so they cannot be mistaken for evaluation matrices.
The [hiding qualification](evidence/cuda-hiding-2026-10-18.json) records 43
successful checks, including 82 native CUDA tests, three shared hiding checks,
and memory/race/synchronization checks across 81 native tests plus both
adapters. Upstream CPU PCS comparisons cover base/quadratic/cubic traces,
preprocessing, quadratic/cubic quotients, shifted domains, both row orders,
and every chunk in 2-, 4-, 16- and 32-way partitions. Independent recomposition
recovers the original quotient. A 13.75 MiB full trace LDE is evaluated in
column tiles within a 4 MiB managed budget and 1 MiB allocation ceiling.
A hidden LDE and replayed salts feed a CPU-audited CUDA commitment without
private intermediate transfers. Relevant OpenCL hiding/storage regressions,
CPU/OpenCL builds, Metal cross-compilation, standalone CUDA and streaming
resource checks pass. Qualification records preserve initial harness filter
and backend-selection errors alongside successful retries on identical pinned
source and executables.
This remains a polynomial-hiding checkpoint. Streaming commitment absorption
across tiles, retained prefixes, complete PCS/opening/FRI integration and the
remaining native proof stages are still required before complete CUDA proofs
or transaction throughput can be qualified.

The [hidden commitment qualification](evidence/cuda-hidden-commitments-2026-10-18.json)
records 36 successful checks, including 89 native CUDA tests, 88 tests under each
sanitizer and seven commitment/query tests with the `stream` feature. Mixed-height
streaming preserves partial-rate sponge absorption and stable matrix ordering.
Salt recipes are captured in original input order before height sorting. Hidden
batches include preprocessing, base/quadratic/cubic traces and complete quotient
partitions; caps and Postcard-encoded openings match upstream CPU implementations.
The unchanged CPU verifier accepts native openings and rejects altered values,
salts and paths. Queries preserve duplicates and original matrix order.

A 13.75 MiB full LDE commits and answers queries within an 8 MiB managed GPU budget
and 2 MiB allocation ceiling. Retained storage is exactly evaluation prefixes plus
Merkle nodes; full LDEs and salt matrices are not retained. Aggregate host/device
admission rejects insufficient budgets before private work, and injected failures
retire all participating RNG families. CPU/OpenCL builds and relevant device
regressions, Apple Metal cross-compilation and standalone CUDA checks pass.

This is a native commitment and MMCS-query checkpoint. Out-of-domain openings,
opening reductions, FRI/final polynomials, remaining proof stages, backend selection
and worker integration still precede complete native CUDA proof qualification.
No complete-proof speedup or transaction-throughput result is established here.

The opt-in `cuda_hidden_commitment_benchmark` compares one-, two- and four-column
tiles for quadratic and wide cubic traces, with two warmups and five measurements
per geometry. Set `LATTICA_CUDA_HIDDEN_BENCHMARK=1` and run that test filter with
`--ignored --test-threads=1 --nocapture` in the bounded CUDA service above. Each
result is checked against upstream CPU commitment/opening construction and CPU
verification, outside the timed regions. It reports hiding preparation, commitment
including cap readback, and queries separately. Runtime/kernel preparation and
trace uploads precede these timings; result cleanup follows them. The 16 MiB
managed budget and 4 MiB allocation ceiling stay fixed across geometries. Normal
debug test builds measure debug host orchestration with NVRTC-compiled kernels;
the results do not measure complete proofs or transaction throughput. Exclude
this opt-in test from general `--include-ignored` correctness/sanitizer runs.

The [post-push benchmark at `a0c68db`](evidence/cuda-hidden-commitment-benchmark-2026-10-18.json)
completed 30 measurements and 12 warmups on the desktop RTX 5080, all CPU-audited.
Median commitment times, including cap readback, were:

| Trace case | One column | Two columns | Four columns |
|---|---:|---:|---:|
| Quadratic, 256 rows and 18 flattened input columns | 5.709 ms | 3.351 ms | 2.278 ms |
| Cubic, 1,024 rows and 51 flattened input columns | 18.423 ms | 11.141 ms | 6.120 ms |

Four-column tiles reduced commitment commands from 199 to 71 and from 465 to 151,
respectively. Query medians stayed around 0.77–0.78 ms for 33 quadratic queries and
1.35–1.37 ms for four cubic queries. Retained commitment storage was independent of
tile width: 614,368 and 2,998,240 bytes. Wider tiles require more scratch, and this
two-case comparison does not qualify a default geometry change. These debug-host
primitive timings do not establish complete proof performance or transactions
per hour; native PCS and remaining proof-stage integration are still unfinished.

The [opening qualification](evidence/cuda-openings-2026-10-18.json) records native
quadratic/cubic out-of-domain evaluation and opening reductions. Evaluation copies
resident challenge points into private storage and processes bit-reversed coset
prefixes in bounded row tiles. Only a domain-validity word is downloaded before
explicit claimed-value reads. Prefixes, copied points and values remain resident
for reduction; input challenge buffers can be reused without changing them.

Reduction combines columns with CUDA alpha powers before extending one
extension-field vector. It preserves point/matrix order and advances the alpha
power cursor across appended matrices. The output domain retains its actual
coset shift. Separate admission covers compression, transform and denominator
tile peaks; scratch is released between phases. Appending consumes the previous
accumulator, so errors cannot expose partial output. Hidden commitments provide a
scoped opening consumer that retires all participating RNG families on errors or
unwinds after private work, while early admission failures preserve them.

Independent CPU polynomial comparisons cover both extensions, shifted domains,
duplicate points, 131,072-row prefixes, 32 points, multiple matrices, zero/one
alpha, single-row constants and nonzero alpha offsets. A 65-column case reduces a
full-width LDE of 1,064,960 bytes using a 256 KiB managed budget and 128 KiB
allocation ceiling. Invalid geometry, allocation counts, memory pressure, alpha
cursor overflow, points on either coset, consumer failures and unwinds are covered.
All 103 native tests
pass; 102 run under each sanitizer, and 14 opening tests also pass with `stream`.
CPU/OpenCL builds, relevant OpenCL regressions, Apple Metal cross-compilation and
standalone CUDA checks pass. Kernels compile for compute_70 and compute_120;
execution remains qualified only on the desktop RTX 5080.

These are opening/reduction primitives and hidden-prefix integration, not a
complete native CUDA PCS or prover. Denominators are inverted on CUDA; batch
inversion and denominator reuse remain optimization candidates. No opening-stage
speedup or complete transaction-throughput result is claimed.

The [FRI primitive qualification](evidence/cuda-fri-2026-10-18.json) adds native
quadratic/cubic folding at arities 2, 4, 8 and 16, lower-height input mixing,
salted layer commitments, bounded queries and final-polynomial extraction.
An explicit rescaled view treats source values as evaluations of
`g(X) = f(shift * X)` on the unit subgroup, matching Plonky3 without changing
the source matrix's domain metadata. Each round owns an immutable device copy
of beta, shared by folding and its `beta^arity` input mixing. Final coefficients
remain resident for transcript absorption before bounded proof egress.

Layer commitments retain values, trees and replayable salt recipes. Query
admission covers aggregate host outputs, index staging and device scratch;
query order and duplicates are preserved. Early admission failures preserve
randomness, while failures and unwinds after private work retire the salt
family. Shared FRI geometry now serves CUDA and the existing OpenCL path.
Independent CPU comparisons cover all arities and both extensions, final
polynomials through 65,536 coefficients, shifted domains, unchanged source
data, matching transcripts, and byte-identical Postcard MMCS openings at cap
heights 0 and 6. The 4,096-query limit and constrained-memory failures are tested.
All 38 qualification checks passed: 113 native tests, 112 under each CUDA
sanitizer, ten FRI tests with `stream`, shared OpenCL regressions and the
CPU/OpenCL/Metal/CUDA build checks. The OpenCL arithmetic launcher needed its
explicit GPU enable setting; the failed setup and successful retry are recorded.
Execution is qualified on the desktop RTX 5080; NVRTC target compilation also
passed for Volta, but V100 execution and Metal execution remain untested.

This primitive checkpoint did not yet include FRI round scheduling, transcript
orchestration or complete proof assembly. The subsequent protocol checkpoint
below adds those operations; complete PCS integration, remaining proof stages,
backend selection and worker integration are still required.

The opt-in `cuda_fri_folding_benchmark` compares one arity-16 fold with four
binary folds using beta, beta squared, beta to the fourth and beta to the eighth.
Both arms compute the same algebraic result; this does not change FRI rounds
or security parameters. Set `LATTICA_CUDA_FRI_BENCHMARK=1` and run the exact
test with `--ignored --test-threads=1 --nocapture` in a bounded CUDA service.
It covers both extensions at 65,536 and 262,144 rows, with two warmups and five
alternating measurement pairs per case. Every result is audited against the
upstream CPU fold outside timing. Preparation, fixture uploads, challenge copies,
result downloads and final-result cleanup are excluded; intermediate allocations,
completion and cleanup are included. Debug-host primitive timings do not measure
complete proofs or transactions.

The [post-push folding benchmark at `f932572`](evidence/cuda-fri-benchmark-2026-10-18.json)
completed 40 measurements and 16 warmups, all CPU-audited. Median elapsed times
on the desktop RTX 5080 were:

| Extension | Input rows | Four binary folds | One arity-16 fold |
|---|---:|---:|---:|
| Quadratic | 65,536 | 0.194 ms | 0.072 ms |
| Quadratic | 262,144 | 0.300 ms | 0.072 ms |
| Cubic | 65,536 | 0.354 ms | 0.074 ms |
| Cubic | 262,144 | 0.340 ms | 0.077 ms |

The fused path issued one kernel command instead of four; both arms issued zero
uploads/downloads within timing. These small debug-host measurements include
submission and allocation overhead and do not qualify a production setting
change or establish whole-proof speedups.

The [native FRI protocol qualification](evidence/cuda-fri-protocol-2026-10-18.json)
adds round scheduling, cap observation, commit PoW, resident beta sampling,
lower-height input mixing, resident final-coefficient absorption, arity binding,
query PoW/index sampling and assembly into the existing Plonky3 proof type.
Original input queries come from retained CUDA hidden commitments. The protocol
requires the reduced-height set to match the original commitments and includes
their salted MMCS openings in every query proof. Host work schedules public
geometry and serializes bounded proof outputs; intermediate polynomials and
challenge arithmetic remain on CUDA.

An aggregate host plan covers raw query batches, reconstruction staging,
typed proof arrays and their coexistence. Individual device stages retain
their allocation preflights. A complete protocol attempt owns transcript and
randomness retirement guards for every input and FRI salt stream. Public shape
and aggregate-host admission failures preserve those states. Failures after
entering the protocol attempt retire all participating families and release
intermediate storage.

Independent CPU verification accepts synthetic hidden-input FRI proofs using
the wallet parameters (96 queries, arity up to 16) and the existing cubic
recursive parameters (128 queries, binary folding), both with blowup 16,
16-bit query PoW, cap height 6 and four random codewords. Additional test-only
settings cover all arities, nonconstant final polynomials and commit PoW.
Five zero-PoW cases match upstream Postcard proof bytes exactly. Tampering with
original values, salts, siblings, arities, final coefficients or opening claims
is rejected. A zero-polynomial case exercises no fold layers and duplicate
authenticated queries. Invalid parameters, missing original heights, aggregate
host rejection, downstream errors and unwinds are also tested.
All 38 checks passed: 120 native tests, 119 under each CUDA sanitizer, 17 FRI
tests with `stream`, and the existing CPU/OpenCL/Metal build and regression
checks. Source hashes for all 771 files matched the staged commit. Execution
remains qualified only on the desktop RTX 5080; V100, multiple-device ownership
rejection and Metal execution still require their own hardware checks.

These are complete FRI proofs over synthetic committed inputs, not complete
wallet or recursive STARK proofs. The native hiding PCS opening wrapper,
remaining proof stages and backend/worker integration are still unfinished;
no complete-prover speedup or transaction-throughput result is claimed.

The [hiding PCS opening qualification](evidence/cuda-pcs-openings-2026-10-18.json)
connects native hidden commitments to complete PCS opening proofs. Each matrix
is evaluated once into a scoped retained opening. All claimed values, including
masking columns, are observed on CUDA before alpha is sampled. CUDA reductions
then feed authenticated FRI; bounded proof egress separates public values from
the masking suffix using the existing hiding PCS format. Public preprocessing
uses the upstream round index and has no masking suffix.

Admission includes all captured points/evaluations, reduction accumulators and
scratch, and aggregate host storage for both opened values and the FRI proof.
Invalid public shapes and insufficient admission leave transcript and RNG state
untouched. Failures after execution begins retire every original randomness/salt
family, FRI salts and transcript snapshots. Retained openings cannot be consumed
after their source family retires, and intermediate allocations are released.

Six new tests use four commitment rounds, eight matrices at three LDE heights,
four quotient chunks, offset/repeated opening points and both public/private
preprocessing. Unchanged CPU PCS verification accepts quadratic and cubic
proofs with production FRI parameters. Four zero-PoW cases match upstream proof
bytes exactly; tampered masking values/shapes, authenticated rows and public
claims are rejected. Tests also cover host boundaries, device pressure, invalid
points, failed consumers and unwinds. All 40 qualification checks passed:
126 native tests, 125 under each sanitizer, and 35 PCS/opening/FRI tests with
`stream`, alongside CPU/OpenCL/Metal build and regression checks. All 774 source
files match the staged source.

This checkpoint opens existing native commitments. The separate STARK
randomization-polynomial commitment, remaining proof stages, complete
PCS/backend wiring, execution receipts and worker integration still need
implementation. It does not qualify full wallet/recursive STARK proving or
establish transaction throughput. CUDA execution remains qualified only on the
desktop RTX 5080.

The [randomization commitment qualification](evidence/cuda-randomization-2026-10-18.json)
adds the separate STARK randomization-polynomial commitment. Native ChaCha20
produces `extension degree + 4` base-field columns on the requested input coset.
Bounded column tiles interpolate those evaluations and extend them to the
commitment coset without trace row interleaving or another hiding draw. The
existing streamed commitment path retains the original-degree prefix, Merkle
nodes and salt recipes. The source randomness and commitment salts participate
in the same failure retirement guards as trace and quotient commitments.

Direct comparisons cover quadratic and cubic profiles, three input heights,
coset shifts 1, 7 and 13, partial column tiles, and continued RNG/salt cursors
across successive batches. Tiles and caps match the unchanged CPU PCS. Resource
and geometry rejection preserve the RNG cursor; errors and unwinds release
scratch and retire affected source/salt families. The six complete PCS opening
tests now use actual randomization polynomials in round zero, alongside trace,
quotient and preprocessing commitments. Production-parameter proofs still pass
CPU verification, and all four deterministic zero-PoW proofs match upstream
encoding. All 41 checks passed: 129 native tests, 128 under each sanitizer,
38 tests with `stream`, and existing cross-backend checks. All 776 source files
match the staged source.

At that checkpoint, complete STARK orchestration, remaining witness/public/lookup
operations, execution receipts, backend selection and worker/pool integration
remained unfinished. The single-AIR integration below preserves the upstream
trace, quotient and randomization commitment/transcript order. No end-to-end
CUDA performance or transaction-throughput result is claimed.

The [single-AIR STARK qualification](evidence/cuda-stark-2026-10-18.json) covers
native orchestration with a bounded public AIR program, optional periodic columns
and a shape-bound quotient handle. Proving accepts resident
trace and public-value buffers. Hiding, trace commitments, quotient evaluation,
quotient commitments, randomization commitments, challenge sampling and complete
PCS openings execute on CUDA. Opening rounds follow the upstream random, trace,
quotient order and assemble the unchanged `p3-uni-stark` proof type. Public AIR
compilation, proof assembly and independent verification remain host work.

Periodic tables use the allocation-free borrowed-source interface shared with
OpenCL. Their geometry is admitted before filling staging storage; expansion
and interpolation execute on CUDA. The retained trace commitment supplies
unmasked quotient inputs through a guarded CUDA column copy. Private prefixes
do not escape as independently reusable aliases. Header and shape failures
preserve input state. Later errors and unwinds retire all three randomness
families and the fresh transcript, and release intermediate device storage.
Caps and assembly metadata have a separate host allowance within the request's
proof-output limit; whole-request worker accounting remains outstanding.

Qualification includes production-parameter quadratic and cubic proofs, six
deterministic full-proof encoding comparisons covering periodic/next-row modes,
and real JoinSplit/HTLC proofs accepted by the production CPU verifier. Tampered
public inputs, openings and degree metadata are rejected. Failure checks cover
trace, quotient and PCS boundaries, a real late PCS output-budget rejection,
unwinds, invalid witnesses and reuse of public preparation with fresh randomness.
All 43 checks passed: 138 native tests, 137 under each CUDA sanitizer, 47 with
`stream`, and the CPU/OpenCL/Metal/standalone-CUDA build and regression checks.
The OpenCL device regression also covers periodic expansion and wallet batch
generation. All 782 source pins match the staged Git blobs. The first OpenCL
build exposed two fields whose visibility needed to move with the shared
periodic geometry; that failure is preserved, and the final qualification
reruns all checks on the corrected source.

This single-AIR interface rejects preprocessed commitments and lookup/permutation
layouts. At this checkpoint, wallet witness/public generation, recursive
batch/lookup orchestration, execution receipts, backend selection and worker/pool
integration remained outstanding. No full-request GPU coverage or transaction
throughput is claimed.

[Native wallet generation](evidence/cuda-wallet-2026-10-18.json) shares raw input
encoding, AIR-owned geometry and integer kernel bodies with OpenCL. A CUDA adapter
compiles those bodies against the native Goldilocks and Poseidon2 operations.
Three completed kernels write
trace regions, accumulator columns, and the public statement/validity result.
Only the raw packet and layout metadata are uploaded; generation downloads one
8-byte validity word. The resulting trace and public values stay resident and
feed native STARK proving without a CPU trace builder.

The shared plan admits all five device allocations before packing private
inputs. Host staging retains its exact-capacity allowance and scrubbing guard;
device scratch and unsuccessful outputs are scrubbed and released on drop.
CPU-required policy rejection and insufficient host, allocation-size or
allocation-count allowances issue no wallet work. The existing stage ledger
now accepts `cuda` observations with actual completion-event timings. Witness
generation reports two witness calls and one public-value call under operation
scope. Wall-clock envelopes, missing/lost/overflowed observations and partial
component reports cannot establish complete GPU-required coverage.

Independent CPU oracles cover JoinSplit range/field boundaries and minting,
plus plain HTLC, redeem, refund and timeout boundaries. Sixteen invalid witness
cases exercise asset/path/conservation/range/mode/ownership/timeout/mint checks.
Three full native proofs, from raw JoinSplit, HTLC redeem and HTLC refund inputs,
pass the unchanged production CPU verifier and reject altered public statements.
All 49 qualification checks passed: 142 native tests, 141 under each CUDA
sanitizer, 72 with `stream`, and the CPU/OpenCL/Metal/standalone-CUDA build and
regression checks. All 789 source pins match the staged Git blobs. The streaming
host-report suite has one extra test; its 21 passing tests were rerun after
correcting the controller's expected count. The successful streaming GPU checks
were preserved. The first streaming service's memory peak was not captured
because that count assertion preceded the controller's resource finalizer.

At that checkpoint, only witness/public generation had operation receipts;
complete wallet request coverage was still pending.

[Attempt-bound wallet reports](evidence/cuda-reporting-2026-10-18.json) bind
actual native kernel completions to their requests. The runtime binds a ledger
while its queue is quiescent, checks the
submitting thread, and captures a stage ticket for each admitted launch. Only an
observed CUDA completion event can complete that ticket. Unlabelled kernels,
unadmitted stages, abandoned completions and escaping pending work fail the
attempt. Completed partial receipts survive errors and unwinds. An abandoned
command retires its runtime, and an old completion cannot satisfy another run.

An internal typed wallet API prepares the fixed JoinSplit or HTLC AIR once and
proves raw witnesses with fresh mask, commitment and FRI randomness. It returns
the unchanged proof format, bounded public statement and a finalized report for
all fourteen required wallet stages. Public preparation remains outside the
private proof attempt; single-wallet proofs have no lookup or preprocessed
commitment. Final-polynomial extraction and interpolation use the same loaded
CUDA functions with their correct stage attribution. Existing standalone wallet
operation reports continue to work without duplicating encompassing receipts.

All fifty qualification checks passed: 152 native tests, 151 under each CUDA
sanitizer, 82 streaming tests, CPU/OpenCL/standalone-CUDA checks and Metal
cross-compilation. All 794 source pins match the staged source blobs.

The [release wallet benchmark](evidence/cuda-wallet-benchmark-2026-10-18.json)
ran after source commit `7f8489f` was pushed. All 36 proofs passed independent CPU
verification. With four Rayon threads and a four-core CPU quota, five measured
pairs per case gave median CPU/CUDA times of 929/94 ms for JoinSplit, 1,009/98 ms
for HTLC redeem and 1,000/112 ms for HTLC refund. The resulting latency ratios
are 9.85, 10.28 and 8.94. These are raw-witness-to-serialized-wallet-proof
measurements on the Ryzen 9 9950X3D2 and desktop RTX 5080. Existing compiler and
driver caches were retained, desktop GPU clients were present, and public
preparation took 342 ms separately from the repeated requests. The comparison
does not establish recursive aggregation or complete-block throughput.

[Native LogUp witnesses](evidence/cuda-lookup-2026-10-19.json) add bounded
quadratic and cubic lookup generation. The prepared program belongs to its
runtime and charges retained vector capacities to the existing public-program
allowance. Generation admits the output, scan levels, terminal and tile scratch
before private work. Resident public values and challenges are counted once;
OpenCL retains its existing uploaded-input accounting.

CPU differential tests cover both physical row orders, current/next rows,
preprocessing, public values, signed multiplicities, empty entries and heights
through 32,768. Partial-block inversion and scan tests check suffix and parent
guards. Active zero denominators reject; zero multiplicity bypasses inversion.
A resident transcript-to-lookup-to-transcript test checks the next challenge
against the unchanged CPU reference, with complete component-stage receipts
and no intermediate polynomial readback. This is a prerequisite component for
recursive proving; it does not implement recursive batch-STARK orchestration.

All 53 qualification checks passed: 162 native tests, 161 under each CUDA
sanitizer, 92 streaming tests, the OpenCL lookup comparisons and planner checks,
CPU/OpenCL/standalone-CUDA checks and Metal cross-compilation. All 802 source
pins match the staged Git blobs. The exact test and release executables are
retained with the ignored raw evidence. V100 execution remains untested.

The [post-push wallet regression screen](evidence/cuda-wallet-benchmark-2026-10-19.json)
at `cf24fed` verified all 36 proofs on CPU. Five measured pairs per case gave
median CPU/CUDA times of 933/94 ms for JoinSplit, 990/98 ms for HTLC redeem and
996/98 ms for HTLC refund, using four CPU threads and the desktop RTX 5080.
Public preparation took 247 ms separately. These single-wallet proofs contain
no lookup or recursive stage, so this screen does not measure the new lookup
component or recursive transaction throughput.

[Native recursive-machine witnesses](evidence/cuda-witness-2026-10-19.json)
reuse the existing bounded program compiler and shared OpenCL execution kernels.
Preparation uploads immutable metadata once and retains only the compact launch
schedule, charged to the runtime's public-program allowance. Each invocation
admits its trace, wires, input/status storage and public output before private
transfers. All thirteen existing opcodes and preprocessing rows match the CPU
AIR across empty, padded, branching and dependent-hash programs. Failed
execution checks release private storage and permit fresh valid attempts.

The generated main trace, preprocessing and public values feed native LogUp
without intermediate readback; only the two eight-byte status flags return
before the independent CPU audit. All seventeen qualification checks passed:
168 native tests, all six new witness tests under each sanitizer, twelve
streaming witness/compiler tests, the affected OpenCL comparisons and
CPU/OpenCL/Metal/standalone-CUDA build checks. All 806 source pins match the
staged Git blobs. These are component correctness results; complete recursive
proof orchestration and performance qualification remain unfinished.

[Native machine batch proofs](evidence/cuda-batch-stark-2026-10-19.json) now
consume raw public/witness packets for one or more immutable `MachineAir`
programs. CUDA generates the witnesses, preprocessing, lookup challenges and
traces, quotient polynomials, commitments, openings and FRI proof. Main and
lookup witness rows are released once their committed prefixes suffice.
Structural transcript integers use the cubic extension encoding; all instances
share one sampled lookup challenge pair and the existing deterministic bus map.
Opening rounds retain the upstream random/main/quotient/preprocessing/permutation
order. Proof parameters and the wire format are unchanged.

Independent CPU setup reconstructs the preprocessing root from each program.
The unchanged CPU batch verifier accepts single and mixed-height native proofs;
the application's existing registered verifier also accepts single-instance
Postcard artifacts with the independently authenticated cap. These fixtures
execute arithmetic and Poseidon2 machine programs, not recursive verifier
programs. Tampered statements, permutation/preprocessing openings, terminals
and instance order are rejected. An operation report records all sixteen CUDA
arithmetic stages without invoking the CPU witness oracle.

The quotient bridge admits main, preprocessing and extension-valued permutation
prefix extractions together and keeps every commitment's randomness guard active
until evaluation finishes. At this initial checkpoint, injected failures/unwinds
retired all participating families and released temporary allocations; failed
attempts required fresh public preparation. The reusable public lifetime is
qualified below. The interface admits at most eight machine instances, also
bounded by the existing 256-matrix PCS and runtime resource limits. Complete
request admission remains future integration work.

All 175 native CUDA tests passed. Each of the seven new batch/quotient integration
tests also passed under memcheck, racecheck and synccheck, and with the `stream`
feature. CPU/OpenCL/standalone-CUDA checks, Metal cross-compilation and affected
OpenCL regressions passed. The qualification pins 810 source files to staged Git
blobs and preserves the tested executables. This is correctness evidence; test
durations do not establish native recursive throughput.

Public request routing, batch wallet traces, production wrapper/merge execution,
whole-request admission and worker/pool integration remain unfinished. The
opt-in CPU/CUDA benchmark measures raw witness to serialized wallet proof, with
independent CPU verification outside timing; it does not measure recursive
aggregation, block processing or distributed transaction throughput.

The [real-recursion qualification](evidence/cuda-recursion-2026-10-19.json)
generates a fresh context-bound cubic JoinSplit proof on CUDA, compiles its
existing verifier, and proves that verifier with the native machine batch engine.
The program has 171,669 active rows in a 262,144-row domain. The inner and outer
operations record all fourteen and sixteen required CUDA arithmetic stages,
respectively, without invoking the CPU witness oracle. Only final proof artifacts
and public statements cross into the independent audit process. That process
rebuilds the public preprocessing cap on CPU and uses the unchanged registered
CPU verifier. It also rejects altered inner proofs, public inputs and outer proofs.
This is a single recursive verifier proof, not the production block aggregation
workflow or a transaction-throughput measurement.
Five fresh outer proofs passed separate CPU audits, covering normal, memory-
checked, synchronization-checked, stream-feature and release runs. Memory checking
reported zero errors and leaks; synchronization checking reported zero errors.
Peak managed device storage was 6.92 GiB. Three executables and 821 source hashes
are preserved in the evidence.
Full-size race instrumentation was interrupted during preparation and remains
unqualified; its partial log is retained alongside the completed checks.

The [post-push release benchmark at `830a6eb`](evidence/cuda-recursion-benchmark-2026-10-19.json)
completed one warmup and three measured runs, followed by independent CPU audits
of all four artifacts. Median outer proving time was 4.790 seconds (range
4.789–4.791); public preparation took 0.597 seconds separately. Each run uses a
fresh process and private randomness. The proving timer covers raw serialized
inner-proof witness inputs through native `BatchProof` construction; it excludes
module startup, inner proof generation, public program compilation/preparation,
final Postcard serialization and independent CPU verification. No CPU/OpenCL
proving comparison, production aggregation throughput or transaction rate is
inferred from these single-verifier samples.

The full-size `cuda_compute::batch_stark::recursive_tests::` tests are deliberately
excluded from the small correctness suite. Set `LATTICA_CUDA_RECURSIVE_ARTIFACTS`
to a fresh absolute directory and run `cuda_recursive_wallet_produces_native_outer_proof`
with `--exact --ignored --test-threads=1 --nocapture` in the bounded 3 GiB GPU
service. Its managed/device-allocation limits are 7 GiB/1 GiB, with the existing
4 GiB context reserve and 1 GiB headroom. Then run
`cuda_recursive_wallet_artifacts_pass_independent_cpu_audit` from a release build
against the same directory in a separate 24 GiB CPU service. Both tests require
their full module path with `--exact`. Use four Rayon threads and zero swap in
both services. Archive the executables, artifacts and logs together; a successful
producer alone does not authenticate its preprocessing cap or qualify its proof.

The [public preprocessing qualification](evidence/cuda-public-preprocessing-2026-10-19.json)
separates the lifetime of deterministic public salts from private proof
randomness. Public recipes share their resident public key and retain immutable
stream boundaries. Each materialization or query obtains two bounded temporary
RNG state slots and an independent failure flag, without uploading another key
or advancing or locking the original cursor. Private replay recipes keep their
shared retirement behavior. Runtime failure still rejects public reuse.
The commitment interface accepts only sealed machine preprocessing traces;
callers cannot turn arbitrary private seeds or recipes into reusable public salts.
Host metadata admission charges the added representation and temporary leases
within the existing limits. This enables retries with the same prepared handle
and fresh private streams; authenticated registered requests, whole-request
admission, cache reporting and worker integration remain unfinished.

All 177 native CUDA tests passed. The 25 affected replay, hiding and batch tests
also passed under memory, race and synchronization checking, and with the
`stream` feature. A fresh real recursive wallet-verifier proof passed independent
CPU reconstruction and registered verification, including rejection of altered
proofs and public inputs. The qualification pins 823 source files and preserves
the debug, stream and release executables plus the unchanged CPU reference.
Full-size recursive race instrumentation remains incomplete; the focused
sanitizer results cover their recorded smaller shapes.

The [post-push release benchmark at `0deed40`](evidence/cuda-public-preprocessing-benchmark-2026-10-19.json)
completed one warmup and three measured proofs, all independently CPU-audited.
Median outer proving time was 4.821 seconds (range 4.821–4.825); public preparation
took 0.592 seconds separately. These fresh-process, single-verifier samples do
not measure retry savings or persistent-worker throughput, and include no paired
baseline from which to infer a speedup or regression.

The [registered-interface qualification](evidence/cuda-registered-2026-10-19.json)
adds a runtime-bound machine handle that checks the approved cubic profile,
height, public/witness input counts and preprocessing cap. Only authenticated
preparation with complete CUDA receipts can produce the handle. Each proof
attempt imports fresh private seeds after checking input encoding and known host
payloads. Setup and proof inventories are checked against their exact component
scope, profile and stage list; even compatible policy cannot return a partially
reported native result. The handle retains public preprocessing and provenance,
and charges its additional host metadata within the existing runtime allowance.

Cached setup can be attached to an enclosing request without inventing new
device work. It cannot replace missing fresh stages or required child components,
and a failed runtime cannot supply a cached success. At that checkpoint,
source/program construction admission, whole-request device planning, production
wrapper/merge requests, public dispatch and worker/pool routing remained
unfinished. It did not change the existing CPU/OpenCL worker routes.

All 183 native tests passed in debug and release builds. The 20 affected
registered, batch and runtime-reporting tests also passed under memory, race and
synchronization checking and with the `stream` feature; 20 host reporting tests
passed in both builds. The full-size registered fixture authenticates its
262,144-row wallet-verifier program against a cap from the earlier independent
CPU qualification before proving. Its five-stage setup and fifteen-stage proof
reports compose into sixteen distinct CUDA stages. A separate CPU audit rebuilds
the cap and verifies the new inner/outer artifacts, including tampering checks.
The evidence distinguishes the earlier sanitizer build from the final 826-file
source manifest; only exports and the additional full-size test changed between
those builds. Full-size recursive race checking is still incomplete.

Run `cuda_compute::batch_stark::recursive_tests::registered::cuda_recursive_registered_wallet_produces_authenticated_outer_proof`
with `--exact --ignored --test-threads=1 --nocapture` in the same bounded GPU
service. Its fresh `LATTICA_CUDA_RECURSIVE_ARTIFACTS` directory must already contain
`approved-cap.postcard` from a successful independent CPU preprocessing audit of
this program. Afterward, run the existing CPU artifact-audit test against the new
outputs; the approved program cap alone does not authenticate the new proof.

The [post-push registered benchmark at `c28140d`](evidence/cuda-registered-benchmark-2026-10-19.json)
completed one warmup and three measurements, with independent CPU audits of all
four proofs. Median registered proving time was 4.814 seconds (range 4.810–4.817);
approved public preparation took 0.591 seconds separately. This timer includes
fresh private-seed import and report finalization, which earlier raw-engine
timers excluded. It measures one registered wallet-verifier program per fresh
process, without a paired baseline, production aggregation or transaction rate.

The [request-admission qualification](evidence/cuda-request-admission-2026-10-19.json)
adds a pure allocation schedule for the complete registered cubic proof, from
witness generation through FRI query egress. It reuses component planners and
models retained prefixes, trees, folded vectors and scratch separately. The
registered entry point checks the schedule under its runtime submission scope
before importing any private seeds. Runtime allocation and RNG-slot accounting
now also reject foreign threads before changing their reservations.

The full-size 262,144-row fixture predicts and measures exactly 7,430,812,728
managed bytes and 99 live allocations at peak, within the existing 7 GiB managed
and 1 GiB individual-allocation limits. Initial commitment queries are the
largest byte peak because all FRI layers remain retained. Returned admission
reports list each phase, known host payloads and required RNG slots. Shared
source-capacity accounting includes spare and nested allocations; OpenCL uses
the same helper.

All 184 native tests passed in debug and release, including planned-versus-actual
peaks for single and mixed-height proofs. Tests reject insufficient managed,
individual-allocation, allocation-count, host and RNG-slot allowances before
private work, preserve preparation, and check the exact host boundary. Twenty
focused tests passed memcheck, racecheck, synccheck and `stream`; twenty host
reporting tests passed in both builds. The CPU-only source test and seventeen
OpenCL resource tests also passed. All GPU qualification builds use the same
830-file source manifest. The unchanged independent CPU auditor rebuilt the
preprocessing cap, accepted the new full-size registered proof, and rejected
altered inner proofs, outer proofs and public values.

This admits a registered proof using already prepared public data. Source
construction before the API call and complete process-RSS accounting still
belong to the caller/controller. Production wrapper/merge requests, public
dispatch and worker/pool routing remain unfinished. Focused sanitizer coverage
does not qualify full-size recursive instrumentation. No proof format, security
parameter or production backend selection changes.

The [post-push benchmark at `3cc135f`](evidence/cuda-request-admission-benchmark-2026-10-19.json)
completed one warmup and three measured registered proofs. Median proving time,
including resource admission, seed import and report finalization, was 4.789
seconds (range 4.789–4.792); separate approved preparation took 0.593 seconds.
Every sample matched its predicted 7,430,812,728-byte and 99-allocation peaks,
and all four artifacts passed independent CPU audits. These are registered
single-wallet verifier timings, without a paired baseline or a production
transaction-throughput claim.

[Public-arithmetic qualification](evidence/cuda-public-arithmetic-2026-10-19.json)
adds native protocol hashing, summary validation, compiler constants and base/cubic
folding. Explicit statement/registry child APIs use the existing symbolic compiler
and bounded folding cache. CPU references confirm statement roots, registry
programs/witnesses, machine and wallet AIR fingerprints, lookup layouts, quotient
degrees and registration templates. Wrong component, run and thread assignments
reject before work. Public receipts cannot satisfy missing setup/proof components.

All 192 native tests passed in debug and release. Eleven focused tests passed
memcheck, racecheck, synccheck and the `stream` build; 34 host checks passed in both
builds. CPU-only and OpenCL builds each passed 12 statement tests. Metal
cross-compilation and standalone CUDA checks passed. All three CUDA executables
use the same 835-file source manifest, matched to staged Git blobs. The first
development run exposed two missing component-scope rejections; the corrected
guard passed every final check. At the exact resource boundary, public arithmetic
uses 33,552 managed bytes and three allocations, including its retained constants,
within a separate 64 KiB host workspace envelope. Caller-owned source/input/output
storage still needs separate admission. Periodic execution was checked through
4,096 values; the 65,536-value admission ceiling was not exercised here.

Production wrapper/merge proving, typed-session cache integration, public dispatch
and worker/pool routing remain unfinished. This checkpoint does not qualify a
complete recursive request or a transaction-throughput rate.

The [post-push public-component benchmark at `74becfa`](evidence/cuda-public-arithmetic-benchmark-2026-10-19.json)
completed one warmup and three release measurements per case, all checked against
CPU references. Deriving and validating a level-five empty statement took a
median 1.413 ms (1.395–1.422 ms). Compiling an empty program with a 12-key,
2,048-height registry prefix took 119.470 ms (119.410–119.588 ms). The context's
initial preparation took 95.554 ms separately. These public fixtures use zero
registry caps and produce no proof or registry approval. No complete aggregation
rate or CPU/OpenCL speedup is inferred from these component timings.

## Implementation sequence

The [V100 results](../lattica-prover-p3/scripts/v100-specialized-benchmark/README.txt)
support keeping the wider query batches as the starting point. The planner now
prefers 2 GiB plus 64 KiB of scratch, enough for sixteen columns in the tall
transform case, and reduces the batch when the remaining memory or allocation
limit is smaller. This is a preference within admission, not a new minimum.

| Evidence | Recorded result | Consequence for CUDA |
|---|---|---|
| V100 query batching, three alternating pairs | Median aggregation 57.545 to 52.499 seconds; 9.61% higher aggregated-input throughput | Port the current query planner and its sixteen-column geometry first. |
| V100 query reconstruction in that comparison | 7.902 to 2.931 seconds; 1,416 to 123 tile readbacks | Preserve device-resident prefixes and reduce repeated transforms and transfers. |
| V100 combined optional candidates, five pairs on earlier source | 57.697 to 64.822 seconds; 12.35% slower | Qualify each optimization separately for each architecture. |
| RTX 5080 typed comparison on `152adf1`, five pairs per candidate | Events reduced median aggregation time 2.13%; cooperative commitments increased it 27.05%; all candidates increased it 24.42% | Investigate submission overhead, and retain the existing hash layout as the initial CUDA implementation. |

The V100 four-input case creates three recursive proofs from four JoinSplit
proofs. The RTX typed case creates four recursive proofs for three user
transactions and one issuance entry. Their timings are separate workloads and
do not establish a hardware speed ratio. The V100 numbers above are recorded
in the pulled documentation; its raw machine-local results are not included in
Git. The RTX results and audit logs are retained locally under
`lattica-prover-p3/benchmark-results/gpu-tuning-20261018-runtime`.

The old RTX baseline's median sums of device event durations were approximately
7.06 seconds for transforms, 5.70 seconds for commitments, and 2.45 seconds for
quotients. A representative root issued 25,652 witness commands, 8,288 quotient
commands, and 5,144 lookup commands. These are profiling signals from the old
source, not a decomposition of elapsed time. Reprofile the newly pulled source
before choosing fusion boundaries or setting speedup expectations.

1. **Establish the baseline and strengthen the qualification tests.**

   Rebuild the current OpenCL prover and independently verify fresh proofs on
   each target GPU. Retain the three host query-planner checks that passed
   after this pull, then run the GPU reconstruction oracle and constrained
   memory cases. Add guard words to the event-batch test and recheck enqueue
   failures, missing timestamps, and unwind cleanup. Its original
   `MatrixSpec::new(1, 1, ...)` reserves two words because the first argument is
   a logarithmic row count; the V100 note describing a one-word allocation was
   mistaken. Explicit guards will test writes beyond the two-word result.

   Pin the fixture, profile, source, executable, driver, device UUID, clocks,
   budgets, and environment. Capture cold initialization and compilation
   separately from warm aggregation. Preserve both the V100 container workload
   and the typed worker workload as separately named cases. The V100 harness's
   28 GiB free-VRAM admission cannot be copied to a 16 GiB RTX 5080.

   **Exit evidence:** CPU-verified OpenCL baselines at this commit, valid test
   buffers, and a stage/launch/transfer profile for every selected workload.

2. **Add CUDA as an explicit backend with complete resource ownership.**

   Add `gpu-cuda` and a `cuda_compute` module. Keep `gpu` selecting OpenCL for
   existing builds and keep Metal independent. Introduce a small typed backend
   interface for contexts, device allocations, streams, events, modules, and
   launches at the current `block_v2::compute` boundary. Separate shared
   scheduling from direct `ocl` calls. Audit feature gates throughout the
   native entry points, wallet worker, recursive PCS, compiler, and reporting;
   adding a third alias alone will not make those paths available.

   Use Rust ownership around the CUDA Driver API, with a pinned binding version
   and a narrow unsafe boundary. Start with one retained context, one compute
   stream, and one worker process per GPU. Select devices by UUID and PCI
   identity, and reuse the existing GPU leases. Preserve allocation admission,
   host staging limits, per-attempt ownership, cancellation, draining, and
   private-buffer erasure before reuse. Account retained allocator capacity,
   events, graph state, modules, compiler scratch, and driver/context memory;
   live tensor bytes alone are insufficient.

   Extend `proving::Backend` with `Cuda`, its serialized reports, GPU-required
   policy, stage observers, native initialization, inventory, and controller
   validators. An accepted CUDA proof must report CUDA execution for all
   required arithmetic stages. Preserve the existing public lifecycle ABI.

   Pin CUDA **12.9.1** initially and compile explicit `sm_70` and `sm_120`
   variants. NVIDIA's [12.9.1 NVRTC target list](https://docs.nvidia.com/cuda/archive/12.9.1/nvrtc/index.html#supported-compile-options)
   includes both; [CUDA 13 removed Volta offline compilation and library support](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-toolkit-release-notes/#deprecated-architectures).
   Verify compiler targets and driver compatibility with a compile/load/launch
   smoke test on both devices. This host has the CUDA driver library, but
   `nvcc`, `nsys`, and `ncu` were not found on PATH or in the inspected CUDA
   locations. Install a pinned development toolchain as an implementation step.

   **Exit evidence:** allocation, copy, launch, event, teardown, and injected
   failure tests on both GPUs; CPU-only, OpenCL, and Metal builds remain valid.

3. **Port exact field arithmetic, transforms, and query reconstruction.**

   Implement Goldilocks arithmetic over `2^64 - 2^32 + 1`, including canonical
   and supported noncanonical inputs, and the existing quadratic and cubic
   extension operations. Use exact integer multiplication and carry reduction,
   including CUDA high-half multiplication where useful. Test boundaries and
   randomized inputs against the CPU implementation before optimizing PTX.

   Port the existing tiled NTT, inverse NTT, coset scaling, bit-reversed storage,
   cached twiddles, prefix reconstruction, and query gathering. Preserve the
   new query scratch accounting and exact sixteen-column boundary. Tune
   workgroup size, columns per block, shared memory, and register use against
   actual matrix shapes. Consider asynchronous global-to-shared copies only
   on architectures that support them, with a separately tuned V100 path.
   Keep outputs on the device between stages. These operations require exact
   finite-field transforms; floating-point FFT kernels do not implement them.

   **Exit evidence:** independent CPU DFT comparisons, both row orders, forward
   and inverse transforms, extension widths, zero padding, repeated queries,
   allocation-boundary tests, and preserved query order and duplicates.

4. **Port commitments and generate CUDA quotient kernels from the existing IR.**

   Port the established Poseidon2 permutation, leaf absorption, Merkle
   compression, and retained paths first. Measure state layouts separately:
   the eight-lane commitment candidate already regressed on both measured
   devices. Explore fusion of compatible transform, normalization, and hashing
   passes only when profiling shows reduced total traffic and elapsed time.

   Reuse validated public AIR bytecode and liveness analysis to emit CUDA
   quotient code. Start with the current bounded 64-instruction blocks, then
   measure block boundaries, register count, spills, occupancy, and scratch
   traffic. Preserve instruction/source-size limits and generic GPU execution
   for shapes outside specialization. Keep a CUDA-only policy fail-closed if
   no correct CUDA implementation exists for a required operation.

   Compile stable kernels ahead of time. Compile public program specializations
   during worker preparation with NVRTC and cache them by program/profile hash,
   code-generator version, compiler options, toolkit, and SM target; bind timing
   qualification to the driver and executable as well. Bound both cache size
   and compilation resources. Cache public code and constants only. The V100
   report's 119.324-second first specialization makes cold preparation worth
   measuring explicitly.

   **Exit evidence:** CPU oracles for hashing and quotient evaluation, valid
   specialized and generic CUDA paths, cache invalidation tests, and measured
   compilation/resource limits.

5. **Complete wallet and recursive proving across all sixteen stages.**

   Port public values, witness traces, preprocessing, lookup evaluation and
   batch inversion, randomness, hiding, openings, FRI folding and queries,
   final polynomial work, scalars, transcript updates, and grinding. Integrate
   the transform, quotient, and commitment implementations from the preceding
   steps. Cover both legacy quadratic wallet proofs and cubic recursive block
   proofs, including the existing JoinSplit and HTLC operations.

   Preserve the current randomness construction, transcript order, hiding
   parameters, domains, and proof encoding. Use controlled randomness only in
   differential tests; production attempts must obtain fresh randomness.
   Host scheduling, public program compilation, serialization, and independent
   verification may remain on CPU. GPU-required arithmetic must have actual
   CUDA execution receipts. A partial GPU path must not be reported as a
   complete CUDA prover.

   **Exit evidence:** fresh wallet and recursive proofs accepted by the
   unchanged CPU verifier, complete stage reports, and rejection of altered
   proofs, missing stages, CPU fallback, and invalid witnesses.

6. **Reduce submission and memory overhead after correctness parity.**

   Reuse kernel handles, public program modules, admitted scratch arenas, and
   bounded event pools across jobs. Profile launch gaps before introducing
   CUDA Graphs for repeated witness waves, lookup sequences, and tiled
   quotient/opening operations. Graph replay must bind the current attempt's
   buffers and fresh randomness. Capture stable public shapes and split
   execution at transcript or host-control boundaries that require it.

   Retain timing and completion receipts for every stage. Start with one
   stream; overlap transfers or independent operations only where measured
   dependencies and memory allowance permit it. Inspect generated instructions,
   register spills, memory efficiency, and occupancy using profiler versions
   that support each GPU. Use separate profiler runs so instrumentation does
   not contaminate the paired throughput measurements. Charge cached and
   in-flight memory until completion, including failure and cancellation paths.

   **Exit evidence:** independently audited proofs with a measurable reduction
   in whole-job time, unchanged memory limits, and correct cleanup under
   injected asynchronous errors and cancellation.

7. **Connect CUDA workers to the existing pool and qualify concurrency.**

   Keep job payloads backend-independent: bind program/profile identity, input
   artifact hashes, dependencies, attempt identity, resource assignment, and
   output identity. Advertise CUDA support, compute capability, driver, binary
   identity, qualified shapes, and available memory through worker inventory.
   Retain existing lease, retry, recovery, and result-acceptance rules. A failed
   attempt must not cause duplicate accepted work or reuse private randomness.

   Schedule independent wallet and recursive DAG nodes across GPUs, beginning
   with one persistent worker per device. Measure additional workers per GPU
   as a separate experiment. On the dual-socket R740, bind worker CPUs and host
   staging allocations to the NUMA node serving each GPU where the topology
   allows. Exchange bounded proof artifacts between workers; raw device
   pointers and CUDA contexts stay local. Peer transfers or splitting one
   transform across GPUs remain later, separately measured options.

   **Exit evidence:** throughput and resource accounting for one and multiple
   devices, durable results after worker failure, and identical verification
   behavior through the existing host/node integration.

8. **Qualify the CUDA backend against current OpenCL before activation.**

   Compare CPU-verified CUDA and OpenCL runs built from the same source and
   proof profile. Warm each arm, then use at least five alternating pairs with
   fixed resource budgets per device. Run the common four-entry and eight-entry
   cases, full 64-entry and separately built 128-entry profiles, wallet proving,
   and complete block processing. Use matching fixtures and auditors for each
   capacity. Preserve the separate grouped V100 case as an additional screen.

   Report aggregation latency, cold preparation, user transactions per hour,
   aggregate inputs per hour, complete-block throughput, host/VRAM peaks,
   launches, transfer bytes, and board energy with explicit measurement
   boundaries. Keep issuance counts separate. Run device memory, race, and
   synchronization checks with supported tools, alongside arithmetic oracles,
   tamper tests, and resource/failure tests.

   Require correctness, full CUDA stage coverage, and valid admission for every
   accepted sample. Apply the existing performance rule per qualified
   device/workload: at least 2% lower median aggregation time and no measured
   workload median regression above 2%; repeat inconclusive comparisons. Keep
   architecture-specific choices opt-in until their full workload set passes.
   A speedup is a benchmark outcome, not an assumed consequence of the API port.

The first implementation increment should combine step 1 with the CUDA runtime
and exact arithmetic tests in steps 2–3. It produces an independently testable
backend foundation before expanding into proof generation. Subsequent changes
can add transforms/query reconstruction, commitments/quotients, complete proof
coverage, graph submission, and pool integration as separately reviewable commits.

The principal integration points are
[`Cargo.toml`](../lattica-prover-p3/Cargo.toml),
[`lib.rs`](../lattica-prover-p3/src/lib.rs),
[`block_v2::compute`](../lattica-prover-p3/src/block_v2/mod.rs),
[`gpu_hash::engine`](../lattica-prover-p3/src/block_v2/gpu_hash/engine.rs),
[`device/query.rs`](../lattica-prover-p3/src/block_v2/gpu_hash/engine/device/query.rs),
[`quotient/specialized.rs`](../lattica-prover-p3/src/block_v2/gpu_hash/engine/quotient/specialized.rs),
[`proving.rs`](../lattica-prover-p3/src/proving.rs),
[`native_public_gpu.rs`](../lattica-prover-p3/src/block_v2/native_public_gpu.rs),
and the existing typed worker controllers. The
[benchmarking guide](gpu-benchmarking.md) defines the existing evidence and
measurement conventions.
