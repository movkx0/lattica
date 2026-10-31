# Direct-spend research profiles

This isolated crate contains two explicitly different research profiles. It does
not change production transaction acceptance or generate an adoptable protocol.
Both fix two inputs, two outputs and 52-bit values. Neither permits unrestricted
splitting, minting or fees in this initial comparison.

| Profile | Implemented | Unfinished / qualification boundary |
| --- | --- | --- |
| `ring-direct-v1` | Direct host relation and an optional bounded constrained-program compiler: one hidden choice among ten ordered account pairs; ternary lattice secrets; exact original NTT/Montgomery equations; input/output commitment openings; integer ranges/balance; AES-derived public serial linkage | Default inline compiler refuses the fixed 256 MiB program allowance. Opt-in `fused-ternary-ranges-v1` compiles and evaluates the complete relation with the existing `2g`/`16m` profiles at 2^20 padded rows in the CPU profile (2^19 with the wide GPU profile). The opt-in `gpu-proving` feature implements fresh registered proving, independent public reconstruction and CPU verification, and a bounded artifact workflow. Complete GPU research screening, forged-envelope checks and a matched public-hash experiment passed. The seven-distinct-statement baseline screen passed with zero recursive aggregate proofs. Fixed N3/N4 aggregate source is implemented behind a separate disabled research feature and still requires source/runtime qualification. Security adoption review remains absent. The legacy host `ring::prove` still returns `IncompleteProofCoverage`. Host checks are **not** proofs. |
| `private-note-direct-v1` | Existing join-split AIR, unchanged: ownership, depth-32 authenticated membership, commitments, nullifiers, ranges and balance. Strict profile/context/canonical statement admission; fresh CPU and opt-in owned GPU research proving; independent CPU verification; bounded artifact round trip | Different keys, anonymity and ledger semantics. Seven-case owned workflows and three alternating matched CPU/GPU pairs were measured for the same note relation. No RingCT graph or aggregate, protocol-redesign comparison, or completed security adoption review. |

On RTX 5080, the opt-in `gpu-public-hash-experiment` build with
`LATTICA_V2_GPU_PUBLIC_HASH=sbox-pair-v1` passed three alternating matched
pairs of complete direct-ring research workflows. Median time fell from
207.82 s to 190.72 s (8.23%); all six fresh proofs passed independent CPU
verification, artifact round trips, mutation checks and terminal audits.
The public fixture, geometry and resource limits were identical, and the six
proof artifacts were distinct. The initial screening pair is excluded because
its baseline included first-session kernel compilation. Peak process memory
was 7,348,432,896 bytes with zero swap. This measures one research relation per
workflow with no recursive aggregate; faithful RingCT throughput and the
protocol redesign's speedup remain unqualified. The default kernel remains
`baseline`. See the [matched evidence](reports/public-hash-matched-20261025.json).

The separate [same-note CPU/GPU comparison](reports/same-note-cpu-gpu-matched-20261025.json)
contains three alternating matched seven-case pairs. Median complete note research
time was 6.886015426 s on CPU and 1.861837604 s on GPU (3.6985x). These are two
backends for the same private-note construction, with independent CPU verification,
artifact round trips and cleanup included. They do not establish a protocol-redesign
speedup against faithful RingCT. The CPU run-two outlier remains in the evidence.

A separate fused-partial-round hashing probe passed raw-arithmetic and CPU
parity checks but was slower in three alternating component repetitions:
2.006 s median versus 1.734 s for `sbox-pair-v1`. It remains an ignored test
and has no runtime selector. Its [rejected experiment evidence](reports/fused-partial-component-20261025.json)
is preserved; no complete-workflow speedup is claimed for this probe.

The ring compiler reuses the actual constrained arithmetic in
`pq-ringct::rust_verify::generic` and `ConstraintContext`; it bypasses the
delegating NTT/product hooks and emits inline constraints. It refuses any pending
cryptographic obligation. It never creates a MatRiCT spend proof or proves the
old MatRiCT verifier. The two differential host oracles are separately named and
cannot be passed to a proof verifier as evidence.

The candidate compiler representation is `inline-public-montgomery-constants-v2`.
Exact public/fixed constants use the existing canonical-from-bits gadget with
known Boolean constant wires. The preceding `inline-public-constant-bits-v1`
representation removed the initial public-constant bottleneck but still refused
the same program allowance during ownership constraints. Inspection found that
the underlying Montgomery helper recreated private-style canonical constraints
for each adjusted public factor, bypassing the folded public-constant path.

The isolated helper now uses that folded path for Montgomery factors too. Only
builder-known constants select it; actual private values cannot specialize the
program. Public zero and Montgomery identity preserve the private operand's
existing canonical input constraints. Other factors keep the unchanged checked
quotient/remainder equation, and private/private products keep both modular
reductions. Inverse Montgomery radices are computed at compile time for the two
unchanged moduli. Production arithmetic modules are unchanged. The candidate
passed 18 unit/relation tests and reduced wires and active rows in all eight
sampled Montgomery cases. One small case's requested builder peak increased by
1024 bytes; the full compiler still refused the unchanged 256 MiB allowance
during input ownership. It does not permit a ring proof or establish a workflow
speedup. See [validation](VALIDATION.md) for all measured cases, preserved
refusals and the scope of the component diagnostics.

## Public preprocessing and proof boundary

The MatRiCT serial gamma is public in the transaction statement. The exact
AES-256 counter stream and original bounded rejection sampler derive G(gamma).
The setup matrices are also public AES-derived data from the fixed setup seed.
The independent verifier implementation recomputes these values from the expected
public statement and rebuilds the registered program and preprocessing cap. It
does not accept a prover-supplied program, matrix, G value or digest as trusted
verification input. The program constrains
`selected_pk = NTT(sk[0..4]) + Mat1 * NTT(sk[4..8]) + G(gamma)` and the original
mint equations with ternary openings. A public canonical statement digest binds
the context, profile, setup seed, ordered ring, ordered recipients, output coins
and serials. This digest is a public identity, **not** a replacement for any
private relation constraint. The new GPU workflow remains gated on complete
phase admission and qualification. It does not change production acceptance.

The default compiler retains its historical 400 MiB logical reservation. The
user-authorized memory experiment adds three explicit profiles; they change only
the builder allowance, with no automatic escalation or retry.

| CLI memory profile | Builder allowance | Fixed witness + auxiliary | Whole compiler requirement |
| --- | ---: | ---: | ---: |
| `256m` (default) | 256 MiB | 128 MiB + 16 MiB | 400 MiB |
| `2g` | 2 GiB | 128 MiB + 16 MiB | 2192 MiB |
| `8g` | 8 GiB | 128 MiB + 16 MiB | 8336 MiB |
| `24g` | 24 GiB | 128 MiB + 16 MiB | 24720 MiB |

Only these selectors are accepted; there is no arbitrary numeric program limit.
The complete requirement must fit the caller's allowance and the unchanged
32 GiB worker host ceiling before compiler allocation. Every memory-only profile
retains the research limits of 2^24 wires, 2^24-4 input values and 2^24 padded rows.
These research row limits are separate from the faithful RingCT workflow's
stricter limits. Success and failure JSON includes the selected profile, every
limit, whole compiler requirement and supplied host allowance. Primitive
failures attach those limits centrally, and finalization distinguishes a row
refusal from a program-backing refusal. Counter snapshots before finalization
do not claim to measure the subsequent packing peak.

Every witness-producing generic primitive checks space before execution;
builder failure aborts immediately. These are logical backing limits, not RSS
measurements. The coordinator's separate `research-compile` process guard uses
16 GiB maximum / 14 GiB high memory, 20 GiB fresh available memory, two threads,
CPU-required execution and zero swap. The separate `research-compile-large`
guard for the `24g` experiment uses a 32 GiB cap, 30 GiB high limit and 36 GiB
fresh-memory admission, retaining two threads, CPU-required execution and zero
swap. These are explicit process guard choices, not automatic compiler retries.
The 8 GiB managed GPU / 4 GiB context /
32 GiB worker host / 24 GiB native / 47 GiB campaign process limits remain
unchanged. Compiler-only execution initializes no GPU. Compiler admission
does not authorize a proof allocation. The separately selected `gpu-proving`
feature requires a complete program-bound GPU admission token before setup. The new
memory-profile tests passed, but `2g` still refused program backing in ownership.
The separate `8g` screen reached input opening and then hit exactly 2^24 wires.
See [validation](VALIDATION.md) for exact counters and process peaks.

That measured wire refusal motivates a separate `--wire-profile 64m` experiment.
It uses the existing core ceiling of 2^26 wires without changing the shared
prover. The default wire selector remains `16m` for every memory profile and
legacy API. The 128 MiB witness, 2^24-4 input and 2^24 padded-row ceilings remain
fixed even with `64m`; memory requirements do not change. Both chosen selectors
are reported. There is no implicit wire increase or retry. The explicit `8g` +
`64m` screen passed 2^24 wires, then refused program backing during input opening
at 24912690 wires. No ring proof started. Its focused suite passed all 22 checks.
The separately selected `24g` profile retains all other limits and requires
24720 MiB in total, within the existing 32 GiB worker allowance. Its `64m`
screen reached the supported core ceiling of 67108864 wires during input opening
and refused further construction. It did not exhaust its program allowance, but
still produced no complete graph or ring proof. The final profile suite passed
all 22 checks. Further growth of this inline representation is blocked by the
existing core ceiling; that ceiling is not raised. These compiler experiments
establish neither proving speedup nor complete-workflow throughput.

Private-note artifacts use a fixed version tag and exact expected public inputs.
The unchanged AIR binds the research profile and context through `tx_binding`
observed by Fiat-Shamir. The wrapper independently rejects duplicate nullifiers,
noncanonical public fields/keys, nonzero fee/mint, and mismatched expected
statements. Ledger anchor authorization and spent-nullifier checks still belong
to the ledger; this research wrapper cannot establish them by itself.

## Reproducible checks

Builds and CPU/GPU validation must hold the coordinator's serialized validation
slot. Run from this directory using the campaign's pinned Rust 1.96 toolchain.

```sh
cargo test --features ring-circuit,native-reference -- --test-threads=1
cargo test --release --features ring-circuit,native-reference \
  note_real_proof_roundtrip_and_cryptographic_statement_mutations \
  -- --ignored --exact --nocapture --test-threads=1
cargo run --release --features ring-circuit -- ring-direct --compile
# Explicit larger-memory screen, under the coordinator's research-compile guard:
cargo run --release --features ring-circuit -- ring-direct --compile --memory-profile 2g
# Distinct supported-core wire-capacity experiment, under the same process guard:
cargo run --release --features ring-circuit -- ring-direct --compile --memory-profile 8g --wire-profile 64m
# Separate 24 GiB profile, under the research-compile-large guard:
cargo run --release --features ring-circuit -- ring-direct --compile --memory-profile 24g --wire-profile 64m
cargo run --release -- private-note --prove
```

`native-reference` is Linux x86_64 only and requires AVX2/AES/FMA. It calls the
unchanged vendored C keygen/mint implementation, then compares its sampled secrets,
public keys, serials and commitments to the direct Rust equations at values zero,
one and `2^52 - 1`. It never generates a native spend proof. Fixed-seed fixtures
and all fixture keys are public test data, unsuitable for real funds.

The note proof test checks the real verifier against root, nullifier and output
commitment mutations after editing both the artifact envelope and expected
statement, then corrupts proof bytes and checks artifact bounds. Relation tests
cover ownership, selection/membership, openings, duplicate spends, noncanonical
arithmetic, overflow/ranges, balance, profiles and contexts. Compiler tests cover
public statement order and preallocation/first-failure admission. These are
engineering checks, not an independent cryptographic audit.

## Measurement interpretation

Reports distinguish native/recursive proof counts, active/padded rows, combined
setup/proving time, independent CPU verification and artifact round trips.
Unknown setup-only and host/GPU peak measurements remain `null`. The legacy note
CLI interval is `profile_prove_verify_roundtrip_ns`; its `complete_workflow_ns`
remains `null`. The separate owned-note and full direct-ring workflows report
their explicit fixture-to-cleanup research intervals and retain process peaks in
guard evidence. None measures authenticated ledger processing or a matched RingCT
recursive aggregation workflow. The same-note backend improvement and direct-ring
public-hash improvement do not establish a 2x protocol-redesign improvement against
faithful RingCT, protocol compatibility or adoption readiness.

Required continuation: qualify the fixed N3/N4 direct-ring aggregate workflow under
the existing envelope; add complete fresh graph/aggregation/artifact/mutation/cleanup
screening for each separately identified profile; compare matched complete workflows against faithful
RingCT; obtain qualified cryptographic review. Keep both profiles separate from
protocol-preserving speedup claims.

See [semantic comparison](SEMANTICS.md) for migration and security differences.

## Gated complete GPU research workflow

The `gpu-proving` feature adds `ring-direct --prove --output-dir NEW_DIRECTORY`.
This path selects `fused-ternary-ranges-v1`, defaults to the existing `2g` compiler
and `16m` wire profiles, and requires `FreshOnly`/`GpuRequired` execution. Its wide
GPU build has 321,793 active rows, 524,288 padded rows, 6,114,044 wires and 59,822
witness values. The complete host constraint check passed with no deferred
cryptographic obligations. A first complete GPU research workflow has now passed
independent verification and artifact/terminal audits; repeated performance and
cryptographic adoption qualification remain separate.

A sealed memory plan binds the immutable program and actual input backing before
GPU setup. The one-shot registration releases witness instructions after the
trace fence. Opt-in host storage retains GPU-produced immutable Merkle trees in
host memory and reloads each tree once for a query batch. Hashing and query
gathering remain GPU operations. The default device-storage path remains available.
The complete admission checks conservative bounds for all simultaneous owners,
physical per-allocation limits, phase scratch and effective runtime allowances.
Unsupported selections remain refused; diagnostic payload floors do not
authorize proving. Focused planner tests and a complete GPU screening run passed.

The implemented orchestration writes `proving.json`, `proof.bin`,
`verification.json` and `workflow.json` to a new directory. It releases detailed
proving state before encoding, round-trips the bounded artifact through disk,
reconstructs the program from the expected public statement, computes fresh
preprocessing, closes the GPU session and verifies numerically on CPU. Public
binding and opening mutations must fail. Reports separate compilation, setup,
proving, codec, disk, independent reconstruction, CPU verification, mutations and
complete research lifecycle time. `fullgpu-direct-workflow-1` passed this sequence
in 207.808 seconds: 96.211 seconds of prover setup, 8.749 seconds of proving,
96.252 seconds of independent verifier setup, and 0.0315 seconds of CPU proof
verification. The 1,783,953-byte artifact passed the disk round trip and two
cryptographic mutations. Managed GPU memory peaked at 8,388,675,144 bytes; the
guarded process peaked at 7,341,268,992 bytes with zero worker swap. These are one
research run's measurements, not a matched RingCT speedup claim.

`fullgpu-forged-envelope-gpu-1` also passed a fresh full proof followed by
independent reconstruction and numerical rejection of recipient/context changes
whose public artifact headers and registered identities were forged to match.
The original artifact was restored byte-for-byte afterward. The measured setup
bottleneck is the sequential GPU program-identity hash: 50,764,992 fields in
12,394 batches took 92.312 seconds in the first run. Identity-hash kernel tuning
remains a separate, unqualified experiment.

All builds and validation remain serialized by the coordinator's guard. The
isolated `direct-full` profile uses a 45 GiB process cap, 43 GiB high limit and
47 GiB fresh-memory admission while preserving the 8 GiB managed GPU, 4 GiB
context reserve, 32 GiB worker host, 24 GiB native and zero-swap limits. It cannot
qualify faithful RingCT throughput. The original 47 GiB `full` process profile
remains unchanged. No result from one direct relation proof establishes complete
RingCT transaction-graph or recursive-aggregation performance.

The new retained-tree kernel passed three actual RTX 5080 parity tests against
CPU and legacy GPU references. Separate host/default-device query tests passed,
including failure cleanup. Repeated measurements and security review remain pending.
See [validation](VALIDATION.md) for run labels and preserved failed attempts.

## Opt-in fused public matrix arithmetic

The compiler also accepts the independent representation selector
`--representation fused-public-linear-v1`. Omitting it preserves
`inline-public-montgomery-constants-v2`; capacity options never select a different
representation. Unknown or duplicate options are rejected. The candidate fuses
fixed-Q public matrix dot products into one bounded quotient/remainder equation
per output coefficient. All NTTs, canonical private inputs, value ranges, balance,
selection and expected-statement binding remain in the compiled relation.
See [LINEAR_REPRESENTATION.md](LINEAR_REPRESENTATION.md) and the independent
[LINEAR_AUDIT.md](LINEAR_AUDIT.md) for the integer bounds and review scope.

Run large screens only through the serialized `research-compile-large` guard
described above. Candidate arguments are `ring-direct --compile --memory-profile
24g --wire-profile 64m --representation fused-public-linear-v1`. Adding
`--evaluate` requests full host constraint execution after compilation. Its
separate admission includes retained program/witness storage, all wire values,
and the complete trace within the unchanged 32 GiB worker allowance. A refusal
does not retry at larger limits. See
[evaluation bounds](src/ring_circuit_evaluation/BOUNDS.md).

Compiler and host-evaluation time are reported separately from guard/build time.
Host constraint execution is not cryptographic proof verification. The compiler
still exposes no direct-ring proof API, and component reductions cannot qualify
a complete-workflow speedup or production adoption.

## Opt-in fused lattice transforms

The separate `--representation fused-public-ntt-v1` candidate keeps the fused
public matrix equations and replaces each of the 52 fixed-Q transforms with
bounded linear output equations. A public table derived from the pinned native
transform supplies all constants; private input constraints, ternary domains,
canonical outputs, balance and serial linkage remain in the relation. The
original inline representation stays the default, and
`fused-public-linear-v1` remains independently selectable. Capacity selection
never selects the new representation. See [transform design](NTT_REPRESENTATION.md)
and [independent audit](NTT_AUDIT.md).

The explicit host-evaluation diagnostic now accounts for the immutable program's
retained vector capacities and nested storage, including the future MachineAir
Arc. Its selected compiler allowance remains a separate ceiling; the full
witness and auxiliary allowances, wire values and padded trace still enter
admission. A sealed evaluation plan holds the exact program and calculated
footprint together so inspection and execution need only one storage scan. This
reduces conservative reservation, not physical storage by itself. The 32 GiB
worker maximum and all other limits are unchanged.

Use the same serialized `research-compile-large` guard for matched full screens:
`ring-direct --compile --memory-profile 24g --wire-profile 64m --representation
fused-public-ntt-v1 --evaluate`. Compiler and host-constraint timings remain
separate from proving or complete-workflow throughput. Results and qualification
boundaries are recorded in the transform design note and campaign evidence.

The audited candidate also fits the existing smaller `--memory-profile 8g
--wire-profile 16m` settings under the serialized `research-compile` guard.
See the [measured report](../../docs/ringct-ntt-optimization-2026-10-24.txt) for
matched compiler results and the remaining proving/workflow requirements.

## Opt-in signed ternary transforms

The separate selector `--representation fused-ternary-ntt-v1` binds each fixed-Q
transform directly to its existing constrained signed ternary inputs. It keeps
the same public transform table and canonical outputs, while removing redundant
input conversions and reducing the bounded quotient to seven bits. All previous
representations and the default remain available unchanged. See the
[representation and integer bounds](TERNARY_REPRESENTATION.md) and
[independent arithmetic audit](TERNARY_AUDIT.md).

Use the serialized `research-compile` guard with
`ring-direct --compile --memory-profile 8g --wire-profile 16m --representation
fused-ternary-ntt-v1 --evaluate`. Across three matched alternating pairs against
`fused-public-ntt-v1`, median compiler time fell from 3.486 to 2.106 seconds
(39.6%) and total compiler-diagnostic time from 3.803 to 2.304 seconds (39.4%).
Wires fell from 12,695,988 to 8,012,253; active rows from 2,063,220 to 1,276,409.
Both full relations still pad to 2,097,152 rows, above the faithful RingCT
workflow's 2^20 row limit. All host constraints passed; no cryptographic proof
or complete-workflow throughput was measured.

The existing `compiler_requested_bytes_peak` field is a snapshot before packing.
The new `compiler_packed_admitted_bytes_peak` includes final packing and scoped
builder scratch. These requested-storage bounds are distinct from retained
program storage, evaluation admission and measured process peaks. The candidate's
packed peak was 2,388,656,128 bytes, above 2 GiB, so no `2g` confirmation was
attempted. The `compiler_diagnostic_total` timing includes fixture construction,
compilation, evaluation planning, requested host evaluation, reporting and owned
data destruction. It excludes Cargo, process launch and cryptographic proving.
See the [measured report](../../docs/ringct-ternary-optimization-2026-10-25.txt)
and its archived records for exact timings, limits and qualification boundaries.

## Opt-in reused range constraints and host evaluation

The independent selector `--representation fused-ternary-ranges-v1` reuses
bounded bit decompositions and the existing sealed canonical-from-bits gadget
instead of emitting duplicate slack decompositions. It also reuses constrained
amount bits. Exact reconstruction, Booleanity, strict comparisons, ownership,
balance, AES-derived serials and lattice equations remain constrained. All
previous representations and the default remain unchanged. See
[range design and measured limits](RANGES_REPRESENTATION.md).

The separate `--evaluation-backend constraints-only` option requires `--evaluate`.
It executes the same host operation evaluator without materializing the unused
trace. Omitting the option preserves `trace` in both CLI and existing APIs.
Equivalence applies to immutable, well-formed finalized programs, not arbitrary
internal layouts. Admission still includes retained program storage, full witness
and auxiliary allowances, and wire values; only trace storage is removed. See
[evaluation admission](src/ring_circuit_evaluation/BOUNDS.md) and the core
[host-evaluation contract](../../lattica-prover-p3/src/block_v2/machine/program/host_evaluation/BOUNDS.md).
Neither backend performs independent AIR validation or cryptographic verification.

Three matched alternating pairs for each experiment used the same frozen
executable, `8g`/`16m` profiles and serialized `research-compile` guard:

| Experiment | Baseline median diagnostic seconds | Candidate | Reduction |
| --- | ---: | ---: | ---: |
| Host backend only | 2.299232 | 2.155173 | 6.27% |
| Range representation only | 2.311421 | 2.061153 | 10.83% |
| Combined | 2.306050 | 1.955442 | 15.20% |

Baseline was `fused-ternary-ntt-v1` with `trace`. The full relation's wires fell
from 8,012,253 to 6,114,044 and active rows from 1,276,409 to 925,151; padded rows
fell from 2,097,152 to 1,048,576. The compiler's admitted packed peak fell from
2,388,656,128 to 1,263,185,448 bytes. Combined median guarded process peak fell
from 1,992,364,032 to 1,192,755,200 bytes. Component packed peaks increased
slightly despite lower active rows, so the full-relation result does not establish
a memory reduction for every component.

A separate `2g`/`16m` confirmation with the `trace` backend passed at the same
geometry. Its 2 GiB ceiling covers program backing; the complete compiler
reservation is 2,298,478,592 bytes including witness and auxiliary allowances.
It is not a 2 GiB whole-process or proving limit. Reproduce only under the
serialized `research-compile` guard:

```sh
cargo run --release --features ring-circuit -- ring-direct --compile \
  --memory-profile 2g --wire-profile 16m \
  --representation fused-ternary-ranges-v1 --evaluate
# Add --evaluation-backend constraints-only to select operation-only evaluation.
```

The diagnostic timer includes fixture creation, compilation, planning, requested
host evaluation, reporting and owned-data destruction; it excludes Cargo and
process launch. Guard wall times include polling and are not performance results.
At the time of that compiler-only round, clearing the row ceiling did not qualify
a proving path. The subsequently added `gpu-proving` API, independently rebuilt
verifier and complete relation measurements are described above; complete
transaction/aggregate closure remains absent. Resource/security limits and
production defaults are unchanged. The [round report](../../docs/ringct-row-optimization-2026-10-25.txt)
and [evidence manifest](../../docs/evidence/ringct-row-optimization-2026-10-25/manifest.json)
preserve all 27 guarded jobs, measurements and remaining qualification limits.

## Isolated seven-case direct-ring screen

The release `gpu-proving` library has one explicitly ignored Linux x86_64 test:
`ring_screen::tests::gpu_seven_distinct_ring_workflows_verify_roundtrips_and_retire`.
The historical [seven-ring screen](reports/seven-ring-gpu-screen-20261025.json)
passed: seven fresh GPU proofs, seven independent CPU acceptances and fourteen
cryptographic mutation rejections in 1,454.393156083 seconds. It generated zero
recursive aggregates and does not qualify the new N3/N4 aggregate workflow.
Run only through the coordinator's exact serialized `direct-full`
host-tree guard, with the baseline public-hash kernel. The guard supplies
`LATTICA_DIRECT_RING_SCREEN_QUALIFICATION=1` and
`LATTICA_DIRECT_RING_SCREEN_OUTPUT_DIR` naming a new absolute UTF-8 directory of
at most 1024 bytes. Existing one-fixture CLI behavior is unchanged.

Before GPU dispatch, the screen regenerates and checks seven genuine native
key/coin fixtures sequentially, retains only their fixed public identity manifest,
and rejects repeated statement digests or any repeated serial. Each proof case
regenerates its fixture and checks that manifest, compiles the same complete
relation, proves freshly on GPU, writes and reads a bounded artifact, independently
reconstructs preprocessing, verifies numerically on CPU and rejects the existing
public-binding/opening mutations. Proving reports are streamed and destroyed
before codec and independent reconstruction; all large per-case owners retire
before the next case. Both fixture passes are included in the suite timing.

The selected pair schedule is 0, 1, 3, 4, 6, 8, 9 under one shared context and
setup seed, with zero, one, ordinary and near-52-bit-limit balanced amounts. All
fixture secrets are deterministic public test data. The implementation writes
`preflight.json`, seven `case-N` directories and a final `screen.json`; partial
failure artifacts remain for audit. Reports retain zero aggregate proofs and
false faithful-RingCT, N3/N4 aggregate, security-adoption and protocol-redesign-2x
flags. See [source memory and lifetime bounds](src/ring_screen/SOURCE_BOUNDS.md).


## Fixed N3/N4 direct-ring aggregate research

The separately disabled `ring-direct-aggregate-experiment` feature adds
`ring_circuit::aggregation::prove_complete`. `BatchInput` consumes exactly three
or four independently expected whole statements and native witnesses. It
returns a `VerifiedAggregate` owning the actual final artifact, plus bounded
phase reports. `verify_independently` consumes an artifact and a separately
constructed `ExpectedBatch`; envelope keys, programs and caps are never trusted.
The original ring relation, ternary/lattice arithmetic, AES serial linkage,
hidden choice among ten pairs, two inputs/two outputs and 52-bit ranges are
unchanged. This is direct-spend protocol research, separate from protocol-preserving
RingCT optimization and production acceptance.

The selected source topology is one final verifier of all N whole-child proofs.
The core uses unknown child-public input wires constrained to independently
expected constants; four root public words bind the ordered statements, all
serials, setup seed, context, fixed count and profile. Duplicated statements or
serials are rejected before setup. Full source geometry must close below the
existing row/wire/input/program limits before any public setup. Exact root/leaf
GPU plans, all retained owners, independent CPU verification and bounded codec
storage are admitted before the first child proof. No post-dispatch topology
change, retry or profile escalation exists.

Each child is freshly proved and CPU verified using its independently rebuilt
public setup. That setup reuse is reported explicitly. The root is freshly
proved, written to a newly created file, read through the same bounded file
owner, canonically decoded, and verified after rebuilding every expected source
again. Original and decoded proofs never overlap. Final artifact domains
`LDAGG301` and `LDAGG401` are distinct from both single-ring and one-child-outer
artifacts. Each child and root receives four numerical public-word mutations, a
restored opening mutation and a positive verification after restoration; only
typed relation rejection earns cryptographic-negative credit. Forged envelope
checks remain separately counted structural rejections.

The ignored complete driver is
`ring_circuit::aggregation::tests::complete::direct_ring_n3_n4_complete_owned_aggregates_roundtrip_and_retire`.
The coordinator must build/execute it under the existing serialized GPU/process
guard. It requires `LATTICA_DIRECT_RING_AGGREGATE_QUALIFICATION=1` and a new
absolute `LATTICA_DIRECT_RING_AGGREGATE_OUTPUT` directory, with the unchanged
strict proving policy/reports/context limits. Fixtures 0–2 form N3; fixtures 3–6
form N4 under the historical shared context/setup and genuine distinct keys,
coins and serials. The driver destroys the N3 artifact and full report before
starting N4, retains failed artifacts/evidence, and times fixture generation
through proof/secret/report cleanup. General API callers must also charge any
other retained outcomes inside their enclosing worker allowance; an API call
does not grant an additional worker budget.

This source has not yet established complete N3/N4 performance, resource
qualification or the redesign's 2x gate. Qualified cryptographic review remains
required before adoption. Private-note proofs remain the original quadratic
`config::MyConfig` join-split construction; the wallet's cubic
`block_v2::profile::Config` aggregator adds 16 context publics. The two profiles
are not silently converted or re-proved into one another. See
[aggregate source and lifetime bounds](src/ring_circuit/aggregation/SOURCE_BOUNDS.md).
