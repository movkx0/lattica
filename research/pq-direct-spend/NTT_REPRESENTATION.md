# Fixed-Q public NTT representation

`fused-public-ntt-v1` is a separately selected research compiler representation.
The default remains `inline-public-montgomery-constants-v2`; the existing
`fused-public-linear-v1` continues to use its original inline NTT schedule.
Capacity selection does not select this representation, and a refused compiler
run does not retry with another representation or resource profile. Success and
failure diagnostics identify the selected representation, including refusals
before arithmetic begins.

The new representation expresses each of the direct ring relation's 52 NTTs as
exact bounded linear equations with public coefficients. It retains the previous
fused matrix equations, amount encoding, statement and context binding, ten-pair
hidden selection, ownership and commitment equations, ternary keys and openings,
52-bit values, balance, and exact AES-derived parameters and serial images. It
does not expose a proof API or change production acceptance, cryptographic
parameters, distribution of witnesses, or any resource ceiling.

## Exact transform

The native Q transform first applies 128 butterflies at stride 128. The first
operand is multiplied by the conversion constant with one Montgomery reduction;
the second is multiplied by the initial twiddle with one Montgomery reduction.
Five subsequent stages use strides 64, 32, 16, 8, and 4. Each stage applies a
public twiddle with the original inverse-R factor, then canonical addition and
subtraction. The final frozen permutation reorders quartic blocks while
preserving their within-block index.

All these operations are linear over integers modulo `Q = 167770241`. Every
stride is a multiple of four. Therefore, for each within-block lane `l`, the
transform has the same 64-by-64 matrix `T`:

```text
output[4*r+l] = sum(T[r][j] * input_residue[4*j+l], j=0..63) mod Q
```

`PublicTransform::derive` constructs T once per full compilation using public
unit vectors through the untouched native implementation of the generic NTT.
It includes every conversion factor, Montgomery factor, sign, twiddle, and the
final permutation. No private value enters coefficient derivation, and no host
acceptance result substitutes for a constraint. The table's fields are private;
the full compiler cannot accept a caller-supplied transform.

The existing sealed ternary constraints and signed-to-canonical conversion are
retained. The NTT helper requires the same-builder signed inputs to have bound
one, and rejects incorrect host values or bounds before adding transform hints.
Each output is constrained as described below. The original canonical
intermediate stage values are uniquely reconstructible from the inputs; their
elimination changes the constraint representation, not the resulting relation.

## Integer soundness bound

Each equation accepts exactly 64 canonical Q residues and 64 public canonical
coefficients. For their nonnegative integer sum S:

```text
S <= 64*(Q-1)^2 = 1801398619498086400
```

The helper adds a quotient hint k and remainder hint r, enforcing:

```text
0 <= k <= 64*(Q-1) = 10737295360
0 <= r < Q
sum(T[r][j] * input[j]) = k*Q + r
```

The maximum actual quotient at the largest permitted sum is 10737295296; the
slightly larger static bound is safe. The largest right-hand side is
1801398630403152000. Both sides, every product, and every nonnegative partial sum
are strictly below the Goldilocks modulus 18446744069414584321. Thus field
equality cannot hide an integer wrap. The sealed canonical inputs and canonical
remainder make the modular output unique; the host values only generate hints.

The quotient bound needs 34 bits and uses the existing bounded comparison
gadget. Compile-time assertions pin Q, geometry and both no-wrap bounds. The
helper refuses noncanonical public coefficients, host residues and incorrect
sealed moduli before its two hints. This 64-term construction must not be
generalized to QHAT or arbitrary arity. It must not omit either quotient bounds
or canonical input/output constraints.

## Geometry and admission

The 52 transforms become 13,312 output equations, each with two witness hints,
for 26,624 transform quotient/remainder hints and 851,968 public coefficient
products. The existing signed inputs and signed-to-residue hints are additional
and unchanged. The old schedule contains 79,872 canonical stage output
reductions and 46,592 Montgomery operations across those transforms. These are
static arithmetic counts, not measured wire, row, time or memory results.

The matrix table occupies 32,768 bytes and is retained for one compilation. A
512 KiB portion of the existing 16 MiB auxiliary allowance covers it, fixed
basis and output buffers, constrained lanes and conservative table moves. A
compile-time layout check includes four table-sized buffers, four native
polynomial buffers and sixteen constrained polynomial buffers, including the
bounded eight- or nine-polynomial NTT result array and transform temporaries.
This does not add to the admitted host allowance. External process
guards still cover allocator and compiler stack overhead; these logical bounds
are not process-memory measurements.

Full admission precedes table construction and all other compiler allocation.
The existing builder and witness limits apply at every helper boundary, and each
dot product checks the phase before its two hints and after its constraints.
The table is derived only for the new representation. No retained child proof,
unverified digest, deferred NTT request, or public preprocessing cache is added.

The new representation also skips the unused canonical public matrix residue
arrays. The fused equations already embed the exact needed public coefficients.
Both older representations retain their existing matrix materialization and NTT
operation sequence. Their wrappers now call extracted matrix-only helpers after
producing the same canonical NTT outputs; the matrix dot helper, coefficients
and amount encoding are unchanged.

## Qualification scope

Focused tests compare every table coefficient and all four lanes with native
basis transforms; check dense integer extremes, quotient/remainder mutation,
full NTT equality against native and existing constrained schedules; check
program shape across different private ternary witnesses; and verify early
domain/context/admission refusals with the correct selector. Independent
arithmetic audit and security review remain required.

The ignored `alternating_ntt_component_screen` requests three matched pairs in
baseline/candidate, candidate/baseline, baseline/candidate order. The baseline
NTT is shared unchanged by the inline and fused-linear representations. Each
measurement compiles and host-evaluates one whole NTT. All 256 outputs are bound:
192 to native diagnostic constants and 64 to public inputs, within the core's
64-public limit. These oracle constants are only for the diagnostic component;
the full compiler uses the actual account equations instead.

The screen reports wire and active/padded row counts, witness hints, builder
requested peak before final packing, public table construction time, total
component construction time, and host evaluation time. Table construction is
included once in each candidate component measurement; a full candidate
compilation derives it once for all 52 NTTs. Native expected-output construction
is outside the timed component. Programs, witnesses and traces are dropped
before the next measurement. Builder snapshots remain separate from packed
admission and observed process memory.

The guarded results below establish correctness checks, component measurements,
and successful full compilation and host evaluation for the candidate. They do
not establish cryptographic proving, independent proof verification, artifact
handling or complete-workflow performance. The existing default is unchanged;
qualified cryptographic review and the 2x complete-workflow qualification gate
remain outstanding.

## Audited results

The coordinator ran serialized qualification on the frozen integrated source on
2026-10-25 UTC. All nine records listed below passed and report unchanged source
and executable, zero swap, completed service cleanup, and all subprocesses
terminal and reaped. Their raw-log hashes and the four C-owned Rust input hashes
were checked. The combined direct-spend suite passed 56 tests with three ignored
tests: 46 library, two CLI, and eight relation tests. This includes all six new
NTT checks and eight independent arithmetic audit checks. No cryptographic proof
was generated by these NTT jobs.

### NTT component

Three alternating matched pairs produced identical counts within each
representation. The following times are medians:

| Measurement | Current inline NTT, shared by both earlier representations | Fused NTT candidate |
| --- | ---: | ---: |
| Wires | 613,334 | 169,042 |
| Active rows | 103,397 | 27,365 |
| Padded rows | 131,072 | 32,768 |
| Witness hints, including signed inputs and conversion | 5,376 | 1,024 |
| Builder requested peak before final packing, bytes | 151,019,520 | 37,761,024 |
| Builder packed admitted peak, bytes | 151,019,520 | 38,484,488 |
| Construction time, seconds | 0.118028012 | 0.033581916 |
| Host evaluation time, seconds | 0.011686625 | 0.003168689 |
| Public table derivation, included in construction, seconds | 0 | 0.000228800 |

The six-measurement job took 2.085897630 seconds of guard wall time and had a
cgroup peak of 212,701,184 bytes. It used the `build` guard: 8 GiB process cap,
6 GiB high watermark, 10 GiB fresh-memory admission, two threads, CPU-required
execution, and zero swap. This is one complete NTT component, with the diagnostic
oracle binding described above; it is not a transaction or proof workflow.

### Matched full compiler and evaluator

All six full runs compiled the direct ring relation and satisfied every host
constraint for the deterministic fixture. They used the same frozen source and
binary, the same sealed evaluation-plan path, explicit `24g` memory and `64m`
wire profiles, and the order baseline/candidate, candidate/baseline,
baseline/candidate. Here the baseline is `fused-public-linear-v1`; the candidate
is `fused-public-ntt-v1`. Counts were identical across their three repetitions.

| Measurement | Fused-linear baseline | Fused-NTT candidate |
| --- | ---: | ---: |
| Wires | 35,806,310 | 12,695,988 |
| Active rows | 6,017,802 | 2,063,220 |
| Padded rows | 8,388,608 | 2,097,152 |
| Witness values | 299,646 | 73,342 |
| Builder requested peak before final packing, bytes | 9,676,259,328 | 2,422,210,560 |
| Builder packed admitted peak, bytes | 9,676,259,328 | 2,662,638,248 |
| Builder packed live bytes | 4,415,564,446 | 1,515,986,940 |
| Retained program source bound, bytes | 4,379,757,128 | 1,503,289,944 |
| Whole-live evaluation admission bound, bytes | 11,125,435,768 | 3,332,911,096 |
| Median compiler-only time, seconds | 9.591446929 | 3.428101539 |
| Median host constraint evaluation time, seconds | 0.788128530 | 0.281384986 |
| Median guard wall time, seconds | 12.108227708 | 4.090608589 |
| Median cgroup process peak, bytes | 9,314,279,424 | 3,216,216,064 |

The compiler summary's `compiler_requested_bytes_peak` is sampled before final
packing. The raw `bounded_program_construction phase=packed` line supplies the
larger candidate packing peak. The retained source bound separately counts
actual immutable program capacities, nested storage and its future Arc. The
evaluation bound includes that retained bound, full witness and auxiliary
allowances, wire values, and the trace. None of these logical counters is a
measurement of process memory; cgroup peaks are reported separately.

| Pair and order | Baseline compiler seconds | Candidate compiler seconds | Baseline evaluation seconds | Candidate evaluation seconds |
| --- | ---: | ---: | ---: | ---: |
| 1, baseline/candidate | 10.037086198 | 3.428101539 | 0.788128530 | 0.283702111 |
| 2, candidate/baseline | 9.591446929 | 3.415430174 | 0.785940173 | 0.281384986 |
| 3, baseline/candidate | 9.583848439 | 3.491908846 | 0.800645695 | 0.273509016 |

Compiler-only timing excludes fixture creation. Host evaluation timing begins
after the evaluation plan scans retained capacities, so their sum excludes that
planning work. Guard wall time includes fixture creation, planning, launch and
other process overhead. The first baseline guard also includes a 27.36-second
Cargo build, giving a 40.173764728-second guard wall time; it must not be treated
as a matched execution-only observation. The common completed driver binary was
`1cbcc764f50b8c835048e396a9be8fb30fe934afb722e25fd2690cfd506a77a6`.
These are scoped compiler/evaluator measurements, not complete-workflow timing.

The full runs used `research-compile-large`: 32 GiB process cap, 30 GiB high
watermark, 36 GiB fresh-memory admission, two threads, CPU-required execution,
and zero swap. Compiler, worker, witness, row, thread and security ceilings were
unchanged. Faithful RingCT GPU policy and resource limits were not modified.

### Existing smaller capacity profile

One separately selected candidate confirmation used the existing `8g`/`16m`
profiles. It compiled and satisfied every host constraint with the same geometry,
packing peak, retained source bound and evaluation bound as the `24g`/`64m`
candidate. Compiler-only time was 3.432467218 seconds, host evaluation took
0.277335913 seconds, guard wall time was 4.098229594 seconds, and the cgroup peak
was 3,215,876,096 bytes.

This confirmation used `research-compile`: 16 GiB process cap, 14 GiB high
watermark, 20 GiB fresh-memory admission, two threads, CPU-required execution,
and zero swap. It was an explicit experiment after successful matched screens,
not an automatic retry or resource increase. Neither smaller capacity nor the
new representation became the default.

### Evidence hashes

Files are retained under `.tools/pq-opencl-opt/runs/` in the integration worktree.
Each label names its corresponding `.log` and `.json` guard files.

| Label | SHA256 of `.log` | SHA256 of `.json` |
| --- | --- | --- |
| `nttopt-integration-direct-tests-1` | `ddafd9c86986ee8558cae83a919acee8149ed42390ec03ba2c086348869f60d3` | `b5fb889356db2c1cce205a977a738e102a84fe80f877774538ec77d30d121fa8` |
| `nttopt-integration-component-screen-1` | `31aaa0edca04107f3f40f951a3bc3a635bba398e59b07d4db6abd3d481e03aa0` | `dfc68ee231075a0ee1a19797364139ea3f24c6e93056cf0f286a1e1bc729609f` |
| `nttopt-full-pair-1-baseline` | `d1cc11c01f28ba0defc2100a8ed7d6a7a9eddb4776319316f1c6e4f5c708448e` | `940b484d51cfd697ed93615ac6e7450dfb0b8d326b2c4cc0a12762051111af38` |
| `nttopt-full-pair-1-candidate` | `2a0502713673d654dd60f5db7c1f6cfc413071f2a79cc28a1ef16c8a717764c7` | `3cafa7138086d890b47f619e07562e5b3485ab08d568d0a4097f3b9999f5eb82` |
| `nttopt-full-pair-2-candidate` | `6546a997280110988716af2f0ac96b6b2029d8a9674db49557e9db968a0a1f72` | `cb43039faacd46faf49a46fce864c4d5a65d6ae38169c1cf2b880dd411037a0f` |
| `nttopt-full-pair-2-baseline` | `e5f67f9b17bbf00e6d70b52465f05ece18c19c00516afa92f0c86c856fd00f9d` | `edab5ed48c080f90d8732b0a8ef34bf08b878a50c2fcadc2326c42b8fef87790` |
| `nttopt-full-pair-3-baseline` | `16fde7393f098b6b656ab93f8eb5c14c5c14c4b8599f3f278e96067a7d90bc3b` | `0a0894d94e6970cfe0d445c20c0bff27f2eed14bfc6106e48c363123f5a862c2` |
| `nttopt-full-pair-3-candidate` | `f1d3d34ae70a1f7d7600cd68dcb58b173966020efd8b0ae115df4a44a4ba94c1` | `1e8c3d4f555580d331a395afe75343aa7379ae64bd1d13979477fb797c9e1f42` |
| `nttopt-candidate-8g16m-confirmation-1` | `5d2b33ad7da61710c32ac6df00f0e42213b39d524bac6ab3b2ffae596f70fee9` | `bc6fd3af51fd4ea914cdefc57ac722b0ee30b19e426bfbd68168f91f140a26d4` |
