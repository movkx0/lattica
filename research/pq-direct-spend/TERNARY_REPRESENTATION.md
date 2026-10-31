# Signed ternary NTT representation

`fused-ternary-ntt-v1` is an independent, explicit compiler representation for
the research ring direct-spend relation. The default remains
`inline-public-montgomery-constants-v2`; `fused-public-linear-v1` and
`fused-public-ntt-v1` retain their arithmetic schedules. Capacity selection does
not select this representation or authorize a proof.

The new representation uses the same frozen public NTT matrix as
`fused-public-ntt-v1`, but binds its equations directly to the already constrained
ternary inputs. It removes the 256 signed-to-canonical-residue conversions per
NTT and uses a smaller quotient range for each output. Each NTT still has four
lanes, 64 public coefficients per output and 256 constrained outputs. The
public matrix is derived once per full compilation, including the original
Montgomery factors, initial conversion and final permutation. The only change
to its implementation is a checked, read-only row accessor.

All 52 NTTs in the ring compiler use the selected representation: the two
eight-polynomial ownership relations and four nine-polynomial commitment
openings. Existing public matrix products, account equations, selected-pair
constraints, 52-bit value ranges, balance, AES-derived serial relationships,
statement binding and rejection behavior remain in place. No deferred NTT
obligation or native private-witness acceptance bit is introduced.

## Exact integer relation

Let `Q = 167770241`, let each public coefficient `a[j]` satisfy `0 <= a[j] < Q`,
and let each same-builder sealed signed input satisfy `x[j] in {-1,0,1}`. For
one 64-term output define:

```text
C = sum(a[j])
B = ceil(C / Q) * Q
S = B + sum(a[j] * x[j])

0 <= C <= 64*(Q-1) = 10,737,295,360
C <= B <= 64*Q     = 10,737,295,424
0 <= B-C <= S <= B+C <= 21,474,590,784 < 2^35
S < 128*Q
```

The circuit constrains the existing signed wires with:

```text
B + sum(a[j] * x[j]) = k*Q + r
0 <= k <= 127
0 <= r < Q
```

Both sides have nonnegative integer interpretations. The accumulator starts
at `B`, so every partial sum, including an all-negative prefix, remains in
`[B-C, B+C]`. Negative field products therefore do not introduce an aggregate
alias. The largest right-hand side is `128*Q-1 = 21,474,590,847`, also below
`2^35`. Both bounds are strictly below the Goldilocks modulus
`18,446,744,069,414,584,321`. Field equality consequently implies integer
equality, and the unique canonical `r` is the original transform modulo `Q`
because `B` is a multiple of `Q`.

The exact worst-case quotient is 127, with remainder `Q-64`. The existing
`assert_at_most` gadget enforces this quotient using seven Boolean
reconstruction bits; the power-of-two-minus-one bound needs no slack comparison.
The canonical remainder retains the existing strict comparison with `Q-1`.
These bounds are specific to 64 terms, this `Q`, and ternary signed inputs.
They do not authorize arbitrary signed domains, `QHAT`, larger batches or a
different transform.

Compile-time assertions pin the dimensions, modulus, quotient and field bounds.
Each row checks canonical public coefficients, the public bias and both row
bounds before allocating its quotient/remainder hints. The complete polynomial
and batch domains are checked before any transform hints. Batch arity remains
restricted to `1..=9`. Host metadata supplies hints only; it cannot choose
coefficients, bias, constants, wire connections or program geometry. The
equation always uses `SignedValue.constrained.wire()`, whose bound must equal
one. Original ternary constraints remain even for public zero coefficients.

## Resource and measurement boundaries

The implementation uses fixed arrays. The retained 64-by-64 public coefficient
table is 32 KiB; its derivation, conservative temporary table moves, signed
lanes and bounded batch output arrays fit in the same 512 KiB subdivision of
the existing 16 MiB auxiliary allowance used by the fused public NTT. This is
not an additional allowance. Inputs are not copied into a new canonical
residue array. Each output still adds exactly two hints, for `k` and `r`.
Existing phase guards and builder/witness admission checks remain active.
No process, worker, device, thread, wire, input, row or security limit changes.

The ignored `alternating_ternary_ntt_component_screen` compares
`fused-public-ntt-v1` with `fused-ternary-ntt-v1` in three matched alternating
pairs. It constructs and host-evaluates one whole NTT in each measurement.
Both representations include public-table derivation in component construction.
The native expected-output calculation is outside the timer. Every output is
bound: the first 192 to diagnostic oracle constants and the remaining 64 to
public inputs, respecting the machine's public-input limit. Those diagnostic
constants are absent from production compiler routing and shape checks.
Programs, witnesses and traces are dropped before the next measurement.

Component reporting includes wires, active/padded rows, witness hints, builder
requested bytes before final packing, table derivation, component construction
and host evaluation. The prefinish builder count is not the packed admission
peak or measured process memory. Full compiler diagnostics must separately
report packed admission, retained source/evaluation bounds, and complete
diagnostic time including fixture construction, planning and drops. None of
these compiler/host timings is cryptographic proving or complete transaction
workflow performance.

## Qualification status

Serialized coordinator correctness and compiler/host diagnostic qualification
passed on 2026-10-25 UTC. The focused tests cover scalar extremes,
quotient/remainder/output mutations, retained domains
under zero coefficients, complete NTT equivalence, witness-independent program
shape, malformed domains/coefficients/batches, selector/default preservation,
and pre-arithmetic context/profile/admission refusal. The independent audit in
`ring_circuit_ternary_audit.rs` adds an integer butterfly oracle and modular
alias attacks; its findings are recorded separately in `TERNARY_AUDIT.md`.

The results below passed immutable-source, terminal-status and evidence audits.
Cryptographic proving, independently reconstructed verifier identity, artifacts, complete
workflow resource qualification and qualified security review remain required
before adoption. The protocol-redesign gate still requires at least a 2x
complete-workflow improvement; compiler or host evaluation speedups do not
satisfy it. Production transaction acceptance and faithful RingCT GPU policy
are unchanged.

## Audited results

The combined direct-spend suite passed 70 tests with four ignored: 60 library,
two CLI and eight relation tests. This includes five new focused ternary tests
and nine independent arithmetic-audit tests. The ignored component screen was
then run separately and passed all three alternating pairs. Each of the six
full compiler/evaluator runs also passed. None generated a cryptographic proof.

All eight guard records below report unchanged source and executable, zero
swap, completed service cleanup, and all subprocesses terminal and reaped.
Raw-log hashes and the four implementation/test Rust files plus the independent
audit source were checked against the integrated frozen source. The integrated
`ring_circuit.rs` includes the coordinator's packed-peak summary field and has
SHA256 `7893ad4a4a597af589988d0ff8032fd49a500792032fc699f080c19a7890cf95`;
this supersedes its earlier pre-integration freeze hash. The bounded core
analysis adapter was qualified separately by the coordinator and is not used
to claim ternary proving performance.

### NTT component

Both representations used the same deterministic ternary input, whole-output
diagnostic binding and measurement boundaries described above. All counts were
identical within a representation. Times are medians of three observations.

| Measurement | Fused-public NTT baseline | Fused-ternary NTT candidate |
| --- | ---: | ---: |
| Wires | 169,042 | 78,973 |
| Active rows | 27,365 | 12,234 |
| Padded rows | 32,768 | 16,384 |
| Witness hints, including signed inputs | 1,024 | 768 |
| Builder requested peak before final packing, bytes | 37,761,024 | 18,886,656 |
| Builder packed admitted peak, bytes | 38,484,488 | 18,886,656 |
| Component construction, seconds | 0.035837779 | 0.017416322 |
| Host evaluation, seconds | 0.002824717 | 0.001363032 |
| Table derivation, included in construction, seconds | 0.000244731 | 0.000244581 |

The six-measurement job took 2.086748569 seconds of guard wall time and peaked
at 87,777,280 cgroup bytes. It used the existing `build` guard: 8 GiB process
cap, 6 GiB high watermark, 10 GiB fresh-memory admission, two threads,
CPU-required execution and zero swap. This measures one NTT component, not a
transaction or recursive proof workflow.

### Matched full compiler and evaluator

Three matched pairs used the same frozen source, completed executable,
deterministic ring fixture and sealed evaluation-plan path, in
baseline/candidate, candidate/baseline, baseline/candidate order. Both selected
the existing `8g` memory and `16m` wire profiles explicitly. The baseline is
`fused-public-ntt-v1`; the candidate is `fused-ternary-ntt-v1`.

| Measurement | Fused-public NTT baseline | Fused-ternary NTT candidate |
| --- | ---: | ---: |
| Wires | 12,695,988 | 8,012,253 |
| Active rows | 2,063,220 | 1,276,409 |
| Padded rows | 2,097,152 | 2,097,152 |
| Witness values | 73,342 | 60,030 |
| Builder requested peak before final packing, bytes | 2,422,210,560 | 2,388,656,128 |
| Builder packed admitted peak, bytes | 2,662,638,248 | 2,388,656,128 |
| Retained program source bound, bytes | 1,503,289,944 | 930,640,144 |
| Whole-live evaluation admission bound, bytes | 3,332,911,096 | 2,722,791,416 |
| Median compiler-only time, seconds | 3.485659641 | 2.106356108 |
| Median host evaluation time, seconds | 0.281550924 | 0.177571111 |
| Median total compiler-diagnostic time, seconds | 3.803359618 | 2.304325456 |
| Median cgroup process peak, bytes | 3,219,984,384 | 1,992,364,032 |

The median compiler time is 39.57% lower and the median total diagnostic time
is 39.41% lower. Both full relations still pad to the same number of rows;
lower active rows and component timings do not establish proving throughput.
The candidate's packed builder peak exceeds 2 GiB, so no `2g` profile
confirmation was attempted. No allowance was increased and no retry or fallback
was used to obtain these results.

| Pair and order | Baseline compiler seconds | Candidate compiler seconds | Baseline total diagnostic seconds | Candidate total diagnostic seconds |
| --- | ---: | ---: | ---: | ---: |
| 1, baseline/candidate | 3.485659641 | 2.104595343 | 3.803359618 | 2.303710668 |
| 2, candidate/baseline | 3.889676384 | 2.106356108 | 4.199796680 | 2.304325456 |
| 3, baseline/candidate | 3.412696475 | 2.110780792 | 3.719615210 | 2.307509803 |

Compiler-only timing starts after fixture creation. Host evaluation timing
starts after the plan scans retained capacities. The new total diagnostic timer
includes fixture creation, planning, reporting and all relation/fixture drops;
it excludes Cargo, process launch and cryptographic proving. The first baseline
guard included a 27.22-second Cargo build and took 32.140572566 seconds overall,
so that guard time is not an execution-only matched observation. The common
completed driver SHA256 was
`9abf6cdcb76388140dcf6d17fb9aa650ef02a7ba6cc7cd845e866d081e9ef967`.

The packed peak is now a separate summary field,
`compiler_packed_admitted_bytes_peak`, obtained from the immutable completed
program. `compiler_requested_bytes_peak` retains its explicitly documented
prefinish meaning. Retained source and whole-live evaluation bounds are logical
admission counts, distinct from observed cgroup memory.

All full runs used the existing `research-compile` guard: 16 GiB process cap,
14 GiB high watermark, 20 GiB fresh-memory admission, two threads,
CPU-required execution and zero swap. The enclosing evaluation worker allowance
remains 32 GiB. Faithful RingCT GPU and complete-workflow resource/security
limits remain unchanged. This research representation stays opt-in; no
complete-workflow qualification or production adoption is claimed.

### Evidence hashes

Files are retained under `.tools/pq-opencl-opt/runs/` in the integration worktree.
Each label names its corresponding `.log` and `.json` guard records. Campaign
`TERNARY_OPT_STATUS.json` records the parsed measurements and audit status.

| Label | SHA256 of `.log` | SHA256 of `.json` |
| --- | --- | --- |
| `ternaryopt-integration-direct-tests-1` | `1a2ae28431c53c2288bf94041104e8f1208cf31ee83957e556f3bca6c38e5e91` | `cd7c571bef883e4065e7241e3c5e1257002bfc28488cd8fe580d184dd061ee57` |
| `ternaryopt-component-screen-1` | `d34ca61f0f28baf3ee99acb684ce03736c92ae90d7d81e4fcb6eaabfc6476efc` | `ccc4c4dce7a0955ce87d69c5aee8a0a5e6a3a1b6eeb02e7c8cff77eeb45f2aff` |
| `ternaryopt-full-pair-1-baseline` | `8673569c2084035e5b584c06a496c3ee9f3bdbe6b20f3c9178ee271dde9f98ff` | `0e86fffe71d20b9920551b8230236e060b7b6cc4321b54aaf92d2f64d2ca6f10` |
| `ternaryopt-full-pair-1-candidate` | `865966251cc444b57fb935002ecbc78df1c1e8fe9d61856f099529e02e59e08e` | `922bea18087368bcf7930255bd84d758054465795a68afa0589aab9f063dbcbf` |
| `ternaryopt-full-pair-2-candidate` | `e16afbd3a0d31872e0db22271e7a19ab68a1c4eea8dae540626d585743f22713` | `8adda912fc6076a877419a3672c26deee8917e1745ca8e41660890c10ef45454` |
| `ternaryopt-full-pair-2-baseline` | `13bd737dd5500f8a1146d510305d838200d7074cae7dd13eb7ecb40969032dcb` | `ebfeeb23e9d45f84ac261ad36ebdfc40bdfd0edb3f40d4e33be7c7ac6acdff14` |
| `ternaryopt-full-pair-3-baseline` | `9fb78b82036e9602ee36d5432fab9bcff380c5a30feec13e61c7ba963c4d0083` | `327813c0e71b89cc8759bb4064c7f8f9a982e2c208a300648f2b1a7861a65630` |
| `ternaryopt-full-pair-3-candidate` | `ccd0f01e0220fe9dd685a034fce484b7c4c5e07fcd6b27162ad64df36b92ac59` | `8606179bc8cc9d2a89ad099ef1cb7c5f82d853098ec75686df49bed63091d60a` |
