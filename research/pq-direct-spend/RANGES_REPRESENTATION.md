# Reused range decomposition representation

`fused-ternary-ranges-v1` is a separately selected research compiler
representation built on `fused-ternary-ntt-v1`. The default remains
`inline-public-montgomery-constants-v2`. Every prior representation retains its
entry points and arithmetic/constraint schedule; memory, evaluator and
representation selection remain independent. This selection does not authorize
cryptographic proving or change production transaction acceptance.

The candidate replaces selected double-decomposition range checks with one
bounded decomposition and the existing public `canonical_from_bits`
constructor. It does not construct `Residue` through private fields, trust a
host comparison, or remove canonicality. The returned residue remains a sealed
same-builder value whose reconstructed wire is explicitly equated to the
original input wire.

## Exact range constraints

For `Q = 167770241`, `canonical_q` first calls `bounded_bits(wire, 28)`.
Every bit is Boolean, and the exact little-endian reconstruction equals the
original field wire. Its integer value lies in `[0, 2^28-1]`, strictly below
Goldilocks `p = 18446744069414584321`, so reconstruction has no field alias.
`canonical_from_bits` then checks the same bits, reconstructs the same integer,
and applies a strict comparison with `Q`. The result satisfies `0 <= r < Q`.
An additional equality explicitly binds its sealed output wire to the original
wire.

The core comparator scans little-endian bits, retaining the comparison for the
prefix already visited; each more significant bit overrides that comparison
when it differs from the corresponding public modulus bit. Its final predicate
is constrained to one. Short encodings are zero-padded. All decisions about
bit count, modulus and comparison structure are public. Private metadata can
provide input hints or trigger early rejection, but it cannot choose constants,
wire connections or program shape.

The existing builder memoizes Boolean constraints and arithmetic expressions.
Consequently, the second constructor reuses the first reconstruction and its
Boolean checks. The added work is the strict comparison and explicit wire
equality. The generic baseline instead decomposes both the value and its
`Q-1-value` slack. No assumption about memoization is needed for soundness:
without it the constraints would simply repeat.

The `assert_at_most` helper is restricted to public bounds at most `u32::MAX`:

* Bound zero constrains the wire to exact zero.
* A bound of `2^k-1`, including 127 and `u32::MAX`, needs only exact `k`-bit
  Boolean reconstruction.
* Other bounds use that reconstruction and strict comparison with `bound+1`,
  followed by explicit equality to the original wire.

The bound is checked before narrowing or adding one. Thus the maximum `u32`
bound takes the all-ones branch and never overflows a comparison modulus.
Nontrivial comparator moduli lie in `[2, u32::MAX]`. Every reconstruction uses
at most 32 bits, strictly below the field modulus. This helper does not extend
the public bound domain to larger integers.

## Scope in the direct relation

The new selector changes only these range encodings:

* Canonical remainders from all 52 signed ternary NTTs. Their public biases,
  original signed input constraints, seven-bit quotients and exact bounded
  integer equations are unchanged.
* Canonical remainders and the fixed `20*(Q-1)+2 = 3355404802` quotient bound in
  fused public linear equations. Coefficients, arity and both no-wrap bounds
  are unchanged.
* Private canonical account coefficients bound to the existing ten-way public
  selector equations. The selected pair affects hints only; every ring entry
  still appears in the fixed public linear selection.
* The four 52-bit input/output amount decompositions. Each existing constrained
  bit is passed as a one-bit slice to `canonical_from_bits`, creating a sealed
  Q residue without another private bit input. The original amount wire,
  52-bit exact reconstruction, and 12 constant-zero padding entries remain.

The amount bits still enter the unchanged Montgomery value encoding, account
equations and integer balance. Ownership, input/output openings, ternary
domains, AES-derived serial relationships, profile/context binding, native
segmentation and cryptographic parameters remain unchanged. No unverified
native acceptance bit or deferred arithmetic obligation is added. The old
linear and ternary entry points select the original range path; separate
`*_ranges` entries select this path explicitly.

## Memory and validation boundaries

The new scalar helper has at most one `bounded_bits` vector live, containing at
most 32 wires. A checked 16 KiB subdivision of the existing 16 MiB compiler
auxiliary allowance covers its vector, headers, comparison state and temporary
moves. The original 52-bit amount vector is retained as before, and each
one-bit constructor only borrows its slice. The public NTT table and bounded
batch arrays retain their existing 512 KiB subdivision. These subdivisions
remain within the existing allowance; none increases it. Phase guards run
before vector allocation and after the added constraints, while builder
backing remains subject to the existing program allowance.

Focused tests check Q boundaries, exact zero/all-ones/maximum-u32 bounds,
overflow rejection before new wires, noncanonical and field-alias inputs,
individual Boolean bit mutations, 52-bit amount reconstruction/padding, private
selection shape and mutations, complete NTT/commitment equivalence, and
selector/default/context/profile admission. An independent implementation audit
is provided by `ring_circuit_ranges_audit.rs`, outside this implementation's
ownership.

The ignored `alternating_range_components_screen` compares the prior ternary
representation with the candidate for one complete NTT and one complete
nine-NTT, five-polynomial commitment. Each component uses three matched pairs
in baseline/candidate, candidate/baseline, baseline/candidate order, under the
same explicit existing `2g`/`16m` builder limits. Every output is bound: the
last 64 to public inputs and all preceding coefficients to diagnostic-only
native oracle constants. Shape tests omit these diagnostic constants.

Native expected-output calculation and public parameter derivation are outside
component timing. One public transform derivation is included in each
construction for both representations. The screen reports wires, active and
padded rows, hints, prefinish and packed builder peaks, public-table time,
construction time and host trace evaluation. Programs, witnesses and traces
drop before the next measurement. This component screen does not measure a
transaction workflow, cryptographic proving or independent proof verification.

## Audited compiler and host results

Serialized coordinator qualification passed on 2026-10-25 UTC against checkpoint
`159a65b966809a87f19cc8844278ffec0cb3810d`. The combined direct-spend correctness
suite passed 90 tests, with five ignored: 79 library, three CLI and eight
relation tests. This includes eight focused range tests and six independent
range-audit tests. The component screen ran separately and passed all 12
measurements. The separate host-evaluator core tests passed five tests in each
of the narrow and wide layouts.

Three independent experiments each completed three matched alternating pairs:
range representation with the existing trace evaluator, the separate
constraints-only evaluator with the prior representation, and their
combination. All 18 full-relation compiler/host diagnostic runs passed. No run
generated a cryptographic proof or measured a complete transaction workflow.
The guards and raw-log hashes, terminal exit status, zero swap, stopped
services and frozen implementation hashes were audited. The completed common
driver SHA256 was
`dc7084fa9e9e538ef86d7cfb0f8246dbe8319dcd5fa04989233cdff4e63180b4`.
The integrated `ring_circuit.rs` includes the coordinator's `EvaluationBackend`
export and has SHA256
`8e042a3c16a66aa0ae511a623be85648df0f0ec887e18507e1743517daa6fefe`;
this supersedes its pre-integration freeze hash.

### Components

Both component screens used the measurement boundaries above. Times are
medians of three observations; counts were stable within each representation.

| Measurement | NTT baseline | NTT ranges | Commitment baseline | Commitment ranges |
| --- | ---: | ---: | ---: | ---: |
| Wires | 78,973 | 64,640 | 1,261,432 | 970,175 |
| Active rows | 12,234 | 9,578 | 200,488 | 146,641 |
| Padded rows | 16,384 | 16,384 | 262,144 | 262,144 |
| Witness hints | 768 | 768 | 9,757 | 9,705 |
| Builder requested peak before packing, bytes | 18,886,656 | 18,952,192 | 302,776,320 | 309,067,776 |
| Builder packed admitted peak, bytes | 18,886,656 | 18,952,192 | 302,776,320 | 309,067,776 |
| Component construction, seconds | 0.017224483 | 0.014637695 | 0.297589812 | 0.249720580 |
| Host trace evaluation, seconds | 0.001415309 | 0.001104786 | 0.023505347 | 0.018178364 |
| Construction plus evaluation, seconds | 0.018641033 | 0.015712580 | 0.321095159 | 0.268426076 |

The component padded heights are unchanged, and their packed builder peaks
increase slightly. The complete relation below crosses a padding threshold;
component geometry alone would not establish that result. Public transform
derivation remains included in construction for both versions. The screen
used the existing `build` guard, with an 8 GiB process cap, two threads and zero
swap; its observed cgroup peak was 346,406,912 bytes.

### Full relation with the trace evaluator

The range-only comparison selected the existing `8g` memory and `16m` wire
profiles for both representations, with the same deterministic ring fixture
and sealed evaluation-plan path. Pair order was baseline/candidate,
candidate/baseline, baseline/candidate. The baseline is `fused-ternary-ntt-v1`;
the candidate is `fused-ternary-ranges-v1`.

| Measurement | Baseline | Range candidate |
| --- | ---: | ---: |
| Wires | 8,012,253 | 6,114,044 |
| Active rows | 1,276,409 | 925,151 |
| Padded rows | 2,097,152 | 1,048,576 |
| Witness values | 60,030 | 59,822 |
| Builder requested peak before packing, bytes | 2,388,656,128 | 1,256,194,048 |
| Builder packed admitted peak, bytes | 2,388,656,128 | 1,263,185,448 |
| Retained program source bound, bytes | 930,640,144 | 675,761,592 |
| Whole-live evaluation admission bound, bytes | 2,722,791,416 | 1,664,198,040 |
| Trace backing, bytes | 1,577,058,304 | 788,529,152 |
| Wire-value backing, bytes | 64,098,024 | 48,912,352 |
| Median compiler-only time, seconds | 2.109942320 | 1.907033184 |
| Median host trace evaluation, seconds | 0.180019233 | 0.138008008 |
| Median total compiler diagnostic, seconds | 2.311420965 | 2.061153140 |
| Median observed cgroup process peak, bytes | 1,992,785,920 | 1,450,991,616 |

Active rows fall by 27.52%, padded rows halve, and the packed builder admission
peak falls by 47.12%. The 208 fewer witness values are exactly the four removed
52-bit duplicate amount-hint arrays. Median compiler time is 9.62% lower;
median total compiler-diagnostic time is 10.83% lower. The candidate reaches
the target `2^20` padded geometry. This does not establish a complete proving
memory bound or authorize proof execution, and the existing research compiler
row ceiling remains unchanged.

Compiler-only timing starts after fixture creation. Host evaluation timing
starts after retained-capacity planning. Total diagnostic timing includes
fixture creation, compilation, evaluation planning, reporting and drops; it
excludes Cargo, process launch and cryptographic proving. Logical admission
bounds and observed cgroup peaks are different measurements. Full runs used
the existing `research-compile` guard: a 16 GiB process cap, 14 GiB high
watermark, 20 GiB fresh-memory admission, two threads, CPU-required execution
and zero swap. The evaluation worker allowance remains 32 GiB. No faithful
RingCT GPU or complete-workflow resource/security limit changed.

### Separate evaluator and combined diagnostic

The constraints-only evaluator is documented in
`src/ring_circuit_evaluation/BOUNDS.md`. Its independent comparison holds the
prior ternary representation constant; the combined comparison selects both
changes. Each row below reports its own three matched pairs, so the baseline
medians differ slightly. None is a proving or independent proof-verification
time.

| Experiment | Baseline host evaluation, seconds | Candidate host evaluation, seconds | Baseline total diagnostic, seconds | Candidate total diagnostic, seconds |
| --- | ---: | ---: | ---: | ---: |
| Ranges, trace evaluator | 0.180019233 | 0.138008008 | 2.311420965 | 2.061153140 |
| Evaluator, prior ternary representation | 0.180931132 | 0.040281352 | 2.299231888 | 2.155173436 |
| Ranges and evaluator combined | 0.180972804 | 0.032157331 | 2.306050042 | 1.955442390 |

The combination's median total diagnostic time is 15.20% lower. It preserves
the range candidate's program geometry and packed builder peak, and admits
875,668,888 bytes for evaluation, including zero trace backing. Its median
observed cgroup peak is 1,192,755,200 bytes. This improvement remains separate
from complete-workflow throughput.

### Smaller compiler profile confirmation

After the matched screens, one separately selected `2g`/`16m` range+trace
confirmation passed. It used the existing 2 GiB program allowance, plus the
unchanged 128 MiB witness and 16 MiB auxiliary allowances: compiler admission
was 2,298,478,592 bytes. The program geometry, packed admitted peak and trace
evaluation bound exactly matched the `8g` candidate. This is a compiler-profile
check, not a claim that the entire process has a 2 GiB cap.

The single run took 2.121638682 seconds for compilation, 0.137812711 seconds
for host trace evaluation and 2.275325940 seconds for the total diagnostic.
Its observed cgroup peak was 1,453,953,024 bytes. This separately selected
measurement is excluded from the matched medians; no retry, fallback or
allowance increase was used.

### Evidence and remaining qualification

Guard `.json` records and raw `.log` files are retained in the integration
worktree under `.tools/pq-opencl-opt/runs/`, with these labels:

* `rowopt-core-host-{narrow,wide}-1` for the separate evaluator core tests.
* `rowopt-integration-direct-tests-1` for combined correctness and range audit.
* `rowopt-component-screen-1` for the 12 component measurements.
* `rowopt-{ranges,evaluation,combined}-pair-{1,2,3}-{baseline,candidate}` for
  the 18 full-relation compiler/host diagnostics.
* `rowopt-range-2g-confirmation-1` for the separate smaller compiler profile.

Campaign `ROW_OPT_STATUS.json` records every parsed measurement, guard hash,
raw-log hash and terminal audit. The correctness raw-log SHA256 is
`b8f729e89ab787f54f37e220de12df02e5adbae6dbc4cfe0036f369bae486e1c`;
the component raw-log SHA256 is
`20622d8fab34036ae4f0173f8b0dbde02aeb235bb52602ff0f5906d5d958d873`;
the `2g` confirmation raw-log SHA256 is
`ccb59180176adcb616f385fe830a63b7ca16ad3216ac65f3a2e79006acc857a6`.

The representation and evaluator remain opt-in with unchanged defaults.
Cryptographic proof orchestration, independently reconstructed verifier
identity, artifacts, complete-workflow resource qualification and qualified
security review remain required before adoption. The protocol-redesign gate
still requires at least a 2x complete-workflow improvement; these compiler and
host-evaluation results do not satisfy it. Production transaction acceptance
is unchanged.
