# Fixed-Q fused public linear representation

`fused-public-linear-v1` is an explicit research compiler representation. The
default remains `inline-public-montgomery-constants-v2`. Select it with
`compile_with_representation_diagnostics(statement, witness, expected_context,
capacity, CompilerRepresentation::FusedPublicLinearV1, host_allowance)`.
Success and failure diagnostics identify the selected representation, including
refusals before compiler allocation. Capacity selection does not select an
arithmetic representation, and a refusal does not trigger another attempt.

This candidate preserves the direct ring relation. It changes how public matrix
products are represented in constraints; it does not change the native protocol,
private key/opening distribution, ring size, value width, serial derivation,
security parameters, proof system or production acceptance. It exposes no proof
dispatch API. Full compiler admission and host evaluation are not cryptographic
proofs and do not establish complete-workflow performance.

## Exact relation being replaced

The direct relation has two ownership equations and four commitment equations.
They use 52 inline NTTs and 120 products of a public matrix polynomial with a
private transformed polynomial. Each commitment contains 22 such products and
nine NTTs. `ring_native::multiply_add` currently expands a product through
`generic::mul_residues`, then adds its canonical result to the accumulator.
The product has 64 independent quartic blocks. Each block performs 16 first
Montgomery reductions, six wrapped second reductions, and 16 modular additions
or subtractions. Each multiplication and addition constructs fresh bounded
reduction hints.

The candidate retains all 52 NTTs, all signed ternary input constraints, and all
canonical transformed values. For each final matrix output coefficient, it
collects the public coefficients of the same linear map and constrains a single
bounded quotient and canonical remainder. It replaces the 120 expanded matrix
products and accumulations with 7168 scalar output equations. The original
52-bit amount encoding and its additional Montgomery operation remain intact.
These are static schedule counts, not measured wire counts or speedups.

## Public coefficient derivation

Let `R = 2^32`, `Q = 167770241`, and `R_inverse = 54987456 (mod Q)`.
For quartic output position `t` and private input position `j`, the public input
position is `i = (t + 4 - j) mod 4`. The coefficient multiplying the private
canonical value is:

| Condition | Canonical public coefficient modulo Q |
| --- | --- |
| `i + j < 4` | `a[i] * R_inverse` |
| `i + j >= 4`, positive wrap | `a[i] * omega * R_inverse^2` |
| `i + j >= 4`, negative wrap | `-a[i] * omega * R_inverse^2` |

The wrap sign and omega position are the existing frozen `MUL_Q` and `OMEGA_Q`
metadata, re-exported by the shared research verifier without changing values.
The second inverse-R factor is necessary because the original wrapped path
performs a second Montgomery operation. Canonicalizing a negative coefficient
changes the unreduced integer sum but preserves its unique canonical result
modulo Q. All coefficients are determined by public parameters, never private
values or witness-selected branches. The same AES-derived matrices and serial
images are used as before.

## Integer soundness bound

The helper accepts at most 20 products of a public canonical coefficient with a
private canonical residue, plus at most two canonical addends. Its modulus is
fixed to Q. Other moduli, noncanonical host inputs and excess arity are rejected
before the helper adds witness hints. The input residue type is sealed by the
existing canonical constraint gadget; the host values only generate hints.

For every permitted input, the unreduced sum S satisfies:

```text
S <= 20*(Q-1)^2 + 2*(Q-1)
  = 562937068928692480
```

The helper supplies quotient k and remainder r, constrains
`0 <= k <= 20*(Q-1)+2 = 3355404802` and `0 <= r < Q`, and enforces
`sum(coefficient * input) + sum(addends) = k*Q + r` in the proof field.
The exact maximum quotient at the largest input is 3355404782; the chosen
slightly larger public bound is safe. Its largest possible right-hand side is
562937072451867522. Both sides are strictly below the Goldilocks modulus
18446744069414584321, so a field equality cannot conceal an integer wrap.
Canonical r makes the modular result unique. Compile-time assertions pin the
modulus, inverse-R identity and both no-wrap bounds.

This 20-term construction must not be generalized to QHAT: the analogous sum
would exceed the base field. It also must not drop the quotient bound, drop
canonical input/result constraints, or treat a supplied output digest as proof
of the linear map. Public zero coefficients do not remove already emitted
canonical constraints on private inputs.

## Admission and binding

The candidate uses the existing closed memory/wire profiles and worker, witness,
input and row limits. Its temporary term/addend arrays have fixed bounds. The
existing builder checks each allocation; the helper invokes the existing phase
guard before creating its two hints and after completing constraints. It keeps
the existing full-circuit row admission and rejects unresolved obligations.

The parent compiler still validates the expected context and full statement,
derives the public AES parameters and serial image, embeds the public statement
binding, constrains one hidden selection among ten pairs, checks both ownership
and opening equations, and enforces balance. This representation does not supply
the missing independently reconstructed ring verifier, proof graph or artifact
protocol. Those remain separate research work requiring qualification and
cryptographic review.

## Verification and qualification scope

Focused tests cover exact integer boundary cases, witness-independent program
shape, changed public coefficients, explicit representation selection and
pre-allocation/context refusal identity. Small quartic matrix diagnostics compare
the candidate to the existing constrained scalar schedule and to the untouched
native full-polynomial oracle for both wrap signs. Independent audit tests check
coefficient derivation, canonicality, quotient/remainder mutations and field-wrap
attacks. All tests are run only by the serialized validation coordinator.

The ignored `alternating_matrix_component_screen` runs three matched pairs in
baseline/candidate, candidate/baseline, baseline/candidate order. It uses one
quartic block of a five-column commitment equation, reporting wire/row counts,
builder requested peak before final packing, hint count, construction time and
host evaluation time. That builder snapshot is neither a final-packing peak nor
a process-memory observation.
Each program, trace and witness is dropped before the next iteration. Its NTT
states are canonical private diagnostic inputs: the screen is not a proof of
their derivation, an implementation of decomposition, or a transaction workflow.
The component has its own fixed historical builder bound; full compilation and
bounded full-witness evaluation require separate guarded jobs.

The guarded measurements below establish component results and successful full
compilation and host constraint evaluation for the candidate. They do not
establish cryptographic proof performance or complete-workflow throughput. The
default representation is unchanged, and qualified cryptographic review remains
required before adoption.

## Audited measurements

The coordinator ran these serialized jobs in the campaign integration worktree
on 2026-10-25 UTC (2026-10-24 local campaign date). All listed guard records report
unchanged source inputs and executable, completed service cleanup, and all
subprocesses terminal and reaped. The raw-log hashes were checked against the
guard records. The three C-owned Rust files also match the source hashes recorded
for every listed job.

The corrected combined correctness run passed 39 tests with two ignored tests
across the library, CLI, and integration suites. This includes the independent
linear arithmetic audit. The first run is retained as failed evidence: one audit
harness requested 256 public outputs although the core permits 64, and received
`TooLarge` before constructing its test circuit. The corrected harness binds 192
expected constants and 64 public outputs, with its input limit bounded by the
remaining wire allowance. No arithmetic constraints or resource ceilings were
weakened to make that test pass.

### Alternating component screen

Three matched baseline/candidate pairs ran in the documented alternating order.
Counts were identical across the three repetitions of each representation; the
times below are medians. This screen covers one quartic block of a five-column
commitment equation, using canonical private NTT-state inputs without proving
their derivation.

| Measurement | Inline public Montgomery baseline | Fused public linear candidate |
| --- | ---: | ---: |
| Wires | 58,688 | 5,684 |
| Active rows | 9,870 | 948 |
| Padded rows | 16,384 | 1,024 |
| Witness hints | 444 | 32 |
| Builder requested peak before final packing, bytes | 18,923,520 | 1,185,792 |
| Builder packed admitted peak, bytes | 18,923,520 | 1,262,568 |
| Median construction time, seconds | 0.011046334 | 0.001004300 |
| Median host evaluation time, seconds | 0.001015201 | 0.000091063 |

The guard used the `build` profile: 8 GiB process cap, 6 GiB high watermark,
10 GiB fresh-memory admission, two threads, CPU-required execution, and zero
swap. The process peak for the entire six-measurement job was 45,019,136 bytes;
this is distinct from the builder counters above. No proof was generated.

### Full compilation and host evaluation

The full candidate used explicit `24g` memory and `64m` wire profiles and
`fused-public-linear-v1`. Compilation completed with no deferred cryptographic
obligations, and the separately admitted host evaluation satisfied every
constraint for the fixture witness.

| Candidate measurement | Result |
| --- | ---: |
| Wires | 35,806,310 |
| Active rows | 6,017,802 |
| Padded rows | 8,388,608 |
| Witness values | 299,646 |
| Builder packed admitted peak, bytes | 9,676,259,328 |
| Builder packed live bytes | 4,415,564,446 |
| Evaluation admitted host footprint, bytes | 32,515,482,416 |
| Compiler-only time, seconds | 9.533136086 |
| Host constraint evaluation time, seconds | 0.800464827 |
| Guard wall time, seconds | 12.107935683 |
| Cgroup process peak, bytes | 9,316,761,600 |

The evaluation footprint reserves the configured program and witness allowances,
trace storage, wire values, and auxiliary storage. It is a conservative admission
bound, not observed resident memory. Builder packing counters and cgroup process
peak measure different things and must remain separate.

The matched current baseline used the same `24g`/`64m` profiles and refused in
`input_opening` at the 67,108,864-wire ceiling. Its compiler-only time to refusal
was 16.548089529 seconds and its cgroup process peak was 14,071,517,184 bytes.
That elapsed time represents incomplete work and cannot be divided by the
completed candidate time to claim a speedup. The baseline guard remains marked
`failed_or_incomplete`; its refusal evidence is preserved.

Both full jobs used `research-compile-large`: 32 GiB process cap, 30 GiB high
watermark, 36 GiB fresh-memory admission, two threads, CPU-required execution,
and zero swap. The existing 32 GiB worker ceiling and all faithful RingCT GPU,
host, thread, row, and security limits remain unchanged.

These results remove the candidate's compiler-capacity blocker for this fixture.
They do not supply proof orchestration, independent cryptographic verification,
artifact round trips, recursive aggregation, or complete-workflow measurements.
Neither a complete-workflow speedup nor the research promotion threshold of 2x
has been established.

### Evidence hashes

Raw files are in the integration worktree at
`.tools/pq-opencl-opt/runs/`. Each label below names both its `.log` and `.json`
files. Failed and incomplete records are retained alongside successful runs.

| Label | SHA256 of `.log` | SHA256 of `.json` |
| --- | --- | --- |
| `wireopt-integration-direct-tests-1` | `b04530429b1baf5ef7ccd4e9872310c49120124d3b3398d6b808a05ed0b745f3` | `7a0e48d05714659162caf4392bf96dbe51ffabc578f620d786d16145ead42f13` |
| `wireopt-integration-direct-tests-2` | `98815de4679130a16795fd4e1b2811d0262c1f515508d3cb2b22c3036186c603` | `f18c3ad69056a195b2f42ec3f9652ce244bb1e51e2356875bfe6185bf6849e2a` |
| `wireopt-integration-component-screen-1` | `7387c237459961a8bbe07ace83e24006e14d925e6e2211659e69aee7fdbca5c3` | `a0cfbc398c1b5d88b0cb57f120f9f4ac9a8ad9db4c9a841adb639ef3e959a8cb` |
| `wireopt-integration-driver-build-1` | `bc9ea4cf0357a57140c00af1d30c217e65baf5901ca9ba4835f76800b79b8602` | `668950196334f011d8c1151014bec45ecf105f5b1d42fab8a69debbf5626e26c` |
| `wireopt-integration-baseline-compile-1` | `26cfd2365dd55d78e66250c6d7927a5027a93b196ee74a7077ff42823c21e51d` | `80eccb6eeeb59ab63d624ad358762fb098bcc277dd7334e5c6032292db26b1ed` |
| `wireopt-integration-fused-compile-evaluate-1` | `b1c7b0417361ce46c7c435459df417b107102157cf0a743059a6119db1c4f30f` | `368119d62d3a628f3654f617104259d1fc349dff792763bd64ebf4b737627d05` |
