# Validation record, 2026-10-24

The coordinator ran these jobs serially under an 8 GiB cgroup memory cap and zero
swap. All listed subprocesses were terminal/reaped, and each guard confirmed its
source inputs remained unchanged. Times below are guarded job wall times; peaks
are cgroup observations for the entire job, which can include Cargo/build work.
They are not proof-only memory peaks or matched transaction throughput.

| Label | Outcome | Job wall seconds | Cgroup peak bytes |
| --- | --- | ---: | ---: |
| `concurrent-c-relation-tests-2` | 4 unit + 8 relation tests passed; separate real proof test ignored here | 2.085 | 276103168 |
| `concurrent-c-note-proof-test-1` | Fresh CPU note proof, independent verification, statement/proof mutations and artifact round trip passed | 4.087 | 276905984 |
| `concurrent-c-ring-compile-screen-1` | `ResourceLimit`; no ring proof started | 2.083 | 173010944 |
| `concurrent-c-ring-compile-screen-2` | Diagnostic build/run; same logical refusal, no ring proof started | 68.220 | 1183805440 |
| `concurrent-c-constant-relation-tests-1` | Constant-only representation build; 6 unit + 8 relation tests passed | 66.198 | 1186279424 |
| `concurrent-c-ring-compile-screen-3` | Constant-only representation passed startup, then refused the same program allowance during ownership constraints | 2.083 | 179613696 |
| `resume-c-montgomery-differential-1` | 9 unit tests passed; unjustified small-case memory monotonicity assertion failed; integration tests did not run | 72.225 | 1220321280 |
| `resume-c-montgomery-differential-2` | 10 unit + 8 relation tests passed; separate real note proof test ignored | 74.220 | 1225166848 |
| `resume-c-ring-compile-screen-4` | v2 build/run; unchanged program allowance refused during ownership constraints, no ring proof started | 30.141 | 958218240 |

The first relation build (`concurrent-c-relation-tests-1`) found a Rust type
inference error before executing tests/proofs. An explicit fixture Vec type
annotation fixed it. The diagnostic-only compiler change was subsequently built
and executed by screen 2.

The original inline representation failed while constructing public constants,
before allocating any private hint inputs. Screen 2 reported phase
`direct_relation_inputs`, logical limit `program_heap_request_allowance`, the
unchanged 268435456-byte builder allowance, an accepted requested-heap peak of
155975680 bytes, 778287 wires, zero input values and zero witness hints. A rejected
container-capacity growth can exceed the allowance even when the previously
accepted peak is smaller. The 134217728-byte witness allowance and 16777216-wire
limit were not exhausted. No complete graph row geometry or proof timing exists
for this failed compile.

Inspection identifies redundant canonical range-decomposition hints on
builder-known public constants as an immediate representation problem. The
`inline-public-constant-bits-v1` candidate uses the existing constrained
bit-reconstruction API on canonical public/fixed constants, preserving private
inputs and production modules. Boundary/no-hint/no-growth tests passed. Screen 3
advanced into `input_ownership`, then refused the unchanged program heap allowance
with accepted requested-heap peak 161480704 bytes, 795709 wires, and 6700 private
input/hint values. No proof started and complete graph geometry remains unavailable.
The original startup bottleneck is removed; the v1 inline representation is
still rejected. The different cgroup peaks above must not be confused with the
logical builder allowance or interpreted as a proof-performance comparison.

The v2 candidate, `inline-public-montgomery-constants-v2`, also folds the
canonical construction of public factors *inside* Montgomery multiplication.
The old helper reconstructed an adjusted public factor using private-style
canonical range constraints on every call. The candidate preserves the exact
operand range constraints, including when public factor zero or the Montgomery
identity folds the result. Nontrivial reductions use the unchanged modular
gadget, and private/private multiplication still has two reductions. Only the
two fixed profile moduli are admitted. The inverse radix is evaluated at compile
time, avoiding repeated public extended-Euclid work during circuit construction.

The first v2 suite passed the
arithmetic/canonical-input/hint-mutation and ownership-component unit tests, but
an assertion that every small case must use no more requested builder backing
failed on Q's public factor Q-1. Bounded maps and operation vectors grow in
steps, with admitted old/new overlap; fewer wires need not monotonically reduce
that peak. The revised test reports both peaks before assertions and keeps the
unchanged actual builder allowance, construction-failure and row/wire checks.
The retry passed all 10 unit and 8 relation tests, with the separate real note
proof still ignored. Its exact eight component measurements follow. `R` denotes
the canonical Montgomery identity `(1 << 32) % modulus`; all values below are
old backend -> v2, using the same folded public-constant inputs.

| Modulus | Public factor | Wires | Active rows | Padded rows | Input/hint values | Requested builder peak bytes |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Q = 167770241 | 0 | 704 -> 203 | 119 -> 34 | 128 -> 64 | 3 -> 1 | 150528 -> 70656 |
| Q | R = 100711271 | 717 -> 215 | 120 -> 36 | 128 -> 64 | 3 -> 1 | 140288 -> 70656 |
| Q | 1 | 708 -> 550 | 119 -> 92 | 128 -> 128 | 3 -> 3 | 150528 -> 150528 |
| Q | Q-1 | 722 -> 569 | 121 -> 94 | 128 -> 128 | 3 -> 3 | 140288 -> 141312 |
| QHAT = 3489661057 | 0 | 800 -> 227 | 135 -> 38 | 256 -> 64 | 3 -> 1 | 297984 -> 70656 |
| QHAT | R = 805306239 | 828 -> 254 | 138 -> 41 | 256 -> 64 | 3 -> 1 | 301056 -> 70656 |
| QHAT | 1 | 804 -> 626 | 135 -> 105 | 256 -> 128 | 3 -> 3 | 297984 -> 150528 |
| QHAT | QHAT-1 | 806 -> 632 | 135 -> 105 | 256 -> 128 | 3 -> 3 | 297984 -> 140288 |

Wires and active rows fell in all eight samples. Q's public Q-1 case increased
the requested builder peak by 1024 bytes (0.73%); no per-case heap monotonicity
claim is made. These are bounded construction diagnostics, not proving times.

The focused differential tests compare the old
backend and native arithmetic for both moduli, public/private operand positions,
zero and Montgomery identity, and canonical quotient/remainder mutation cases.
They also compare program equality for different private witnesses and report
wire/active-row/padded-row counts, hints and requested builder heap peaks. Those
heap peaks are sampled before builder finalization, matching the existing
compiler failure diagnostics; they are not process, proof, or complete-workflow
measurements. A separate first-four-coefficient ownership matrix diagnostic uses
the original AES-derived matrices, serial image and partial-NTT product oracle.
Its NTT states are private canonical inputs for the diagnostic only: this is not
a complete ownership circuit, decomposition, or proof API. The full relation
and native-reference differential tests remain required alongside it.

Full ring compiler screen 4 still refused `program_heap_request_allowance` in
`input_ownership`: unchanged 268435456-byte program allowance, accepted requested
peak 161480704 bytes, 796322 wires and 7724 private input/hint values. Screen 3
had 795709 wires and 6700 input/hint values at the same phase and accepted peak.
More private inputs/hints were constructed before refusal, but no phase closure,
complete graph geometry, ring proof or complete-workflow benefit was established.
The full 400 MiB compiler reservation and every wire/input bound remain unchanged.
Screen 4's 30.141 seconds include 29.17 seconds of release compilation and must
not be compared with prior screen wall times as a compiler/prover speedup.

No typed decomposition or limit increase was implemented. For future research,
the exact relation contains 52 NTTs and 120 NTT-ring products. Existing typed AIR
geometry would yield 46592 active NTT rows (65536 padded) and 145920 active product
rows (262144 padded) if each type were a single batch. Those counts do not establish
resource admission or recursive-parent fit. Any fixed component schedule would
need complete child verification, exact joins, independent expected-statement
verifier reconstruction and complete resource admission. Ring proving remains
unfinished; this screening does not authorize further proof dispatch or a speedup
claim.

Raw JSON guard records and logs are preserved in the agent-C worktree's ignored
`.tools/pq-opencl-opt/runs/` directory. Raw log SHA-256 values:

```text
concurrent-c-relation-tests-2       9cb2caa472eb12269d5ed5dedd2ae665effac627b7b5559cc1762fe2d2cd5efe
concurrent-c-note-proof-test-1      6e0c1f94a63a351eff510507e2cdfba76ed87c90623557c981d8e0af53127336
concurrent-c-ring-compile-screen-1  add4e607962c339ad05065bd94689dac36f022c98dcba8fa82b287f56c71a2b6
concurrent-c-ring-compile-screen-2  807d6469babaf31cedd81c39b0093fe880c533482b8f261f79db5e38a8587a1f
concurrent-c-constant-relation-tests-1 3b65703bfe2f1d553f9c6eef8193b87db3dbbd88e19292c45a19a0c95f368514
concurrent-c-ring-compile-screen-3  b7987f2574a606b503f4aef2aa6db880c591a19d12270cc65b90cd0cf0556b88
resume-c-montgomery-differential-1  a0c411d5878f639a7b37750795176918f119bef68d0976bc717339407d7c5a2c
resume-c-montgomery-differential-2  35f30eeff3cdc66b630c76c99388c72675d192938264540a5c7e75c2522d4f6d
resume-c-ring-compile-screen-4     7364cecb80d083670d1151f6f8c109a5e3eeee25185a23b7b788e9c96938f44a
```

The three `resume-c-*` guard JSON SHA-256 values are respectively:

```text
resume-c-montgomery-differential-1  7cd622ad10dd856bea6b2f261727681ba799553a038327810f4b031080428769
resume-c-montgomery-differential-2  fea49560f74d085a84883e7882409886545cfc0278aac38648ab26f05d2a2d8e
resume-c-ring-compile-screen-4     fe8c90b3faf851efabcd5183e522a90aa09f669b725f76cd280c887c65a3158f
```

Those records and logs live in the resumption C worktree's ignored run directory;
the earlier `concurrent-c-*` evidence remains in the original frozen C worktree.
All three resumption guards confirmed terminal/reaped subprocesses and unchanged
source inputs and executable. The failed first v2 suite is retained as evidence.

Agent B's read-only engineering review found no remaining blocker for the isolated,
unqualified research scope after fixes to compiler admission and public statement
binding. Qualified cryptographic/security review remains outstanding. Ring full
proving, aggregation and matched complete-workflow measurement remain incomplete;
the note test establishes correctness of this CPU research wrapper, not a 2x claim.
The subsequent v2 review also found no implementation blocker in its fixed-modulus
constant folding, retained canonical constraints and modular reduction equations.
It does not replace the required cryptographic review or admit the rejected ring
compiler.

The subsequently user-authorized memory experiment keeps all the above runs as
the `256m` baseline and adds explicit `2g` and `8g` program allowances. Their
complete logical compiler requirements are 2192 MiB and 8336 MiB, respectively;
the 128 MiB witness, 16 MiB auxiliary, wire/input/row and cryptographic limits are
unchanged. The coordinator's separate `research-compile` process guard has a
16 GiB cap, 14 GiB high limit, 20 GiB fresh-memory admission, two threads,
CPU-required execution and zero swap. Those guard limits do not describe the
earlier 8 GiB-guarded table. The new profile suite passed all 13 unit and 8
relation tests, with the separate real note proof still ignored. The two
memory-only screens retained the 16m wire ceiling:

| Label | Guard | Outcome | Guard wall seconds | Cgroup peak bytes |
| --- | --- | --- | ---: | ---: |
| `allowance-c-profile-tests-1` | build (8 GiB) | 21 passed; 1 real proof test ignored | 72.215 | 1270108160 |
| `allowance-c-ring-2g-screen-1` | research-compile (16 GiB) | `input_ownership` / `program_heap_request_allowance`; no proof | 32.139 | 1272401920 |
| `allowance-c-ring-8g-screen-1` | research-compile (16 GiB) | `input_opening` / `program_wire_count`; no proof | 6.091 | 3508461568 |

The `2g` program allowance was 2147483648 bytes, with a total logical compiler
requirement of 2298478592 bytes. The refusal reported 1247805440 accepted requested
builder bytes, 6240518 wires and 52642 private input/hint values. Its guard time
includes 29.01 seconds of release compilation, so it is not a matched runtime.

The `8g` allowance was 8589934592 bytes, with total requirement 8740929536 bytes.
It reached input opening, then refused at exactly 16777216 wires, with 136583
private input/hint values and an accepted requested builder peak of 4838129664
bytes. The program memory cap was not exhausted. This closes neither the entire
input-opening phase nor the complete circuit: no graph geometry, cryptographic
proof or complete-workflow benefit has been established.

All three guards confirmed unchanged source and executable, raw log hashes and
terminal/reaped subprocesses. Their guard JSON and raw log SHA-256 values are:

| Label | Guard JSON SHA-256 | Raw log SHA-256 |
| --- | --- | --- |
| `allowance-c-profile-tests-1` | `d1d36ae20d6715b64380a8eb1c9517d4b377fc566fc6e1a94f0374c530d27e64` | `f36b01ef05e1283f68cc4869ca21b8e1f09a525ff06a3bfc00e29da1a5f065b5` |
| `allowance-c-ring-2g-screen-1` | `457ceb2951b95d8b7b613344300e2db85b860f6ef6f883e2e8f35e93c7234d51` | `5ae54bad29a0df463688124c491f1270bf0326c28323f64127bec54acf4e4cad` |
| `allowance-c-ring-8g-screen-1` | `dbe58d4fa11953b0d88f919692aa8e7d852ac2f68826c7d6c241f8dbb25421d4` | `72a1192f4129fbac829d22baca9ea62ac2968c7a5f8de96fb43019a974315671` |

In response to the measured wire limit, a distinct, explicitly selected `64m`
wire profile now uses the core's existing 2^26 ceiling. It does not change any
memory-only default, shared prover code, witness/input/row limit or cryptographic
parameter. Its focused suite passed 14 unit and 8 relation tests, with the real
note proof ignored. The `8g` + `64m` screen refused program backing during input
opening at 24912690 wires and 203193 input/hint values. The accepted requested
builder peak was 4978638848 bytes; a refused capacity growth need not first reach
the 8589934592-byte logical allowance. No ring proof started. These results remain
separate from the memory-only evidence above.

| Label | Guard | Outcome | Guard wall seconds | Cgroup peak bytes |
| --- | --- | --- | ---: | ---: |
| `allowance-c-capacity-tests-1` | build (8 GiB) | 22 passed; 1 real proof test ignored | 4.088757297 | 330899456 |
| `allowance-c-ring-8g-64m-screen-1` | research-compile (16 GiB) | `input_opening` / `program_heap_request_allowance`; no proof | 8.101673758 | 4767637504 |

Both guards confirmed unchanged source and executable, raw log hashes and
terminal/reaped subprocesses. Their SHA-256 values are:

| Label | Guard JSON SHA-256 | Raw log SHA-256 |
| --- | --- | --- |
| `allowance-c-capacity-tests-1` | `a287ad8cea716e457a1a66f9ddc30852ffb8b3f3393d13309939830cfdca67e7` | `9e43ad6a7cfd54476d6a25d3ea16bc5a6510a7442dc8f96b93ccdabd8c76d7e1` |
| `allowance-c-ring-8g-64m-screen-1` | `8ffefdec6c839f3eae08b4433cca3e1f0c38c2eaae1f01339414a01e21cd4252` | `83e9b06eb152a9db88b6181a806c3f4f165d5de140ef696d3ae49cb50aea97d1` |

The next explicit memory profile is `24g`: 25769803776 program bytes and
25920798720 bytes (24720 MiB) for the whole logical compiler. It retains the
32 GiB worker host ceiling, 128 MiB witness and 16 MiB auxiliary allowances,
2^24-4 input limit, 2^24 padded-row limit, default `16m` wire selector and
separately selected core `64m` ceiling. The coordinator's new
`research-compile-large` process guard provides a 32 GiB cap, 30 GiB high limit,
36 GiB fresh-memory admission, two CPU-required threads and zero swap. The
`24g` + `64m` screen again refused during input opening, this time at the existing
core ceiling of exactly 67108864 wires. It reported 540528 private input/hint
values and 19339935744 accepted requested builder bytes, below the selected
25769803776-byte program allowance. The program allowance was not exhausted.
The 14056914944-byte cgroup peak is a separate whole-process measurement. The
guard wall time includes 29.20 seconds of release compilation and is not a
matched compiler/prover runtime. No intermediate profile, automatic retry,
shared-core limit change or proof dispatch was introduced.

| Label | Guard | Outcome | Guard wall seconds | Cgroup peak bytes |
| --- | --- | --- | ---: | ---: |
| `allowance-c-24g-profile-tests-1` | build (8 GiB) | 22 passed; 1 real proof test ignored | 76.216884732 | 1252175872 |
| `allowance-c-ring-24g-64m-screen-1` | research-compile-large (32 GiB) | `input_opening` / `program_wire_count`; no proof | 46.161986175 | 14056914944 |

Both guards confirmed unchanged source and executable, raw log hashes and
terminal/reaped subprocesses. Their SHA-256 values are:

| Label | Guard JSON SHA-256 | Raw log SHA-256 |
| --- | --- | --- |
| `allowance-c-24g-profile-tests-1` | `d268f20f297195e8c62ad98524467c7eb4eb5aedd739f596f7890b380749ff96` | `c05372235f89243d099a65eb6c0fc1711549f0ab0ed6d1162f6d23f5489d265a` |
| `allowance-c-ring-24g-64m-screen-1` | `20ab365af5c1b9870adf7e1e6b58f7836530343b141d38b100261cb2efa51071` | `b786ee73f247d3f63e510f5472d1e548e25a2a4f68ce242fd7ca27866d4ce1a2` |

The final focused suite exercises all four closed memory choices, exact
admission boundaries and pre-builder refusal, unchanged small-program semantics,
and single-attempt failures. Its explicit 64m checks cover both 8g and 24g actual
builder configuration and diagnostic serialization without allocating a large
circuit. Agent A's read-only review found no blocker in either the capacity
extension or the 24g delta; it does not replace qualified cryptographic review.

The inline full-ring compiler is rejected at the supported core wire ceiling.
No complete ring graph, proof, aggregation or complete-workflow measurement
exists for these screens. The default remains 256m/16m, all earlier evidence is
retained, and no profile is promoted on a speedup claim. Further research would
require a separately designed representation that fits the existing core limits
and preserves the full relation; no such decomposition is implemented here.


## Full GPU implementation component checks (2026-10-25)

The optional `gpu-proving` path and complete phase admission are implemented.
The first full-proof screening run is recorded below. The wide relation host check passed
321,793 active / 524,288 padded rows with no deferred obligations. This is host
constraint evidence, not a cryptographic proof or throughput result.

The following guarded runs have terminal integrity, unchanged-source/executable,
log hash and zero-swap audits. Times and peaks describe the entire guarded job,
including any build; they are not isolated proof measurements.

| Run | Status | Guard seconds | Process peak bytes |
| --- | --- | ---: | ---: |
| `fullgpu-direct-focused-tests-1` | passed | 6.096 | 344891392 |
| `fullgpu-direct-updated-tests-2` | passed | 82.242 | 1488617472 |
| `fullgpu-core-codec-tests-1` | passed | 248.549 | 5439500288 |
| `fullgpu-direct-tree-gpu-parity-1` | passed | 22.129 | 516825088 |
| `fullgpu-host-tree-batch-1` | failed_or_incomplete | 2.090 | 179081216 |
| `fullgpu-host-tree-batch-2` | passed | 2.090 | 177168384 |
| `fullgpu-device-tree-batch-1` | passed | 2.096 | 178774016 |

`fullgpu-direct-tree-gpu-parity-1` passed three actual GPU tests, including odd
counts, both offset orders, complete caps/paths and rejected geometry. The first
combined tree-storage test passed the default-device case, then refused the host
case because the runner selected `device`. Its failed record is preserved. The
explicit `host` rerun and isolated default-device regression each passed.

Evidence records and logs live under the campaign integration worktree's
`.tools/pq-opencl-opt/runs/<label>.{json,log}`; their SHA-256 hashes are retained in
`GPU_PROVING_STATUS.json`. None of these runs establishes a complete direct-spend
GPU proof, a complete faithful RingCT graph or a measured workflow speedup.


Further source-qualified component checks:

| Run | Status | Guard seconds | Process peak bytes |
| --- | --- | ---: | ---: |
| `fullgpu-consuming-unit-tests-1` | passed | 244.552 | 5319991296 |
| `fullgpu-drain-failure-cleanup-1` | passed | 2.088 | 186904576 |
| `fullgpu-independent-reconstruction-1` | passed | 92.245 | 2080083968 |
| `fullgpu-full-height-codec-1` | passed | 4.091 | 313655296 |
| `fullgpu-research-guard-policy-5` | passed | 2.073 | 19664896 |
| `fullgpu-complete-admission-tests-2` | passed | 250.555 | 5342638080 |

The lifecycle suite passed five tests; complete phase planning passed ten tests;
the numerical evidence policy suite passed 71 tests. The independent full-program
comparison passed for actual, zero and patterned private hints and the existing
2g/8g compiler capacities. This comparison performs no GPU dispatch or proof.

The full-height codec shape encoded to 1,783,741 inner bytes (1,783,953 total),
leaving 313,411 bytes under the unchanged 2 MiB inner limit. Bounded decode,
canonical re-encoding and one-byte-short rejection passed. This is a fixed-shape
transport check, not a valid cryptographic proof.

Preserved attempts include `fullgpu-research-guard-policy-3`, refused before
execution because the Rust-binary receipt flag was used for Python unittest,
and `fullgpu-complete-admission-tests-1`, which failed compilation on a missing
borrow in configuration capture. Subsequent labeled runs corrected those errors.
A further reviewed fix binds the effective host-output ceiling to preflight;
all 12 focused admission tests passed in `fullgpu-complete-admission-tests-3`.

### First complete GPU research screening

All runs below passed unchanged-source/executable/log and terminal cleanup
audits with zero worker swap. The larger `direct-full` guard is the existing
research profile; the faithful RingCT limits were not changed.

| Run | Guard seconds | Process peak bytes | Result |
| --- | ---: | ---: | --- |
| `fullgpu-direct-updated-tests-3` | 84.248 | 1497022464 | 101 tests passed; 9 explicit expensive tests ignored |
| `fullgpu-complete-memory-diagnostic-1` | 4.093 | 1224183808 | Complete numeric phase plan; no GPU dispatch |
| `fullgpu-small-consuming-gpu-1` | 24.125 | 1183932416 | 3 fresh GPU proofs, 6 mutations, 5 closed contexts |
| `fullgpu-baseline-registration-smoke-2` | 72.205 | 1224613888 | Default registration/fresh randomness GPU regression |
| `fullgpu-direct-workflow-1` | 208.421 | 7341268992 | Fresh complete relation proof, disk round trip, independent CPU verification, 2 mutations |
| `fullgpu-forged-envelope-gpu-1` | 406.811 | 7368585216 | Authentic proof rejects forged recipient/context envelopes numerically |

The first complete research workflow itself took 207.807508885 seconds. Prover
setup took 96.211046703 seconds, proving 8.749326500 seconds, independent verifier
setup 96.252463235 seconds, and CPU proof verification 0.031487190 seconds. The
valid artifact is 1,783,953 bytes. The GPU managed peak was 8,388,675,144 bytes,
below the unchanged 8 GiB limit. No proof or public preprocessing was reused.
The identity sponge alone consumed 92.312224896 seconds of preprocessing device
time; transform and commitment are separately reported and must not be conflated
with that bottleneck.

The complete diagnostic's conservative host peak is 19,245,260,080 bytes;
its minimum device requirement is 8,403,918,872 bytes and adaptive ceiling is
8,589,934,592 bytes. Its largest allocation is 2,147,483,648 bytes. The effective
host-output binding means the smaller smoke profile cannot admit this complete
plan. The explicit ignored diagnostic and consuming tests therefore use the
existing `direct-full`/host profile. The verifier caller census is 1,040,376 bytes
inside the unchanged 1 MiB reservation (8,200 bytes spare).

The forged-envelope test uses a second fresh GPU proof, then independently
rebuilds preprocessing for changed recipient and context statements. All public
transport claims are changed to match those statements before numerical proof
verification rejects them. Restoring the envelope reproduces the original
canonical artifact digest.

Source/evidence provenance is summarized in
[`direct-ring-gpu-screen-2026-10-25.json`](../../docs/evidence/direct-ring-gpu-screen-2026-10-25.json).
The original records, logs and four workflow artifacts remain in the campaign
worktree. Repeated matched performance, complete faithful RingCT graph/aggregate
screening and qualified security review are still pending; this result does not
establish the research profiles' 2x improvement gate. The guard refusal
`fullgpu-feature-build-6` (relative artifact path) is preserved; the subsequent
absolute-path build was audited successfully.
