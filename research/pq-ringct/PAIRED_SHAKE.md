# Paired SHAKE wrapper candidate

`ShakeWrapperLayout::Singleton` is the default and retains the existing proving
path. `PairedV1` has an exact, allocation-free schedule, but **paired proving is
not implemented or qualified**. Selecting it through
`SpendPipeline::with_shake_wrapper_layout` returns a qualification error before
any proof dispatch. There is no fallback to Singleton and no retry after proof
execution. This is a rejected admission experiment, not a throughput result.

`Request::shake_wrapper_schedule` borrows the immutable registered serial SHAKE
request. It checks complete coverage and every segment's original first unit,
count, height and width. PairedV1 groups two consecutive native segments; only
the final odd segment is a singleton. Native batching, the padding and squeezing
AIRs, AES, transcripts and security parameters are unchanged. The reported
native/recursive counts describe a schedule, not measured work. The historical
445-to-327 estimate has not been established by this implementation.

The bounded group compiler rejects missing, reordered, overlapping or duplicate
intervals and all 108 interior state/input/output field mismatches before
acquiring endpoint preparation or allocating compiler storage. It continues to
emit all 108 recursive equality constraints. Host endpoint checks cannot replace
native proof verification or recursive proof acceptance.

## Why full-workflow admission is still refused

The source-complete checkpoint includes useful prerequisites, but composing them
does not yet establish a complete memory bound:

| Existing component | Qualified scope | Missing enclosing admission |
| --- | --- | --- |
| `ConstructionLimits` and bounded SHAKE compiler | Requested builder/program storage, wire count, total witness-value limit; explicit bounded CPU symbolic recording; public-shape auxiliary storage admission before endpoint sessions | Its numeric auxiliary allowance is not yet a planner-issued ownership token. Enclosing retained proofs, GPU endpoint/backend storage, allocator overhead and recursive closure still need admission. |
| `NativeRetentionShape` and `RetainedNativeChild` | Public-shape output-capacity bound and post-generation nested capacity audit | No ownership token reserves the output and siblings before allocation and follows the child through moves/drop. Numerical native-verifier scratch needs a source-derived enclosing reservation. |
| Remaining-host native/outer proving APIs | Reduced registered/native GPU host allowances; FreshOnly and GpuRequired checks | A numeric remaining allowance does not retain accounting for sibling proofs, carry-stack nodes, reports, compiler inputs or independent CPU verification. |
| Registered outer verification | `RegisteredVerifier::host_reservation_bytes` exposes the existing checked release-x86_64 lifecycle plan before cap/setup allocation; its source-derived ceiling is 257 MiB | The caller still needs ownership admission for the matching cap geometry and retained proof/key owners. Unqualified target/build profiles refuse the public reservation. This bound does not apply to native uni-STARK verification. |
| Component geometry diagnostics | Exact geometry for the particular compiled node; some tests register invalid proof-shaped fixtures | No pre-dispatch closure qualification for every selected component wrapper, component merge, consuming graph leaf, graph merge, and final N3/N4 aggregate. Sampled shape geometry is not complete closure evidence. |

A numeric scratch allowance alone cannot fill the ownership and closure gaps. The
existing 32 GiB worker, 24 GiB native, 8 GiB managed GPU, 4 GiB context, 47 GiB
process and zero-swap limits have not been increased to make this candidate fit.
Source inspection alone does not show that PairedV1 cannot fit; it shows that the
current code cannot safely admit it. No claim of a measured memory failure is
made.

## Next implementation gates

1. Qualify the new bounded symbolic/periodic/compiler prerequisite with the
   guarded reference-parity and refusal tests. Preserve the independent
   unbounded reference used by default Singleton. These are compiler checks;
   they do not qualify native numerical verification or the complete workflow.
2. Introduce planner-issued ownership reservations for native outputs, recursive
   proof/key outputs, carry-stack nodes and reports. Keep each reservation with
   the owner, reserve compiler inputs/temporaries and CPU verifier scratch before
   their phases, and release reservations on every success/error/drop path.
3. Compile the complete selected public-shape graph and final aggregation under
   the same row/resource limits before native proof dispatch. Shape fixtures
   must remain explicitly invalid and cannot become proof acceptance receipts.
4. Only then connect the immutable pair schedule to the bounded compiler and
   fresh proving path. Propagate every refusal; do not change grouping or retry
   after dispatch. Run focused proof/mutation/closure checks and the separately
   guarded alternating component and full-workflow benchmarks.

The added fast tests cover Singleton default/refusal, exact pair/odd-tail
schedules, absorb/padding/squeeze transitions, missing/reordered/duplicate and
registration mutations, AES exclusion, and each interior boundary field. They
do not qualify paired proofs, cleanup after real asynchronous proving, recursive
height closure, or a full-workflow speedup.

## Bounded compiler prerequisite

`verifier::uni::verify_bounded` uses the existing bounded recorder and normalizer
on the CPU. It borrows a caller-owned periodic table, preserving the constrained
verifier, proof-input order and transcript operations. Both 64 MiB recording and
normalization quotas remain enforced. AIR callbacks' own vectors are admitted by
the enclosing SHAKE footprint, separately from those internal quotas.

The exposed symbolic allowance has two independent parts: **192 MiB transient
workspace** and **64 MiB retained normalized graph**. Recording and normalization
scratch drops before lowering; the returned normalized expressions stay owned
until lowering finishes. The auxiliary formula conservatively adds both, even
though some output storage is also covered during the workspace phase. It never
uses the transient allowance as permission to retain the graph after its phase.
ProgramBuilder storage remains a separate reservation throughout both phases.

`ShakeGroupCompileFootprint::for_group` performs checked, allocation-free
arithmetic for the pinned release-x86_64 lane SHAKE source. It includes one
42-by-128 periodic table and construction overlap, AIR public/periodic/counter/
update vectors, descriptor and endpoint containers, verifier helper containers,
two simultaneous ProofInputs value buffers and cumulative returned-wire backing.
Overflow and unsupported profiles return small typed errors. The grouped
compiler checks the footprint before opening an endpoint preparation session or
allocating AIR/compiler storage. This payload formula excludes allocator/RSS,
already-owned proofs, recursive reports and device/backend endpoint workspace;
those require the future enclosing planner. The 512 MiB test auxiliary allowance
is an explicit test limit, not a replacement for the derived footprint.

The compiler qualification uses deliberately invalid native shape fixtures and
compares complete program manifests, input order and public/spec metadata with
the independent reference. Cases cover one segment, absorb/padding and
padding/squeeze transitions, and native batches of eight permutations. A separate
core test proves a small counter AIR and checks bounded/reference equality plus
wrong-public and proof mutations. No grouped proof or GPU speedup is inferred.

## Qualification results, 2026-10-24

The coordinator serialized these CPU-required runs under the unchanged build
guard: 8 GiB process maximum, 6 GiB high watermark, zero swap, two build jobs,
two Rayon threads and one test thread. Every report records success, unchanged
source/executable inputs and terminal/reaped subprocesses. Core tests used
release `block-v2-wide-lanes,stream`; research tests used release
`opencl native-matrict recursive-wide`, with no endpoint GPU context or grouped
proof dispatch. Unsupported-profile rejection is source-gated and has a debug
test; this run qualifies only the release x86_64 profile.

| Check | Outcome |
| --- | --- |
| Bounded uni reference/input-order parity, real counter proof and mutations | 2 passed |
| Independent registered-verifier lifecycle and allocation-free cap/overflow admission | 7 passed |
| Ordinary SHAKE boundary, resource classification and auxiliary tests | 5 passed; 2 explicit screens ignored in this invocation |
| Guarded compiler parity screen | 1 passed, covering all five cases below |
| Guarded resource/proof-shape classification screen | 1 passed |

| Template case | Padded rows | Wires | Proof input values |
| --- | ---: | ---: | ---: |
| Single padding segment | 131072 | 1504008 | 155319 |
| Absorb then padding | 262144 | 3004416 | 310638 |
| Padding then squeeze | 262144 | 3002631 | 310638 |
| N8 native absorb segment plus singleton tail | 262144 | 3208244 | 337268 |
| N8 native squeeze segment plus singleton tail | 262144 | 3204662 | 337268 |

The paired compiler screen reserved **2147483648 builder bytes** and
**536870912 auxiliary bytes**, with at most 1048576 proof-input values and the
unchanged `MAX_WIRES`. The largest builder-accounted requested peak was
**647219296 bytes**. Separately, the guard recorded **553648128 bytes process
cgroup peak**, **10.094897 seconds job wall time**, and **8.84 seconds test time**.
Requested storage and observed process memory are different measurements.
These figures cover compilation of invalid templates and reference comparisons;
they are not valid native/recursive proofs, GPU measurements or workflow speedup.
Pairs fit this compiler screen. Ownership admission and full descendant closure
remain unresolved, so PairedV1 still refuses before execution.

Raw evidence remains outside Git under
`/home/access/code/lattica/.tools/ringct-concurrent/campaign-20261024/agent-b-shake/.tools/pq-opencl-opt/runs/`.
Each stem below has a `.json` guard record and `.log` raw output. SHA-256 hashes
pin the inspected artifacts; no benchmark binaries or result directories were
added to the source commit.

| Stem | Guard JSON SHA-256 | Raw log SHA-256 |
| --- | --- | --- |
| `concurrent-b-bounded-uni-tests-1` | `ec4afa478c3cac9110c21eaaf0a2ec89fa0f5276c7c9508e051395d05d13a23e` | `680d278d3de259c0851a807f7b6e6a61e6b0eb0909c8eb07f6d34128137d7b39` |
| `concurrent-b-verifier-lifetime-tests-1` | `7fa5caa78fd4564beeebf104343cf0afbfb3f37906134aa64df3c9a952dcc239` | `f5e2933fd40d775a59b8165822347a3a7a763d6458380a2ba8536084f71ff6b1` |
| `concurrent-b-bounded-shake-tests-1` | `6249c70ee943524c53e95eb4093ad24d5a2e5d66f755a92ab0556aa1bf66a04f` | `ef4d37200c9f2a392bd5f1faa58b034427447115dd670676e4510905767b6bb4` |
| `concurrent-b-paired-compiler-screen-1` | `f7d2792e548c745149694f5d7b4305d65784e7807e52dcf882d88a7150a53589` | `a48181aee77e2d06d53d9c716274801f5763cf83cf270cefa140ecd7c0b00dba` |
| `concurrent-b-paired-resource-errors-1` | `96b9037563f8fffae416240df492dff80eb09653e0b7a3b7efc488f65da19cb3` | `840a454cbad3aae8fa063ebc2d14119f32a382606b440608779a83ee5202f1e8` |
