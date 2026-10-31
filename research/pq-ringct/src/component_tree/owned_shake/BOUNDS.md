# Closed SHAKE compiler ownership prerequisite

The additive [CPU endpoint constraint qualification](endpoint_qualification/BOUNDS.md)
uses valid source-derived byte roots in a test-only bounded evaluator. Its
authored coverage and pending validation are distinct from the earlier
placeholder-root compiler-equivalence evidence below.

`GroupCompilePlan` borrows one exact immutable `Request`, selects one ordinal
from its fully checked Singleton or PairedV1 schedule, and copies fixed endpoint
context. It does not accept caller-selected budgets, proofs, compiler limits,
or a generic dispatch token. PairedV1 remains refused by the runtime gate.
Endpoint context is descriptive caller input; this prerequisite does not
authenticate it against a transaction statement or obligation manifest.

The native child now has a private variant retaining the complete closed
`VerifiedNativeSingleton` owner. Its consuming conversion keeps the original
proof/report claims and admits additive metadata before key construction; see
[the adapter source bounds](../../graph_crypto/retention/owned/preparation/production/attachment/SOURCE_BOUNDS.md).
The separate pending native dispatch permit remains unissued and its CPU
helpers remain test-only. The CPU compiler entry point cannot manufacture a
native owner; its sealed result exposes only fixed summary, exact-request
comparison, and bounded report bytes. It has no registration, proving,
evaluation, raw program extraction, or CPU-to-GPU fallback API.

## Preceding storage reservations

Each `ReservedNativeChild` retains its exact request borrow, segment index,
source identity and immutable artifact under its original 64 MiB NativeProof
reservation. This reservation must be claimed before proof production.
For CPU fixtures, `NativeProductionPlan` includes the source-derived nested proof
capacity, temporary fixed public Vec, key descriptor Vec, and ownership headers.
The test CPU producer's original proving/verification scratch is separately
process guarded; this source owner does not admit that producer or claim a GPU
execution receipt. The GPU singleton variant keeps its already admitted core
output/report and research bookkeeping intact, with separately admitted adapter
metadata. `shake_artifact` borrows the actual SHAKE proof without cloning it or
constructing an artifact wrapper. Final compiler verification still consumes an
independent verifier token and borrows that original proof reservation.

The compiler consumes a single exact, same-ledger phase reservation while all
native output reservations remain live. It checks ledger identity, unchanged
worker ceilings, exact request pointer, each scheduled segment index and arity
before allocating report backing. The phase recipe includes:

| Category | Retained / temporary source allowance |
| --- | --- |
| SymbolicCompiler | 2 GiB builder ceiling, Program Arc header, fixed plan/output headers; retained through output destruction |
| CompilerInputs | twice 2^20 field elements plus twice the fixed public header storage and Vec header; retained through output destruction |
| PhaseScratch | bounded symbolic workspace and graph, returned proof-input wires, and pinned compiler helpers from `ShakeGroupCompileFootprint` |
| IndependentVerifier | 64 MiB per native child, split and consumed before each independent CPU verification |
| Report | exact `PhaseReportOwner::requirements()`, reserved before its fixed payload and encoding allocation |

The auxiliary recipe must fit the existing 512 MiB ceiling. The existing
MAX_WIRES, 2^20 input-value and 2^20 padded-row limits are unchanged. No storage
is granted beyond the enclosing worker's existing allowances. Row checks use
the compiled Program's fixed counters, without allocating analysis state.

Independent verification rechecks exact source identity and source proof
capacity. Public array copies are covered by the native owner's source bound.
Compiler members live in a two-slot stack array. The existing bounded grouped
compiler preserves every native verifier and all 108 interior state/input/output
equalities. Native proof storage remains live until all copied proof inputs are
owned by the compiled result. Independent-verifier tokens retire after each
verification; program, inputs and report reservations follow the moved result.
Standalone compiler scratch retires when the compiler returns. Actual-context
scratch stays charged until successful context cleanup, or successful retirement
after cleanup failure. The compiled payload is declared before its tokens, so it
is destroyed first.

Failures before identity/token admission allocate no report. Later failures move
one fixed report out, release compiler locals and consumed child owners, and
preserve typed compiler-refusal metadata when applicable. Standalone phase
storage then retires; actual-context phase storage remains charged through its
cleanup path, including poisoning on failure. Original compiler Strings are
copied into bounded diagnostics and explicitly destroyed before temporary
reservations retire. No failure retries compilation or proving.

## Qualification boundary

The compiler's original error construction, enclosing report/backend transients,
GPU endpoint preparation, whole native production phase, recursive proof output
owners, complete live-workflow storage, and dispatch authority remain separate
prerequisites. This owner does **not** claim complete runtime memory admission.
Requested backing is not RSS, and allocator metadata, stacks and the enclosing
worker's existing state still need their own allowances.
In particular, existing graph/fixture storage and original serialized input
(`E_graph` and source storage) are not charged here. The separate
[`ReservedShakeRequest`](../../graph_crypto/request_owner/BOUNDS.md) can now
charge its own copied input/segment/partition storage before construction; a
bare Request borrow alone remains no receipt for that enclosing charge.

The standalone diagnostic retains its own PhaseScratch token. The additive
`compile_in_admitted_cpu_phase` entry instead accepts only execution's sealed
`AdmittedShakeCompilation`, which borrows the exact plan and actual PhaseLease.
Its private fixed-split adapter obtains report, per-child independent verifier,
program and input tokens; it cannot extract PhaseScratch or retarget the plan.
Scratch remains held in the actual context until real cleanup. No caller-supplied
quota or generic split callback is exposed. Both entries share the same source
validation, compiler body and ownership-preserving error paths.

If actual cleanup fails after compilation succeeded, `into_cleanup_failure`
accepts only the closed lifecycle CleanupFailure code, retains the existing
bounded report, and explicitly destroys the compiled payload before its output
reservations. No usable output escapes failed cleanup. The context continues
holding its poisoned phase charge. Execution's separate qualification notes
cover actual cleanup, retirement, preconditions and remaining lifecycle limits.
A fixed minimal compiler-output helper exists only in release x86_64 tests for
that lifecycle qualification; it is deliberately non-proving and records zero
independent native verifications.

Authored tests cover exact schedules, missing/reordered/foreign/extra children,
wrong/foreign/mixed/short phase tokens, invalid native verification, bounded
failure-report retention, and cleanup. Two ignored, explicitly process-guarded
tests create real CPU native proofs: a 137-byte input/output request supplies a
pair spanning absorption/padding and an odd squeezing tail; a separate valid
singleton forces typed compiler initialization refusal. The success test hashes
every existing-reference Program manifest field and witness value and compares
fixed public values/geometry before releasing all new owners. The historical
reference compiler is independently process guarded and is not admitted by this
new ownership API. No outer proof, GPU work, throughput or runtime admission is
inferred from these checks. The fixture context contains placeholder roots;
compiler identity comparison does not establish compiled-witness satisfaction,
transaction endpoint binding or obligation-manifest acceptance.

A and C found no source blocker within this prerequisite-only scope; neither
review is cryptographic adoption approval. Source authors and peer reviewers did
not run overlapping builds, tests or GPU jobs.

The first frozen fast-test job, `resume-b-owned-shake-tests-1`, failed compilation
at the test-only invalid-fixture constructor: `Val::ZERO` needed the
`PrimeCharacteristicRing` trait import. No test or proof ran. The coordinator
audited terminal/reaped status and unchanged source, executable and raw-log
identities before thawing the tree for the scoped import fix. Guard time was
48.166314239 seconds and peak was 1,163,124,736 bytes. Preserve the failed receipt
as evidence: JSON SHA256
`50a952ce867454dd53be33119524183c5db47725615086d8a7ddd5a4856eea2e`,
raw-log SHA256
`409143e23c26a7434e96f992cfdec86d1cd239664392ff528c4c82e2046a6360`.

The coordinator then ran all checks serially against the frozen source, with
Rust 1.96 release, the native-matrict/recursive-wide feature profile, two build
and Rayon threads, one test thread, an 8 GiB process cap, 6 GiB high watermark,
and zero swap. Each job was terminal/reaped before the next action, and the
source manifest, executable identity and raw log were audited unchanged.

| Check | Result | Guard seconds | Peak process bytes |
| --- | --- | ---: | ---: |
| Corrected `component_tree::owned_shake::tests` focused suite | 4 passed, 2 ignored | 40.158342208 | 1,204,326,400 |
| Existing native-owner regression suite | 4 passed | 2.087645899 | 26,910,720 |
| `resume-b-owned-shake-native-1`, explicitly enabled ignored tests | 2 passed | 30.131804579 | 840,843,264 |

The two real-native tests took 28.81 test seconds in total and created four
fresh CPU native segment proofs. The three-segment reference-equivalence
fixture yielded:

| Compiled wrapper | Native children independently verified | Active rows | Padded rows | Wires | Input values |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pair | 2 | 203,181 | 262,144 | 3,004,067 | 310,638 |
| Odd tail | 1 | 101,600 | 131,072 | 1,501,833 | 155,319 |

Both matched the existing reference's complete manifest/input digests and fixed
public values. The other real-native test verified a valid singleton and then
forced a typed compiler initialization refusal, retaining only its bounded
report until destruction. All requested-storage counters returned to zero
after final owner destruction. These are small-fixture CPU correctness results,
not outer proof execution, GPU measurements, N3/N4 workflow timing, a new memory
allowance, or evidence of a paired speedup.

Audited receipt identities (SHA256):

| Check | JSON receipt | Raw log |
| --- | --- | --- |
| Corrected focused suite | `c7dd8718eb1e87be7be6d6848313c6b2d116c8ce9bdf65791d53d60b1075975b` | `2b39c21eeaf1c3a2fb5e7787a9877ca7785a2b23b598ae1290d030acef2998c7` |
| Native-owner regression | `9f103bc4635cb553f87571fa0b0862f25804af2387d2c795b5e415c6b3bed494` | `e629de1ac90917a46e928e9577ae8bf184af76adce2f9c31933b78c86f09a710` |
| Real-native tests | `fc3c6cba0da02da7d2da252b0e126ac78f51ba82c3b45429aee43d9bcae164f4` | `011f6692bba729b2c1ba2e3bac349894744b2ee5a27083656352762b5820d129` |

## Combined request and actual-phase qualification

On 2026-10-24 the coordinator ran the frozen A+B changes together in the
integration worktree: the pre-admitted immutable request owner, fixed compiler
adapter, and actual execution-context phase owner. No Rust source changed during
qualification. The jobs used Rust 1.96 release with
`recursive-wide,native-matrict,native-verification-allocation-audit`, two build
and Rayon threads, one test thread, an 8 GiB process cap, a 6 GiB high watermark,
and zero swap. Terminal/reaped status, frozen/current source manifests,
executable identity and raw logs were audited before documentation thaw.

| Correctness job | Result | Guard seconds including build | Peak process bytes |
| --- | --- | ---: | ---: |
| `allowance-ab-ownership-tests-1` | 40 passed, 4 ignored | 84.22731129400199 | 1,503,223,808 |
| `allowance-ab-native-ownership-tests-2` | 2 passed | 130.31840506198932 | 2,247,233,536 |

The focused suite includes request identity/budget/error paths, existing native
and compiler owner regressions, fixed phase/report accounting, and actual-context
cleanup failure, poisoning, abandonment, unwind and retirement. The ignored job
explicitly enabled `LATTICA_REQUEST_OWNER_QUALIFICATION=1` and
`LATTICA_PHASE_SHAKE_QUALIFICATION=1`. It passed the request allocation observer
and produced three fresh CPU native proofs from the reserved 137-byte
input/output request. The pair and odd tail then compiled through the actual
context, each reporting `actual_cleanup=true`:

| Actual-context output | Native children independently verified | Active rows | Padded rows | Wires | Input values |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pair | 2 | 203,181 | 262,144 | 3,004,067 | 310,638 |
| Odd tail | 1 | 101,600 | 131,072 | 1,501,833 | 155,319 |

After each compile, only its sealed output and the request owner remained
charged. Output destruction left the request charge; request destruction and
context retirement left zero. The allocation observer separately found zero
requests in planning/rejected-token paths and all construction/failure requests
within the preceding source bounds, detailed in
[`request_owner/BOUNDS.md`](../../graph_crypto/request_owner/BOUNDS.md#qualification).
These results qualify the small CPU fixture and ownership paths only. No outer
proof, GPU work, transaction closure, complete-workflow timing or speedup was
measured. All existing runtime gates and resource limits remain unchanged.

The first ignored-job invocation, `allowance-ab-native-ownership-tests-1`, was
rejected by Cargo argument parsing before any build, test or proof ran. Its
command-line failure is preserved separately; the corrected invocation did not
change Rust source. Receipt and raw-log SHA256 identities are:

| Job | JSON receipt | Raw log |
| --- | --- | --- |
| Focused suite | `9a9eef05fb2a8c9be049a8851e561d0b629ed50b50d2249c1e7401bc9cdba4c8` | `c5ce1f1b0fd03254376f0ce186e098f858289104536cbbbd227ecf653736d5be` |
| Initial argument-parsing failure | `8a0089c6ffbe995b2a10dfcdd21326de33d2406807464748aa6828962bf342b4` | `02ccf83ac992ea9f4db1630b774c7ef9903d65700369f94b38221c4a9a217e42` |
| Corrected ignored qualification | `e195606a4f290c392e766897ff71e80b0e2e2e9c3d4c850df2fe94596be5ec7d` | `bf03329f4fc31af88fdf5230854b9faeaf3ea11ed107f17df535abbf2a05832a` |
