# Actual phase ownership for CPU-reference SHAKE compilation

This adapter closes one lifetime gap: the owned SHAKE compiler's exact
`GroupCompilePlan::requirements()` now enters the actual execution context's
`PhaseCapability` ledger. A private borrowed `AdmittedShakeCompilation` couples
that exact plan to the resulting `PhaseLease`. There is no constructor, raw
lease accessor, caller requirement, numeric allowance, generic token, or
callback on the compiler-facing handle. A separately supplied plan cannot
retarget the borrowed admission.

The entry is restricted to execution-owned code and a CPU-required context
without an attached GPU session, busy registry, prepared program, or attempted
baseline work. Status/remaining allowance checks still occur in actual phase
admission. These are entry checks, not a claim that every existing baseline API
consults the lifecycle. The default baseline remains unchanged. The reference
compiler does not emit a fresh GPU-work receipt or authorize native dispatch.

## Source recipe and destruction order

The recipe remains the closed compiler plan documented in
[`owned_shake/BOUNDS.md`](../../component_tree/owned_shake/BOUNDS.md): program,
compiler inputs, report, each native child's independent verifier component,
and compiler scratch. It is admitted atomically while native-child reservations
are already live. Each child must still belong to the exact request, scheduled
segment and ledger; a token from another context or standalone ledger fails.

The handle permits only these fixed splits:

| Split | Source |
| --- | --- |
| report | `PhaseReportOwner::requirements()` |
| independent verifier | one fixed native SHAKE verifier component |
| program | the exact borrowed plan's program requirement |
| inputs | the exact borrowed plan's input requirement |

The underlying phase split rejects `PhaseScratch`; no new escape is added.
The compiler's temporary locals and consumed native children die before the
adapter invokes `PhaseLease::complete_after_cleanup()`. That invokes actual
prepared-state release and any actual queue drain. Scratch remains charged
through the cleanup call, including compilation/refusal/verification failure.
Successful cleanup releases the remaining phase reservation; sealed output
and report reservations continue following their own data.

On cleanup failure the phase becomes poisoned and its remaining reservation
stays held until actual successful retirement. A successful compiler result
is converted to a bounded cleanup failure: its compiled payload is destroyed
before its program/input tokens, while its already-reserved report survives.
A prior compiler failure keeps its original report and the wrapper adds only
a fixed lifecycle error, preserving both causes without allocating another
diagnostic. No usable compiled output escapes failed cleanup. Abandonment or
unwind likewise poisons the actual phase rather than releasing its scratch.

## Qualification limits

This remains an ownership prerequisite. It does not establish enclosing
`E_graph`, borrowed source/transaction storage, complete native production,
GPU endpoint preparation, original backend/report/error temporary storage,
recursive proof/frontier ownership, transaction endpoint/manifest binding,
compiled witness satisfaction, or exclusive trusted workflow issuance. B's
separate request owner must charge the request it owns; borrowing any `Request`
here is not evidence that all enclosing storage has been charged. The existing
native production permit remains uninhabited, paired production dispatch stays
disabled, and there is no GPU-required-to-CPU fallback.

Tests use real CPU contexts and actual cleanup for admission, foreign-context
children, native-verification failure, retained report/output destruction,
busy/prepared/baseline-policy refusal, poisoned cleanup and unwind. The minimal
sealed compiler-output fixture is test-only, deliberately non-proving and
reports zero independent native verifications. It exercises output lifetime,
not cryptographic acceptance or full compiler equivalence. No benchmark,
runtime admission, N3/N4 closure, GPU cleanup or speedup follows from these
focused tests.

The ignored `fresh_native_pair_and_odd_tail_compile_through_actual_context_and_release_outputs`
test requires `LATTICA_PHASE_SHAKE_QUALIFICATION=1` and the coordinator's serial
process guard. It constructs B's pre-admitted immutable request owner and
produces three fresh CPU native children on the actual context ledger, compiles
the pair and odd tail through the closed capability entry, and checks retained
request/output charges after actual cleanup. Each destroyed output leaves only
the request's source-derived charge; destroying that owner and retiring the
context must leave zero. The original borrowed input and enclosing graph remain
separate. Existing
standalone reference-equivalence tests remain separate; this does not duplicate
their full reference compile or claim an outer proof, GPU work, transaction
endpoint binding, or complete-workflow admission. All campaign resource and
thread/row limits remain unchanged.

## Serialized qualification, 2026-10-24

The coordinator qualified the exact combined A/B source under
`recursive-wide,native-matrict,native-verification-allocation-audit`:

- `allowance-ab-ownership-tests-1`: 40 passed, four explicitly guarded tests
  ignored. This includes ten focused actual-context compilation lifecycle tests.
- `allowance-ab-native-ownership-tests-2`: both selected ignored tests passed:
  the fresh-native actual-context pair/odd-tail test and B's request-allocation
  census. Three fresh CPU native proofs were produced and independently verified
  by the compiler. Actual cleanup succeeded, output destruction retained only
  the request's charge, and request destruction/context retirement left zero.

| Group | Native children | Active rows | Padded rows | Wires | Input values |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pair | 2 | 203181 | 262144 | 3004067 | 310638 |
| Odd tail | 1 | 101600 | 131072 | 1501833 | 155319 |

Both accepted jobs passed source, executable, log, current-manifest and terminal
cleanup audits. Their guard wall times, including build work, were 84.227311294
and 130.318405062 seconds; cgroup memory peaks were 1503223808 and 2247233536
bytes. These are qualification-job measurements, not complete-workflow or
proving-throughput benchmarks. No outer proof or GPU work occurred.

The first ignored-test invocation, `allowance-ab-native-ownership-tests-1`, was
rejected by Cargo's command-line parser before any test ran. Its source and
executable remained unchanged and its processes were terminal. It is retained
as failed invocation evidence and supplies no correctness qualification.

The audited receipts and logs are retained under the campaign integration
worktree's `.tools/pq-opencl-opt/runs/`, identified by the labels above and these
SHA-256 hashes:

| Job suffix | Receipt SHA-256 | Log SHA-256 |
| --- | --- | --- |
| `ownership-tests-1` | `9a9eef05fb2a8c9be049a8851e561d0b629ed50b50d2249c1e7401bc9cdba4c8` | `c5ce1f1b0fd03254376f0ce186e098f858289104536cbbbd227ecf653736d5be` |
| `native-ownership-tests-1` (parser refusal) | `8a0089c6ffbe995b2a10dfcdd21326de33d2406807464748aa6828962bf342b4` | `02ccf83ac992ea9f4db1630b774c7ef9903d65700369f94b38221c4a9a217e42` |
| `native-ownership-tests-2` | `e195606a4f290c392e766897ff71e80b0e2e2e9c3d4c850df2fe94596be5ec7d` | `bf03329f4fc31af88fdf5230854b9faeaf3ea11ed107f17df535abbf2a05832a` |
