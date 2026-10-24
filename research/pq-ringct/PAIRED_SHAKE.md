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
| `ConstructionLimits` and bounded SHAKE compiler | Requested builder/program storage, wire count, total witness-value limit | The `verifier::uni::verify` call allocates periodic columns and `symbolic::native_uni` expression trees before builder limits apply. AIR symbolic scratch, endpoint storage, returned arrays and allocation overhead remain outside those limits. |
| `NativeRetentionShape` and `RetainedNativeChild` | Public-shape output-capacity bound and post-generation nested capacity audit | No ownership token reserves the output and siblings before allocation and follows the child through moves/drop. Numerical native-verifier scratch needs a source-derived enclosing reservation. |
| Remaining-host native/outer proving APIs | Reduced registered/native GPU host allowances; FreshOnly and GpuRequired checks | A numeric remaining allowance does not retain accounting for sibling proofs, carry-stack nodes, reports, compiler inputs or independent CPU verification. |
| Registered outer verification | Core release-x86_64 code checks a source-derived 257 MiB lifecycle ceiling | The ceiling and storage plan are crate-private. The caller needs a checked public reservation API before setup/verification, while separately charging its retained proof/key owners. This bound does not apply to native uni-STARK verification. |
| Component geometry diagnostics | Exact geometry for the particular compiled node; some tests register invalid proof-shaped fixtures | No pre-dispatch closure qualification for every selected component wrapper, component merge, consuming graph leaf, graph merge, and final N3/N4 aggregate. Sampled shape geometry is not complete closure evidence. |

A guessed 512 MiB or 1 GiB scratch reserve cannot fill the first two gaps. The
existing 32 GiB worker, 24 GiB native, 8 GiB managed GPU, 4 GiB context, 47 GiB
process and zero-swap limits have not been increased to make this candidate fit.
Source inspection alone does not show that PairedV1 cannot fit; it shows that the
current code cannot safely admit it. No claim of a measured memory failure is
made.

## Next implementation gates

1. Add a checked native SHAKE symbolic/periodic/compiler scratch model, or a
   bounded symbolic compiler, before those allocations. Expose the existing
   registered-verifier lifecycle reservation from the core backend with its
   release/x86_64 and pinned dependency restrictions.
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
