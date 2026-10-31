# Closed ordinary returned-refusal qualification (B064)

These four seams are test-only additions beneath the private B062 sequence.
They do not add production acceptance, a dispatcher, callback, external child,
compiler, runtime continuation or mutable proof access. The entire non-test
sequence has no probe field, probe Cause variant or injected branch. The fixed
probe is selected by consuming the initial Attempt before preparation; neither
an intermediate constructor nor a running-sequence setter exists.

Each seam returns a distinct `Cause::Injected(Probe)` only after checking the
actual private progress/frontier. The genuine producer and original A lifecycle
remain unchanged. A different seam, any earlier real admission/compiler/proof/
retirement/acceptance failure, or unexpected component success fails the test.

| Seam | Native proofs before refusal | Recursive proofs before refusal | Accepted leaf outputs installed in State | Successful compiler reclamations |
| --- | ---: | ---: | ---: | ---: |
| After all source backends and successors are preissued | 0 | 0 | 0 | 0 |
| After native children compile/bind, before first outer start | 10 | 0 | 0 | 0 |
| After the real first producer retires and authenticates output | 10 | 1 | 0 | 0 |
| After that accepted output/originals are installed in State | 10 | 1 | 1 | 0 |

The third seam holds the actual local LeafCompletion while returning; Rust drops
that later-declared completion before the local BankedLeaf. At the fourth seam,
the actual accepted key/output, retirement originals and support reside in State
until Attempt destroys it. The local compiled payload drops first, without bank
reclamation; accepted-key storage has its own full original backing and owns the
reconstructed public-only verifier Program, not the compiled proving Program.
Neither seam reports successful bank reclamation. The first two seams also
destroy their actual prepared runtime/bank/originals through the existing owners.
All returned errors consume the complete Attempt. No retry or fallback exists.

Probe/Option/Cause, State/Attempt/Failure/Result growth, fixed receipt-count tuple,
immutable state borrow and added frontier iterators are included in B062's
pre-native caller census. B063's separately admitted driver census includes the
complete new mode, failure/Result, probe, category iterator/counters, snapshots,
checked-release and diagnostic frames. No dynamic fault log or heap callback is
introduced. All of these claims precede pending native capacity assignment;
existing source, output, independent verifier and actual compiled payload claims
remain independently held. Worker/process/device/security limits are unchanged.

The guarded driver checks the exact typed trip, original caller ledger identity
and exact caller requirements while Failure still owns that reservation. Its
provisional reached diagnostic is emitted before dropping Failure, then exact
per-category/current caller release and unchanged peaks are checked under the
separate driver caller. All source/closure/group/request/driver owners are then
destroyed. Only a successful returned-refusal classification followed by actual
all-category terminal zero may emit `ringct_hashx_sequence_returned_refusal_complete`.
That marker always reports `component_success=false`, zero compiler reclamations,
`owner_quota_cleanup_complete=true`, `process_engine_device_audit_complete=false`,
and ordinary returned-refusal scope. Owner destruction and ledger balance do not
establish external process/engine/device teardown; the coordinator must audit it
separately. It never emits the ordinary component
complete marker or any component proof-success credit. Earlier provisional
diagnostics cannot establish cleanup. The final terminal marker also reports
`component_success=false` even when the expected-refusal test passed.

Each selector is separately ignored and requires both
`LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION=1` and
`LATTICA_OWNED_HASHX_SEQUENCE_REFUSAL_QUALIFICATION=1`, plus the exact coordinator
source/binary/environment/process and exclusive physical-GPU guard. The root
coordinator must add exact selectors and audit real stage receipts separately:
0, 10, 12, 12 report lines respectively, with 10 native and one preprocessing/
registered-proof pair for the latter two. No selector is enabled by this source
capsule; the CPU-only capacity selector must continue rejecting GPU/refusal
selectors. The successful full component path is unchanged and has no probe.

This is source only. Rustfmt is not a type check or execution. The focused
synthetic Failure test establishes caller accounting only and never manufactures
an accepted proof, runtime retirement or execution-success marker. Genuine
guarded executions, external process/engine/device cleanup audits, asynchronous
GPU faults, unwinding, public/proof/interior-boundary mutations, artifact round
trips and complete transaction/aggregate workflows remain unqualified. All
mutation, artifact and complete-RingCT flags stay false; asynchronous-failure and
unwind flags stay false. These ordinary returned errors cannot stand in for any
of that evidence or establish a performance improvement.
