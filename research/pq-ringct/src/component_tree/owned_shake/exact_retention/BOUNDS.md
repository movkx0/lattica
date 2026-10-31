# Immutable SHAKE output retention qualification

This opt-in experiment exists only in release/x86_64 tests. It changes the
logical retained program/input reservations after a completed owned compiler
phase. Existing constructors keep their conservative construction ceilings,
production code has no selector for this experiment, and paired dispatch stays
disabled. No new worker allowance, smaller construction peak, physical memory
saving, proving admission or throughput improvement is claimed.

## Exact owned source and unchanged construction peak

`retain_exact` consumes one `OwnedCompiledShake` and accepts only its ledger.
It accepts no byte claim, numeric quota, generic token, raw program or callback.
The qualification invokes it on the returned actual compiler result after the
capability has returned to `Ready`. At this point compiler temporaries and
native children have been destroyed and actual phase cleanup has completed.
The existing program ceiling, input ceiling, request and report tokens remain
live before the transfer begins.

The source scan calls `Program::retained_host_bytes` in
`lattica-prover-p3/src/block_v2/machine/program/storage.rs`. That checked method
counts the `Program` allocation and its Arc header/alignment, operation/row/
reference vector capacities, nested SelectHint entry/bit capacities, and nested
ALU/cubic row capacities. It does not use RSS, allocation observations or logical
row counts as a substitute for retained source backing.

Input backing is the checked sum of public and witness vector capacities times
the field-element size. Spare capacity counts even when the logical length is
smaller. The exact program charge adds `size_of::<ExactRetainedShake>()` to the
source scan. That enclosing header contains the original owner, vector handles,
tokens and a fixed-size before/after receipt. The existing phase report retains
its own unchanged token, including its bounded encoding buffer. Request/source
owners remain separately charged. No source allocation or input is resized,
copied, deallocated or reconstructed by this accounting transfer.

The scan also validates program/summary/public/witness shape, source limits,
same-ledger program/input/report ownership, pure host reservation categories,
and that each exact charge is no larger than its existing category reservation.
All capacity addition/multiplication and enclosing-header addition are checked.
Malformed or excessive source cannot manufacture a smaller reservation.

## Scan, transfer and failure lifetime

A fixed, source-derived `PhaseScratch` reservation precedes the source scan.
It counts transfer/plan/receipt/snapshot/token headers and the short String
transients on the core source scan's error paths. The normal scan and transfer
allocate no heap. This scratch comes from the same worker allowance. If it
cannot be admitted, the original owner and all construction charges remain
attached to a bounded failure owner. The original compiler header includes a
plan header; a static size assertion ensures that it also covers the small
failure wrapper before scan admission.

The transfer guard declares its owned payload before detached tokens and
scratch. `Reservation::split` partitions the original program and input tokens
without changing the total ledger charge. Both new tokens must exist before
either surplus token is released. Success replaces both tokens inside the same
owner, constructs the receipt-owning output, and only then drops the surplus
program/input charges. Scan/transient-report scratch retires last. The final
receipt records the ledger charge after that scratch has retired.

If the second split fails, the guard owns the payload, the original remainder,
the first exact token, the untouched input token, the phase report and scan
scratch. Failure returns no usable compiled owner. Destruction and unwinding
drop the payload before its reservations; no error can release detached
storage while the payload still lives. The returned exact owner exposes only
immutable access and a copy of its fixed-size receipt, so the same output cannot
be transferred a second time or grown through this API.

## Qualification scope

Focused accounting tests use tiny private non-proving fixtures. They cover
checked overflow, spare capacity, foreign ledgers, mismatched summary/category,
insufficient scan headroom, insufficient retained capacity, moves, second-split
failure, and unwinding after both splits. Those fixtures make no native proof
verification or transaction-acceptance claim.

The ignored test
`exact_owned_retention_preserves_payload_and_keeps_pair_preflight_incomplete`
requires `LATTICA_SHAKE_EXACT_RETENTION=1`,
`native-verification-allocation-audit`, no `opencl`, and a serialized process
guard with one test thread. It constructs four fresh native CPU proofs and
three actual wrappers: singleton zero, paired zero and the odd tail. It first
inspects each unchanged conservative owner, then performs the explicit exact
transfer and repeats the same closed recursive preflight. Allocation addresses,
capacities, request identity, summary geometry and the report charge must remain
unchanged. The source scan/transfer and both preflights are observed under a
zero requested-allocation bound. Scan scratch must be gone before the final
inspection; the receipt remains charged through a move, then all output/request/
source charges must disappear and the context must retire.

The pair's previously qualified partial lower bound is 32,749,125,568 bytes.
Exact source retention is expected to remove the conservative ledger deficit
for this fixture. If that bound fits, the only result remains
`IncompleteFullPhaseBound`. The experiment keeps the original preflight's two
outcomes and never adds an admitted/successful-proving outcome.

The partial lower bound still omits the other three commitment trees, their
salts, natural matrices, preprocessing/proving/transform temporaries, proof
outputs, independent verifier storage, allocator overhead and process storage.
Their simultaneous lifetimes require a complete phase bound. No recursive
registration, trace or proof is created here, no full transaction or final
aggregate is closed, and no faithful GPU workflow is qualified. Fitting this
partial bound cannot establish that the complete phase is feasible.

`shake_exact_retention` and `shake_exact_retention_complete` report fixed
before/after charges and explicit scope flags.

## Audited qualification results

The coordinator ran the frozen source serially in the integration worktree.
An independent read-only audit matched both raw-log hashes, the recorded Cargo
executable hash, and all five Rust files in this change against each receipt's
source manifest. Both receipts contain 1,309 source-input hashes and record
unchanged source and command executable, successful exit, all subprocesses
terminal and reaped, completed service stop, and an inactive/dead, absent unit
with no remaining PID or cgroup. Their terminal limits were 6 GiB memory high,
8 GiB memory maximum, and zero swap. These are CPU qualification processes;
they do not change the production resource envelope.

| Evidence label | Result | Test execution | Guard wall time | Peak process memory (bytes) |
| --- | --- | ---: | ---: | ---: |
| `rowopt-integration-shake-tests-1` | 56 passed, 0 failed, 9 ignored | 0.26 s | 66.1980232570204 s | 1,329,143,808 |
| `rowopt-shake-exact-retention-1` | 1 passed, 0 failed | 27.07 s | 28.1338729269919 s | 840,851,456 |

These durations include different test/build scopes and are not comparative
workflow timings. Both receipts set `performance_qualified=false`. The recorded
executable is Cargo 1.96.0, SHA-256
`f30f9fd1b1d0b8fd10dc33219eb4cd4bec3543f40e434ac71f5a03fd0359063f`.
The built-artifact maps are empty; no separately audited test-binary hash is
claimed.

The actual-fixture test produced four fresh native CPU proofs and compiled
three wrappers. All three began with program and input construction charges
of 2,147,485,296 and 16,777,976 bytes, respectively, and total worker ledger
charge 2,164,491,644 bytes. The worker allowance remained 34,359,738,368 bytes
(32 GiB). The measured retained backing and ledger charges are:

| Wrapper | Active / padded rows | Source program bytes | Source and retained input bytes | Retained program bytes | Ledger charge after transfer |
| --- | ---: | ---: | ---: | ---: | ---: |
| Singleton ordinal 0 | 101,683 / 131,072 | 111,903,116 | 2,097,520 | 111,903,876 | 114,229,768 |
| PairedV1 ordinal 0 | 203,181 / 262,144 | 223,533,336 | 4,194,672 | 223,534,096 | 227,957,140 |
| PairedV1 odd tail ordinal 1 | 101,600 / 131,072 | 111,772,796 | 2,097,520 | 111,773,556 | 114,099,448 |

Each retained program charge includes the 760-byte owner/receipt header. The
4,056-byte scan scratch charge was released before the final preflight, and
the phase report charge was unchanged. Allocation addresses, capacities,
payload, and request were preserved. The test's allocation observer accepted
the transfer/scan and both preflights with a zero requested-allocation bound.

| Wrapper | Remaining worker host bytes | Partial lower bound bytes | Final preflight reason |
| --- | ---: | ---: | --- |
| Singleton ordinal 0 | 34,245,508,600 | 16,374,562,752 | `incomplete_full_phase_bound` |
| PairedV1 ordinal 0 | 34,131,781,228 | 32,749,125,568 | `incomplete_full_phase_bound` |
| PairedV1 odd tail ordinal 1 | 34,245,638,920 | 16,374,562,752 | `incomplete_full_phase_bound` |

The pair's logical ledger charge decreased by 1,936,534,504 bytes, leaving
1,382,655,660 bytes beyond its partial lower bound. Its refusal reason changed
from `partial_bound_exceeds_remaining_ledger` to
`incomplete_full_phase_bound`; the singleton and tail already had the latter
reason. This transfer changes logical charges after compiler cleanup and
retains the same buffers. It establishes no physical-memory savings. The
three other commitment trees and salts, natural matrices, preprocessing,
proving and transform scratch, proof outputs, independent-verifier storage,
and allocator/process overhead still need complete simultaneous bounds.

All three outputs, requests and source charges were cleaned up, and the
execution context retired. The run created zero recursive proofs, started no
outer registration, trace or proof, closed no full transaction graph, and
performed no GPU work. The complete-footprint and runtime-enabled flags
remained false. Paired runtime remains disabled; this result does not admit
outer proving, establish a feasible complete phase, or qualify any throughput
improvement.

Receipts and logs are in the integration worktree under
`.tools/pq-opencl-opt/runs/`:

- `rowopt-integration-shake-tests-1.json`: SHA-256
  `e2f6cc0106e0187fd6c3d356b1d583c87913b54927297a34589693060589a4ef`;
  its `.log`: `640ba72f11ff1842c3d3b3f610162198a6c21996fc8c81090e7287e6fbffbf92`.
- `rowopt-shake-exact-retention-1.json`: SHA-256
  `47c661ae4d2bb9e04301a50b244eb7c35480472c99e362b6f367eeb9ebf6032e`;
  its `.log`: `0cc4a55df5bb9b92ac8354de429fb1348dc7c41a5fa6b15217124495c2d76ee4`.
