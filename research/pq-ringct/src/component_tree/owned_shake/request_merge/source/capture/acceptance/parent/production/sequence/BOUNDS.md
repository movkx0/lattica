# Private original HashX sequence (B062)

This is an isolated source implementation, not execution qualification. All
types and execution entries remain private under `parent::production::sequence`.
No request, graph, transaction or final aggregate dispatcher can invoke it.
B051's `Result<Infallible, RefusedRequest>` remains unchanged. The successful
private component keeps `workflow_admitted=false`, and every accepted child
keeps `transaction_context_authenticated=false`.

`Attempt::reserve_before_native` accepts only immutable original parent source,
the five exact group plans and their ledger. It constructs its own bank, all
five leaf/four parent outputs and acceptance claims, and A's original pending
native sequence. It does not accept a bank, first producer, external compiler,
old accepted child, standalone completion or detached A originals. There is no
intermediate-state constructor or continuation accessor. The fixed execution
order is `L0,L1,P0,L2,L3,P1,P2,L4,P3` and the four exact edges are checked again
by the maintained authenticated parent compiler.

All output, source-capture, independent-verifier, wrapper, report, planning,
bank and added caller claims exist before native PCS capacity is assigned.
Every leaf/parent source backend is preissued against that same actual native
capacity, and all eight successor backends are bound before native zero. A
refusal destroys the whole attempt; no post-proof fallback, re-admission or
retry is possible. The worker ceilings remain 32 GiB host and 8 GiB device,
with existing 4 GiB device reserve, 24 GiB native limit and row/thread/profile
limits. Actual feasibility has not been measured.

The actual first producer drains only its ten native outputs into fixed slots.
Each leaf consumes its next two originals. Every accepted child originates in
this private sequence, after actual producer retirement and independent source
authentication. First and later leaves share one execution body; only their
fixed A binding differs. Parents use the existing maintained producer and
capture their actual compiled Program/source cap. A proves original runtime
order; B separately proves source/proof acceptance. Matching numeric source,
ledger or step never imports external lineage.

The ancestor-private `finish_source_acceptance` now has this third closed
producer caller, in addition to the two standalone opaque-attempt callers
described in its existing comment. The sequence passes only the actual retired
original's checked receipt; it introduces no numeric-retirement argument or
public wrapper for an external caller.

Each compiler is borrowed through registration, proving, output retention,
actual retirement and source acceptance. Those borrows and registration aliases
end before bank reclamation. Successful reclamation additionally requires the
actual proving Program to have strong count 1 and weak count 0, destroys the
real witness/Program/public/report payloads, and reunifies the same original
reservation categories. Registered verifiers retained by NodeKey reconstruct
their own empty public Program; the full proving Program is not their source
allocation. Every surviving key/verifier alias nevertheless keeps its own full
backing claim, including terminal failures. No alias or cap is given partial
ownership credit.

`State` owns all outputs/producers/native children/runtime originals before its
bank, and `Attempt` declares its state before the added caller original. Local
compiled owners outlive the consumed producer call. Both returned errors and
unwinding preserve the established actual Session retirement/poisoning rules.
Every returned proof/setup/output error goes through `ActiveHashxOuter::finish`
before acceptance or propagation. A terminal compiler failure retains its
bounded report in `Cause::Compiler` before `Failure::caller` is released. The
private success retains its root, A originals and retired support before its
caller; no proof or continuation can be extracted.

`claims.rs` adds eight copies of every complete State/Attempt/result, banked
compiler/result, native/outer owner/result, fixed proof/producer/backend/support
array, leaf capture/output/result, report, iterator and helper frame. Private A
return layouts are measured from function-item types without executing them.
Backing storage and lower callee claims remain separate; this is not a claim
that inlining, moves, lifetime shortening or slot reuse will save space. The
64 KiB helper allowance is additive to the complete named owners and checked
array/sum work. Exact one-byte-short and terminal-caller tests exercise this
formula, not complete runtime admission.

The component timer starts immediately before preparation and ends after the
last accepted/reclaimed parent. It excludes initial request/source construction
and retains the successful root afterward, so it is not complete-workflow time.
Reported proof counts increment only on actual internal production/acceptance.
No performance or full RingCT throughput claim follows from this source draft.

Required qualification before any dispatcher can call the sequence: compile,
complete caller/physical-source capacity audits, source-boundary refusal before
native zero, first-leaf equivalence to B056, all nine genuine banked cycles and
actual retirement on returned errors, accepted-output and request-context
mutations, final root coverage/height checks, terminal ledger/session audits,
then separate transaction/final aggregate closure and complete workflow tests.
