# One-child recursive outer proof research qualifier

`ring-recursive-outer-experiment` is a separate opt-in feature depending on
`ring-recursion-experiment`. It adds one fresh recursive proof and independent
CPU verification after C030's complete direct-ring child verification. It does
not alter any transaction acceptance rule, cryptographic parameter, native
segmentation or default. Source implementation is not execution qualification.

## Expected-public key provenance

C030 reconstructs the complete direct-ring program from independently supplied
expected statement/context/profile, freshly registers that expected program,
captures its actual preprocessing cap, numerically verifies the genuine child
and performs restored mutations. Only that private verified owner can create
`ExpectedRecursiveSource`. The new owner retains the original trusted cap,
source bound, four public words, and validated child context/representation. It is not cloneable or deserializable and
has no caller cap, geometry, Boolean or report constructor. The original child
proof is explicitly destroyed before any outer GPU phase. Its required proof
values already belong to the bounded recursive `ProofInputs`.

The small separate core `batch::source_program` module reconstructs the same
single-child, four-public recursive verifier from trusted source geometry and
the trusted cap. A private invalid proof supplies only fixed protocol layout;
every proof field enters through a fresh unknown input. The invalid proof and
its input values are destroyed without hint evaluation. Only a verifier program
leaves this helper. The cap's authentication remains the enclosing research
owner's responsibility; calling the core helper by itself grants no trust or
admission. Existing bounds-only shape APIs and ordinary verifier paths are
unchanged.

Before the first outer proof, independently reconstructed source geometry and
canonical manifest must match the program compiled from the actual child.
The actual source classes, rows, wires, inputs and retained program must also
fit the original opaque-cap source bound. A mismatch is terminal. After outer
proving, verification reconstructs the program again from the private expected
source, registers it in a new session with no identity hint, checks the complete
descriptor and actual registered identity, destroys all GPU/program/synthetic
owners and then verifies the decoded outer artifact numerically on CPU. Four independently changed public
words and one restored proof opening must reject; a panic is always failure.

This is independent outer-program reconstruction from an already authenticated
expected-public source. It does not perform another direct-ring child-cap GPU
setup or count such a setup as fresh GPU work. Each actual outer prover/verifier
registration does perform and report its own fresh setup.

## Phase admission and ownership

The unchanged worker is 32 GiB host, 8 GiB managed GPU and 4 GiB context reserve.
The core planner retains the 24 GiB native ceiling, existing host-tree policy,
row/thread limits and consuming-registration schedule. The enclosing coordinator
guard retains the 47 GiB process cap and zero swap.

| Phase | Simultaneous source-derived reservations |
| --- | --- |
| Genuine recursive compiler/evaluation | Original C030 child/program/input/symbolic/evaluation envelopes |
| Pre-dispatch source comparison | Full core source constructor, one additional 2 GiB genuine program allowance, two maximum input backings, original 1 MiB caller |
| Fresh outer proof | Core original registered-memory plan for actual immutable program/public/input capacity; original child already destroyed |
| Outer serialization and decode | Entire 64 MiB original-or-decoded proof slot, full maximum encoded capacity, unchanged 16 KiB codec scratch, additive source-sized transport frames, original 1 MiB caller |
| Independent source reconstruction | Full source constructor, entire retained 64 MiB outer-proof allowance, maximum synthetic input backing, original caller |
| Independent outer registration | Core plan limited to `32 GiB - 64 MiB`; the separate original outer proof remains charged inside the unchanged worker |
| Independent CPU verification and sequential probes | Source-qualified registered-verifier lifecycle including its 64 MiB proof slot, plus original caller |

The additional source constructor counts its own helper/return/array frames on
top of existing `PlanningStorage`. It enforces the original 2 GiB construction,
2^26 wire and 2^20 input ceilings. It never treats an observed small program as
permission to enlarge a later phase. Both outer GPU plans and the independent
CPU-verifier/source-storage and transport phases are admitted before the first outer proof.
Execution selection is captured before dispatch and checked again at entry;
there is no fallback, profile change or retry.

All expected source, report, result, moved-owner, manifest and session frames are
additive inside the original caller allowance. The existing recursive 192 KiB
sub-ceiling and full 1 MiB census still apply. Additional bounded native report
backing is charged from its exact retained observation/component capacities;
native receipt validation rechecks those capacities before retaining a report.
The coordinator must run the existing caller-census test with the outer feature
first and refuse if it does not fit. No increased allowance is authorized.

Source comparison destroys its reconstructed program before outer proving.
The consuming outer prover drops original program/input owners before session
retirement; initialized recursive witness values are zeroized on all exits.
The independent verifier drops reconstructed program/synthetic inputs and the
fresh session before CPU verification. Original proofs and private source state
are destroyed before success reports return. The encoded owner dies after bounded decode and canonicality checks; the original outer proof dies before the decoder can allocate another. Failure preserves prior child and
outer terminal receipts; cleanup failure withholds success. No raw proof or
reusable registration escapes this qualification API.

## Qualification boundary

Authored focused tests cover pre-allocation source shape/cap/storage refusal,
retained-proof partitioning, malformed height, unwinding ownership order and
terminal cleanup failure. The existing C030 complete caller-census test must
also pass with the added outer feature. One separately ignored test creates a
fresh complete direct-ring child and exercises actual outer proving, repeated
source reconstruction, independent CPU verification, all five negative probes
and terminal cleanup. It requires
`LATTICA_DIRECT_RING_OUTER_QUALIFICATION=1` and a coordinator-authored exact
source/executable/environment/physical-device guard. Agent C ran only isolated
rustfmt parsing/formatting and source/hash inspection, not builds or tests.

The result distinguishes one verified child and one verified outer proof. Its
qualification timer starts with an already owned child artifact; the fixture
prints child generation evidence separately. No complete-workflow timing or
speedup claim follows. The outer artifact now makes an in-memory bounded encode/decode round trip before independent CPU verification. This does not write an external artifact file or audit storage-system transport. Pairs, odd tails, request/transaction/final aggregation, external artifact round trips, full N3/N4 workflows, matched complete workflow measurements and qualified cryptographic review remain required.

## Outer transport revision C037

The separately tagged `LDOUTR01` envelope reuses the child header layout and
bounded proof codec. Its local profile digest additionally domain-separates one
outer proof of one direct-ring child with four public words. Child artifact
parsing always requires `LDRING01`; even replacing only the magic cannot cross
the profile domain. The envelope contains no program, cap, verifier, or matrix.
Expected context/representation/public binding come from the private source
owner that consumed the independently verified child, never from the packet.
The actual producer descriptor is checked during decode and again against
independent source reconstruction and fresh registration before CPU acceptance.

The original proof moves into the transport helper after all outer GPU owners
and the session retire. Encoding reserves the full maximum output capacity;
original proof destruction precedes decoder allocation. The decoder charges
input capacity including spare bytes and the full cumulative decoding plus
canonicalization bound. Its packet owner dies before reconstruction/CPU
verification. The CPU phase retains its original independent proof/scratch
reservation. Neither serialization nor public-source reuse is reported as
fresh GPU work. Any transport error or panic refuses with the prior outer
terminal receipt; there is no alternate profile, retry or fallback.

The fixed 16 KiB child codec allowance is unchanged and has an expanded
compile-time frame census for the shared helper wrappers. The outer transport
adds a separate source-sized fixed-frame charge inside its phase's 32 GiB
worker partition; it does not consume an extra worker or enlarge the caller.
Persistent metrics and private-source fields remain additive in the existing
192 KiB recursive sub-ceiling and 1 MiB full caller census. Every old count and
allowance remains. The coordinator must recompute both censuses before GPU
qualification and refuse if either does not fit.

`artifact_roundtrip=true` is emitted only after the decoded proof passes all
existing independent verification and typed mutation checks. New
`artifact_transport` fields are `encoded_bytes`,
`decoded_proof_retained_bytes`, and `total_ns`; the last measures encoding,
original-proof destruction, decoding and canonicality checks. The existing
prover-lifecycle `proving.total_ns` includes this transport phase, while its
native `proving_ns` and setup timings remain the actual backend reports.
`storage.artifact_roundtrip_peak_bytes` includes caller plus the full phase
reservation. No report is a verifier key or grants acceptance authority.

## Driver-owned complete component timer C038

The ignored genuine outer driver now starts one monotonic timer immediately
before fixture construction, after its fixed profile/context selection and
orchestration admission. It includes fixture creation, direct-ring compilation,
original witness destruction, input admission, fresh child setup/proving and
retirement, child report output, artifact wrapping, independent child
reconstruction/registration/CPU verification and mutations, recursive
compilation/evaluation/source checks, fresh outer setup/proving and retirement,
the C037 bounded artifact round trip, independent outer reconstruction/setup/CPU
verification and mutations, outer report output and destruction, and explicit
destruction of the final expected statement. Only then does it read elapsed
nanoseconds and emit:

`direct_ring_recursive_outer_component_timing elapsed_ns=<positive u128>`

The marker has no JSON report or library layout field. It uses one fixed
39-byte decimal buffer and a static prefix; it allocates no String, Vec, proof,
report clone or retained source. Any prior refusal, panic, assertion, report
output or cleanup failure prevents the marker. A marker output failure panics;
the coordinator must additionally require the exact successful test footer.
Marker output and the test footer are outside this timer and inside the guard's
wall interval. There is no failure timing accepted as a completed component.

The test-only helper explicitly counts the complete surviving fixed driver
selectors/borrows/assertion and report-stream formatting frames, plus every
introduced timer, duration, scalar, decimal buffer, writer, result and admission
frame. Existing large report/proof/program/source/statement owners and move
counts remain in their original independent censuses. No existing owner is
removed, reclassified as spare, or charged twice as an extra allowance. The
helper admits its sum within the already reserved 32 KiB
`verification::CALLER_ORCHESTRATION_BYTES`, before timer or fixture construction.
Proving already reserves that same slice. The exact recursive caller-census
test repeats this admission and prints the total, added timing frames and
unchanged allowance. The full 1 MiB caller and 192 KiB recursive ceilings remain
authoritative and must be remeasured after source integration.

The existing JSON reports have fixed nesting below 16 compound levels and only
integer/Boolean/string leaves; their one-dimensional list lengths do not add
nesting. The stream census conservatively counts four copies at each of 16
levels, plus eight independent serializer/writer/formatting and integer-escape
scratch copies. The pinned serde_json 1.0.154/itoa 1.0.18 implementation uses at
most 40 bytes of integer and six bytes of escape scratch per sequential leaf;
64 bytes are reserved for each copy. New report nesting, floating-point leaves,
custom serialization or dependency versions require renewed source review.

The coordinator must require exactly one positive-u128 marker after the outer
report and before the successful exact-test footer. Its value must be at least
`child.total_proving_lifecycle_ns + outer.total_qualification_ns` and no greater
than the guard wall interval. Nested proving, transport, setup and verification
durations must not be added again. The resulting measurement is one fresh child
plus one fresh outer component from a deterministic fixture, with fresh proof
randomness. It is not seven distinct transactions, a complete RingCT graph,
final aggregate, external artifact audit or complete-workflow speedup evidence.
