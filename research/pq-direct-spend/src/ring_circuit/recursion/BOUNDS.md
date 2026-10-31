# Single-child direct-ring recursive constraint qualification

This separately selected `ring-recursion-experiment` feature is a research
diagnostic. It compiles and evaluates the full recursive verifier of one genuine
direct-ring proof. It produces no outer cryptographic proof or aggregate and
does not change transaction acceptance. The default direct-ring proof and
verification interfaces remain selected when the feature is absent. Qualified
cryptographic review and full workflow validation are still required before any
protocol adoption.

The public entry consumes an `Artifact` and independently supplied expected
statement/context/compiler profile. The existing independent verifier rebuilds
the full direct-ring program from those expected public inputs and synthetic
domain-valid hints. Transport descriptors only undergo comparison with that
reconstruction; they do not select the reconstructed program or verifier key.
Synthetic hints are never evaluated.

Before that verifier's GPU registration, the actual reconstructed program
supplies the source height and public width to the bounded registered-verifier
planner. All original program/witness capacity, the full 64 MiB child-proof
allowance, the existing 1 MiB caller allowance, and planner construction and
auxiliary bounds must fit the unchanged 32 GiB worker allowance. Source rows,
wires and inputs must fit before registration. A rejected plan is terminal;
there is no larger profile retry.

After those unchanged checks, a private retained subset keeps exactly the three
operation counts and four wire/input/active-row/padded-row ceilings needed by
later compiler conformance. Every field retains its original `usize` width.
The planner's complete `PlanningStorage` must still equal the pre-admitted
storage before conversion; the original `MemoryBounds` and reports are unchanged.
The planner diagnostic peak, selection-hint backing count and duplicate storage
record are not retained after preflight because this direct-spend path does not
read them again. The full raw planner result, its original `Result` and
`catch_unwind` frames remain charged, with additional conversion value/result
and reference frames. Every existing source/evidence/result/move multiplicity
remains intact and uses the actual smaller owner type. No allocation, numeric
narrowing or new source authority is introduced. This source change requires a
fresh compiled census against the unchanged 192 KiB recursive and 1 MiB complete
caller ceilings; source-estimated savings alone do not qualify either limit.

The fresh independently reconstructed `RegisteredProgram` is the sole source
of the captured preprocessing cap. The cap remains private through session
retirement, numerical CPU verification and both restored negative probes. Only
successful independent verification can produce `VerifiedRecursiveChild`, which
owns the original artifact, the cap, the prior source bound and the verification
report. A report, transport cap, raw proof or caller-written geometry cannot
construct that owner. This initial path has no identity-reuse selector.

The recursive program exposes exactly the four child public-binding words. It
passes those outer public wires directly to the full registered-machine
verifier, with the independently reconstructed cap embedded as constants. The
empty child `MachineAir` supplies only the expected registered height/public
geometry; the trusted cap binds the full program. Every child proof value
remains a fresh witness input to the recursive verifier. No host-verification
Boolean replaces the verifier constraints.

The small shared-core hook uses the existing maintained bounded CPU symbolic
registry, the same private path used by `verifier_core_bound`. It is not a new
proof protocol. The ordinary public CPU symbolic path is not used by this
qualifier. The hook itself provides neither allocation admission nor trusted key
provenance; the private research owner and source plan supply those boundaries.

The fixed recursive compiler profile is 2 GiB program construction, 2^26 wires,
2^20 input values and 2^20 padded rows. `PlanningStorage::for_children` accounts
bounded symbolic workspace/retained constraints, old/new ProofInputs backings,
returned wires, helper allocations and the planner's invalid template storage.
The actual compiler conservatively retains that complete auxiliary allowance,
although it uses the original genuine proof and creates no template. Its
original child proof is charged separately. The planner's opaque-cap
specialization argument remains restricted to the pinned registered-machine
compiler: replacing fresh cap words with constants and four fresh child-public
inputs with outer public wires cannot add operation classes, rows or inputs.
The compiler verifies each resulting class/count against that prior bound.

The private trusted cap owns one exact-capacity `Vec<[Val; 4]>`, allocated
fallibly only from the genuine registered program after caller admission. The
64-root, 2,048-byte backing is charged once for its complete lifetime, plus all
allocation/result/reference frames. No inline cap array is materialized. The
sole Vec moves through the private evidence, verified child and expected source;
there is no clone, raw-cap constructor or mutable accessor. Every existing
conservative owner/result/move multiplier remains, now counting the actual
smaller inline owner type. This changes storage ownership, not source identity.

The completed child verification report also has one private heap owner. A
fallible exact-layout `Box<MaybeUninit<VerificationReport>>` is admitted and
allocated before public reconstruction or GPU setup. Failure before completion
drops the uninitialized slot without reading or dropping uninitialized bytes.
Only a successful independently verified child initializes the whole report and
converts that same allocation into `Box<VerificationReport>`. The box moves
through child ownership, recursive qualification, the outer input and the final
report without cloning its backing. Its serialized contents are unchanged.
The full report backing, four additional by-value initialization frames, all
slot/box/result/layout/pointer/allocation-source frames, and the original
independent verifier's report/result frames are charged additively. Existing
owner and result multiplicities remain unchanged. The null-allocation and
caller-refusal paths are tested before any verifier setup can begin.

Outer preflight refusal diagnostics similarly move one boxed immutable planner
footprint through failure/results instead of repeatedly embedding that large
footprint inline. Only an already caller-admitted phase refusal allocates it,
before outer dispatch. Null allocation remains a terminal preflight failure;
it grants no execution token and performs no retry. The sole footprint backing,
four by-value transfer frames and every allocation/helper/result frame remain
additive alongside the original plan/admission/error/result multiplicities.
Both report and footprint allocators use one common real/null-result branch
within their respective private allocation method. Private, smaller drop probes
exercise the actual initialized and uninitialized slot cleanup paths without
manufacturing trusted evidence or verification reports.

Child and outer negative probes use the core `verify_classified` entry. Only
the unchanged numerical `verify_batch` returning an error qualifies as a
rejected relation. Lifecycle, statement/degree/lookup shape, entire structural
envelope, call-memory admission, verifier configuration and fallible public
copy failures terminate qualification with no mutation credit. This is
conservative for malformed proofs: early structural rejections deliberately
receive no credit. Diagnostic text never determines classification. Panics
remain terminal, and opening mutations are restored before any result returns.
The existing unclassified core verification path is literally unchanged.

The classified entry exports `classified_call_extra_bytes`; the shared research
classifier adds its own enum/result/string/reference/census frames. This whole
charge is additive to the original caller census for child verification and
again inside the recursive outer inline census. Original error/catch/result
multiplicities are retained. Sequential probes share one charge; no concurrent
verification is introduced. Native configuration/proof/scratch bounds and the
existing 1,024-byte diagnostic bound remain unchanged. The returned diagnostic
is dropped before a research terminal error is constructed. These source-only
changes need exact release type-census and failure-test qualification; they do
not infer a fitting postimage or permit dispatch from prior C034 evidence.

All fixed source, result, cap-owner and orchestration frames are additive inside
the existing 1 MiB caller charge. The recursive addition has a 192 KiB ceiling;
the full original caller census is still authoritative and may refuse sooner.
No typed array-return or move elision is assumed to release storage. The source
planner's original program and synthetic witness backing are retained only
through preflight and verifier setup, then destroyed before CPU verification.

Constraint evaluation admits the full 2 GiB retained-program ceiling, both
bounded input backings, one value per maximum wire, original proof and fixed
caller state. It evaluates operations without creating a trace matrix. After a
valid evaluation, each public-binding word is independently changed by one
field element and must be rejected by those same emitted constraints. These
checks are sequential and each evaluation releases its wire values before the
next. Panics are failures, never successful negative probes.

Ownership follows moves through compilation and evaluation. Ordinary errors and
unwinding drop program, inputs, artifact and cap. The independent verifier
session has already retired before recursive compilation starts. Recursive
failures preserve its terminal receipt. Successful reports retain only bounded
metadata and the independent verification report; all proof/program/input/cap
owners are destroyed before returning. The enclosing process guard still owns
allocator/stack overhead and enforces the unchanged 47 GiB process cap, zero
swap, thread limits, 8 GiB managed GPU and 4 GiB context reserve. Requested
storage bounds do not constitute observed RSS or device peaks.

The authored focused tests check the actual feature-specific caller census and
spare-capacity refusal, incomplete/changed reconstruction geometry, additive
overlap accounting, exact worker boundary and overflow rejection. A separately
guarded ignored test creates one fresh complete direct-ring proof, independently
reconstructs/registers/verifies it, compiles the genuine recursive verifier and
requires all four public mutations to fail. Only the coordinator may build or
run these tests under the serialized source/executable/physical-device guard.
The ignored test requires `LATTICA_DIRECT_RING_RECURSIVE_QUALIFICATION=1` and the
existing `gpu-required` environment. No tests or builds were run by Agent C.

This step closes the genuine-child-to-recursive-constraints seam. Remaining
work includes outer GPU proof generation, independent reconstruction and CPU
verification of that outer proof, bounded outer artifacts, pair/odd/full graph
and final aggregation ownership, full fresh N3/N4 workflows, matched complete
workflow measurements and qualified semantic/security review. No complete
workflow, aggregate, throughput or speedup claim follows from this qualifier.
