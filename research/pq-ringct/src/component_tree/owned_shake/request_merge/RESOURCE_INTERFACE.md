# Request-parent merge resource interface: implementation draft

The companion `request_merge.rs` implements only a bounded metadata preflight
and enforced refusal; see `BOUNDS.md`. Its `require_complete` returns
`Result<Infallible, RefusedRequest>`, including after all five genuine leaf
source bounds have been retained. B054 now implements a separate test-only
bounded compiler for the first two leaf/leaf parents; see
`source/capture/acceptance/parent/BOUNDS.md`. The complete parent graph,
correlated workspace and dispatch interfaces proposed below remain unimplemented.

The existing `component_tree::compile_merge`, `merge_impl`, `merge_geometry`,
and `graph_crypto::prover::RequestProver` are reference implementations for
semantics and scheduling. They cannot be inserted into the owned request path:
`compile_merge` independently verifies children before bounded admission;
`merge_impl` uses the default builder/input allocation paths; and the carry and
report vectors have no complete ownership-following ledger plan.

## Exact HashX request tree

Preserve the current carry algorithm, original segments, and asymmetric final
merge. With the active-policy native source fixed by A035/B050, the tree is:

| Node | Children | Unit interval | Spec level |
| --- | --- | --- | ---: |
| Group 0 | Native 0, 1 | [0, 32) | 0 |
| Group 1 | Native 2, 3 | [32, 64) | 0 |
| Group 2 | Native 4, 5 | [64, 96) | 0 |
| Group 3 | Native 6, 7 | [96, 120) | 0 |
| Group 4 | Native 8, 9 | [120, 122) | 0 |
| Parent 0 | Group 0, Group 1 | [0, 64) | 1 |
| Parent 1 | Group 2, Group 3 | [64, 120) | 1 |
| Parent 2 | Parent 0, Parent 1 | [0, 120) | 2 |
| Parent 3 | Parent 2, Group 4 | [0, 122) | 3 |

This is ten native and nine recursive request proofs, as scheduling metadata.
The singleton schedule has ten leaves and nine parents. Neither count proves
speedup, admissibility, or complete transaction/final-aggregate closure. Do not
add padding proofs, split a native batch, reorder children, or silently choose
a different tree to fit memory. Any tree alternative needs a separately named,
pre-dispatch plan and semantic/resource qualification.

## Source-bound interfaces

The following are proposed opaque interfaces, not implemented methods:

```text
TrustedRecursiveSource
    derives from a closed group source or an earlier closed parent source

ParentSourcePlan::derive(left_source, right_source, fixed_profile)
    -> counts and complete construction/verification/storage census

ParentSourcePlan::inspect(original_source_claim, original_ledger)
    -> ParentSourceBound, retaining only identity/counts/original metadata

WholeRequestSourceClosure::derive(five_group_sources, four_parent_sources)
    -> exact immutable request tree and complete phase inventory

WholeRequestSourceClosure::preissue(original_worker_ledger)
    -> original compiler/parent/output/key/report/carry/verification owners

PreissuedParent::compile(exact_owned_left, exact_owned_right, typed_workspace)
    -> LiveCompiledParent or terminal failure ownership
```

`TrustedRecursiveSource` is not constructed from an arbitrary `NodeKey`, proof
header, caller-chosen height, padded row count, or numeric footprint. Its group
constructor consumes/borrows an original source bound. Its parent constructor
requires a completed closed source census for that exact ordered pair. Source
counts may use private invalid templates only if all proof/public inputs become
fresh unknown witnesses, synthetic hints are never evaluated, complete planner
allocation is admitted first, and no template/program/key/proof escapes.

The parent source planner must derive the recursive verifier's full instruction,
wire, input, selection-hint, AIR/periodic/symbolic, cap/public/helper/diagnostic,
program finish/compaction, report, and CPU-verifier lifetimes. The native SHAKE
compiler census does not bound the machine recursive verifier. A caller-selected
byte allowance or the existing retained-LDE estimate cannot fill a missing
component. Missing or overflowing bounds refuse the complete request before
the first native proof. No post-proof discovery, fallback, or retry is allowed.

The existing registered-machine `verifier::batch::shape` planner already
bounds its closed core and construction path, and C030's separate research
compiler uses that bounded symbolic path. The missing bound here is the
composed request-parent source and binding/caller census, its trusted child
source heights/caps, complete independent CPU verifier storage, and all
overlapping request/compiler/output/runtime phases. This document does not
claim that the generic recursive core planner is missing.

Compute row/width/quotient/input/hint/key/proof bounds through all four parent
levels from those trusted source descriptions. Before proving, the full graph
planner must also close the consuming transaction graph and final aggregation
under the unchanged row, thread, host, managed-device, context and process
limits. A fitting leaf does not establish a fitting parent or final aggregate.
If conservative source height bounds cannot close, record refusal; do not use
observed smaller outputs to retroactively admit an already started request.

## Ownership and verification contract

Each parent fixes its original request, attempt identity, contract, context,
ordered child slots, exact adjacent intervals, expected levels, and complete
source envelope. Original child key/proof/report owners stay live through
independent verification and copying every proof/public value into the bounded
compiler input owner. The cap comes from actual trusted child preprocessing
and stays bound to that child's source and produced key; an externally supplied
cap plus a successful proof verification is not source-key provenance.

Admit the simultaneous peak before verifying either child: both retained child
keys/proofs/reports, the complete parent compiler and input workspace, independent
CPU verification, source/cap/header helpers, parent registration/proving runtime,
parent output/key/report, and all return/carry/serialization owners. A compiler
workspace may be reused only through the correlated retirement protocol in
`../request_workspace/LIFECYCLE.md`, after prior payload destruction. Its maximum
must include parent requirements; a leaf-only maximum is insufficient.

The new closed bounded compiler preserves `Spec::merge` and `bind_merge`:
contracts match; left end equals right first; counts add without overflow;
level is `max(left.level, right.level) + 1`; all shared header fields remain
equal; the left/right interior four-field boundary roots match; and the outer
endpoints equal the left initial and right final roots. The full child verifier
is emitted into the parent circuit. Independently checking children on the CPU
does not replace that predicate. The native paired leaf continues to bind all
108 internal SHAKE boundary fields before the compressed parent-root interface.

Typed verified children must retain trusted key/program provenance so their
public headers and levels correspond to the registered child predicates. Actual
compiler output is checked against the exact prior source envelope before
registration. Actual parent production uses FreshOnly/GpuRequired and returns
an opaque correlated proof/key/runtime completion owner, using the same success
and terminal-failure rules as a leaf. Existing default/reference paths remain
unchanged during qualification.

For this fixed request, use source-counted fixed carry slots and report slots,
or explicitly census every capacity/growth overlap if a vector is necessary.
No generic carry callback may allocate or verify outside its owned phase.
Retaining children until parent compilation completes overlaps all parent
temporaries; early release is not permitted merely because a future schedule
will consume them. Parent output and report storage remains charged after child
destruction. Numeric counters never replace these original owners.

## Completion and required checks

A complete request result requires root interval [0, 122), exact original
contract/profile/context and expected request endpoints, all five leaf and four
parent source identities, independent CPU acceptance, actual source-key and
native/recursive receipts, artifact round trips, mutations, and terminal runtime
cleanup. It remains a component proof until the constrained transaction graph
authenticates its manifest context and the final aggregation closes. Placeholder
contexts, source-only screens, and final-aggregation-only benchmarks cannot be
reported as a complete fresh RingCT workflow.

Required negative cases include swapped/missing/duplicated children; wrong
request, workspace, context, cap provenance or level; nonadjacent or overflowing
intervals; mutated interior roots or endpoints; undersized category claims;
source-vs-actual compiler mismatch; CPU-verifier/configuration failure; proving
failure; and cleanup failure. Qualification must also cover the asymmetric
Parent 3 merge and destruction of every native/leaf/parent/report/carry owner
after both success and failure. The coordinator alone runs builds and guarded
CPU/GPU tests; this interface draft has no execution evidence.
