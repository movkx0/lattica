# Sealed outer startup continuation

This inactive continuation seam accepts `RetiredRuntime` from the real
`Session::finish_reserved_with_owner`. It does not accept a raw reservation,
copied receipt, or caller-created numeric authority. Default singleton dispatch
is unchanged. This increment does not issue a sequential native/paired plan.

Before consuming the real Runtime, core records whether its new private binding
was the sole phase binding of the still-live epoch. Each binding carries a Weak
reference to a separate private marker owned by the runtime; read-only retirement
fences observe only the lease allocation and cannot count as phase bindings.
The Runtime is thread bound,
the binding has no Clone or upgrade operation, and the synchronous consuming
retirement cannot issue another binding. After retirement, Weak counts cannot
recover this fact, so it is retained in a private boolean. A live native phase's
separate marker Weak prevents this outer-only extraction even if dropped later. Native
continuation continues to require the existing matching phase extraction.

The core bridge checks the captured fact, actual retired epoch, zero live
managed/tree storage, released lease, exact `OuterHostV1` source footprint,
original ledger, and startup claim category/device bytes/minimum host bytes.
Research first requires the exact enclosing `requested()` census and original
worker allowance and limits. Every refusal returns the complete sealed owner.
Success destroys the binding before moving the unchanged original claim to an
unstarted `PendingRuntime`. No environment/device query, admission, dispatch,
quota release, or numerical replacement occurs during this move.

The old startup claim covers explicit additional core and research result,
move, frame, plan, requirement, footprint and boolean storage. Its requirement
is source-derived before the first runtime starts. No stack reuse or unused
allocation is credited. The lease and private binding-marker allocations are
both charged wherever a binding can survive retirement. Live runtime startup also charges the marker
independently, including non-quota and fixed-note startup paths. No overlap
credit is taken for the live and moved owners. Ledger control-block charges
remain in force. All downstream phase, PCS, compiler,
output, verifier, report and planning claims remain the caller's separate
preissued owners; this API cannot construct or expand them.

CPU tests cover exact Arc/Weak identity, the last-strong-owner gate, observer
independence, and the fact that a later phase drop cannot revise a captured
refusal. The ignored identity-cohort GPU qualifier uses authentic owned startup,
retirement, and CPU prefix completion for two and sixteen streams, and checks
that all original ledger reservations retire. No test
fabricates a Runtime, selected device or sealed retired owner. Source review,
formatting and hash audits do not qualify the typed GPU bridge. An actual outer
producer continuation qualifier must check complete snapshots, failure owner
preservation, independent verification, and final cleanup before adoption.
