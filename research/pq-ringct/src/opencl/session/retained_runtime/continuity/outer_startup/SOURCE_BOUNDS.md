# Sealed outer startup continuation

This inactive continuation seam accepts `RetiredRuntime` from the real
`Session::finish_reserved_with_owner`. It does not accept a raw reservation,
copied receipt, or caller-created numeric authority. Default singleton dispatch
is unchanged. This increment does not issue a sequential native/paired plan.

Before consuming the real Runtime, core records whether its new private Weak
binding was the sole Weak of the still-live epoch. The Runtime is thread bound,
the binding has no Clone or upgrade operation, and the synchronous consuming
retirement cannot issue another binding. After retirement, Weak counts cannot
recover this fact, so it is retained in a private boolean. A live native phase's
separate Weak prevents this outer-only extraction even if dropped later. Native
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
allocation is credited. The existing runtime binding allocation and ledger
control-block charges remain in force. All downstream phase, PCS, compiler,
output, verifier, report and planning claims remain the caller's separate
preissued owners; this API cannot construct or expand them.

Two CPU tests cover actual Arc/Weak ownership before and after retirement and
the fact that a later phase drop cannot revise the captured refusal. No test
fabricates a Runtime, selected device or sealed retired owner. Source review,
formatting and hash audits do not qualify the typed GPU bridge. An actual outer
producer continuation qualifier must check complete snapshots, failure owner
preservation, independent verification, and final cleanup before adoption.
