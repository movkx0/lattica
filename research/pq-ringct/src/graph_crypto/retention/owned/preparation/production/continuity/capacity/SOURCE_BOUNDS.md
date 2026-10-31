# A029: original capacity declaration before native dispatch

This read-only addition follows A028 and provides no new owner or execution
entrypoint. `PreparedNativeSingleton::outer_continuation_capacity` checks the
exact source/request/index/ledger, host-profile pending runtime, verifier and
bookkeeping originals. Its core call additionally requires an unattempted
host-profile phase, original pending output, and exact wrapper/PCS claims.
The reported startup and PCS bytes are copied from those retained originals,
with the unchanged 8 GiB host-tree quota and managed startup-plus-PCS total.
Changing the copy grants no allocation, restoration or dispatch authority.

The core native wrapper census includes fixed Bytes/Result/Requirements and
footprint moves. The existing research continuation bookkeeping includes its
numeric result/record/header moves before the native phase is constructed.
No new dynamic allocation, ledger operation, environment inspection or device
selection occurs in either getter. Limits and cryptographic parameters are
unchanged. The existing device-profile path cannot return this host declaration.

The A028 ignored continuation qualifier is extended to read the declaration
before native dispatch under an unchanged complete ledger snapshot and compare
it afterward against the actual sealed restored startup and original PCS
owners. This is authored qualification only; no tests or GPU work were run by
Agent A. No extra fixture can fabricate a Runtime, NativeShakePhase or retired
owner. Source review does not establish that the next phase fits: B's closed
planner must reserve its separate compiler/output/report/verifier owners before
the native constructor, inspect its full source envelope against this exact
remaining capacity before dispatch, and match the actual originals after
retirement. Existing full-workflow and security qualification requirements stay
separate.
