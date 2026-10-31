# A028: retaining original native phase claims

This opt-in research continuation requires A026 and A027. It changes neither
production transaction acceptance nor the existing standalone producer. It is
not a complete RingCT or recursive workflow and establishes no speedup.

`Session::finish_reserved_with_owner` consumes the actual private
`RuntimeLifetime` pair. Only this source-closed pair is passed to A027's unsafe
core retirement method. Success destroys the actual Runtime and Selection
before issuing the marker; the original startup claim survives all remaining
Session identity destruction. Refusal destroys Runtime, then Session, then the
original claim. Uncertain GPU cleanup still aborts. No raw numeric receipt can
stand in for actual runtime retirement.

`PreparedNativeSingleton::produce_retaining_originals` performs the same one-shot
native proof, exact actual retirement, and independent CPU verification as the
standalone producer. It obtains the original startup, native wrapper and PCS
claims only through A027's exact runtime binding and native phase extraction.
Complete ledger snapshots, including category and aggregate historical peaks,
must be unchanged across successful runtime retirement and extraction. The
native proof, report, request identity and their original owners remain intact.
There is no new admission, retry, fallback or host profile change after dispatch.

`PendingRuntime::restore_outer_host_v1` accepts only sealed
`RetiredNativeReservations`, never a raw reservation. It validates the original
ledger, exact original startup request and fixed host profile before consuming
the owner. Refusal returns it intact. Success restores a source-only pending
runtime and returns the original native wrapper and PCS claims unchanged. It
does not inspect the environment, select a device, or construct a new runtime.
The later preflight/start still checks the immutable process and physical device
contract. The CPU tests exercise only its pure source validation; they fabricate
no runtime, binding or retired owner and do not qualify actual restoration.

Before dispatch the original startup requirement additionally covers overlapping
Session/RuntimeLifetime/Reservation/Ledger headers, both consuming retirement
Result owners, two restoration tuple/refusal Result owners, Requirements copies,
and source StartupPlan/Result moves. The existing source startup census separately
covers device identity storage and A027's Weak-retained lease allocation. The
original production bookkeeping claim additionally covers two result/verified
continuation moves, original retired-native headers, Requirements copies and
four complete Snapshot headers. A027 independently covers its native phase
binding/control-block backing. No overlap credit or increased limit is used.

The ignored exact GPU qualifier uses the immutable `outer_host_v1` profile,
8 GiB retained-tree host quota, existing 8 GiB managed device and 32 GiB worker
host allowances, unchanged proof parameters and row limits. All fixture headers,
original child adapter and two extra verifier claims are reserved before native
preparation. Reports are streamed to stderr without an intermediate JSON String.
For two fresh one-byte inputs it is authored to check actual retirement and
extraction, four independent CPU acceptances, two mutation rejections, intact
child attachment, sealed startup restoration, original wrapper/PCS split-reunite,
unchanged transfer snapshots and terminal zero quota. Actual managed/tree live
bytes must be zero with the lease released even while the original 8 GiB managed
claim is retained. Restored runtime dispatch is explicitly false. Its timer is a
component timer including mutation, attachment, verification and transfer.

No build, CPU test or GPU test was run by Agent A. The qualifier does not exercise
an actual failed native proof, asynchronous GPU failure, second restored runtime
dispatch, recursive pair/odd-tail graphs or full transaction closure. Those
remain separate qualification requirements. A closed whole-graph planner must
preissue complete compiler/outer/output/report/verifier ownership and establish
the remaining original PCS capacity before any native-to-outer dispatch is
enabled. Metadata caching and prepared public-state retention remain unrelated.
