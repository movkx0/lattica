# Exact native runtime retirement and original scratch ownership

The internal `RuntimeBinding` holds a private `Weak<JobLease>` and the exact
selected OpenCL device handle. Only the actual `OwnedRuntime` can issue one,
after checking its live Engine identity. There is no clone, upgrade, raw epoch,
public constructor or numeric receipt conversion. Matching requires the same
original Arc allocation and selected device. Weak does not add a strong owner,
so the existing exact-last-two-strong-owner retirement check is unchanged.
It does prevent Arc allocation reuse while the identity remains live.

Weak retains the entire Arc allocation after `JobLease` is destroyed. The core
startup census adds that exact `arc_bytes::<JobLease>()` backing plus retired
owner, binding, success/refusal and move headers. The native wrapper census also
charges the complete backing independently, because a refused native phase can
outlive a dropped retired-runtime owner. Native bindings drop before their phase
wrapper reservations. Neither census takes credit for this overlap.

The original native phase binds only after the existing source/preparation,
output, verifier, runtime profile, original startup/phase ledger and exact wrapper
and PCS claim checks. The bound field survives every later proof failure. A
pre-bind failure cannot extract scratch through a generic idle marker. Existing
one-shot attempted state still rejects retries.

`Runtime::retire_with_original` is an unsafe closed-orchestrator boundary: its
caller must move the exact original Session startup reservation, never a token
recreated from a receipt. It checks ledger/category/footprint ownership before
retirement. Failure returns the actual runtime and original token intact. Success
uses unchanged actual runtime retirement, including queue drain, zero live host
trees and managed allocations, and lease release; uncertain cleanup still aborts.
It destroys Runtime and Selection/environment/device backing before creating
`RetiredRuntime`. This sealed type bundles the actual reservation last with its
opaque marker and bounded receipt. Callers can report the receipt but cannot
construct this owner or extract marker/token separately.

`NativeShakePhase::into_retired_reservations` consumes the complete phase and
that sealed runtime owner. It requires original binding/device identity, a truly
retired marker, the exact source-built tree profile/footprint, the same worker
ledger, and unchanged wrapper and PCS claims. Refusal returns both complete
owners. Success destroys any pending output, PCS planner, phase binding and
retired marker before returning the three original startup/wrapper/PCS tokens.
It performs no allocation, ledger admission, category conversion, proof clone,
fallback, retry or dispatch. The original native proof/report owner remains
separate and intact in the producer.

One CPU test exercises actual Arc/Weak lifetime identity, wrong allocation and
device rejection, unchanged last-strong-owner semantics, post-retirement
non-reuse, and exact backing census. It uses a closed `/dev/null` lease fixture
and a private generic comparison helper, without fabricating a real OpenCL
handle, Runtime, sealed retirement marker or proof. Actual success/failure
retirement extraction requires the coordinator's later exact GPU qualifier.
No build, tests or GPU work was performed by Agent A.

Default Session/native retirement entrypoints remain available with their
existing behavior. Their new internal weak binding is separately backed until
native phase destruction. This patch alone provides no new full workflow:
research Session plumbing, original source preclaims, compiler/backend/output/
report/verifier admission before the first native proof, and native-to-outer
orchestration remain prerequisites. No faithful RingCT or speedup claim follows.
