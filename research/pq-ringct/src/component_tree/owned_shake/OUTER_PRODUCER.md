# Owned outer producer qualification

`outer_producer::production::PreparedOuter` is a fixed, one-shot implementation
behind release tests, Linux x86_64 and the explicit `owned-gpu-runtime` feature.
It does not enable `PairedV1` transaction dispatch. The legacy inspection API
remains an inspection and cannot convert its report into permission to prove.

The constructor borrows the actual `OwnedCompiledShake` and its original
`ReservedShakeRequest`. It checks their ledger identities, immutable source
geometry, member coverage and native verification count. It then reserves the
fixed planner, report, proof, key, CPU verifier, additive OpenCL wrappers and runtime owners. The runtime
preflight bounds environment capture and physical selection before any core
planner can inspect them. Only then does the exact `OuterBackendPlan` derive its
native allowance from the remaining host budget, including the full retained
tree quota. Admission occurs while the Engine is still idle.

The backend device census includes `retained_query_base_bytes`, hence its
Engine constants and staging allocation. The phase claim subtracts exactly
`PendingRuntime::reserved_bytes().device` from that inclusive census. This is
the same original startup token, covering 64 MiB plus 752 bytes, that moves into
the Session and remains live through cleanup. No other device ownership is
subtracted. The ledger admits runtime plus backend together inside 8 GiB;
the separate context reserve remains 4 GiB.

With `gpu-bounded-info`, every backend physical-selection recheck uses the
fixed scanner supplied by the runtime owner. It does not allocate the legacy
device list and its per-device identity Strings. Ordinary OpenCL feature
selection retains its existing path. The fixed scanner's source geometry and
environment/error backing belong to the original runtime token. The unsafe
producer contract requires the existing serialized process guard to keep the
environment immutable from preflight through retirement.

`produce` starts that runtime once, holds its borrowed ledger guard, rechecks
the admitted selection, and calls the existing fresh registration and consuming
GPU proof entries. It supplies neither identity receipts nor cached proofs.
The exact setup and proving reports must have the fixed scopes, required
OpenCL inventories and completed device receipts. Their original backing and
errors die under `FixedProofReportStorage`; the setup report is destroyed before
the proof Run starts. The fixed report census includes capability construction,
observation and finish collections, original closed-enum error formatting,
JSON publication overlap and inline/Arc owners. It excludes OpenCL/compiler
errors and proof/key payloads, which retain their separate owners.

The key comes from that actual registration. The existing output claim checks
source/public identity and retained capacities, then executes the independent
CPU verifier before splitting its original reservation into retained proof,
key and report ownership. Setup, proving and CPU verification times are retained
separately. Session retirement runs while backend/report claims are still live;
an uncertain shutdown follows the runtime owner's fail-closed contract. The
original additive wrapper claim also survives this retirement. There
is no retry, fallback, caller callback, supplied proof or extraction API.

Focused tests cover exact report scope, missing/duplicate receipts, incomplete
or CPU work, impossible device counts, optional CPU serialization, and the core
report census against original formatted errors and observed allocation
requests. An ignored hybrid qualification exercises a genuine singleton, pair
and odd tail using fresh CPU native fixtures and reference compilation, then
the actual owned GPU outer producer, independent CPU verification and ledger
cleanup. It requires `LATTICA_OWNED_OUTER_QUALIFICATION=1` under the coordinator's
serialized process/GPU guard. Its CPU fixture scratch remains an external test
harness obligation. It must not be counted as a faithful all-GPU RingCT workflow.

Source review and rustfmt do not qualify execution. The coordinator must build
and run these tests after integrating the runtime dependency and parent hooks.
Complete native GPU production, source-key and transaction-context
authentication, recursive graph closure, artifacts and N3/N4 workflow
measurements remain separate qualification requirements. Their report flags
stay false; this component makes no throughput or speedup claim.

## Additive OpenCL wrapper and specialization claim

`FixedOuterOclStorage` is a pure source census. `PreparedOuter::new` converts it
into an original `PhaseScratch` reservation before `PendingRuntime::reserve`,
environment capture or any backend planner. `produce` checks its same-ledger
identity and keeps it live through Session destruction, including errors.
The backend native allowance is computed after this claim, so these bytes
reduce the existing 32 GiB worker budget. No device or context allowance grows.

The pinned `ocl 0.19.7` wrapper bounds are specific to the existing registered
machine entry. Preprocessing and proving run sequentially. No Kernel cache or
named arguments occur in that path. All builder/kernel locals die in their
statement, unsafe block or loop iteration; `compact_kernel` only borrows its
caller-owned Kernel, and event batches retain Events, not Kernels. Two full
16 KiB builder/kernel pairs are charged even where only one is live.

The largest supplied argument count is 16: the resident NTT has 14 scalar or
buffer arguments plus at most two local-memory descriptors. The owned quotient
has 15, quotient gathering has 14, lookup kernels at most 14, commitment kernels
at most 10, and the remaining witness, transform, opening, FRI, transcript,
randomness and retained-query kernels fit below that ceiling. Local descriptors
do not allocate their device-local word counts on the host. The pinned builder
starts with 16 argument slots, clones its bounded buffer BTreeMap, and checks
the returned argument count against supplied arguments before allocating the
ArgType vector. ArgType retains fixed enum/boolean fields, not metadata Strings.
Bounded metadata queries and their original formatted errors have a separate
additive 8 x 64 KiB + 4096-byte allowance.

`owned_quotient` constructs one `PreparedQuotient`; its optional specialized
Program survives that quotient operation and is destroyed on its return.
`specialized::prepare` uses at most 8192 instructions, 512 registers, 129 fixed
64-byte liveness bitmaps and a source allocation capped at 2 MiB. It passes a
borrowed source to ProgramBuilder with one device and `-cl-std=CL1.2`.
The census charges five source-length requests: original allocation, builder
clone, CString source clone, terminator growth and the final CString clone.
Another 64 KiB covers its fixed 64-entry option/source vectors, path table,
device/pointer vectors, compiler option and inline Program/core-Kernel handles.
The bounded checkpoint command and 8193-byte read buffer are included. No
overlap credit is taken against the runtime startup's raw-only wrapper claim.
Opaque driver/compiler storage and at most 128 MiB of resident private backing
remain inside the unchanged 4 GiB context reserve.

The additive host claim is 11,133,134 bytes on the pinned x86_64 source. Its
five core tests cover pure planning, real borrowed-source ProgramBuilder copy
requests, actual specialization emission at block boundaries and the maximum
instruction count, actual argument-builder/map backing, and the checkpoint
command. A research test checks one-byte-short refusal, exact admission,
same-ledger identity, moved ownership, failure and unwind release. These are
source/request-backing canaries; only the serialized genuine GPU qualification
can establish execution, and neither establishes complete workflow speedup.
