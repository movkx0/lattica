# Reserved RingCT runtime startup

This experimental Linux/x86_64 path supplies actual startup ownership for the
RingCT graph and outer-proof research owners. It changes neither transaction
acceptance nor default `opencl` startup. The research feature is
`owned-gpu-runtime = ["opencl", "lattica-prover-p3/gpu-bounded-info"]`.

`PendingRuntime::reserve(&Ledger, Limits)` builds the source plan without reading
the environment or calling the driver, then reserves the original ledger's
`PhaseScratch` bytes. A failed admission cannot start a context. No numeric
runtime budget can construct the capability, and it cannot be cloned or have its
token extracted.

The optional unsafe `preflight` captures 61 bounded environment values and an
exact physical `Snapshot` while the engine is idle. An outer backend holds the
returned borrow while planning its own admission. Consuming `start` rechecks and
moves that same selection and original reservation into the actual `Session`.
Both entry points require a dedicated guarded process whose environment remains
immutable until retirement. Bounded `getenv` copies and subsequent rechecks do
not lock arbitrary process environment mutation.

The fixed source profile requires an RTX 5080, 8 GiB managed device allowance,
4 GiB context reserve, 32 GiB worker host allowance, 24 GiB native host output
allowance, eight Rayon threads, baseline public hashing, device retained trees,
the existing 128-query / log-blowup-4 / 191-bit cubic challenge profile, and a
power-of-two row limit no larger than 2^20. Each owning phase still applies its
own smaller shape limits. The external guard continues to enforce the 47 GiB
process cap, zero swap and existing task/stack limits.

The startup device reservation is **64 MiB + 752 bytes**: mapped staging and
the Engine's four constant buffers. It is never zero. The mapped staging is
also charged to host memory. An inclusive backend device peak may subtract this
exact overlap only while retaining the same pending/runtime owner through all
backend work. `reserved_bytes` reports the original claim; it transfers no quota
and grants no dispatch authority. The 4 GiB context reserve stays separate.

The source-derived host claim includes the exact joined kernel-source length
and SHA3 digest, the cumulative source/CString construction requests, 64 KiB of
constructor descriptor backing, 8 x 64 KiB + 4 KiB of bounded metadata/error
overlap, two 16 KiB raw kernel builder/kernel pairs, bounded selection scratch
and identity strings, sealed environment copies, core session backing and
actual inline ownership types. The raw graph has at most eight supplied kernel
arguments and one simultaneous builder/kernel pair. Native AIR, registered
quotient specialization, proof/output/compiler/report storage and additional
Program owners are separate phase obligations. This source census cannot be
generalized to them merely because startup is admitted.

`gpu_device::bounded::fixed::capture` uses the existing fixed scanner for later
backend physical rechecks. It returns inline device/index/UUID/memory facts
without an `Identity` string or an enumerate-all identity vector. It accepts an
already bounded selector request and reads no environment. Its scratch is
charged by the runtime plan. The ordinary feature path continues to use the
existing selector. Calls outside this reserved workflow must establish their
own enclosing storage ownership.

`Session::check_reserved_runtime(&Ledger)` checks the original ledger identity,
the sealed environment, the physical device snapshot and the exact Engine epoch
before the caller creates a Run/DeviceSession or releases prepared state. Its
returned borrow must remain live through the fixed operation and cleanup. Root
owns Run/capability/report/JSON storage and typed operation boundaries; a runtime
borrow alone grants none of those budgets.

The `Session` owns the runtime before its original reservation. The runtime
owns the exact `OwnedRuntime` epoch before its selection/environment. Reserved
shutdown drains and destroys that exact Engine, checks zero managed and retained
tree storage, and releases its lease before the quota can drop. Any uncertain
cleanup aborts. `finish_reserved` returns only an inline cleanup receipt.
Legacy JSON completion methods reject reserved sessions with an allocation-free
empty `String`; they cannot return payloads after the startup token is released.

No `nvidia-smi` helper is invoked by this path. Opaque driver/libc/allocator
storage and compiled thread stacks remain under the existing external guard and
trusted context reserve. Requested Rust backing is not a complete RSS census or
a proof of unobserved driver peaks.

The capsule includes CPU policy/admission/identity tests, allocation canaries and
an ignored two-startup GPU cleanup check. They are authored, not executed by
Agent A. The coordinator serializes builds and GPU validation. This work claims
no proof completion, whole-transaction closure, performance promotion or
cryptographic qualification.

The separate `StartupPlan::outer_host_v1` profile admits exactly 8 GiB of host
tree payload before any environment capture, physical query or runtime startup.
`PendingRuntime::reserve_outer_host_v1` holds that payload and a separately
counted `Arc<HostQuota>` wrapper in the same original worker-ledger reservation
as startup. Its private source-built profile accepts only retained storage
`host` with host-tree bytes `8589934592`. Default `StartupPlan::new` and
`PendingRuntime::reserve` remain device-only and reject the host budget variable.
No process environment value can choose or broaden the private profile.

Selection retains the profile through its immutable-environment rechecks,
initialization and live runtime checks. Both profiles still require the same
RTX 5080, managed/context budgets, 24 GiB native/output cap, zero swap and eight
Rayon threads. The host-tree payload is inside the original 32 GiB worker
allowance; the process cap remains 47 GiB. It does not increase managed VRAM or
replace the 64 MiB + 752 byte startup device charge. Existing HostQuota admits
each tree before allocation and the original device construction/offload peak
and query upload remain separately admitted by the outer backend.

`PendingRuntime::reserved_tree_host_bytes()` returns only the exact payload
already held by that non-cloneable owner: zero for device, 8 GiB for outer host.
It accepts no caller-provided amount. A same-ledger outer producer may add this
exact value back while deriving its native partition, then subtract it from
the backend's inclusive host-tree claim, only while retaining the original
runtime reservation through backend destruction and exact epoch retirement.
It must verify that the source-selected backend tree limit equals the getter.
The extra HostQuota wrapper is not credited as overlap. This accounting keeps
the aggregate 32 GiB envelope and avoids charging the same tree payload twice;
the getter itself provides neither a reservation nor dispatch authority.

The profile does not change the outer producer or validation guard by itself.
Those are separate reviewed patches. Raw graph/native note selections continue
using the device profile. CPU tests cover both disjoint selector policies,
exact host-budget rejection, allocation-free planning, one-byte-short original
ledger admission, identity, ownership moves and cleanup. Agent A has not run
those tests or a host-profile GPU workload; the coordinator owns qualification.

The separate `ReservedRuntime::borrow_core` operation rechecks the same bounded
environment, physical selection and epoch before returning a thread-local
exclusive `RefMut` owner. It exposes only shared borrows of the core runtime
and original startup reservation. Its actual inline type is included in the
startup host claim. It cannot extract either owner or extend the worker budget.
Overlapping runtime borrows are refused before another physical check.

The successful idle `PendingRuntimeGuard` likewise exposes only a shared borrow
of the original startup `Reservation`. Precontext planners can verify its exact
ledger and category requirements while the successful preflight remains held.
The getter cannot extract, split, clone, or replace the token, and supplies no
operation capacity or dispatch authority.

A core capacity consumer may then call `Runtime::check_engine` while holding
the actual Engine lock. This non-locking check compares the original epoch,
the concrete device handle captured at that Engine's initialization, exact
managed/tile/staging limits and the source-fixed
tree-storage profile against that live Engine. It allocates nothing, reads no
environment and makes no driver query. It grants no capacity by itself; the
consumer must still derive and admit its complete operation under that same
lock and retain all original reservations through cleanup.
