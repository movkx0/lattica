# Explicit native SHAKE host-tree research profile

`NativeShakePhase::new` keeps the qualified device-tree component path.
`NativeShakePhase::new_outer_host_v1` is a separate unsafe, source-closed entry
for the fixed original `StartupPlan::outer_host_v1`. It accepts no profile enum,
numeric host allowance, AIR callback, proof attachment or fallback. The closed
research caller must hold the original pending-runtime reservation before
selection inspection, keep the process environment immutable, and retire that
exact runtime before releasing any preparation or phase owner. A matching
research constructor and its qualification are separate coordinator work.

The host runtime claims the full 8 GiB tree allowance and actual HostQuota Arc
wrapper in the same 32 GiB worker ledger. Native PCS gets only the actual
remaining host allowance after all earlier original owners and the additive
wrapper claim, capped at the existing 24 GiB native limit. A lower remaining
allowance is never replaced with the configured 24 GiB or a measured peak.
Managed GPU remains 8 GiB, context reserve remains 4 GiB, and the native phase
claims the full managed allowance minus its original startup baseline.

Both the fixed phase and its capacity consumer check the exact source runtime
footprint, including source fingerprint, host payload and quota wrapper. The
source device census captures retained-tree mode/quota and compares them with
the PCS admission selection. Under the original engine lock, the actual capacity
lease additionally requires the exact runtime epoch, matching tree selection,
and zero live host-tree charge before dispatch. Original preparation, runtime
and PCS tokens remain in the same ledger through configuration, proof and exact
retirement. The one-attempt/no-retry rule and fresh entropy are unchanged.

The existing host opening planner charges the complete graph before startup.
For trace rows R, let H = 32R and
T(h) = (2h - 1) * 32 + min(h, 64) * 32 + sizeof(RetainedTree).
It charges 3T(H), then every FRI T(H/2), T(H/4), ..., T(16), without early-release
credit. Representative payload-plus-cap totals (before headers) are:

| R | Bytes | Tree headers |
| --- | ---: | ---: |
| 4,096 | 33,583,104 | 16 |
| 8,192 | 67,139,552 | 17 |
| 32,768 | 268,470,176 | 19 |
| 524,288 | 4,295,010,080 | 23 |
| 1,048,576 | 8,589,979,392 | 24 |

The last case exceeds 8 GiB even before its headers and is refused. Geometry,
device feasibility and complete host feasibility are all necessary; this table
does not claim that every smaller row count is dispatchable. The original host
opening model deliberately recharges some initial-tree/runtime partitions in its
local feasibility calculation. No new overlap credit is taken.

## Additional host-transfer census

`shake_source::transfer_storage` adds a separate original PhaseScratch claim
before native startup. It does not borrow the existing kernel/program estimate.
The default device profile adds zero. Host transfer source has one synchronous
borrowed-slice command and one Event per loop iteration, no owned event list or
RwVec, and no retained command cache. A completed tree's caller fence overlaps
its offload fence; reload completes before scalar gather starts. The inventory
conservatively sums four QueueFence owners (including both Queue handles), both
directions' command/Event/iterator/timing descriptors and their move destinations,
original/uploaded Allocation and optional transition owners, and HostBacking
transition owners. Host tree payload/caps/headers, mapped staging, retained
timeline backing, and device allocations keep their separate existing owners.

`QueueFence::finish` retains both queue Results before `a.and(b)`. The additive
census retains eight error/Result/String owner slots: the original error, both
queue results and formatted error for each of two overlapping fences, plus
fatal-cleanup formatting. Each slot has a separate 64 KiB bounded reply slab and
4 KiB fixed-format backing. This takes no credit against the original common
OpenCL error inventory. Enqueue, wait and finish supply no function-info String
to ApiError. Profiling uses two sequential replies, each bounded before allocation
to eight bytes by the pinned ocl-core implementation; both vector owners and
payloads are charged. Kernel/source/program wrappers remain in the original
native OpenCL census and opaque driver memory stays under the context reserve.

The reviewed ocl 0.19.7 registry source is pinned in capsule metadata:
`standard/buffer.rs` contains borrowed Slice variants and blocking `enq`;
`standard/event.rs` and `standard/queue.rs` forward the scalar wait/profiling/finish
calls. Repository dependencies pin the bounded ocl-core functions, error
formatting, profiling decoder and reply ceiling. Authored CPU tests exercise
the real API-error formatting and profiling decoder without invoking a driver,
and source canaries guard command/event/fence liveness. These tests are not an
observed runtime transfer peak or a failure-injection qualification.

## Qualification and composition boundary

This capsule adds six focused CPU tests; Agent B performed source inspection
and formatting only. Coordinator builds, tests, separate host-profile GPU
qualification, fresh proof/CPU verification, mutation checks, exact-runtime
cleanup, source/executable/terminal audits remain required. Existing device
component evidence does not qualify this host path.

This remains native-component plumbing. Before any native-to-recursive graph
dispatch, the complete workflow must pre-admit retained native proof/report and
adapter metadata, all child owners, recursive compiler inputs/witness copies,
output/report storage, and independent verifier scratch. A023's post-production
child conversion alone does not establish that pre-admission. Native runtime
retirement can precede a separate matching outer_host_v1 runtime in the same
immutable process environment; phase-transition admission must still follow
ownership, and no live receipt may be reattached as a replacement reservation.
No PairedV1 full transaction dispatch, complete-workflow speed claim, security
parameter change, or production transaction acceptance is enabled here.
