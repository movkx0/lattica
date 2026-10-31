# Pending HashX quota projection

`PendingNativeHashx::project_outer_quota` borrows the exact original request and
ledger. It requires the complete immutable pending native source, preparation,
ten outputs/verifiers/retained children/attachments, original bookkeeping and
an already reserved outer bridge. The expected request must be pointer-identical
to the original owner. It never consumes or mutates that pending source.

The projection creates a real `PendingRuntime::reserve_outer_host_v1` in the
same ledger. That pure constructor reserves the complete startup, 8 GiB host
trees and research runtime/continuity wrapper accounting without reading the
environment, inspecting a driver, or creating a context. A private runtime
adapter borrows its original reservation. Core's distinct
`NativeShakeQuotaProjection` reserves actual source-derived phase wrappers and
PCS quota while that borrow remains alive. It contains no PCS plan, runtime,
compiler or dispatch entry, and exposes no raw reservation.

Both the actual native phase constructor and this projection call the same
checked `reserve_wrappers`, `operation_host_budget` and `pcs_request` helpers.
The PCS host assignment is the remaining host quota after wrappers, capped at
24 GiB; its device assignment is 8 GiB minus the original startup device bytes.
The real constructor still performs all original preflight, physical PCS
planning and profile checks before admitting its actual PCS owner. Successful
projection does not run or replace those checks.

The numeric `ProjectedHashxQuota` has a separate type from actual prepared
`OuterContinuationCapacity`. It reports startup, phase-wrapper and PCS bytes,
plus the fixed retained-tree payload. Before returning, the projection checks
that the live ledger equals the original current bytes plus all three new
claims and reaches exactly 8 GiB managed device quota. It then destroys the
projection before the original pending runtime, checks current-byte restoration,
and returns only numbers. All returned failures and unwinds destroy the same
local owners. Historical ledger peaks remain historical; they are not reset.

The complete new core owner/result/shared-helper census is added to core phase
wrappers for both real and projected construction. Research additionally charges
that complete core census before a projection wrapper exists, plus eight copies
of projection/report/runtime/result/snapshot/argument layouts and fixed source,
quota, diagnostic and iterator frames in original native bookkeeping. This
bookkeeping is reserved before either capacity calculation. No later admission
obtains an older, larger capacity. B must reserve every source/compiler/output,
recheck and caller/result/report claim before invoking this method, and charge
its own caller storage separately.

Default proof selection and cryptographic behavior do not change. New source
accounting slightly increases default wrapper/bookkeeping requirements, so
immutable PCS capacity and all source feasibility results must be recomputed.
No resource allowance, row/thread limit, freshness policy or GPU requirement
is changed. CPU reporting must identify projected quota fit separately and
report physical/backend fit as unqualified. The genuine GPU path must still
use actual `prepare` and its original admitted phase.

This capsule has source inspection and isolated rustfmt validation only. Tests
cover identity/ledger refusal, missing ownership, exact source preservation,
one-byte host/device shortages, and release of temporary quota, but are not run
by the author. No physical-fit, proof, complete-workflow, performance or security
adoption claim follows from this diagnostic helper.
