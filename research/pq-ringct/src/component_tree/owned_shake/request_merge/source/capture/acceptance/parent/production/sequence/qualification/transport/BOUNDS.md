# Private original-root transport qualification driver

This file describes the inactive, ignored `qualification::transport` driver
against checkpoint `959088dec4a2c5bc2c04ab4bb858168fb3a3f3ba`. It does not
enable a wrapper, CLI selector, ancestor module, GPU launch, or production
transaction acceptance. The exact event contract is
`ringct-c-root-transport-driver-contract-v1-20261025.json`, SHA-256
`d1345e045f6b8e0f3ed8ea4bec04977876a21d9156bceadbd989bd0436bc3bd7`.

## Admission and ownership order

`exercise` first obtains the complete baseline-plus-additive driver requirement
from `transport::claims::driver_requirement` and admits one original
`PhaseScratch` caller on the same ledger. This caller remains live through all
guard, request, source, attempt, error, plan, report, formatting, and destruction
work. A failed admission returns before this work. Requirements and census
bootstrap are bounded harness work under the external process guard, as in the
existing private qualification driver.

The source request, deliberately different request owner, five group plans,
request closure, five retained original leaf sources, and parent source use the
existing qualification helpers. No source/key/proof identity is substituted.
The driver calls `PreissuedRootTransport::reserve_before_native` on this actual
parent source before `Attempt::reserve_before_native`. The ordering therefore
precedes even creation of the original `PendingNative`, not only proof dispatch.
Both A047 transport reservations remain held through the same Attempt's graph
and its root transport; the transport plan report is read while those originals
and the complete caller are live.

The actual GPU branch consumes that one Attempt. It first emits the existing
component graph and source-acceptance summaries, then consumes that same
Component through `roundtrip_root`. The closed component adapter supplies only
its own Parent3 source/key/proof/request. The driver never accepts a different
root or constructs a detached continuation. It checks and formats measurements
only through the retained report's borrowed accessor and drops the complete
report before releasing source/request/caller owners.

Normal teardown drops attempt and transport options, parent source, the closed
request result, group plans, both request owners, and finally the caller. The
request closure still returns `Result<Infallible, RefusedRequest>`; the driver
checks retention of all five original leaf sources. An actual production failure
is classified using fixed static strings while both the complete caller and the
returned Failure are live; Failure is then destroyed before scope teardown.
There is no fallback, second attempt, retry, or quota transfer. The actual
transport and terminal observer use only the original ledger. The inherited
CPU projection helper creates a separate foreign ledger solely to check that
wrong-ledger projection is refused without acquiring quota on either ledger;
that negative identity probe provides no terminal-observer admission credit.

## Complete claims and retained transport

A048 supplies the additive concrete caller census and preserves the whole
baseline driver census. It includes the transport owners, complete result/error
variants, plan and retained reports, borrowed measurements, nested header report,
format arguments, numeric arrays, and forwarding/drop frames. This supplements
A047's fixed original owner/caller claim and additive packet/decoder/verifier
claim; no category replaces or credits another original claim.

The underlying transport independently reserves both complete 2 MiB packets,
the cumulative 64 MiB bounded decoder, all 18 codec heights, all 18 independent
CPU verifier lifecycles and their classified extra storage, before Attempt. Each
height must satisfy `2480 + inner_with_magic + 1 <= 2097152`. Original retained
proof/key/runtime storage stays additive. The driver emits all twelve plan fields
plus its own caller bytes and checked sum. That sum is only the driver/transport
subset, not a complete component memory measurement. The subsequent source
claims snapshot includes the complete Attempt and source claims.

No native/recursive row limit, security parameter, segmentation, transcript,
ownership boundary, FreshOnly policy, or GpuRequired proving requirement changes.
The GPU mode retains the existing exact sequence opt-in, GPU-required runtime,
host retained-tree policy, and 8 GiB retained-tree host setting. Its ledger still
allows 32 GiB host and 8 GiB device; the coordinator's exclusive process, engine,
device, zero-swap, and source/binary audit remains mandatory.

## Fixed terminal observer

After `exercise` returns and every ledger category is zero, `run` retains only a
fixed result, Snapshot, mode, timing and census value in `TerminalObservation`.
Ledger bootstrap, this terminal observer, and its output belong to separately
identified harness scope covered by the external full-process guard. Released
worker reservations do not cover or admit these frames. No second ledger or
manufactured reservation is used to observe zero quota.

`terminal_observer_bytes` is a positive, checked, at-most-1-MiB source-layout
census. It takes no Ledger and issues no Requirements or Reservation. It is not
a physical memory measurement, process admission, or source-storage allowance.
Both final events explicitly emit `terminal_observer_scope=process-audit-only`,
`released_claims_cover_terminal_observer=false`, and
`process_engine_device_audit_complete=false`. Completion requires successful
exercise and zero current bytes in every category; a destruction abort or error
cannot produce a successful completion event.

The complete event and terminal event contain only fixed ASCII literals, fixed
enum/boolean renderings and unsigned decimal integers. Substituting maximum u128
timings, maximum u64 counters and the longest mode/boolean strings gives 1,209
and 628 ASCII bytes respectively, including newlines: 1,837 combined, below the
4,096-byte observer-output allowance. C's external guard independently bounds
their actual combined output. No terminal event serializes a proof, packet,
key, dynamic error, plan report, or retained transport owner.

## Evidence scope and capacity entry

The GPU entry covers exactly one immutable same-source root in memory after ten
native proofs, five recursive leaves and four recursive parents. Transport adds
two actual independent CPU numerical positives, one bounded decode, two header
structural positives, and 629 typed header refusals (24 syntax, 46 public,
256 cap, one height, and 302 canonical). The genuine bounded decoder diagnostic
must appear once between acceptance and transport scope. The six disjoint
positive operation intervals must be positive and sum to at most the complete
transport action interval. The scope event is provisional until destruction.

Header refusals are not cryptographic proof negatives. This driver claims no
generic decoder-failure classification, raw/interior mutation suite, disk or
full artifact suite, transaction-context authentication, complete RingCT workflow,
physical resource qualification, or performance improvement. Source inspection
and synthetic guard fixtures are not actual proof or GPU evidence.

The ignored CPU capacity entry requires the separate source qualification flag,
uses the same original source and preclaims, then calls the existing pure numeric
`project` path. It never creates a backend, dispatches native/GPU work, numerically
verifies a proof, allocates packet/decoder payloads, or emits transport success.
It reports capacity mode and `component_success=false`. The coordinator will
provide separate exact CPU routing and a dedicated guard; there is no GPU/CPU
fallback. Preserve the existing `research-compile-large` source-only profile
(32 GiB memory.max, 30 GiB memory.high, 36 GiB fresh-admission threshold). These
are process limits/availability requirements, not a 36 GiB worker allowance or
evidence of actual GPU fit.
