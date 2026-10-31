# Explicit host-tree native singleton component

The separately selected `PreparedNativeSingleton::new_outer_host_v1` constructor
owns one native 4096-by-517 SHAKE singleton. It retains the same original source,
output/report, verifier and bookkeeping claims as the device constructor. It
selects `PendingRuntime::reserve_outer_host_v1` before environment preflight and
uses the matching fixed core `NativeShakePhase::new_outer_host_v1`. It never
mutates environment, changes the default constructor, or retries a device proof.

The original pending runtime reserves the full 8 GiB host-tree payload and its
HostQuota Arc wrapper inside the same 32 GiB worker allowance before preflight.
The core phase admits additive OCL storage and derives its PCS assignment from
the actual remaining ledger, capped at the unchanged 24 GiB native allowance.
The configured 24 GiB ceiling is not an additional reservation above host trees.
The managed phase is still 8 GiB; only its original startup device baseline can
overlap its PCS claim. The process remains capped at 47 GiB with zero swap and
the separate 4 GiB device-context reserve. This child changes none of those
guards or limits, and does not select an environment for its caller.

The core source plan binds the exact tree mode and 8 GiB quota before startup,
checks the complete native tree graph, and checks again under the original
runtime/engine lease. A row ceiling is not guaranteed admission: at 2^20 rows
the complete native graph exceeds 8 GiB before headers. This first research
constructor still rejects all batched native segments before runtime selection.

No new payload or inline owner is introduced in this constructor. All owners
are the existing source/prepared/runtime/core types whose actual sizes are
charged by their original source plans. The returned value uses the existing
one-shot producer and explicit `Session::finish_reserved` success/failure path.
Preparation and core claims survive exact runtime retirement; independent CPU
verification then retains the original output, report and bookkeeping claims.
Zero live managed/tree storage and release of the original lease remain required.

Four pure release CPU tests cover the exact additive host startup charge, its
reduced remaining PCS room, original-ledger and source-index refusal, one-byte
short admission before preflight, and future retained claims in the same ledger.
One separate ignored qualifier exercises two fresh witnesses, actual native
reports, independent CPU verification, public mutation rejection and terminal
cleanup. Its dedicated selector requires the unchanged immutable host runtime
environment plus `LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION=1`; the coordinator
owns that exact guard. The device qualifier and evidence remain separate.
The component timer starts after original request construction, matching the
device qualifier, and includes admission, setup, proving, independent verification,
report serialization and mutation checks. It is not complete-workflow timing.
No tests, build or GPU execution have been performed by Agent A for this child.

## Combined workflow admission is a separate prerequisite

This constructor is component-only. Its three arguments do not constitute an
admission token for a complete native-to-compiler-to-outer graph. Before a future
combined entry may dispatch its first native proof, it must complete the following
source planning using the original immutable request and worker ledger:

1. Determine the complete segment/layout/recursive graph, including odd tails,
   interior boundaries and final height closure. Refuse unsupported source or
   profiles before the first runtime starts.
2. Preissue exact original claims for every retained native proof/report, adapter
   metadata, compiler inputs/owners, every recursive output/report, final output,
   independent verifier and orchestration record. Those claims follow their
   payloads through moves. A023's isolated post-proof adapter admission cannot
   serve as this complete workflow plan; it needs an original preissued adapter
   owner and a closed conversion that consumes that same owner.
3. Bind each sequential phase to trustworthy source bounds and the original
   tokens. Account retained previous children plus all active/temporary storage.
   Reusable phase scratch may overlap only through an explicit original-owner
   lifetime proof; a peak estimate is not a second allowance. Source profiles and
   the same immutable host environment must be chosen before dispatch.
4. Derive each native/outer operation assignment only after all overlapping
   retained and fixed runtime claims have been deducted from the original
   32 GiB worker allowance. Confirm each complete phase fits before dispatch,
   keeping managed/context/native/process/thread/row limits unchanged.
5. Consume the originally issued adapters/compiler/output owners, then retain
   them through their exact runtime and payload cleanup. Never attempt a later
   admission merely because native PCS scratch was just released. Unexpected
   runtime failure terminates the attempt; no fallback or retry is admitted.

Such a workflow must be independently reviewed and qualified. This child offers
no complete RingCT coverage, recursive closure, artifact round trip, N3/N4
screening or workflow speedup claim. The existing adapter remains unchanged.
