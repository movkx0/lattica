> Historical snapshot. Local `benchmark-results/` paths refer to artifacts on the original test host and are not included in Git. Current commands are in [GPU benchmarking](../gpu-benchmarking.md).

# GPU-accelerated proving (opt-in)

The latest [development checkpoint](dag-gpu-implementation-2026-10-17.md#9309-coordinator-cost-attribution-and-isolated-request-binding-candidate--2026-10-16)
measures coordinator CPU costs and prepares an isolated optimization that retains
the binding between an assignment and its immutable request. Request preparation
takes about **181 ms** in the diagnostic, while verifier metadata takes about
**5.5 ms**. Two selected regression runs pass **138 tests**, but overlap from
another session excludes their resource qualification. Short serial batches have
qualified **123 tests** so far. The candidate's idle queue is stopped after the
resource conflict recurs across three goal turns; a saved controller resumes from
the completed batches when the host is free. Remaining lifecycle checks, full-size
proof replay, source integration and fresh production qualification are pending. The shared
proving source and accepted production images are unchanged; no delivered speedup
is established.

The latest [native delivery](dag-gpu-implementation-2026-10-17.md#9308-owned-completion-delivers-a-fresh-native-block--2026-10-16)
uses the rebuilt owned-completion images to generate **127 fresh GPU proofs**
and durably apply **48 user plus 16 issuance transactions**. Independent CPU
wallet, graph and history audits pass. The workflow takes **587.303 seconds**,
leaving **12.697 seconds** under its original deadline; accepted history is now
**ten blocks at height 19**. The coordinator timing gap is 64.435 seconds,
down from 70.420, while total workflow time falls by 2.671 seconds. These are
single-run observations, not a matched speedup or sustained-throughput result.
The original resource/deadline limits and full-GPU qualification gates remain.
See [source evidence](../evidence/gpu-owned-completion-workflow-2026-10-16.json).

The preceding [image qualification](dag-gpu-implementation-2026-10-17.md#9307-owned-completion-production-images-and-fresh-calibration--2026-10-16)
rebuilds the owned-completion snapshot's optimized CPU/GPU native images and
matching test harness. **32 fresh GPU proofs** pass interface, recursive-worker,
retirement and calibration checks. Independent CPU replay covers the complete
63-node graph and 64 archived wallets; **14 new timing classes** bind these
images. All required wallet/recursive proving stages report OpenCL. An initial
duplicate-order preflight is preserved separately from the successful fresh
calibration. That qualification consumed no native block or funded slots and
did not establish delivered throughput or a production deadline bound.
See [source evidence](../evidence/gpu-owned-completion-proving-2026-10-16.json).

The preceding [completion-source checkpoint](dag-gpu-implementation-2026-10-17.md#9306-owned-local-node-completion-avoids-repeated-artifact-digests--2026-10-16)
removes two repeated operational digests when locally CPU-verified immutable
proof bytes pass through storage and DAG acceptance. Independent verification,
existing-file checks, attempt fencing and durable publication remain enforced.
**160 CPU tests** pass, including full-size proof replay/recovery and malformed
result rejection; CPU/GPU all-target checks also pass. An optimized probe measures
**44.08 ms** per 1.68 MiB node digest. That checkpoint did not qualify production
images or a fresh GPU workflow; no throughput gain is claimed.
See [source evidence](../evidence/gpu-owned-node-completion-2026-10-16.json).

The preceding [native delivery checkpoint](dag-gpu-implementation-2026-10-17.md#9305-reserved-handoff-delivers-a-fresh-native-block--2026-10-16)
passes with **64 fresh wallet and 63 recursive GPU proofs**, independent CPU
verification and durable application of **48 user plus 16 issuance transactions**.
The new reserve check defers an unsealed prefix when only 33,409 ms remain,
drains that worker and completes the seven final proofs on its replacement.
The full workflow takes **589.974 seconds**, leaving **10.026 seconds** of its
original deadline; post-seal application takes **79.899 seconds**. Accepted
history is nine blocks at height 18. The original budgets and native image
build manifests remain. Deadline margin, matched controls, sustained qualification
and the full all-GPU goal remain open. See
[source evidence](../evidence/gpu-handoff-reserved-workflow-2026-10-16.json).

The preceding [handoff checkpoint](dag-gpu-implementation-2026-10-17.md#9304-reserve-final-proving-time-before-live-handoff--2026-10-16)
fixes admission after an optimized delivery trial generated 64 wallet and 56
recursive GPU proofs but applied no block. Its completed prefix left 34,180 ms
in the worker window; sealing consumed most of that time. Callers must now
reserve final proving time explicitly, and a short window defers before sealing.
All 43 handoff/phase regressions pass. The proposed 75,000 ms reserve is a trial
allowance requiring fresh live validation. Native binaries and their calibration
remain unchanged; the four Python changes have a separate source manifest.
See [source evidence](../evidence/gpu-handoff-continuation-window-2026-10-16.json).

The preceding [optimized-image checkpoint](dag-gpu-implementation-2026-10-17.md#9303-optimized-native-images-and-cli-calibration--2026-10-16)
qualifies the same 880-file snapshot with release optimization level 3,
one codegen unit and thin LTO. The CPU interface suite passes 32 tests
(one GPU-only skip), and the GPU suite passes all 36. Native worker and
retirement checks, followed by fresh CLI calibration, produce **32 GPU
proofs** in total. The calibration has **14 independently approved timing
classes** and a complete CPU replay of 63 graph nodes and 64 archived wallets.
The original resource caps remain. These are interface, lifecycle and job
calibration results; fresh native delivery, matched throughput and sustained
qualification remain open. See
[source evidence](../evidence/gpu-current-optimized-proving-2026-10-16.json).

The preceding [CLI calibration checkpoint](dag-gpu-implementation-2026-10-17.md#9302-current-cli-calibration--2026-10-16)
adds **17 fresh GPU proofs** across eight serial phases and **14 independently
approved timing classes**. The current CPU CLI verifies the complete 63-node
graph and all 64 archived wallet inputs; every new request covers 16 OpenCL
stages. The graph uses archived subtrees and is not a fresh delivered workflow.
These timings belong to the opt-level 1, 64-codegen-unit, no-LTO images.
Optimized release images require their own qualification and calibration. See
[source evidence](../evidence/gpu-current-cli-calibration-2026-10-16.json).

The preceding [native lifecycle checkpoint](dag-gpu-implementation-2026-10-17.md#9301-current-source-native-startup-and-retirement--2026-10-16)
adds four startup rejection cases and two full-size GPU finalizer proofs
across forced worker retirement and replacement. Physical process-exit
observers confirm that replacement starts after the first worker exits.
Both returned proofs verify on CPU after shutdown; all 16 required stages
run on OpenCL. The incomplete first attempt remains preserved. These
checks retain the existing resource limits and establish no throughput
claim. See [source evidence](../evidence/gpu-current-native-lifecycle-2026-10-16.json).

The preceding [native worker checkpoint](dag-gpu-implementation-2026-10-17.md#9300-current-source-native-worker-jobs-and-pool-roots--2026-10-16)
qualifies assigned jobs through the newly linked C service: **eight fresh
GPU proofs**, including six full-size pair/merge/finalizer proofs and two
small padding proofs. All 16 required recursive stages report OpenCL.
Three separate CPU-only processes verify all six persisted nonempty proofs
after coordinator and worker exit. Two roots pass the local pool adapter;
context updates, cache reuse, shutdown and reservation release pass. Four
malformed-configuration/job/disconnect cases clean up while retaining their
reservations. No native block or funded slot is consumed. Fresh calibration,
matched delivered throughput and sustained qualification remain open. See
[source evidence](../evidence/gpu-current-native-worker-2026-10-16.json).

The preceding [native integration checkpoint](dag-gpu-implementation-2026-10-17.md#9299-current-source-native-builds-and-wallet-abi--2026-10-16)
rebuilds CPU/GPU Rust libraries, worker CLIs and Zig bridges from the same
880-file snapshot. Both bridges independently report capacity 64. The CPU FFI
suite passes 32 tests with one GPU-only skip; the GPU FFI suite passes all 36,
producing five fresh GPU wallet proofs and one tree-root operation. All 15
required wallet proving stages report OpenCL, with CPU verification after
shutdown. Fourteen source archives and eight native images are checked.
Assigned public-worker execution, fresh calibration, delivered throughput and
complete resource ownership remain open. See
[source evidence](../evidence/gpu-current-native-integration-2026-10-16.json).

The preceding [mixed-policy tree qualification](dag-gpu-implementation-2026-10-17.md#9298-mixed-policy-tree-with-cold-and-cached-recursion--2026-10-16)
adds **four fresh GPU proofs**: cold and cached merge/finalizer runs over four
archived inputs spanning JoinSplit, HTLC redeem/refund and issuance. The
12-key registry uses 262,144 rows. All **16 request stages** report OpenCL;
cache hits are explicitly recorded. Every proof verifies after shutdown and
again in a separate CPU-only process, with altered statements rejected.
Two geometry checks and the GPU-host all-target check pass. Evidence verifies
**880 sources, three archives and 163 artifacts**. Only the test harness
changes; native delivery, complete resource ownership and sustained/hardware
qualification remain open. See
[source evidence](../evidence/gpu-mixed-policy-tree-cache-2026-10-16.json).

The preceding [ordered wallet-pair qualification](dag-gpu-implementation-2026-10-17.md#9297-full-size-ordered-wallet-policy-pairs--2026-10-16)
adds **14 fresh GPU proofs** across all nine ordered JoinSplit/HTLC/issuance
combinations and five HTLC-refund cases, using the **12-key, 262,144-row
registry**. All **16 request stages** run on OpenCL. Every proof verifies after
GPU shutdown and again in a separate CPU-only process, with altered statements
rejected. Nine geometry checks and the final GPU-host all-target check pass.
Only the test harness changes; evidence verifies **879 sources and 827
artifacts**, preserving unsuccessful attempts. Mixed-policy trees, other
registries, native delivery, complete lifetime ownership and throughput remain
open. See [source evidence](../evidence/gpu-mixed-policy-pairs-2026-10-16.json).

The preceding [nonempty recursive qualification](dag-gpu-implementation-2026-10-17.md#9296-current-source-nonempty-recursive-proof-tree--2026-10-16)
produces **four fresh GPU proofs**: two pairs, their four-transaction merge and
its depth-6 finalizer. The unchanged 878-file source uses the **12-key registry,
262,144 rows and default capacity 64**. All **16 request stages** run on OpenCL;
all four proofs verify on CPU after GPU shutdown. Three additional CPU-only
processes verify persisted outputs after worker exit and reject altered
statements. Evidence pins **180 artifacts and 78 fixture files**. This qualifies
direct Rust requests; native service delivery, full-capacity roots, complete
lifetime ownership and throughput remain open. See
[source evidence](../evidence/gpu-current-nonempty-recursion-2026-10-16.json).

The preceding [recursive size-reporting change](dag-gpu-implementation-2026-10-17.md#9295-recursive-size-reporting-without-an-output-allocation--2026-10-16)
removes a **2 MiB temporary allocation per legacy recursive proof** used only
to report encoded size. A bounded counting serializer preserves both encodings
and the existing size cap. **25 codec tests, four all-target checks and three
fresh CPU-verified GPU proofs** pass on the final isolated source. This reduces
known host allocation requests; throughput and complete output ownership remain
unqualified. See [source evidence](../evidence/gpu-recursive-size-count-2026-10-16.json).

The preceding [recursive budget/cache check](dag-gpu-implementation-2026-10-17.md#9294-recursive-session-budget-and-cache-reuse--2026-10-16)
adds **three fresh CPU-verified proofs** on the combined snapshot. Cold setup,
warm reuse, explicit eviction, insufficient-budget rejection and altered-proof
rejection pass, with all **16 request stages** on OpenCL. This verifies a small
legacy session case; complete host/output ownership remains open. See
[source evidence](../evidence/gpu-recursive-budget-cache-2026-10-16.json).

The preceding [combined-source integration](dag-gpu-implementation-2026-10-17.md#9293-combined-source-integration--2026-10-16)
checks **877 source/support files**, incorporating the concurrent session's
capacity and host/pool changes. **135 Rust tests, 205 Python tests, four
all-target checks and 25 GPU tests** pass, producing **44 fresh CPU-verified
proofs**, 18 opening/FRI component cases and two tree operations. GPU evidence
covers the default capacity; opt-in capacity 128 has compilation/CPU coverage
only. Two stale Python fixtures were corrected and given capacity-boundary
checks. The audit verifies **40 source archives and 1,053 artifacts**; the shared
source whitelist matched the final snapshot when packaged. Native Zig/ABI,
complete resource ownership and production/sustained qualification remain open.
See [source evidence](../evidence/gpu-combined-source-integration-2026-10-16.json).

The preceding [recursive request qualification](dag-gpu-implementation-2026-10-17.md#9292-public-recursive-requests-with-cached-preprocessing--2026-10-16)
adds **eight fresh CPU-verified proofs** on the unchanged §9.291 source. Four
tests cover 3-, 5-, 6- and 12-key registries, each with a cold setup and a warm
preprocessing hit. All **16 request stages**, including public values, report
completed OpenCL work. Evidence pins **745 sources, eighteen inherited archives
and 78 artifacts**. These 2,048-row padding proofs leave nonempty recursive jobs,
complete resource ownership and production/sustained qualification open. See
[source evidence](../evidence/gpu-recursive-request-qualification-2026-10-16.json).

The preceding [transcript ownership change](dag-gpu-implementation-2026-10-17.md#9291-session-owned-transcript-and-scalar-host-quota--2026-10-16)
composes concurrent transcript/scalar backing within the existing **1 MiB**
session allowance. Each state retains its charge through cleanup; nested GPU
operations exclusively borrow a reservation checked against the owning session.
**126 unit/policy tests, 21 GPU test executions, 36 fresh CPU-verified proofs,
18 opening/FRI component cases and CPU/GPU all-target checks** pass. Evidence
verifies **745 sources, eighteen current-source archives, one preserved initial
archive and 737 artifacts**. Escaped output and enclosing lifetime ownership,
combined-checkout validation and broader qualification remain open. See
[source evidence](../evidence/gpu-transcript-host-ownership-2026-10-16.json).

The preceding [transcript/scalar change](dag-gpu-implementation-2026-10-17.md#9290-bounded-transcript-and-scalar-host-storage--2026-10-16)
bounds the existing 1 MiB host envelope and charges it alongside retained
commitments/runtime storage before opening/FRI. **120 unit/policy tests, 20 GPU
test executions, 36 fresh CPU-verified proofs and CPU/GPU all-target checks**
pass. The largest tested transient plan is **721,880 bytes**. Evidence verifies
**743 sources, seventeen current-source archives, one preserved initial archive
and 704 artifacts**. Combined-checkout validation, concurrent clone/escaped-output
ownership and broader qualification remain open. See
[source evidence](../evidence/gpu-transcript-host-storage-2026-10-16.json).

The preceding [retained runtime change](dag-gpu-implementation-2026-10-17.md#9289-retained-runtime-storage-shares-the-opening-budget--2026-10-16)
charges engine, session and current GPU transcript storage alongside commitments
before opening/FRI. **108 unit/policy tests, 33 fresh CPU-verified wallet proofs,
18 component cases and CPU/GPU all-target checks** pass. Evidence verifies **741
sources, sixteen current-source archives, one preserved initial archive and 581
artifacts**. Transient buffers, concurrent future clones, enclosing lifetimes and
combined-checkout validation remain open. See
[source evidence](../evidence/gpu-opening-runtime-storage-2026-10-16.json).

The preceding [retained commitment change](dag-gpu-implementation-2026-10-17.md#9288-retained-commitment-storage-shares-the-opening-budget--2026-10-16)
deducts device-only commitment backing before opening construction and FRI.
Private/public prefixes, salt capacities, replay/cleanup wrappers and tree caps
now share the configured operation allowance. **100 unit/policy tests, nine wallet
GPU integrations with 33 CPU-verified proofs, and four focused tests with 18
CPU-verified component cases** pass, along with CPU/GPU all-target checks.
Evidence verifies **738 sources, fifteen archives and 511 artifacts** in an
isolated source copy. Combined-checkout validation, shared engine/session and
transcript budgets, enclosing lifetimes and full qualification remain open. See
[source evidence](../evidence/gpu-opening-commitment-storage-2026-10-16.json).

The preceding [opening construction change](dag-gpu-implementation-2026-10-17.md#9287-exact-opening-construction-storage-before-arithmetic--2026-10-16)
replaces growable admission metadata and a fixed overhead estimate with an
allocation-free plan for retained caller metadata, exact output/descriptors and
readback buffers. Point and alpha words use fixed stack storage. **91 unit/policy
tests, nine qualified wallet GPU integrations with 33 CPU-verified proofs, and
four focused tests with 18 CPU-verified component cases** pass, along with CPU/GPU
all-target checks. Evidence retains **736 sources, fourteen current-source
archives, fourteen initial archives and 701 artifacts**, including corrected
compile/test failures and an interleaved tree run. Validation remains isolated
from the other session's edits; combined-checkout and full lifetime qualification
remain pending. See [source evidence](../evidence/gpu-opening-construction-storage-2026-10-16.json).

The preceding [opening/FRI host partition change](dag-gpu-implementation-2026-10-17.md#9286-opening-and-fri-share-the-configured-host-allowance--2026-10-16)
passes the configured operation allowance into opening evaluation and deducts
retained opening/round capacities and exact hiding output before FRI. **84
unit/policy tests, nine wallet GPU integrations with 33 fresh CPU-verified proofs,
and four component tests with 18 CPU-verified cases** pass, with CPU/GPU all-target
checks. Evidence verifies **734 sources, thirteen archives and 460 artifacts** in
an isolated copy of the verified parent plus twelve changed paths. **Concurrent
shared-checkout edits are excluded; combined validation remains pending.** Complete
resource ownership and production/sustained qualification remain open. See
[isolated source evidence](../evidence/gpu-opening-host-partition-2026-10-16.json).

The preceding [wallet serialization change](dag-gpu-implementation-2026-10-17.md#9285-bounded-wallet-serialization-with-retained-proof-storage--2026-10-16)
checks retained proof/public capacities and one final output against the actual
operation allowance before allocation. Cubic proofs serialize directly into their
envelopes, preserving the encoded bytes. **70 unit/policy tests, nine GPU
integrations and 33 fresh independently CPU-verified proofs** pass, with CPU/GPU
all-target checks. Evidence verifies **732 sources, ten current-source archives
and 317 artifacts**. This covers the serialization boundary; whole-proof and
exported-output lifetime ownership and production/sustained qualification remain
open. See [source evidence](../evidence/gpu-wallet-serialization-storage-2026-10-16.json).

The preceding [wallet host partition change](dag-gpu-implementation-2026-10-17.md#9284-wallet-operation-budgets-exclude-retained-preparation--2026-10-16)
carries one operation allowance through witness generation, public readback and
the PCS, after charging retained preparation. Preflight and runtime budgets must
match. **63 unit/policy tests, nine GPU integrations and 33 fresh independently
CPU-verified proofs** pass, with CPU/GPU all-target checks. Evidence verifies
**729 sources, nine current-source archives and 286 artifacts**. Whole-proof host
ownership and production/sustained qualification remain open. See
[source evidence](../evidence/gpu-wallet-operation-host-partition-2026-10-16.json).

The preceding [wallet preparation change](dag-gpu-implementation-2026-10-17.md#9283-combined-wallet-preparation-host-allowance--2026-10-16)
charges symbolic compilation and overlapping periodic source/staging against a
single host allowance, then rechecks it at runtime. **60 unit/policy tests, nine
GPU integrations and 33 fresh independently CPU-verified wallet proofs** pass,
with CPU/GPU all-target checks. Evidence verifies **729 sources, eight current-source
archives and 310 artifacts**, including the preserved initial test-helper failure.
Whole-proof host ownership, remaining operation coverage and production/sustained
qualification remain open. See [source evidence](../evidence/gpu-wallet-preparation-host-admission-2026-10-16.json).

The preceding [wallet AIR recording change](dag-gpu-implementation-2026-10-17.md#9282-wallet-air-recording-owns-all-callback-heap-requests--2026-10-16)
replaces temporary heap vectors with fixed arrays and index iterators. Independent
allocator observations find no requests outside recorder accounting across all
seven maintained wallet AIR variants. Circuit fingerprints remain unchanged.
**58 unit/policy tests, nine GPU integrations and 33 fresh independently
CPU-verified wallet proofs** pass, with CPU/GPU all-target checks. Evidence verifies
**729 sources, eight current-source archives and 246 artifacts**. Combined host
lifetimes, remaining operation coverage and production/sustained qualification
remain open. See [source evidence](../evidence/gpu-wallet-air-recording-storage-2026-10-16.json).

The preceding [quotient-input admission change](dag-gpu-implementation-2026-10-17.md#9281-shared-quotient-projection-and-partition-admission--2026-10-16)
checks projection copies, later transforms and partitioned evaluation before
transfers or domain arithmetic. Ten shared input plans account for cached-workspace
overlap and preserve single-coset aliases. **51 unit/policy tests, fourteen GPU
integrations and 33 fresh independently CPU-verified wallet proofs** pass, with
CPU/GPU all-target checks. Evidence verifies **729 sources, eight current-source
archives and 413 artifacts**, including the initial passing CPU campaign before
the alias review. Full resource ownership, recursive integration and
production/sustained qualification remain open. See [source evidence](../evidence/gpu-wallet-quotient-input-admission-2026-10-16.json).

The preceding [commitment-input admission change](dag-gpu-implementation-2026-10-17.md#9280-shared-commitment-input-storage-and-evaluation-shapes--2026-10-16)
shares runtime and preflight checks for hiding samples, quotient masks and
commitment parameters. Eleven input plans distinguish resident storage from
pending allocations. **51 unit/policy tests, thirteen GPU integrations and 33
fresh independently CPU-verified wallet proofs** pass, with CPU/GPU all-target
checks. The corrected differential test uses the explicit upstream CPU oracle
while strict GPU mode stays enabled. Evidence verifies **726 sources, eight
current-source archives and 426 artifacts**, including the initial oracle failure.
Full resource ownership, recursive integration and production/sustained qualification
remain open. See [source evidence](../evidence/gpu-wallet-commitment-input-admission-2026-10-16.json).

The preceding [witness staging admission change](dag-gpu-implementation-2026-10-17.md#9279-allocation-free-witness-shape-admission-and-bounded-staging--2026-10-16)
checks the actual request host allowance before allocating batch/tree geometry.
Static AIR tables and fixed planner layouts avoid admission staging allocations;
tree bounds include canonical-dummy generation. **51 unit/policy tests, thirteen
GPU integrations and 33 fresh independently CPU-verified wallet proofs** pass,
alongside CPU/GPU all-target checks. Focused tests cover both 64-tile batch witnesses
and tree roots through 1,024 statements. Evidence verifies **724 sources, six
current-source archives and 273 artifacts**. Complete memory lifetimes, recursive
integration and production/sustained qualification remain open. See [source evidence](../evidence/gpu-wallet-witness-admission-2026-10-16.json).

The preceding [shared FRI admission change](dag-gpu-implementation-2026-10-17.md#9278-shared-fri-fold-final-polynomial-and-gather-admission--2026-10-16)
reuses runtime checks for folds, final-polynomial output and query gathering before
wallet arithmetic. **47 unit/policy tests, eleven GPU integrations and 33 fresh
independently CPU-verified wallet proofs** pass, alongside CPU/GPU all-target checks.
Both fields retain their distinct proof profiles; focused GPU tests preserve CPU
arithmetic results and duplicate query order. Evidence verifies **724 sources, six
current-source archives and 245 artifacts**. Remaining operation coverage, full
host/recursive lifetimes and production/sustained qualification remain open. See
[source evidence](../evidence/gpu-wallet-fri-admission-2026-10-16.json).

The preceding [shared randomness-storage admission change](dag-gpu-implementation-2026-10-17.md#9277-shared-randomness-storage-admission-before-wallet-arithmetic--2026-10-16)
reuses runtime checks for sampling buffers, retained draws and sequential salt
replay before wallet arithmetic. **48 unit/policy tests, thirteen GPU integrations
and 33 fresh independently CPU-verified wallet proofs** pass, alongside CPU/GPU
all-target checks. Evidence verifies **721 sources, six current-source archives
and 282 artifacts**, including the preserved first test-oracle failure. The report
adds 43 randomness plans per request. Complete stream/host lifetimes, remaining
operation coverage and production/sustained qualification remain open. See [source evidence](../evidence/gpu-wallet-randomness-admission-2026-10-16.json).

The preceding [bounded periodic-table construction change](dag-gpu-implementation-2026-10-17.md#9276-bounded-periodic-table-construction-before-gpu-work--2026-10-16)
checks table geometry, construction storage and expansion staging before allocation.
Internal providers fill bounded buffers; all seven maintained AIR variants match
their independent existing tables. **56 unit/policy test executions, nine GPU
integrations and 33 fresh independently CPU-verified wallet proofs** pass, alongside
CPU/GPU all-target checks. Evidence verifies **718 sources, eight current-source
archives and 257 artifacts**, including the preserved initial test-fixture build
failure. Complete host/resource lifetimes, remaining operation coverage and
production/sustained qualification remain open. See [source evidence](../evidence/gpu-wallet-periodic-construction-2026-10-16.json).

The preceding [periodic-source admission change](dag-gpu-implementation-2026-10-17.md#9275-retained-periodic-sources-and-shared-expansiontransform-admission--2026-10-16)
retains and validates static periodic tables before wallet arithmetic, then shares
expansion and transform storage checks with runtime. It checks period geometry,
retained vector capacity and subsequent staging; the AIR's initial table allocation
still needs enclosing ownership. **40 unit/policy tests, nine GPU integrations and
33 fresh independently CPU-verified wallet proofs** pass, along with CPU/GPU
all-target checks. Evidence verifies **718 sources, six archives and 218 artifacts**.
Complete memory ownership, operation coverage and production/multi-device
qualification remain open. See [source evidence](../evidence/gpu-wallet-periodic-admission-2026-10-16.json).

The preceding [opening/query admission change](dag-gpu-implementation-2026-10-17.md#9274-wallet-admission-reuses-opening-and-query-operation-planners--2026-10-16)
reuses the production opening-evaluation, opening-reduction and query planners
before wallet arithmetic. It checks all quotient partitions and bounds query host
staging even when runtime has room for a wider tile. The quadratic/cubic profiles
retain their distinct 96/128 query counts. **42 unit/policy tests, nine GPU
integrations and 33 fresh independently CPU-verified wallet proofs** pass, alongside
CPU/GPU all-target checks. Evidence verifies **716 sources, seven accepted archives
and 246 artifacts**, including the preserved first synthetic-test failure. Full
host/recursive ownership, complete planner coverage and production/sustained
qualification remain open. See [source evidence](../evidence/gpu-wallet-opening-query-admission-2026-10-16.json).

The preceding [recorded-program admission change](dag-gpu-implementation-2026-10-17.md#9273-recorded-wallet-programs-admit-quotient-rows-and-tiles-before-arithmetic--2026-10-16)
checks conservative compiled row/tile geometry before wallet arithmetic. Each AIR
is recorded once and retained through GPU normalization; exact normalized degree,
optimized instructions and proof formats are preserved. All supported quotient
partitions fit the shared runtime planner, including the preceding 1 MiB tile.
**77 unit/policy tests, nine GPU integrations and 33 fresh wallet proofs** pass,
with CPU/GPU all-target checks and independent CPU verification after GPU shutdown.
Twenty-two resource-rejected requests stop before arithmetic. Evidence verifies
**715 sources, seven archives and 230 artifacts**. Complete operation-planner
coverage, host/recursive lifetimes and production/sustained qualification remain
open. No throughput improvement is claimed. See [source evidence](../evidence/gpu-wallet-program-admission-2026-10-16.json).

The preceding [wallet phase-admission change](dag-gpu-implementation-2026-10-17.md#9272-wallet-device-phase-storage-and-atomic-capacity-admission--2026-10-16)
adds conservative device storage checks from witness generation through FRI queries
and grants capacity against the same locked allocation snapshot. It covers all
supported quotient partitions and cached-workspace/salt-draw overlap. **53 unit/
policy tests, nine GPU integrations and 33 fresh GPU proofs** pass, with independent
CPU verification. Twenty resource-rejected requests stop before GPU work.
Evidence verifies **711 current sources, nine current-source archives and 307
artifacts**. Exact compiled-program tile admission, complete host ownership and
recursive-request integration remain open. These correctness builds establish no
new production qualification or throughput result. See [source evidence](../evidence/gpu-wallet-phase-admission-2026-10-16.json).

The preceding [wallet shape-admission change](dag-gpu-implementation-2026-10-17.md#9271-wallet-geometry-rejects-impossible-storage-before-arithmetic--2026-10-16)
checks necessary retained and periodic-transform storage against managed and
per-buffer limits before wallet arithmetic, then acquires the existing capacity
owner. It covers quadratic singles/batches and cubic join-split, HTLC and issuance.
**47 unit/policy tests, nine GPU tests and 33 fresh wallet proofs** pass, together
with CPU/GPU all-target checks and CPU verification after shutdown. Eighteen
insufficient-storage requests reject before GPU work. Independent checking covers
**709 current sources, nine current-source archives and 371 artifacts**, including
the preserved failed first test fixture. See [source evidence](../evidence/gpu-wallet-shape-admission-2026-10-16.json).
This is a storage floor, not a complete phase-peak or host-memory bound. No new
production qualification, native block, funded-slot use or throughput result is
claimed; those remain on their preceding-source attribution.

The preceding [wallet-capacity source change](dag-gpu-implementation-2026-10-17.md#9270-wallet-provers-retain-managed-capacity-through-completion--2026-10-16)
holds the existing managed GPU ceiling through quadratic and cubic wallet proving
and serialization. Existing allocations count once; competing callers cannot
consume future phase capacity, and ending the owner leaves actual buffers charged.
**43 unit/policy tests, eight GPU integration tests and 31 fresh GPU wallet proofs**
pass, alongside CPU/GPU all-target checks. CPU verification after shutdown and
negative input checks pass. Evidence verifies **707 sources, eight archives and
214 artifacts**. Original caps hold without new memory-limit/OOM events.
See [source evidence](../evidence/gpu-wallet-capacity-2026-10-16.json).

This is correctness-image validation. Shape-derived peak admission, host/caller
ownership and recursive-request integration remain open. Production images and
timing approvals have not been rebuilt or transferred; the latest full native
workflow below retains its preceding-source attribution. No block or funded
slot is consumed by these source tests.

The preceding [entrypoint and ownership review](dag-gpu-implementation-2026-10-17.md#9269-proving-entrypoint-census-and-resource-owner-lifetimes--2026-10-16)
maps **89 proving declarations in 30 files**, **20 command candidates** and
**seven ownership domains across six lifetime phases**. Source/anchor verification
passes. It identifies fixed-shape wallet capacity admission as the next source
change: context guards and per-allocation checks do not yet establish one
reservation across all proof phases. Full call-path/cfg coverage and resource
lifetime admission remain open, including backend-specific Metal reporting.
This review changes no application source and generates no proofs or transactions.
See [review evidence](../evidence/gpu-entrypoint-ownership-review-2026-10-16.json).

The latest [complete native workflow](dag-gpu-implementation-2026-10-17.md#9268-local-digest-reuse-delivers-an-eight-block-history-workflow--2026-10-16)
qualifies the local request digest change for one full trial: **64 fresh GPU
wallet proofs, 63 recursive GPU proofs and 64 durably applied transactions**
(48 user + 16 issuance), with independent CPU verification. Accepted history
reaches **eight blocks at height 17**. The workflow takes **592.262 seconds**,
leaving **7.738 seconds** inside the original deadline; the campaign including
terminal chain audit and cleanup takes **606.218 seconds**. All reported proving
arithmetic stages use OpenCL. Original resource gates pass without new limit/OOM
events. Native wallet libraries retain separately qualified source provenance.
Independent verification checks **705 sources, the complete archive, 1,734
artifacts, all 127 proof reports and all 63 worker timing records**. See
[workflow evidence](../evidence/gpu-local-request-digest-workflow-2026-10-16.json) and
current metadata revision 01 (local artifact: `../../lattica-prover-p3/benchmark-results/gpu-local-request-digest-workflow-20261016/control/current-native-validation-01.json`).

Recursive worker phases total **340.167 seconds** against **410.126 seconds**
of coordinator job time. The **69.959-second** difference is not exclusively
attributed. Sampled coordinator and fleet peaks are **864.02 MiB** and
**1,568.67 MiB** at different instants; sampling may miss short spikes. Different
transactions and seven versus six imported blocks prevent a matched speedup
claim. Adequate repeated margin and sustained throughput remain open. The fixed
cadence ceiling is **240 user + 80 issuance = 320 total transactions/hour**.
Next native slots are **1152–1215**; qualification slots remain **9556–9559**.
The **8,288 unused slots** require at least **1,312 additional unused slots**
for a fresh 150-root campaign before controls, failures and qualification.
Full API/arithmetic coverage, whole-proof resource ownership, matched controls,
long history, 24 hours AND 150 roots and multi-device qualification remain open.

The newest [local request digest change](dag-gpu-implementation-2026-10-17.md#9266-local-request-ownership-reuses-one-coordinator-digest--2026-10-16)
computes each local pool request identity once and retains it with immutable
bytes through launch, dispatch and result collection. Worker-side hashing,
full assignment binding and independent proof verification remain unchanged.
**97 tests**, CPU/GPU checks, both normal production CLI builds and independent
CPU replay of the accepted **64-wallet/63-node** graph pass. A synthetic CPU
diagnostic measures a 2 MiB request at **57.638 ms for one hash** versus
**172.849 ms for three**; these are not live workflow savings. The complete native
trial above now passes on this revision. See the
[source evidence](../evidence/gpu-local-request-digest-2026-10-16.json).

Its [fresh calibration and live pool probe](dag-gpu-implementation-2026-10-17.md#9267-local-digest-reuse-passes-fresh-calibration-and-live-pool-probing--2026-10-16)
now pass: **17 calibration proofs, 14 new timing classes and seven live pool
proofs**, all independently CPU-verified. Live coordinator job time totals
**49.497 seconds**, with **41.874 seconds** in worker phases. The difference is
**7.623 seconds**, compared with 8.437 seconds in the previous unmatched probe;
this does not establish a causal speedup or adequate full-workflow margin.
Original limits hold. No native block or funded slot is consumed by these
trials. See the [calibration](../evidence/gpu-local-request-digest-calibration-2026-10-16.json)
and [live probe evidence](../evidence/gpu-local-request-digest-probe-2026-10-16.json).

The preceding accepted [complete native workflow](dag-gpu-implementation-2026-10-17.md#9265-prepared-dispatch-delivers-a-seven-block-history-workflow--2026-10-16), on the preceding source,
passes with **64 fresh GPU wallet proofs, 63 recursive GPU proofs and 64 durably
applied transactions** (48 user + 16 issuance). Independent CPU verification
passes; accepted history reaches **seven blocks at height 16**. The workflow
takes **595.418 seconds**, leaving **4.582 seconds** inside its original
600-second deadline. All reported proving arithmetic stages use OpenCL and
the original resource gates pass without new memory-limit/OOM events. Native
wallet libraries retain their separately qualified source provenance.

Independent verification checks **705 sources, their complete archive, 1,730
artifacts, all 127 proof reports and all 63 worker timing records**. Worker
phases total **339.053 seconds** against **417.295 seconds** of coordinator job
time; the **78.242-second** difference spans several boundaries and is not yet
attributed. This unmatched trial does not establish a speedup or adequate
repeated deadline margin. See the
[workflow evidence](../evidence/gpu-pool-prepared-dispatch-workflow-2026-10-16.json)
and current metadata revision 02 (local artifact: `../../lattica-prover-p3/benchmark-results/gpu-pool-prepared-dispatch-workflow-20261016/control/current-native-validation-02.json`).
The revision corrects inherited unchanged-history/source flags without altering
the original metadata, proof evidence or archived historical host.

The newest [dispatch change](dag-gpu-implementation-2026-10-17.md#9263-local-pool-dispatch-consumes-one-prepared-packet--2026-10-16)
prepares each local worker packet once and transfers its ownership into dispatch.
It removes a second encoding and validation pass while retaining launch-token
checks, independent proof verification and existing memory reservations.
**51 tests**, CPU/GPU checks, both production builds and a CPU audit of the
accepted 64-wallet/63-node graph pass. See the
[dispatch evidence](../evidence/gpu-pool-prepared-dispatch-2026-10-16.json).

Its [calibration and live probe](dag-gpu-implementation-2026-10-17.md#9264-prepared-dispatch-passes-calibration-and-a-live-pool-probe--2026-10-16)
now pass: **17 calibration proofs**, **14 fresh timing classes** and **seven live
pool proofs**, all independently CPU-verified. In the live probe, coordinator
job time totals **50.259 seconds** and worker phases total **41.822 seconds**.
The 8.437-second difference is smaller than the earlier probe's 9.354 seconds,
but these unmatched candidates do not establish a speedup. No block or funded
slot is consumed in that probe; the complete workflow is now recorded above.
Sustained throughput remains unqualified. See the [live evidence](../evidence/gpu-pool-prepared-dispatch-probe-2026-10-16.json).

The latest [worker timing checkpoint](dag-gpu-implementation-2026-10-17.md#9262-worker-phase-timings-survive-the-live-pool-path--2026-10-16)
retains input-verification, proving and serialization durations through the real
pool completion reports. All **seven fresh recursive GPU proofs** in an
eight-wallet prefix carry timings and pass independent CPU verification.
Worker phases total **41.744 seconds**, compared with **51.098 seconds** of
coordinator job time; the difference includes dispatch, collection, verification
and durable acceptance and is not exclusively attributed. Source tests, normal
CLI builds and 14 new timing classes pass. Native wallet libraries retain their
previously qualified provenance. No new block or throughput improvement is
claimed. See the [probe evidence](../evidence/gpu-pool-worker-timings-probe-2026-10-16.json).

The preceding complete [public proof cache workflow](dag-gpu-implementation-2026-10-17.md#9261-public-proof-cache-workflow-passes-memory-gates-with-773-ms-remaining--2026-10-16), on the earlier source,
passes all original memory gates and durably applies **64 transactions** after
64 fresh GPU wallet and 63 recursive proofs. Accepted history reaches **six
blocks at height 15**. Coordinator usage peaks at a sampled **855.65 MiB** under
1 GiB, with no new limit/OOM events. The workflow takes **599.227 seconds**, leaving
only **0.773 seconds**: adequate margin, matched speedup and sustained throughput
remain unqualified. Independent verification checks 705 sources, their archive,
1,737 artifacts and all 127 proof reports. See the
[workflow evidence](../evidence/gpu-public-proof-cache-workflow-2026-10-16.json).

The cache source's [production qualification and calibration](dag-gpu-implementation-2026-10-17.md#9260-public-proof-cache-images-pass-production-qualification-and-calibration--2026-10-16)
pass all six normal builds, ABI/history checks, 68 fresh wallet proofs and
17 recursive calibration proofs. These exact images receive 14 new timing
classes; independent CPU graph replay passes. See the
[production](../evidence/gpu-public-proof-cache-production-2026-10-16.json) and
[calibration evidence](../evidence/gpu-public-proof-cache-calibration-2026-10-16.json).

The [public proof storage change](dag-gpu-implementation-2026-10-17.md#9259-immutable-public-proof-storage-retires-cached-file-pages--2026-10-16)
requests file-specific cache release after durable publication and bounded reads.
**18 storage tests**, a disk-residency diagnostic and CPU/GPU compilation checks
pass. The diagnostic observes **96 MiB cached after ordinary reads and zero
resident file pages after the updated store operations**, with byte preservation
and corruption rejection. The rebuilt CPU auditor verifies all 64 archived
wallets and 63 graph nodes without changing the failed candidate. This does not
by itself qualify the live coordinator; the subsequent workflow above supplies
one passing live trial. See the
[source evidence](../evidence/gpu-public-proof-cache-2026-10-16.json).

The [native workflow on the preceding source](dag-gpu-implementation-2026-10-17.md#9258-host-runtime-workflow-reaches-the-coordinator-memory-gate--2026-10-16)
produces **64 wallet and 63 recursive GPU proofs**, but **fails the shared 1 GiB
coordinator memory gate and applies no block**. Ten local memory-limit events
occur during handoff, without an OOM kill. A separate CPU-only audit after
shutdown verifies every wallet and graph node without resuming or applying the
failed candidate. Independent evidence verification checks 705 sources, their
archive, 1,734 artifacts and all 127 proof reports. The accepted history remains
five blocks at height 14 at that checkpoint. See the
[terminal evidence](../evidence/gpu-wallet-host-runtime-workflow-2026-10-16.json).

The preceding source's [timing calibration](dag-gpu-implementation-2026-10-17.md#9257-host-runtime-images-receive-fresh-timing-approvals--2026-10-16)
gives the updated executables **14 new timing classes**, supported by **17 fresh
recursive GPU proofs** across eight serial phases. CPU replay verifies all 64
archived wallets and all 63 graph nodes. Independent verification checks 705
sources, 17 archives and 2,705 artifacts, including the 68 native wallet proofs
below. Original limits hold in calibration. The subsequent native trial above
fails its memory gate, so complete-workflow qualification remains pending;
the mixed timing changes do not establish more deadline margin or sustained
throughput. See the [calibration evidence](../evidence/gpu-wallet-host-runtime-calibration-2026-10-16.json).

That source's [production qualification](dag-gpu-implementation-2026-10-17.md#9256-private-wallet-host-limits-pass-production-and-64-wallet-qualification--2026-10-16)
passes all six production builds, native replay, 17 rejection checks, ABI
compatibility and **68 fresh native GPU wallet proofs**. This includes a balanced
64-wallet batch with CPU verification and native body checks. Its GPU phase takes
17.829 seconds and peaks at 413.14 MiB under the unchanged 3 GiB cap. All reported
wallet arithmetic stages use OpenCL. These **705-source** images now have the
timing approvals above and still need a passing complete recursive/native workflow; the wallet-stage
result is not delivered transaction throughput. See the
[production evidence](../evidence/gpu-wallet-host-runtime-production-2026-10-16.json).

The earlier [wallet runtime source checkpoint](dag-gpu-implementation-2026-10-17.md#9255-private-wallet-startup-installs-host-request-ceilings--2026-10-16)
installs private wallet host allocation ceilings before Rayon/GPU initialization
and checks actual caller/Rayon stacks. Runtime admission errors and caught panics remain
pinned until process exit. **43 top-level tests** pass, including six fresh GPU
wallet proofs across full and compact storage, independently verified on CPU
after GPU shutdown. All 15 reported arithmetic stages use OpenCL. The **705-source**
checkpoint's production images and timing classes are now qualified above.
The complete workflow below belongs to the earlier source. These ceilings do not reserve a whole
proof or establish a complete process RSS bound. See the
[runtime evidence](../evidence/gpu-wallet-host-runtime-2026-10-16.json).

The earlier accepted [complete native workflow](dag-gpu-implementation-2026-10-17.md#9254-retained-wallet-admission-passes-a-fresh-five-block-history-workflow--2026-10-16)
qualifies the retained-admission production images through **64 fresh GPU wallet
proofs, 63 recursive proofs, CPU verification and durable application in 598.099
seconds**. It adds 48 user and 16 issuance transactions, extending verified history
to five blocks at height 14. All reported proving arithmetic stages use OpenCL;
original limits hold. The 600-second deadline has only **1.901 seconds of margin**.
Independent verification checks 703 sources, archived contents, 1,736 artifacts
and 127 proof reports. See the
[workflow evidence](../evidence/gpu-wallet-admission-workflow-2026-10-16.json).

These trials do not establish sustained capacity or matched speedup. Next unused
native slots are **1088–1151**; failed slots 896–959 remain excluded. Full
request/resource admission and other-GPU qualification remain open. The funding
inventory has **8,352 unused slots**, supporting at most **130** additional
balanced roots or **129** aligned groups. A fresh 150-root campaign needs at
least **1,248** more unused funded slots, plus allowance for
controls and failures. The fixed cadence still caps delivery at **240 user +
80 issuance = 320 total transactions/hour**; a passing single trial does not
establish sustained operation at that rate.

The earlier retained-admission source has [qualified production images and timing classes](dag-gpu-implementation-2026-10-17.md#9253-retained-wallet-admission-passes-production-qualification-and-calibration--2026-10-16).
All six builds pass, along with native replay, 17 rejection checks, ABI compatibility,
four fresh GPU wallets and 17 fresh recursive calibration proofs. Independent CPU
replay verifies 64 archived wallets and all 63 graph nodes; all **14 timing classes**
have new approvals for the exact executable. Original limits hold. Independent
verification checks **703 sources, 17 archives and 2,432 artifacts**. No native block
or delivered-throughput result is produced by that checkpoint. See the
[production evidence](../evidence/gpu-wallet-admission-production-2026-10-16.json).

The earlier [source checkpoint](dag-gpu-implementation-2026-10-17.md#9252-wallet-admission-retains-the-gpu-context-through-requests--2026-10-16)
retains the GPU context across wallet requests, including all seven legacy ABI
proving entry points. Invalid host-output budgets return admission errors.
**64 test executions, 22 CPU reference proofs and 29 GPU proofs** pass, with two
separately scoped tree-container operations. Concurrent shutdown is refused at
21 actual private-input boundaries; rejection and unwind cleanup release the guard.
Original limits hold. Full resource reservation remains open; production API and
calibration qualification are recorded above. See the
[source evidence](../evidence/gpu-wallet-admission-lifetime-2026-10-16.json).

The preceding [fixture source checkpoint](dag-gpu-implementation-2026-10-17.md#9251-typed-fixture-exports-reuse-admitted-prover-statements--2026-10-16)
removes CPU public-value recomputation from mixed-wallet fixture exports. The CLI
builds its body from verified wallet statements, and stopped engines reject before
synthetic input preparation. **24 corrected test executions, eight CPU reference
proofs and four GPU proofs** pass. Every reported GPU proving arithmetic stage uses
OpenCL. Synthetic input construction still uses CPU arithmetic, and complete
request/lifetime coverage remains open. This source has no new production or
throughput qualification. See the [source evidence](../evidence/gpu-typed-fixture-export-2026-10-16.json).

The preceding [complete native workflow](dag-gpu-implementation-2026-10-17.md#9250-corrected-native-wallet-exports-pass-a-fresh-four-block-history-workflow--2026-10-16)
validates the rebuilt wallet export fix through **64 fresh GPU wallet proofs,
63 recursive proofs, independent CPU audits and durable application in 590.227
seconds**. It delivers 48 user and 16 issuance transactions and extends the
accepted history to four blocks at height 13. All reported proving arithmetic
stages use OpenCL; the identified wrapper CPU recomputation is removed. Original
resource limits hold with no new memory-limit/OOM events. Independent verification
checks 701 sources, archived source contents, 1,724 artifacts and 127 proof reports.
See the [workflow evidence](../evidence/gpu-native-wallet-export-workflow-02-2026-10-16.json).

A preceding trial stopped at a callback affinity assertion before selection and
applied no block. That candidate remains terminal. The successful successor uses
a callback bound to four CPUs, unused slots 768–831 and a distinct journal/root.
Next slots are **832–895**. This single workflow does not establish sustained
throughput, matched speedup, complete lifetime/API coverage or other-GPU support.

The latest [native wallet export source fix](dag-gpu-implementation-2026-10-17.md#9247-native-wallet-exports-reuse-the-admitted-provers-public-statement--2026-10-15)
reuses the public statement produced by the admitted leaf prover and removes
the native wrapper's CPU recomputation. Corrected subprocess checks and GPU
oracle-call guards pass: **39 test executions, eight CPU reference proofs and
11 GPU proofs** on the current test image. CPU verification after GPU shutdown
accepts exports and rejects altered publics/context. See the
[source evidence](../evidence/gpu-native-wallet-export-2026-10-15.json).

The rebuilt [production images](dag-gpu-implementation-2026-10-17.md#9248-native-wallet-export-production-images-pass-qualification-and-calibration--2026-10-15)
now pass native API/ABI qualification, four fresh GPU wallet proofs and 17 fresh
recursive calibration proofs. Independent CPU replay verifies the complete
63-node graph; all **14 timing classes** have new approvals for the exact rebuilt
executable. All reported wallet/recursive arithmetic stages use OpenCL. Original
resource limits hold. Independent verification checks **701 sources and 2,475
artifacts**. That checkpoint applies no block; the complete workflow qualification
for these images is recorded above. See the
[production evidence](../evidence/gpu-native-wallet-export-production-2026-10-15.json).

The earlier [native streaming-history workflow](dag-gpu-implementation-2026-10-17.md#9246-streamed-host-history-passes-a-fresh-native-workflow--2026-10-15)
durably applies one new block in **588.126 seconds**, after 64 fresh wallet
proofs, 63 recursive proofs and independent CPU audits. All reported inner
proving stages use OpenCL. The new block contains 48 user and 16 issuance
transactions; independent replay verifies the resulting three-block history.
Original limits hold with no new memory-limit/OOM events. The source review
also identifies CPU public-value recomputation in the native wallet wrapper
before the reported GPU leaf scope. Complete request GPU coverage and sustained
throughput remain open. See the
[workflow evidence](../evidence/gpu-native-streaming-history-2026-10-15.json).

The latest [host history checkpoint](dag-gpu-implementation-2026-10-17.md#9245-native-history-snapshots-stream-proof-payloads--2026-10-15)
loads proof payloads individually while preserving native replay and publication
checks. **114 tests and 20 real native replay checks** pass. In the same
150-record storage model, peak Python memory falls from **708.7 MiB to 11.75
MiB**; cold loading takes longer. The accepted two-block history replays and
rejects altered proofs under the 1 GiB auditor limit. Original evidence and
production images remain unchanged. This checkpoint generates no new proofs
and makes no throughput claim. See the
[source and replay evidence](../evidence/gpu-host-history-streaming-2026-10-15.json).

The latest [standalone CLI policy checkpoint](dag-gpu-implementation-2026-10-17.md#9244-standalone-cpu-cli-workflows-admit-policy-before-work--2026-10-15)
closes early-admission gaps in `field_compare`, `block-v2-feasibility` and the
demo binary. These CPU reference workflows reject `gpu-required` before work;
compatible and CPU-required reference proofs still verify. **45 test executions**
and CPU/GPU all-target checks pass. The private batched FRI caller review is
recorded without changing explicit CPU test-oracle behavior. Production proving
code and the retained GPU images are unchanged. See the
[source evidence](../evidence/gpu-cli-entrypoint-policy-2026-10-15.json).

The latest [native history-extension workflow](dag-gpu-implementation-2026-10-17.md#9243-rebuilt-images-extend-accepted-native-history-within-the-original-deadline--2026-10-15)
qualifies one complete block on the rebuilt images: **64 GPU wallets and 63 GPU
recursive proofs**, independent CPU verification, and durable application in
**582.582 seconds** under the original 600-second limit. It imports one accepted
historical block into a separate journal, then applies 48 new user and 16 issuance
transactions. Independent replay verifies both records and rejects a corrupted
root. Original history bytes and resource limits remain unchanged, with no new
memory-limit/OOM events. See the
[verified evidence](../evidence/gpu-native-wallet-policy-history-2026-10-15.json).
This single workflow does not establish sustained throughput or matched speedup.

The latest [production-image qualification](dag-gpu-implementation-2026-10-17.md#9242-rebuilt-production-images-pass-native-api-and-fresh-gpu-calibration--2026-10-15)
rebuilds both CLIs and native bridges from the updated helper/policy source.
Four fresh production GPU wallet proofs, 17 recursive calibration proofs and a
63-node independent CPU replay pass. All **14 timing classes** have new approvals
for the exact rebuilt executable; previous approvals were not transferred.
Native replay/ABI checks also pass. The complete native workflow is recorded
above; sustained throughput qualification remains open. See the
[verified evidence](../evidence/gpu-wallet-policy-production-2026-10-15.json).

The latest [wallet-helper entry-point work](dag-gpu-implementation-2026-10-17.md#9240-wallet-helpers-use-gpu-proving-and-cpu-reference-paths-enforce-policy--2026-10-15)
routes eight join-split/HTLC convenience APIs through the existing owned GPU
prover. Twelve fresh helper proofs cover valid calls and altered-public-input
rejection; eight ordinary wallet API proofs also pass CPU verification after
GPU shutdown. All fifteen proving arithmetic stages run on OpenCL. Independent
CPU verification remains separate. Unsupported demo, research aggregation and
streaming proof entry points now reject `gpu-required` before CPU proving.

All **44 test executions** and CPU/GPU all-target checks pass under the existing
resource limits. These are correctness tests using retained test images, with
no transaction-throughput claim. Earlier production images retain their own
14 timing approvals; those approvals do **not** cover binaries rebuilt from
the new Rust source. See the
[helper checkpoint evidence](../evidence/gpu-wallet-helper-entrypoints-2026-10-15.json).

The [follow-up policy checkpoint](dag-gpu-implementation-2026-10-17.md#9241-recursive-fixtures-and-research-debug-audits-admit-policy-before-work--2026-10-15)
also closes the two recursive demo helpers and moves research quotient admission
ahead of its debug constraint audit. **41 additional test executions** pass,
including actual debug-assertion builds and valid CPU reference proofs. These
CPU research paths reject unsupported policy; they are not newly GPU-enabled.
The production rebuild and API/calibration qualification are recorded above.
Standalone benchmark/component coverage and full lifetime admission remain
open. See the
[latest source evidence](../evidence/gpu-research-entrypoint-policy-2026-10-15.json).

The latest [random-sample offset scan](dag-gpu-implementation-2026-10-17.md#9238-parallel-random-sample-offsets-and-terminal-handoff-timeout--2026-10-15)
passes all ten GPU random-stream tests. Million-word compaction is about **7.2×
faster on device** and **3.6× faster in wall time** than serial offsets. These
kernel measurements do not establish delivered transaction throughput.

Production GPU wallet qualification and fresh calibration pass: four wallets,
17 recursive proofs, independent CPU verification, and **14 approved timing
classes**. Full proving still requires **12,288 MiB free VRAM**; the smaller
random-test gate remains specific to those tests.

The fresh large-state workflow produces 64 GPU wallets and 56 audited recursive
proofs, then times out during final handoff validation after selection seals at
474.277 seconds. No final root or native block is produced, and the failed
candidate remains terminal. The handoff stays below 448 MiB; memory observations
show no new limit/OOM events. See the [preserved evidence](../evidence/gpu-random-offset-scan-2026-10-15.json).

The [handoff-admission controller](dag-gpu-implementation-2026-10-17.md#9239-handoff-window-admission-passes-a-complete-large-state-workflow--2026-10-15)
now reserves 30 seconds before starting handoff and safely drains a short phase
before recovering the completed prefix under the original workflow deadline.
All **231 controller/integration tests** pass. A fresh 9,600-slot workflow
exercises deferral, completes all 64 GPU wallets and 63 GPU recursive proofs,
passes independent CPU verification, and durably applies a 64-transaction block
in **577.708 seconds**, leaving **22.292 seconds** before the original deadline.
Independent journal replay passes, with no new memory-limit or OOM events.
Native images and all 14 timing approvals remain unchanged. See the
[verified workflow evidence](../evidence/gpu-handoff-window-2026-10-15.json).
This qualifies one exploratory workflow; sustained throughput remains open.

The preceding [audited prefix cache retirement](dag-gpu-implementation-2026-10-17.md#9235-audited-prefix-cache-retirement-removes-observed-memory-pressure--2026-10-15)
passes **172 Python tests**. After independent CPU prefix verification, the
handoff authenticates the completed public outputs and releases their file cache
while preserving all bytes and proof checks. Isolated paired measurements recover
**90.2 MiB**. Native libraries and CLI images remain unchanged; a fresh calibration
after a host reboot validates all **14 timing classes** with **17 GPU proofs**.

The fresh **9,600-slot** workflow generates 64 GPU wallet proofs and 57 recursive
proof reports. Its handoff passes at **376.6 MiB** under the original **448 MiB**
cap. The coordinator reaches an observed **938.5 MiB**, with **zero new memory-limit
or OOM events**. Sealing still takes **534.208 seconds**, and the owner stops
because the remaining proof path cannot fit before the original deadline. No
final root is produced and no block is applied. The next work is reducing proving
and worker-phase overhead while preserving deadline and verification checks.
This is a memory improvement in one trial; complete workflow and sustained
throughput qualification remain open. See the
[partial evidence](../evidence/gpu-native-prefix-cache-2026-10-15.json).

The preceding [bounded input-reference change](dag-gpu-implementation-2026-10-17.md#9234-bounded-input-references-and-observed-handoff-overlap--2026-10-15)
passes **155 Python tests**. Pending preparation reads authenticated bodies and
wallets individually instead of retaining every payload. In an isolated paired
diagnostic, input-list memory growth falls from **34.2 MiB to 1.1 MiB**, with all
64 payloads and native expected statements unchanged. Native libraries and CLI
images are unchanged.

The fresh **9,600-slot** trial generates 64 GPU wallet proofs and 57 recursive
proof reports. Independent CPU checks verify the wallets and 56 prefix nodes.
The **448 MiB handoff** passes at **375.1 MiB**, but the shared **1 GiB
coordinator** records **206 new memory-limit events** during final preparation.
The scheduler subsequently rejects further work as unable to fit before the
original deadline. No final root is produced and no block is applied.
Half-second observations locate the pressure at **529.3–534.9 seconds**, while
owner, callback, controller and public file-cache memory overlap. That trial
motivated the cache retirement above; deadline margin remains open. See the
[partial evidence](../evidence/gpu-native-input-refs-2026-10-15-02.json).

The [checked intake-host reuse change](dag-gpu-implementation-2026-10-17.md#9233-checked-intake-host-reuse-passes-handoff-but-fleet-pressure-remains--2026-10-15)
passes **148 Python tests**. Preparation shares the intake host through the same
independent configuration and journal checks as candidate validation. Real native
state/preflight checks take **36.9 ms with reuse versus 1.069 seconds separately**,
with identical results. Native libraries and CLI images are unchanged.

A fresh **9,600-slot** trial passes the **448 MiB handoff** at **374.6 MiB** and
produces **64 GPU wallet proofs plus 63 recursive proofs**. Its final phase still
rejects **147 new memory-limit events** in the shared **1 GiB coordinator**, so
no block is applied. A separate read-only CPU audit verifies the entire graph and
root in **10.788 seconds**; it does not qualify or resume the failed workflow.
The remaining coordinator overlap and end-to-end deadline margin need further
work. See the [partial checkpoint evidence](../evidence/gpu-native-intake-store-2026-10-15.json).

The earlier [idle native-cache release](dag-gpu-implementation-2026-10-17.md#9232-idle-native-cache-release-and-remaining-handoff-pressure--2026-10-15)
remains in place. It released 183.4 MiB across two caches in a bounded diagnostic,
while preserving full native revalidation afterward.

The preceding [handoff store-reuse checkpoint](dag-gpu-implementation-2026-10-17.md#9231-handoff-store-reuse-and-coordinator-memory-pressure--2026-10-15)
produced all 64 GPU wallets and 63 recursive proofs. Its separate read-only CPU
audit verified the retained graph and root in **11.041 seconds**, but coordinator
pressure prevented application. Its successful 439.2 MiB handoff did not establish
sufficient memory margin for the next candidate. Neither trial qualifies capacity.

The earlier [streaming native audit](dag-gpu-implementation-2026-10-17.md#9230-streaming-native-audit-and-large-state-handoff-limit--2026-10-15)
independently reconstructs chains one body/root record at a time. Its 37 boundary
tests, real two-block replay and 17 native rejection checks remain valid. No native
library or CLI image changes in the latest Python-only checkpoint.

The latest successful full workflow is the 9,600-slot run above; the smaller-state
runs below are earlier checkpoints. Genuine
150-record history, lifetime admission and sustained capacity remain unqualified.

The [incremental native Merkle cache](dag-gpu-implementation-2026-10-17.md#9229-incremental-native-merkle-caching--2026-10-15)
passes two consecutive native workflows in **580.903 and 581.892 seconds**, with
**19.097 and 18.108 seconds** remaining before their original 600-second deadlines.
All 128 GPU wallet proofs and 126 recursive proofs pass independent CPU audits
and durable application. Full chain replay, restart and corrupted-root rejection
also pass, with no new memory-limit events.

The tree retains internal hashes, making append and authentication paths O(depth)
and root lookup O(1). Funding **9,600 synthetic slots now takes 2.104 seconds**;
the earlier implementation timed out at 180 seconds. Identical-input two-block
replay falls from **629.351 to 150.722 ms**. Tree, native and FFI checks pass,
and four additional GPU wallet proofs qualify the rebuilt bridge at the largest
tested slot indices. The Rust libraries and CLI executables are unchanged.

The short campaign delivers **96 user transactions plus 32 issuance transactions**
in 1303.485 seconds, an observed **265.1 user transactions/hour**. Sustained
capacity, matched speedup and 150-block lifetime qualification remain open.
See the [evidence](../evidence/gpu-native-tree-cache-2026-10-15.json).

The earlier checkpoints below retain their qualification status at the time.

The [closed workflow input cleanup](dag-gpu-implementation-2026-10-17.md#9228-closed-workflow-input-retirement-passes-consecutive-delivery--2026-10-15)
passes **two consecutive native blocks** in one journal, completing in **592.972
and 598.198 seconds** under their original 600-second deadlines. All 128 fresh
wallet proofs and 126 recursive proofs report GPU arithmetic and pass independent
CPU verification. Durable application includes **96 user transactions and 32
issuance transactions**; both post-seal deadlines pass.

The change retires cache pages for reopened public journals and private fixtures
after every reader has stopped. It fixes the coordinator memory-pressure failure
observed in the preceding two-block attempt, without changing proof bytes,
resource limits, shader caches or prover images. **30 focused Python tests** and
five native-session preflight tests pass. The short campaign observes **261.3
user transactions/hour**, including its startup, pacing and audits; this does
not qualify sustained capacity. The second block has only **1.8 seconds** of
deadline margin. See the [evidence](../evidence/gpu-workflow-cache-retirement-2026-10-15.json).

The [owned wallet recovery update](dag-gpu-implementation-2026-10-17.md#9226-owned-wallet-recovery-adds-deadline-margin--2026-10-15)
completes a fresh native workflow in **584.187 seconds**, leaving **15.813
seconds** before the original deadline. It generates 64 GPU wallet proofs and
63 recursive GPU proofs, independently audits them on CPU, and durably applies
64 transactions in an isolated native test journal. The capped post-seal deadline
also passes. Sustained delivered throughput remains unqualified.

Sharing authenticated wallet buffers through recovery reduces the matching
production-profile journal audit from **13.356 to 10.648 seconds** while keeping
full proof, policy and disk-identity checks. **511 Rust tests**, CPU/GPU checks,
production builds and fresh exact-image calibration pass. See the
[accepted evidence](../evidence/gpu-wallet-recovery-ownership-2026-10-15.json).

The [verified wallet ownership update](dag-gpu-implementation-2026-10-17.md#9225-verified-wallet-ownership-completes-the-bounded-native-workflow--2026-10-15)
completes a fresh native workflow: **64 GPU wallet proofs, 63 recursive GPU
proofs, independent CPU verification and durable application of 64 transactions**
in an isolated native test journal in **599.557 seconds**, inside the original
600-second limit. Application also
meets the capped post-seal deadline. The full workflow has only **443 ms** of
margin in this run; sustained delivered throughput remains unqualified.

Sharing verified immutable wallet buffers reduces the matching preparation and
admission diagnostic from **18.401 to 7.559 seconds** without removing proof
verification or disk-integrity checks. **507 Rust tests**, CPU/GPU checks and
production builds pass. Fresh calibration verifies 17 GPU proofs and all 63
graph nodes, approving fourteen timing classes for the new executable. See the
[accepted evidence](../evidence/gpu-wallet-input-ownership-2026-10-15.json).

The [live prefix handoff](dag-gpu-implementation-2026-10-17.md#9224-live-prefix-to-sealed-transition-retains-the-worker--2026-10-15)
now keeps the verified DAG and GPU worker across an authenticated native seal.
It passes **494 Rust tests and 64 Python tests**, and fresh calibration passes
17 GPU proofs plus independent CPU replay of all 63 nodes. The bounded callback
stays within its existing 448 MiB allowance.

The fresh native trial completes 56 prefix proofs and **one post-seal proof**
on the same worker. Remaining work still fails deadline admission; **no root or
block is applied**. Both original clocks remain intact, and the failed candidate
is retained without renewal. Delivered throughput remains unqualified. See the
[accepted evidence](../evidence/gpu-prefix-seal-transition-2026-10-15-02.json).

The [optimized native prefix run](dag-gpu-implementation-2026-10-17.md#9223-optimized-native-prefix-seals-earlier-but-still-misses-admission--2026-10-15)
seals at **536.156 seconds**, 18.627 seconds earlier than §9.218. It generates
and independently verifies 64 fresh GPU wallets, proves 56 GPU subtrees in
**19 + 18 + 17 + 2** jobs, and verifies/imports all 56 for final selection.
The scheduler still rejects further work for insufficient remaining time;
**no block is applied**. Cleanup finishes at 564.493 seconds, with no new
memory-limit events and no candidate renewal. The full prefix workflow and
delivered throughput remain unqualified. See the
[evidence](../evidence/gpu-native-handoff-workflow-2026-10-15.json).

The [handoff-build calibration](dag-gpu-implementation-2026-10-17.md#9222-fresh-calibration-for-the-preparation-handoff-build--2026-10-15)
passes **17 fresh GPU proofs**, independent replay of all **63 graph nodes**,
and **fourteen approved timing classes** for the new executable. Root samples
are **9.575 seconds cold / 7.315 seconds warm**. All recursive proving stages
report OpenCL, with no new memory-limit events. The native 60-plus-4 workflow
still needs a fresh test; these calibration runs do not establish transaction
throughput. See the [evidence](../evidence/gpu-handoff-calibration-2026-10-15.json).

The [bounded preparation handoff](dag-gpu-implementation-2026-10-17.md#9221-retain-the-verified-preparation-for-one-bounded-request--2026-10-15)
removes a second verification of the same wallet selection inside each bounded
service. In four retained-input diagnostics, that repeated preparation costs a
median **4.343 seconds**; moving the immutable preparation takes about **3 µs**.
**148 Rust tests, 19 Python tests**, CPU/GPU checks and production builds pass.
The controller now names the owner's verified private snapshot, with exact
native-binding, path and original-deadline checks. This is a component result;
fresh GPU calibration and the full native prefix workflow remain open. See the
[evidence](../evidence/gpu-bounded-preparation-2026-10-15.json).

The [verified-buffer import optimization](dag-gpu-implementation-2026-10-17.md#9220-verified-buffer-prefix-import-and-matched-component-measurements--2026-10-15)
reduces median retained-prefix import time from **16.10 to 7.35 seconds (54.4%)**
in a test-profile diagnostic, and production prefix-audit time from **11.78 to
8.42 seconds (28.5%)**. All 56 proofs still receive full verification; inventories
and audit receipts match. **232 Rust tests** and four retained-proof diagnostics
pass, alongside CPU/GPU checks, production builds and native export verification.
These component measurements do not qualify the full workflow or transaction
throughput. The new GPU executable needs fresh timing approval. See the
[evidence](../evidence/gpu-prefix-import-ownership-2026-10-15.json).

The [pool receipt accounting](dag-gpu-implementation-2026-10-17.md#9219-pool-completion-receipts-count-imported-proofs--2026-10-15)
centralizes fresh/reused counts and passes **142 Rust and 12 Python tests**,
both all-target checks, production builds and native export verification.
The original interpretation of a bounded-import receipt defect was incorrect:
that path already attaches a candidate before dispatch and counted its imports.
The measured prefix handoff still needs performance work before the full
workflow can meet its deadline. See the
[evidence](../evidence/gpu-pool-import-report-2026-10-15.json).

The [fresh native prefix experiment](dag-gpu-implementation-2026-10-17.md#9218-fresh-native-prefix-succeeds-sealed-continuation-lacks-time--2026-10-15)
passes **64 fresh GPU wallet proofs, 56 GPU subtree proofs and independent CPU
prefix verification**, then admits the final four transactions. Sealing at
**554.783 seconds** leaves too little of the original 600-second clock for the
remaining work. All 56 subtrees import successfully, but the scheduler rejects
further proving; **no block is applied**. Cleanup finishes at 596.098 seconds
without new memory-limit events. A corrected native CPU build passes 66 tests
and its export smoke. Prefix/import behavior is validated; the complete prefix
workflow, post-seal gate and throughput remain unqualified. See the
[evidence](../evidence/gpu-native-prefix-workflow-2026-10-15.json).

The [prefix-build calibration](dag-gpu-implementation-2026-10-17.md#9217-fresh-calibration-of-the-prefix-enabled-gpu-cli--2026-10-15)
passes with **17 fresh GPU proofs, fourteen approved timing classes and an
independent 63-node CPU replay**. Cold/warm root samples are **9.555/7.311
seconds**. All sixteen recursive arithmetic stages report OpenCL; no new
memory-limit events occur and GPU leases are released. The graph replay and
recovery audit takes **41.467 seconds**. These diagnostic runs use archived
wallets; the fresh native prefix workflow and delivered throughput remain
unqualified. See the [evidence](../evidence/gpu-prefix-calibration-2026-10-15.json).

The [bounded prefix implementation](dag-gpu-implementation-2026-10-17.md#9216-bounded-native-prefix-pooling-and-durable-post-seal-clock--2026-10-15)
now schedules complete non-root subtrees while native arrival intake remains
unsealed. Recovery preserves scope and the original workflow deadline; final
selection independently verifies imported proofs. A durable selection clock
bounds post-seal application, intake publication and replay to 180 seconds.
**329 Rust and 201 Python test executions**, four CPU/GPU all-target checks and
both production builds pass. These are implementation checks: fresh timing
approval is recorded above, while a fresh 60-plus-4 arrival workflow remains open.
No new GPU throughput or post-seal runtime qualification is claimed. See the
[evidence](../evidence/gpu-pool-prefix-2026-10-15.json).

The [complete fresh native workflow](dag-gpu-implementation-2026-10-17.md#9215-fresh-native-workflow-completes-within-600-seconds--2026-10-15)
passes in **593.759 seconds**, including **64 fresh GPU wallet proofs, 63 fresh
recursive GPU proofs, independent full-graph CPU verification, and durable
application of all 64 transactions** to an isolated synthetic journal. All
proving arithmetic reports OpenCL; resource limits remain unchanged with no
new memory-limit events. This is one successful workflow with 6.241 seconds of
deadline margin. Matched throughput runs, sustained testing and the separate
post-seal gate remain open. See the
[evidence](../evidence/gpu-native-complete-workflow-2026-10-15.json).

The [recovery-build calibration](dag-gpu-implementation-2026-10-17.md#9214-fresh-calibration-after-recovery-digest-reuse--2026-10-15)
approves **fourteen timing classes** for the §9.213 GPU CLI. Eight bounded
services produce **17 fresh GPU proofs** with complete OpenCL coverage and
independent CPU audits. Cold/warm root samples are **9.527/7.317 seconds**;
a complete diagnostic graph replay and journal recovery takes **40.850 seconds**.
No new memory-limit events occur. These archived-wallet experiments prepare
the fresh native workflow test; delivered throughput remains unqualified. See
the [evidence](../evidence/gpu-recovery-digest-calibration-2026-10-15.json).

The [recovery digest optimization](dag-gpu-implementation-2026-10-17.md#9213-owned-verified-artifacts-during-recovery--2026-10-15)
reduces a matched full-graph CPU audit from **22.474 to 15.252 seconds (32.1%)**.
All 63 nodes and 64 wallets still receive full verification. Immutable owned
node bytes avoid duplicate digest work; detached bytes retain their digest
check. **106 Rust test executions**, four all-target checks and both production
builds pass. This is one audit comparison, not delivered transaction throughput.
The rebuilt GPU CLI's fresh calibration is recorded in §9.214 above; older
calibration remains bound to its earlier executable. See the
[evidence](../evidence/gpu-native-recovery-digest-2026-10-15.json).

The [rebuilt CLI calibration](dag-gpu-implementation-2026-10-17.md#9212-fresh-timing-approval-for-the-rebuilt-gpu-cli--2026-10-15)
now passes: **17 fresh GPU proofs, fourteen new timing classes and an independent
63-node CPU replay**. Cold/warm root proofs take **9.595/7.313 seconds**.
Eight bounded GPU services pass complete OpenCL stage checks, independent
proof verification and cache retirement with no new memory-limit events.
At that checkpoint the source and executables were unchanged from §9.211. These experiments use
archived wallets; full native workflow throughput remains unqualified. See the
[evidence](../evidence/gpu-cli-recalibration-2026-10-15.json).

The [independent pool graph audit](dag-gpu-implementation-2026-10-17.md#9211-independent-pool-graph-audit-without-journal-mutation--2026-10-15)
now verifies **all 63 retained nodes and 64 wallets in 22.211 seconds** without
resuming the journal or renewing its deadline. Five negative cases reject, and
all 2,428 prior artifact hashes remain unchanged. **104 Rust test executions,
CPU/GPU checks and production builds pass.** Calibration for its rebuilt GPU
executable is recorded in §9.212 above. This audit ran after the original
workflow; full end-to-end throughput remains unqualified. See the
[evidence](../evidence/gpu-native-journal-audit-2026-10-15.json).

The [native wallet and pool integration](dag-gpu-implementation-2026-10-17.md#9210-native-gpu-wallets-phase-recovery-and-durable-application--2026-10-15)
now passes: **192 fresh GPU wallet proofs are independently verified**, and a
different candidate completes **63 recursive GPU proofs across four bounded
services**. A separate CPU audit verifies the root, durably applies one
64-transaction block to an isolated test journal, and reopens and reverifies it.
The pool integration takes **575.432 seconds** with no new memory-limit events.
All applicable proving arithmetic uses OpenCL. Explicit native GPU linking,
semantic configuration binding and optional-plan recovery fixes are validated;
the final Python suites pass 53 tests. The clock excludes wallet preparation
and independent full-DAG audit, so complete workflow throughput is unqualified.
See the [evidence](../evidence/gpu-native-wallet-pool-2026-10-15.json).

The [complete CLI calibration and graph replay](dag-gpu-implementation-2026-10-17.md#9209-complete-cli-calibration-and-full-graph-replay--2026-10-15)
now pass: **nine new GPU proofs, fourteen approved timing classes and an
independently verified 63-node graph**. Cold/warm root proofs take
9.712/7.300 seconds. Five bounded GPU runs exercise integrated cache retirement
without new memory-limit events. The full CPU replay takes 48.397 seconds after
aligning its artifact-store limit with the existing 256 MiB proving limit;
RAM budgets stay unchanged. **104 Rust tests and all-target checks pass**.
The GPU executable is byte-identical to the calibrated image. Native workflow
and delivered transaction throughput qualification remain open. See the
[evidence](../evidence/gpu-cli-upper-calibration-2026-10-15.json).

The [coordinator cache-retirement fix](dag-gpu-implementation-2026-10-17.md#9208-coordinator-public-artifact-cache-retirement--2026-10-15)
addresses retained proof-file cache across bounded services. Three calibration
runs add **42 independently verified GPU proofs**; a fourth produces 12 valid
proofs but fails outer memory accounting and receives no timing approval.
File-scoped cleanup preserves 1,497 file hashes and reduces coordinator memory
from 824,471,552 to 24,936,448 bytes. **84 Python tests pass**. The integrated
cleanup still needs fresh GPU validation; delivered throughput remains
unqualified. See the [evidence](../evidence/gpu-cli-cache-retirement-2026-10-15.json).

The [fresh maintained CLI calibration](dag-gpu-implementation-2026-10-17.md#9207-fresh-maintained-cli-calibration-and-six-approved-timing-classes--2026-10-14)
passes on a different ordered candidate: **six GPU proofs, independent CPU
verification, complete OpenCL stage coverage, clean shutdown and controller
accounting**. The workflow stops at 67.091 seconds; its separate audit takes
5.193 seconds. Six timing classes are approved for the frozen CLI executable,
desktop RTX 5080, drivers and resource settings. Higher merge/root calibration
and the complete native workflow remain open; delivered transaction throughput
is unqualified. See the
[evidence](../evidence/gpu-cli-fresh-calibration-2026-10-14.json).

The [independent calibration audit](dag-gpu-implementation-2026-10-17.md#9206-independent-calibration-proof-audit--2026-10-14)
now verifies complete retained GPU proofs through the CPU-only paired CLI.
Both retained mode-4 proofs and all 64 fixture wallets pass; **13 negative
cases reject, and 104 Rust test executions pass**. The failed outer trial
remains unchanged and has no timing approval. Fresh calibration with the
corrected controller and current executable is still required. See the
[evidence](../evidence/gpu-cli-proof-audit-2026-10-14.json).

The [owned maintained CLI startup](dag-gpu-implementation-2026-10-17.md#9205-owned-maintained-cli-startup-and-first-live-gpu-samples--2026-10-14)
now produces GPU proofs under the unchanged 3/1/4 GiB host limits. Its first
trial produced two mode-4 proofs, both verified by the CPU coordinator, with
8.422/6.573-second cold/warm samples. The worker drained cleanly, but the outer
trial failed during controller cpuset accounting. That setup is fixed and passes
a separate real accounting smoke test; the failed workflow was not renewed.
**62 Rust test executions and 229 Python tests pass. No timing classes are
approved.** The independent proof audit is recorded in §9.206 above. See the
[evidence](../evidence/gpu-cli-owned-startup-2026-10-14.json).

The [maintained CLI calibration collector](dag-gpu-implementation-2026-10-17.md#9204-maintained-cli-calibration-collector-and-verified-startup-admission-gap--2026-10-14)
now has a bounded path for collecting verified live histories through the shared
worker protocol and rejects recovery that would renew a failed experiment. **317 Rust test
executions and 95 Python tests pass**, and the matching CPU CLI verifies all
64 archived wallet proofs. Preflight identifies the next integration gap: the
maintained host/worker still enforce the legacy compact RAM floor above 11 GiB,
which cannot fit the fixed 3 GiB worker. The owned public GPU startup/admission
path must be connected before live calibration. **No GPU worker was launched
and no timing approval was granted**. See the
[evidence](../evidence/gpu-cli-calibration-2026-10-14.json).

The [bounded native pool phases](dag-gpu-implementation-2026-10-17.md#9203-bounded-native-pool-phases-with-one-workflow-deadline--2026-10-14)
now preserve one sealed candidate and its original workflow deadline across
services, with startup/stop reconciliation before replacement. Completed phases
retain the candidate and proof artifacts for independent audit and delivery
recovery. Qualified controllers and coordinators share the existing 1 GiB
budget, within the 4 GiB fleet and four aggregate CPU threads. **287 Rust test
executions and 79 Python tests pass**, along with all-target checks and production
builds. This checkpoint makes **zero new GPU proofs**; exact-image CLI calibration
and native phase runtime qualification remain open. See the
[evidence](../evidence/gpu-native-pool-recovery-2026-10-14.json).

The [journal recovery API](dag-gpu-implementation-2026-10-17.md#9202-deadline-preserving-recovery-of-an-exact-sealed-candidate--2026-10-14)
now resumes an exact sealed candidate using its original recorded deadline.
It checks expiration after old attempts and workspaces are reconciled and
publishes the recovered candidate atomically with the new epoch. **172 recovery
and pool test executions pass** across CPU and both GPU builds; the production
library build also passes. The caller must preserve the original clock domain.
Native phase restart orchestration is still pending, and this checkpoint makes
**zero new GPU proofs**. See the
[evidence](../evidence/gpu-pool-deadline-recovery-2026-10-14.json).

The [maintained native pool CLI](dag-gpu-implementation-2026-10-17.md#9201-maintained-native-pool-timing-admission-and-bounded-dispatch--2026-10-14)
now accepts host-approved timings bound to each worker's actual executable,
device, drivers and settings, and enforces a 150-second dispatch window within
180-second services. **262 Rust test executions and 52 Python tests pass**, along
with CPU/GPU all-target checks and the production storage probe. The CLI reserves
576 MiB for shared state within the unchanged 1 GiB coordinator limit. This
checkpoint makes **no new GPU proofs**: native phase recovery, calibration of the
CLI executable, fresh wallets and durable application remain open. See the
[evidence](../evidence/gpu-native-pool-timing-2026-10-14-02.json).

The [fresh full-64 GPU pool](dag-gpu-implementation-2026-10-17.md#9200-fresh-full-64-gpu-pool-and-independent-audit-within-deadline--2026-10-14)
now completes all **63 proofs and the independent CPU audit in 586.770 seconds**,
within the unchanged 600-second deadline. The count-64 root is durably accepted
at 559.756 seconds and is 1,683,948 bytes. All sixteen proving stages report
OpenCL, and all workers exit cleanly within the existing resource limits.
That tested C-worker executable has 14 approved timing classes. This measures recursive
aggregation from archived wallet proofs; fresh wallet generation and durable
application remain outside the result, so delivered transactions per hour are
still unqualified. See the
[evidence](../evidence/gpu-paired-cache-calibration-2026-10-14.json).

The [paired-wrapper cache](dag-gpu-implementation-2026-10-17.md#9199-paired-wrapper-input-binding-cache--2026-10-14)
now binds fresh wallet-proof inputs to validated cached programs for all nine
ordered wallet-type pairs. **36 test executions pass**, including 72 compiler
comparisons across both layouts and four native GPU proofs independently verified
on CPU. Warm native wrapper samples take **6.065 and 6.079 seconds**. The new
production image's calibration and fresh recursive pool result are recorded in
§9.200 above; delivered transactions per hour remain unqualified. See the
[evidence](../evidence/gpu-paired-input-cache-2026-10-14.json).

The [fresh full-64 pool](dag-gpu-implementation-2026-10-17.md#9198-exact-image-calibration-and-fresh-full-64-deadline-result--2026-10-14)
completes all **63 GPU proofs** and durably accepts its root in **586.968 seconds**.
Independent CPU verification passes for the complete DAG, but finishes at least
**613.851 seconds** from workflow start, exceeding the unchanged 600-second
limit. This remains a failed complete-workflow timing candidate. That production
image has **14 approved timing classes**, backed by 35 new calibration proofs.
Repeated paired-wrapper compilation accounted for about 39.8 seconds across that
run and motivated the cache extension in §9.199. Delivered transactions per hour remain
unqualified. See the [evidence](../evidence/gpu-input-cache-calibration-2026-10-14.json).

The [recursive input cache](dag-gpu-implementation-2026-10-17.md#9197-registered-program-input-binding-cache--2026-10-14)
now reuses validated merge/finalizer layouts and completed compilation receipts
inside each worker's immutable registered-program cache. Every invocation binds
fresh witness values within its assigned input budget. **32 test executions and
four new native GPU proofs pass**, including independent CPU verification after
worker exit. Warm native samples take **7.483 seconds for a root** and **5.895
seconds for a finalizer**. These are individual job measurements; complete
workflow throughput remains unqualified. At that checkpoint the rebuilt image
had zero approved timing classes; §9.198 records calibration and the fresh pool.
See the [evidence](../evidence/gpu-recursive-input-cache-2026-10-14.json).


The [recursive input-binding prototype](dag-gpu-implementation-2026-10-17.md#9196-validated-recursive-input-binding-prototype--2026-10-14)
passes seven tests in both circuit layouts, including 28 compiler comparisons
and shape/budget rejection coverage. CPU input preparation falls from
738.395 ms to 0.721 ms for merges and 359.363 ms to 0.322 ms for finalizers
when a validated public program is already available. The binder remains
test-only; worker-cache integration and native proof validation are next.
No native throughput gain or new timing class is qualified. See the
[evidence](../evidence/gpu-recursive-input-prototype-2026-10-14.json).

The [event-batching experiment](dag-gpu-implementation-2026-10-17.md#9195-bounded-event-observation-experiment-and-native-cost-review--2026-10-14)
adds nine isolated comparisons, 60 arithmetic cases, 12 failure-cleanup cases
and four zero-denominator checks. Batching event profiling saves roughly
8 ms per 1,025 launches in these shapes; production accounting remains unchanged.
The native cost review identifies approximately 2 seconds of repeated warm-root
registry compilation as a larger next target. This evidence qualifies no new
workflow throughput or timing classes. See the
[experiment record](../evidence/gpu-event-batches-2026-10-14.json).

The [opening-reduction checkpoint](dag-gpu-implementation-2026-10-17.md#9194-larger-opening-reduction-tiles-within-existing-budgets--2026-10-14)
raises the admitted reduction tile cap to 1,048,576 rows while retaining the
existing memory limits and per-event accounting. **Thirteen tests and four
fresh native GPU proofs pass**, including independent CPU verification after
worker shutdown. Opening-stage launches fall from **8,420 to 1,220 per proof**.
The warm root sample takes **9.737 seconds**; cold timing is slightly slower
than the previous image, and complete-workflow throughput remains unqualified.
The new executable needs fresh timing calibration. The checkpoint also updates
the maintained entry-point review and preserves both rejected preflights.
See the [evidence](../evidence/gpu-opening-reduction-2026-10-14.json).

The [opening-tile checkpoint](dag-gpu-implementation-2026-10-17.md#9193-larger-opening-evaluation-tiles-within-existing-budgets--2026-10-14)
raises the evaluator's maximum tile to 65,536 rows while retaining all existing
memory admission checks. **Twelve tests and four additional native GPU proofs
pass**, with CPU verification after worker shutdown. Opening-stage kernel
calls fall from **18,020 to 8,420 per proof**. Overall native timing samples
remain mixed, so full-workflow throughput is still unqualified. The rebuilt
image needs fresh timing calibration. See the
[evidence](../evidence/gpu-opening-tiles-2026-10-14.json).

The [verified-input checkpoint](dag-gpu-implementation-2026-10-17.md#9192-immutable-verified-inputs-for-native-merge-and-finalization--2026-10-14)
removes repeated verification of immutable merge/finalization inputs between
typed worker preparation and its proving session. Public caller checks,
output verification, acceptance and recovery remain intact. **33 tests and
four native GPU proofs pass**, including independent CPU verification after
worker shutdown. The targeted saving is about **36 ms per child**; complete
workflow throughput remains unqualified. The rebuilt native image has **zero
approved timing classes** until it is recalibrated. See the
[evidence](../evidence/gpu-verified-inputs-2026-10-14.json).

The [transform experiment checkpoint](dag-gpu-implementation-2026-10-17.md#9191-transform-experiments-and-sustained-measurement--2026-10-14)
archives 44 OpenCL experiment runs with independent CPU oracles. Sustained
batches show approximately 0.5–4.3% improvements from cached-power reuse and
about 47.5% faster wide row scaling, whose baseline cost is only 1.4–2.8 ms.
These are kernel measurements; no candidate is activated and no workflow
throughput gain is established. Earlier single-launch observations remain
preserved. See the [evidence](../evidence/gpu-transform-workgroups-2026-10-14.json).

The [full-64 timing checkpoint](dag-gpu-implementation-2026-10-17.md#9190-complete-exact-image-merge-and-root-calibration--2026-10-14)
adds **31 GPU merge proofs**, including two distinct count-64 roots, with
independent CPU verification. The unchanged native executable now has **14
approved timing classes**, covering cold and warm execution at every merge
level. The root samples take **11.977 seconds cold and 10.311 seconds warm**.
Both build layouts pass, along with ten test executions across the two test
images. See the [evidence](../evidence/gpu-sixty-four-calibration-2026-10-14.json).

These are seeded calibration runs. The first run retains 62 proofs before the
cold-root bootstrap estimate exceeds the time remaining; its deadline and
failed journal remain unchanged. A separate calibration produces the two
roots from independently verified count-32 seeds. The scheduler's conservative
warm estimates total **653.625 seconds for all 63 jobs**, excluding cold starts
and recovery overhead. A fresh full-64 workflow and delivered transactions per
hour remain unqualified.

The [large-transform geometry checkpoint](dag-gpu-implementation-2026-10-17.md#9189-nvidia-grouping-for-large-sixteen-column-transforms--2026-10-14)
uses eight-column workgroups for NVIDIA transforms with exactly sixteen columns
and 2^22 or 2^23 rows. Matched kernel comparisons improve the proving output
order by approximately **25% and 45%**, respectively. Smaller and irregular
shapes keep their original grouping because unrestricted changes regressed.
Global allocations and the 32 KiB local-memory ceiling are unchanged.

**16 final-source tests pass**, including six small and four native GPU proofs
verified on CPU; 192 independent oracle cases also pass. Native warm completion
samples are mixed: **8.209 versus 8.324 seconds** for mode 4 and **8.218 versus
8.102 seconds** for mode 8. These samples do not establish an overall throughput
gain. Four timing classes are approved for the new executable, with no old-image
imports. Merge/root calibration and a fresh full-64 workflow remain open.
See the [evidence](../evidence/gpu-transform-geometry-2026-10-14.json).

The [completion-reporting checkpoint](dag-gpu-implementation-2026-10-17.md#9188-preserve-completed-proof-notifications-on-deadline-rejection--2026-10-14)
fixes the lost notification exposed by the full-64 attempt. A durably accepted
proof is returned before a subsequent placement rejection; the next poll still
enforces the original deadline. A real archived proof reproduces the failure
before the fix and passes afterward, including independent durable recovery.
**55 tests pass**, along with both build layouts and the production rebuild.
The rebuilt native executable has a different hash, so its timing calibration
starts at **zero approved classes**; older measurements remain bound to their
original image. No new GPU proofs or throughput qualification are claimed.
See the [evidence](../evidence/gpu-pool-completion-2026-10-14.json).

The [fresh full-64 pool checkpoint](dag-gpu-implementation-2026-10-17.md#9187-fresh-full-64-pool-execution-and-deadline-rejection--2026-10-14)
adds execution and independent recovery coverage for the natural-order
64-transaction graph. Its first fresh candidate produces **33 of 63 GPU proofs**:
all 32 wallet pairs and one merge, with zero imported recursive proofs. All
retained proofs pass CPU verification with all sixteen OpenCL arithmetic stages.
Three workers exit cleanly; the scheduler rejects the remaining path against
the original 600-second deadline. The final audit ends at **401.305 seconds**,
with no root. This does not qualify full-64 throughput. See the
[evidence](../evidence/gpu-sixty-four-pool-2026-10-14.json).

The [specialized-image merge checkpoint](dag-gpu-implementation-2026-10-17.md#9186-specialized-image-merge-calibration--2026-10-14)
adds eleven independently CPU-verified GPU proofs and brings the unchanged
executable to **fourteen approved timing classes**. Warm merges take
**9.844–10.373 seconds**. The scheduler's conservative estimates now sum to
**619.634 seconds for 62 known jobs**, down from 741.344 seconds on the earlier
image. That diagnostic excludes the final merge and workflow overhead; it does
not establish a fresh 64-transaction run within the unchanged 600-second limit.
See the [evidence](../evidence/gpu-quotient-specialization-merge-2026-10-14.json).

The [quotient specialization checkpoint](dag-gpu-implementation-2026-10-17.md#9185-bounded-nvidia-quotient-specialization--2026-10-14)
compiles public AIR instructions into bounded **64-instruction GPU functions**.
The native workload executes the specialized kernel within the existing memory
limits. Warm quotient device time falls from **2.043 to 0.629 seconds**; warm
pair samples improve from **9.259 to 8.324 seconds** and **9.875 to 8.102 seconds**.
These are individual native samples, not delivered transaction throughput.

**Sixteen final-source test executions pass**, including six small and four
native proofs verified on CPU with all sixteen OpenCL arithmetic stages.
That checkpoint approves four timing classes with no old-image imports;
§9.186 adds merge measurements. A fresh full-64 workflow remains unqualified.
Unsupported devices and programs retain the GPU interpreter. The Metal feature
guard is corrected, but Apple hardware remains untested. See the
[evidence](../evidence/gpu-quotient-specialization-2026-10-14.json).

The [quotient workgroup checkpoint](dag-gpu-implementation-2026-10-17.md#9184-nvidia-quotient-workgroup-sizing--2026-10-14)
uses at most **32 rows per NVIDIA workgroup**, with unchanged arithmetic kernels
and memory limits. Quotient device time in full-size proofs falls about **13%**,
from 2.356 seconds to 2.043 seconds. **Fourteen final-source tests pass**, including
six small and four full-size native proofs verified on CPU.

Warm native pair samples are mixed: mode 4 changes from **9.720 to 9.259 seconds**;
mode 8 changes from **9.773 to 9.875 seconds**. These individual samples do not
establish a delivered-throughput improvement. The rebuilt executable has **four
approved timing classes**, with no old-image records imported. Its merge timings
and fresh full-64 workflow remain unqualified. Other GPU vendors retain their
existing launch behavior. See the [evidence](../evidence/gpu-quotient-workgroups-2026-10-14.json).

The preceding [merge calibration checkpoint](dag-gpu-implementation-2026-10-17.md#9183-optimized-image-merge-calibration--2026-10-14)
adds **11 CPU-verified native GPU proofs** using twenty public subtree seeds.
The optimized executable now has **14 approved timing classes**, with no timings
from older images. Warm merge samples take **11.277–12.270 seconds**. This is
seeded calibration; it does not qualify a fresh workflow.

The full-64 inventory sums warm estimates for **62 jobs to 741.344 seconds**,
excluding the final merge and workflow overhead. The previous executable's
diagnostic was 836.096 seconds. Both are scheduling diagnostics; the unchanged
600-second deadline still requires further optimization. That diagnostic belongs
to the earlier executable; §9.185 requires new merge measurements. See the
[evidence](../evidence/gpu-transform-merge-2026-10-14.json).

The [GPU transform cache checkpoint](dag-gpu-implementation-2026-10-17.md#9182-workgroup-transform-power-cache--2026-10-14)
shares transform powers within the original **32 KiB local-memory budget**, with
no new global GPU allocations. Groups that do not fit retain the original
kernel. Four native proofs and six small proofs pass CPU verification with all
sixteen arithmetic stages on OpenCL; **14 final-source tests pass**.

Warm mixed-pair samples take **9.720 and 9.773 seconds**, approximately **13–18%**
less than the preceding executable. These are single native samples per class;
five alternating comparisons measure individual kernels only. The new executable
has **four approved timing classes**, with no old-image timings imported.
Full-64 workflow, delivered throughput and Metal hardware qualification remain
open. See the [evidence](../evidence/gpu-transform-cache-2026-10-14.json).


The earlier [full-64 workload checkpoint](dag-gpu-implementation-2026-10-17.md#9181-full-64-fixture-admission-and-mixed-pair-timings--2026-10-13)
CPU-verifies all **64 transaction inputs** and confirms a **63-proof graph**:
32 mixed pairs and 31 merges, with no separate finalizer. Both new pair types
fit the existing memory assignment. Four fresh native GPU proofs pass
independent CPU verification and retain all sixteen OpenCL arithmetic stages.
Their cold/warm timings add four approved classes, bringing the unchanged
native executable to **15 classes**.

The scheduler's warm estimates sum to **836.096 seconds for 62 jobs**, before
the unmeasured final merge, preparation and worker restarts. This is a model
diagnostic, not a measured full-64 run. Transforms and quotient computation
are the largest measured GPU stages and are the next optimization targets.
The 600-second candidate deadline and resource caps remain unchanged. See the
[evidence](../evidence/gpu-sixty-four-workload-2026-10-13.json).

The [registry-bound preprocessing checkpoint](dag-gpu-implementation-2026-10-17.md#9180-registry-bound-gpu-preprocessing--2026-10-13)
completes a fresh **32-wallet pool candidate in 509.365 seconds**: all 32 proof
jobs and the root, zero imported recursive proofs, real scheduling, and
independent CPU verification within the original 600-second deadline. All
sixteen proving arithmetic stages remain on OpenCL. Workers authenticate their
computed preprocessing commitment against the approved registry, avoiding an
unused standalone diagnostic-ID hash. Standalone IDs remain unchanged.

**163 tests pass**. Cold pair/merge samples fall to approximately **12–15 seconds**;
a seeded finalizer takes **11.630 seconds**, versus 36.274 seconds previously.
Eleven timing classes are approved for the new executable. Resource and runtime
caps remain unchanged; the release test harness disables ThinLTO to fit its
3 GiB cap, while the production library retains its original ThinLTO profile.
Full-64, sustained and multiple-device qualification, complete lifetime
admission, and durable application remain open. Delivered transaction
throughput is not yet qualified. See the
[evidence](../evidence/gpu-registry-prover-2026-10-13.json).

The preceding [NVIDIA round-unrolling checkpoint](dag-gpu-implementation-2026-10-17.md#9179-nvidia-public-hash-round-unrolling--2026-10-13)
reduces long public-hash device time by **about 2%** in both layouts. CPU
reference checks and seven fresh GPU proofs pass, including a native
32-wallet finalizer taking **36.274 seconds** with 31 existing subtree proofs.
The portable OpenCL path and resource caps are unchanged. At that checkpoint,
the executable had one approved cold-finalizer timing class; §9.180 supersedes its timing
qualification. This does not establish delivered transaction throughput. See
the [evidence](../evidence/gpu-public-hash-unroll-2026-10-13.json).

The earlier [native pool service-window checkpoint](dag-gpu-implementation-2026-10-17.md#9178-native-pool-service-windows-and-cache-reuse--2026-10-13)
added worker retirement based on the estimated time needed for the next proof.
That fresh mixed 32-wallet candidate produced **22 GPU proofs**, with **three
cold setups and 19 warm jobs**, before the scheduler rejected the remaining
path against the original 600-second deadline. Every retained proof passes
independent CPU verification; all workers exit cleanly. The final audit ends at
**479.938 seconds**, with no final root. **108 scheduler/pool tests pass** in
both layouts. Cold merge preprocessing consumed about 49 seconds of GPU time;
§9.180 removes its unused diagnostic-ID hash. Complete worker lifetime admission
remains open.
This does not qualify delivered transaction throughput. See the
[evidence](../evidence/gpu-pool-service-window-2026-10-13.json).

The [cache-reuse scheduler update](dag-gpu-implementation-2026-10-17.md#9177-measured-cache-reuse-with-deadline-slack--2026-10-13)
keeps measured cached work on its fastest worker when the delay fits existing
deadline slack. Using identical approved timings, a CPU-only replay now selects
**all 32 jobs**, with **three mode switches and 28 warm jobs**, at **582.460
estimated seconds**. The prior scheduler selects only 12 jobs. Both layouts and
pool regressions pass. That replay excludes worker restarts, recovery and audit
overhead; the §9.178 native checkpoint includes them and stops short of the
root. Neither result establishes a delivered throughput improvement.

The earlier [32-wallet timing checkpoint](dag-gpu-implementation-2026-10-17.md#9176-exact-image-mixed-wallet-timings-and-scheduler-diagnosis--2026-10-13)
adds eleven CPU-verified native GPU proofs and approves the missing timing
classes for the current worker. Wallet pairs take about **45 seconds cold and
11 seconds warm**; merges take about **65 seconds cold and 13 seconds warm**.
A CPU-only replay of the previous scheduler exposes repeated cache switching
and cannot select all 32 jobs within the existing deadline. These seeded measurements and the
simulation do not qualify a fresh workflow or transaction throughput.

The earlier [NVIDIA hashing checkpoint](dag-gpu-implementation-2026-10-17.md#9175-shuffle-compiler-ordering-and-exact-image-requalification--2026-10-13)
reduces cooperative public-hash device time by **about 2.9%** on the RTX 5080.
Supported NVIDIA devices use warp exchanges; other OpenCL devices retain the
portable kernel. Both layouts match CPU digests. Six small GPU proofs and one
native 32-wallet finalizer retain all sixteen OpenCL arithmetic stages and
independent CPU verification. The finalizer takes **37.191 seconds**, using
31 previously verified subtree proofs; a fresh 32-wallet workflow and delivered
transaction throughput remain unqualified. Existing memory and deadline caps
are unchanged. The shuffle instructions are volatile to preserve participation
by every lane. See the [evidence](../evidence/gpu-public-hash-shuffle-ordering-2026-10-13.json).

Three preceding experiments—double buffering, explicit limb multiplication and
fixed-diagonal arithmetic—were correct but slower. Their rejected source and
benchmark results remain archived in §§9.171–9.173 of the implementation log.

The preceding [32-wallet calibration checkpoint](dag-gpu-implementation-2026-10-17.md#9170-mixed-32-wallet-native-calibration-and-deadline-rejection--2026-10-12)
CPU-verifies a depth-six root for 16 join-split and 16 issuance wallets, using
**17 fresh GPU proofs plus 15 reused public subtree proofs**. The original
600-second candidate correctly rejects its unmeasured finalizer when less than
the 180-second bootstrap remains. A separate seeded candidate measures that
finalizer at **37.826 seconds**, preserving the failed
candidate and its deadline. All new proofs report sixteen OpenCL arithmetic
stages; a fresh 32-wallet pool workflow remains unqualified.
See the [evidence](../evidence/gpu-thirty-two-calibration-2026-10-12.json).

The earlier [GPU hashing checkpoint](dag-gpu-implementation-2026-10-17.md#9169-cooperative-gpu-public-hashing-and-native-pool-qualification--2026-10-12)
shares each public-hash permutation across eight GPU work items, preserving
exact CPU-reference digests. The million-field hash benchmark improves by about
**1.96×**. A fresh sixteen-wallet pool workflow with the rebuilt worker
finishes in **422.874 seconds**, within its original 600-second deadline.
All sixteen proofs retain all sixteen OpenCL arithmetic stages and independent
CPU verification after worker exit. Global scratch and host/GPU/service caps
are unchanged; the kernel adds 64 bytes of static workgroup memory. Larger
workloads, complete lifetime admission and delivered transaction throughput
remain open. See the [evidence](../evidence/gpu-public-hash-lanes-2026-10-12.json).

> **Research status:** Feature-gated, prove-only, and outside the production
> audit. CPU verification and the proof format remain authoritative. The latest
> [numerical verifier checkpoint](#native-numerical-verifier-scratch-2026-10-10)
> adds a source-derived allocation-request bound and a 64 MiB component ceiling
> for registered verification on release x86_64. Both CPU layouts pass
> conformance, and full-size GPU proofs retain all 16 OpenCL proving arithmetic
> stages. Configuration, caller storage, complete scheduler lifetimes and
> sustained throughput qualification remain open.

The latest [registered
> verifier checkpoint](#registered-verifier-shape-admission-2026-10-10) bounds
> proof dimensions before cloning and rejects an unexpected empty next row
> that otherwise reaches an upstream assertion. Both machine layouts pass
> conformance; wallet, multi-AIR and full-size GPU checks pass, with all 16
> finalizer proving arithmetic stages on OpenCL. Complete scheduler lifetime
> profiles and sustained throughput remain open. The earlier [lookup checkpoint](#quadratic-and-cubic-gpu-lookups) adds quadratic
lookup generation and shared opening inversion. The preceding
[tree checkpoint](#legacy-tree-gpu-proving) qualifies GPU leaf proofs and root
construction in existing `LJSTREE1` containers through 1,024 leaves on the
desktop RTX 5080. Full-size recursive proofs have since passed the limited
[native-worker qualification](dag-gpu-implementation-2026-10-17.md#993-native-numerical-verifier-scratch-2026-10-10).

The [October 6 full GPU proving review and plan](dag-gpu-implementation-2026-10-17.md#9-plan-for-all-proving-arithmetic-on-the-gpu)
maps the CPU/GPU boundaries for wallet and recursive proofs. Persistent GPU
workers, transforms, commitments, lookup/quotient/opening arithmetic, FRI, and
recursive witness construction have GPU paths with CPU-reference proof checks.
Registered proving now supports `LATTICA_V2_GPU_RANDOMNESS=1` with the owned
GPU witness/PCS path: all four private streams and public preprocessing salts
feed GPU consumers, with immutable selection and additive worker reservations.
CPU randomness remains the default.

The [registered transcript checkpoint](dag-gpu-implementation-2026-10-17.md#929-registered-gpu-transcripts-reporting-and-worker-reservations--2026-10-07)
adds immutable `LATTICA_V2_GPU_TRANSCRIPT=1` selection for registered proving,
requiring the owned GPU witness/PCS and private randomness path. Transcripts,
grinding and derived scalars report actual GPU calls and device timings. Two
live transcript states are enforced; worker reservations add 723,272 managed
bytes and 1 MiB host memory. CPU transcripts remain the default, and public
preprocessing and verification keep their CPU challengers.

Its 84 Rust cases include 45 native GPU checks across both AIR layouts and debug;
135 Python resource/controller/worker cases pass. Eighteen registered proofs
preserve registry identity and verify with the original CPU verifier after GPU
shutdown. Eighteen additional owned proofs match CPU bytes. Setup/public-value
arithmetic, wallet and other proving routes/profiles, full stage coverage and
AMD/Metal qualification remain unfinished. Strict GPU-only admission, full-size
memory and sustained pool throughput remain unqualified. The dated measurements
below are historical evidence, not measurements of a completed all-GPU prover.

The [setup checkpoint](dag-gpu-implementation-2026-10-17.md#930-gpu-setup-domains-and-registered-identity-hashing--2026-10-07)
moves registered GPU witness program-identity hashing onto GPU and removes CPU
domain inversion from its preprocessing path. Intermediate hash state stays on
device in a fixed 32,800-byte workspace; the canonical manifest and CPU identity
remain unchanged. Worker reservations include the added scratch. Its 76 Rust
cases include 41 native GPU checks; 135 Python cases pass. Forty-two registered
proofs preserve CPU identities and verify after GPU shutdown.

The [statement checkpoint](dag-gpu-implementation-2026-10-17.md#931-gpu-statement-derivation-in-recursive-sessions--2026-10-07)
moves proving-side leaf, empty, merge and finalizer hashing onto the selected
GPU witness backend in both recursive session APIs. CPU verification and host
acceptance remain independent. Its 75 Rust cases include 29 native GPU checks
and 32 recursive empty proofs; 135 Python cases pass.

The [compiler registry checkpoint](dag-gpu-implementation-2026-10-17.md#932-gpu-compiler-registry-fingerprints--2026-10-07)
moves AIR fingerprint hashing onto the selected backend during recursive
compilation and all five registration APIs. Prepared prefixes preserve exact
CPU programs and registry identities, with actual GPU preprocessing reports and
no new worker reservation. Its 90 Rust cases include 35 native checks and 47
successful registry-compilation reports; 135 Python cases pass.

The [compiler constant checkpoint](dag-gpu-implementation-2026-10-17.md#933-gpu-public-compiler-constant-helpers--2026-10-07)
adds explicit GPU inverses, periodic interpolation and quotient normalization.
Interpolation streams 2,048-value tiles through the existing scratch reservation
and covers periods through 65,536. Complete bounded verifier programs match CPU
references, and maintained wallet periodic columns match an independent inverse
DFT. Its 108 Rust cases include 44 native checks; 135 Python cases pass.

The [compiler folding checkpoint](dag-gpu-implementation-2026-10-17.md#934-gpu-compiler-constant-folding--2026-10-07)
moves known base/cubic arithmetic in `ProgramBuilder` onto its explicitly
selected backend. Scoped builders preserve identical programs, use a bounded
64-entry device-result cache and reject compilation after any folding failure.
Its 150 Rust cases include 50 native checks; 135 Python cases pass.
The [symbolic AIR checkpoint](dag-gpu-implementation-2026-10-17.md#935-gpu-symbolic-air-compilation--2026-10-07)
moved registry/compiler symbolic constant arithmetic and registration-template
geometry onto the selected backend while preserving DAG fingerprints and
lookup packing. The [setup and quotient checkpoint](dag-gpu-implementation-2026-10-17.md#936-gpu-symbolic-setup-and-quotient-compilation--2026-10-08)
extends this to registered-key analysis, identity constraints and quotient
compilation. It normalizes each quotient AIR once and retains bounded immutable
instructions, with a 16 MiB per-proof cache and a shared 192 MiB transient host
reservation in both worker resource models. Its 189 Rust cases include 68
native checks; all 135 Python cases pass. Host-input batch evaluation retains
multi-AIR support; owned main traces and owned quotient commitment remain
single-AIR. The [execution coverage checkpoint](dag-gpu-implementation-2026-10-17.md#937-gpu-execution-receipts-and-stage-coverage--2026-10-08)
adds per-session operation receipts, separate `device_calls` and device event time,
exclusive observation scopes, and failure/overflow accounting. Wall-clock envelopes
cannot satisfy GPU coverage. Its 198 Rust cases include 71 native checks; all 135
Python cases pass. Forty-five successful proof reports have positive receipts for
all 15 selected stages, while six rejected assignments retain completed witness
work. Real reports still mark coverage incomplete: the outer prover envelope and
public-value/preprocessing inventory require whole-request accounting and explicit
fallback rejection. Whole-request GPU admission, wallet/batch proving and AMD/Metal
qualification remain open; these checks make no throughput claim.

The [checked completion checkpoint](dag-gpu-implementation-2026-10-17.md#938-checked-gpu-completion-and-explicit-cpu-audits--2026-10-08)
makes `Run::finish` return a `Result`: a GPU-required request with missing,
unlisted or unfinished operations, or lost observations, cannot release its
output. Existing proof-return paths enforce that result. Debug CPU constraint
audits are now recorded and checked against policy before execution; they do
not satisfy the GPU inventory. Validation covers 204 Rust cases, including 74
native checks, and 135 Python cases. Six native completion rejections release
withheld output buffers; the accepted fixtures cover an isolated GPU fold, not
a full GPU-required proof. Registered and recursive request qualification are described below.

The [coverage scopes checkpoint](dag-gpu-implementation-2026-10-17.md#939-explicit-gpu-coverage-scopes-and-registered-proofs--2026-10-08)
qualifies release registered-program proving for `gpu-required` when all owned
OpenCL stages are selected. It starts from supplied circuit/public inputs and
requires completed device receipts for all 15 declared arithmetic stages.
Reports now identify their scope, so complete statement, registry or preprocessing
coverage cannot qualify a whole recursive request. Preprocessing follows the
selected randomness backend; partial selection rejects GPU-required setup.
Debug proofs declare CPU constraint audits and reject strict private proving
before witness work, while their public GPU preprocessing remains supported.

Validation covers 214 Rust cases (80 native checks) and 135 Python cases, including
12 GPU-required registered proofs CPU-verified after shutdown across wide/narrow
lanes and full/compact storage. Immutable transform-root tables replace a remaining
CPU inversion and are checked over all 33 supported domains. The following checkpoint adds request composition. Legacy wallet/batch proving,
owned multi-AIR support, AMD/Metal and production-size throughput remain open. These are bounded correctness results.

The [recursive request composition checkpoint](dag-gpu-implementation-2026-10-17.md#940-recursive-request-receipt-composition--2026-10-08)
adds explicit request coverage across statement derivation, registry compilation,
statement validation, preprocessing and registered proving. Each component must
complete; overlapping arithmetic stages cannot hide omitted work. Cached
preprocessing contributes its original provenance without replaying device calls
or time. Release GPU-required requests enforce all 16 proving arithmetic stages;
debug requests reject that policy before component work because of CPU audits.

The bounded matrix validates 24 GPU-required recursive empty requests and eight
debug-compatible requests, all CPU-verified after GPU shutdown. Both cold and
cached setup are covered across three/five/six/twelve-key registries, wide/narrow
lanes, and full/compact release storage. All 238 Rust cases (80 native checks) and
135 Python cases pass. Root reports aggregate child receipts: consumers should
select one scope to avoid double counting. Host verification and serialization
remain separate from proving arithmetic. Full-size wrap/pair/merge/finalizer
requests, legacy wallet/batch proving, owned multi-AIR commitment, AMD/Metal and
sustained throughput remain unqualified or unfinished.

The [wallet witness checkpoint](dag-gpu-implementation-2026-10-17.md#941-gpu-join-split-witness-generation-and-explicit-host-prover-bridge--2026-10-08)
adds GPU-owned join-split trace and public-value generation. Ownership/note hashes,
Merkle paths, nullifiers, range columns and balance arithmetic run on OpenCL;
generation reads back only an eight-byte validation status. The opt-in
`block_v2::leaf::prove_joinsplit_with_gpu_witness` API then explicitly reads the
trace and public values into the existing single-AIR prover. Its proof format
and CPU verifier are unchanged. This mixed route rejects GPU-required whole
proofs and public recursive worker assignments before private work; it needs an
initialized bounded engine, a 1,245,600-byte host staging allowance, and separate
CPU prover memory enforcement.

All 249 Rust cases (85 native checks) and 135 Python cases pass. Nine wallet
fixtures match every CPU trace cell/public value, 15 invalid witnesses reject
with device receipts preserved, and four fresh wallet proofs verify after GPU
shutdown. The following checkpoint adds device-owned single-AIR proving without
full trace readback. HTLC, legacy wallet/batch integration and private wallet
worker support remain open.
These are correctness results on the selected NVIDIA GPU, with no AMD/Metal or
throughput qualification. See the [evidence manifest](../evidence/gpu-wallet-2026-10-08.json).

The [owned wallet prover checkpoint](dag-gpu-implementation-2026-10-17.md#942-owned-single-air-wallet-proving-and-periodic-quotients--2026-10-08)
adds `block_v2::leaf::prove_joinsplit_on_gpu`. Release GPU-required requests keep
the private trace, quotient and PCS arithmetic on GPU and enforce receipts for
all 15 wallet arithmetic stages. The AIR has no lookup argument. GPU periodic
polynomial evaluation supplies auxiliary quotient inputs without changing the
public AIR, transcript, proof encoding or CPU verifier. The handoff reads only
208 public-value bytes; debug builds explicitly read the trace for CPU constraint
auditing and reject GPU-required admission before private work.

Eight fresh GPU-required release wallet proofs and four compatible debug proofs
verify after GPU shutdown across full/compact storage and wide/narrow profiles.
All 258 Rust cases (91 native checks) and 135 Python cases pass. Owned wallet
checks use a 1 GiB managed GPU allowance inside 3 GiB, zero-swap services; this is
a correctness setting, with production memory and throughput still unqualified.
Private wallet worker admission, legacy quadratic wallet/batch and HTLC proving,
owned multi-AIR support and AMD/Metal qualification remain unfinished. See the
[validation evidence](../evidence/gpu-uni-2026-10-08.json).

The [HTLC checkpoint](dag-gpu-implementation-2026-10-17.md#943-owned-htlc-witness-generation-and-typed-gpu-proving--2026-10-08)
adds `block_v2::typed_leaf::prove_htlc_on_gpu`. Three GPU kernels generate the
4096-row, 36-column HTLC trace and 31 public values, including ownership,
membership, mode-independent nullifiers, timeout/range and nonzero-hashlock
arithmetic. Release proofs use the owned single-AIR path and complete all 15
applicable GPU stages, with no private trace handoff readback and only 248 public
bytes. The typed encoding and CPU verifier remain unchanged. Debug explicitly
audits the trace on CPU and rejects GPU-required admission. SHA-256 preimage
acceptance and independently expected block height remain external requirements.

Sixteen GPU-required release HTLC proofs and eight compatible debug proofs verify
after GPU shutdown across full/compact storage and the three build profiles.
Eighteen trace fixtures match every CPU cell/public value; 42 invalid engine
witnesses and six invalid whole requests retain their device receipts. All 270
Rust cases (100 native checks) and 135 Python cases pass, including the existing
join-split and recursive regressions. These checks use the designated RTX 5080
Laptop GPU with 1 GiB managed GPU memory for complete proofs, bounded 3 GiB RAM
services and no swap. Private wallet worker admission, legacy quadratic/batch
integration, owned multi-AIR commitments, full-size recursive qualification,
AMD/Metal and sustained throughput remain unfinished or unqualified. See the
[HTLC validation evidence](../evidence/gpu-htlc-2026-10-08.json).

The [issuance and wallet API checkpoint](dag-gpu-implementation-2026-10-17.md#944-owned-issuance-proving-and-candidate-wallet-entrypoint-routing--2026-10-08)
connects the maintained candidate join-split, HTLC and issuance request/research
APIs to the complete explicitly initialized owned GPU selection. It adds
`block_v2::typed_leaf::prove_issuance_on_gpu`, preserving host mint authorization,
issuance-count enforcement and the existing typed verifier/encoding. Selected
but retired engines reject before configuration construction; compatible
requests cannot silently fall through to CPU proving after shutdown.

Forty-two additional wallet proofs, including 18 issuance proofs, CPU-verify
after GPU shutdown across full/compact storage and all three profiles. There are
28 GPU-required release proofs and 14 compatible debug proofs with explicit CPU
audits. Nine issuance fixtures match every CPU trace cell/public value through
the maximum 52-bit mint amount; six invalid whole requests retain device
receipts. All 283 Rust cases (109 native checks) and 135 Python cases pass.
Legacy quadratic Rust/C ABI and batch integration, full-size recursive workloads,
private wallet worker admission and AMD/Metal/throughput qualification remain
unfinished. See the [issuance validation evidence](../evidence/gpu-issuance-2026-10-08.json).

The [generalized FRI checkpoint](dag-gpu-implementation-2026-10-17.md#945-generalized-gpu-fri-and-final-polynomial-interpolation--2026-10-08)
adds quadratic/cubic folds of arity 2–16 and GPU interpolation for nonconstant
final polynomials. The candidate prover retains its pinned binary/cubic
parameters. Thirty-six standalone FRI proofs CPU-verify after GPU shutdown and
match upstream proof bytes when using the same independently checked PoW
witnesses. All 295 Rust cases (121 native checks) and 135 Python cases pass.
These component fixtures supply reduced inputs and initial matrix openings on
CPU; full legacy quadratic witness/quotient/opening and STARK/PCS integration
remain unfinished. No transaction-throughput or AMD/Metal qualification is
implied. See the [validation evidence](../evidence/gpu-general-fri-2026-10-08.json).

The [owned PCS opening checkpoint](dag-gpu-implementation-2026-10-17.md#946-quadraticcubic-owned-pcs-openings-and-gpu-input-queries--2026-10-08)
connects quadratic/cubic opening evaluation and reduction to GPU FRI and input
query openings. Prefixes and reduced vectors remain on GPU. Thirty-six complete
PCS opening proofs CPU-verify after GPU shutdown across full/compact storage
and wide release, narrow release and debug builds. Each component requires
strict GPU receipts for all nine stages, including commitment and opening.
All 322 Rust cases (139 native checks) and 135 Python cases pass.

Public base evaluations and opening points are supplied as test fixtures.
Complete legacy quadratic hiding PCS/STARK, witness/quotient and scalar
integration remain unfinished. The next work is quadratic quotient evaluation
and connecting the resident PCS to legacy whole proofs. These correctness
checks establish no transaction-throughput or AMD/Metal qualification. See the
[owned PCS evidence](../evidence/gpu-quadratic-opening-2026-10-08.json).

The [quadratic/cubic quotient checkpoint](dag-gpu-implementation-2026-10-17.md#947-quadraticcubic-gpu-quotients-hiding-commitments-and-scalar-points--2026-10-08)
adds extension-aware constraint compilation, GPU quotient evaluation and hiding
commitments, plus compact quadratic next-row scalars. Both direct and
partitioned quotient evaluation feed GPU commitments before value readback.
GPU-generated hiding samples preserve the existing mask and salt order.

All 376 Rust cases (163 native checks) and 135 Python cases pass across wide
release, narrow release and debug qualification. This includes 96 quotient
comparisons, 12 owned-adapter comparisons and 48 hiding-commitment comparisons
with independent CPU references and CPU verification of GPU query openings.
The PCS, FRI, wallet and recursive regressions remain green. Public input
matrices are component fixtures. The subsequent resident PCS checkpoint below
adds generic hiding configuration; the legacy wallet checkpoint below completes single-wallet integration. No throughput
or AMD/Metal qualification is implied. See the
[quotient evidence](../evidence/gpu-quadratic-quotient-2026-10-08.json).

The [generic resident hiding PCS checkpoint](dag-gpu-implementation-2026-10-17.md#948-generic-resident-hiding-pcs-for-quadratic-and-cubic-profiles--2026-10-08)
adds field-specific resident configuration, randomization widths and extension
trace commitments while preserving the candidate's binary FRI admission.
Thirty-six quadratic/cubic hiding PCS proofs match upstream bytes and CPU-verify
after GPU shutdown across full/compact selections and three build profiles.
All 400 Rust cases pass in 262 bounded checks (181 native), alongside
CPU-only and GPU-only library builds. Six explicit host-mode proofs separately
check stream continuity; compact host prefixes are rejected. These public
fixtures do not establish complete legacy wallet STARK proving or throughput.
See the [resident PCS evidence](../evidence/gpu-resident-generic-2026-10-08.json).

The [legacy GPU wallet checkpoint](dag-gpu-implementation-2026-10-17.md#949-legacy-quadratic-wallet-proving-and-native-abi-delivery-on-gpu--2026-10-08)
completes legacy quadratic join-split and HTLC proving, including the Rust APIs
and single-wallet raw/demo C ABI entrypoints. The explicit complete GPU selection
keeps private traces resident and supplies GPU-produced public values to native
serialization. Legacy proof bytes, verifier configuration and mint semantics
remain unchanged. Default CPU behavior is preserved.
The C ABI checks use the existing Rust-side resident initialization in the same
process; standalone native GPU initialization/lifecycle remains to be added.

All 72 new wallet proofs verify through the unchanged CPU APIs after GPU shutdown.
The 48 release proofs require GPU completion; debug proofs declare CPU constraint
audits. Host serialization remains explicit. Full/compact storage, both lane
profiles, invalid/admission cases and existing recursive/PCS regressions pass:
415 Rust test executions and 193 native checks, with CPU-only and GPU-only
library builds. Batches, private wallet workers, quadratic lookup generation and
larger recursive qualification remain open. These checks do not measure sustained
transaction throughput or qualify AMD/Metal. See the
[legacy wallet evidence](../evidence/gpu-legacy-wallet-2026-10-08.json).

The [legacy batch checkpoint](dag-gpu-implementation-2026-10-17.md#950-legacy-batch-proving-gpu-periodic-setup-and-32-chunk-quotients--2026-10-08)
adds GPU batch trace assembly, canonical padding, statement/root folding and
periodic-table expansion. The Rust and native batch APIs serialize the GPU root
and proof without CPU root recomputation when the complete GPU path is selected.
HTLC's 32-chunk quotient is admitted independently of the unchanged 16x LDE
blowup; heap and verifier limits remain in place.

All 72 batch proofs verify after GPU shutdown in full/compact storage; 48 release
proofs require GPU completion and debug proofs declare CPU constraint audits.
The matrix passes 433 Rust executions and 208 native checks, plus CPU-only
and GPU-only builds. Both AIRs' trace/root assembly matches CPU references through
64 tiles, while full proofs are qualified only through four padded tiles. The
managed GPU allowance stays at 1 GiB. Larger complete proofs, private workers,
recursive delivery and sustained throughput still
need qualification; no AMD/Metal result is claimed. See the
[batch evidence](../evidence/gpu-legacy-batch-2026-10-08.json).

The [native lifecycle checkpoint](dag-gpu-implementation-2026-10-17.md#951-native-gpu-lifecycle-and-standalone-c-delivery--2026-10-09)
adds `lattica_gpu_initialize_from_env()`, `lattica_gpu_drain()` and
`lattica_gpu_shutdown()` to the public C header. Configure the complete owned GPU
path, explicit UUID and memory allowance before initialization. The functions
return 0 on success, 1 on rejection and 2 when `block-v2,gpu` support is absent.
Startup failures preserve borrowed engines; changing a live engine's device
selection rejects. Shutdown requires released sessions/commitments, and selected
GPU proving rejects after shutdown until the engine is reinitialized.

All **30 standalone C proofs** verify through the unchanged CPU APIs after GPU
shutdown; 20 release proofs require GPU completion and ten debug proofs declare
CPU audits. The final desktop RTX 5080 matrix also passes **442 Rust executions
and 214 native GPU checks**, preserving the 1 GiB managed proof allowance and
serial 3 GiB host services. This qualifies native library startup and delivery;
private workers, larger proofs, other GPU backends and sustained throughput
remain open. Application startup is covered by the subsequent Zig checkpoint. See the
[lifecycle evidence](../evidence/gpu-native-lifecycle-2026-10-09.json) and
[`gpu_lifecycle.c`](../../lattica-prover-p3/tests/gpu_lifecycle.c) for the standalone
calling sequence.




The [integrated GPU lookup path](dag-gpu-implementation-2026-10-17.md#912-gpu-lookup-integration-and-permutation-commitments--2026-10-07)
recovers original rows from captured prefixes, generates LogUp witnesses, and
commits permutation traces on GPU. Enable it with `LATTICA_V2_GPU_LOOKUP=1` and
the owned OpenCL quotient route. Full/compact proof-byte and CPU verification
checks pass; random expansion and host opening matrices remain. Complete proving
is still hybrid, and no throughput improvement has been qualified.

The experimental [integrated opening path](dag-gpu-implementation-2026-10-17.md#914-gpu-opening-integration--2026-10-07)
evaluates claimed values and produces reduced FRI inputs from retained GPU
commitment prefixes. Select `LATTICA_V2_GPU_OPENING_EVAL=1` with GPU openings
and the owned OpenCL quotient route. Full/compact proof bytes, CPU verification,
RNG preservation and allocation cleanup pass, including GPU lookup composition.
With opening evaluation alone, FRI vectors return to the host prover.
Add `LATTICA_V2_GPU_FRI_RESIDENT=1` to keep binary FRI inputs, layers,
commitments, folding and input mixing on GPU and gather only final proof rows.
This [resident FRI checkpoint](dag-gpu-implementation-2026-10-17.md#915-resident-binary-fri-integration--2026-10-07)
passes exact proof-byte and original CPU-PCS verification checks. Its
[initial PCS queries now reuse device prefixes](dag-gpu-implementation-2026-10-17.md#916-owned-initial-pcs-query-reconstruction--2026-10-07)
through bounded GPU reconstruction and gathers, with no query-time prefix
transfers. Owned opening/query geometry is independent of host matrices.
Add `LATTICA_V2_GPU_PCS_DEVICE_ONLY=1` with GPU lookup and the owned
quotient/opening/resident-FRI route to remove commitment-time host polynomial
allocation, readback and reorder. This [device-only PCS checkpoint](dag-gpu-implementation-2026-10-17.md#917-device-only-pcs-storage--2026-10-07)
passes 93 Rust cases and 36 resource tests, preserves exact full/compact
proof bytes and reuses public preprocessing across fresh sessions. Salts,
random expansion, witness construction and transcript/grinding still use
the CPU. Complete GPU proving and throughput remain unqualified; the
full-size workload still fails conservative aggregate memory admission.

[GPU witness and preprocessing primitives](dag-gpu-implementation-2026-10-17.md#918-gpu-witness-and-preprocessing-primitives--2026-10-07)
now match CPU columns for every recursive opcode in both AIR layouts,
with 103 Rust cases passing. Reusable program metadata and private device
traces avoid trace transfers; execution downloads only an eight-byte
status. The [device witness-to-proof handoff](dag-gpu-implementation-2026-10-17.md#919-gpu-witness-to-proof-handoff--2026-10-07)
now connects those buffers to complete batch proofs and deterministic
preprocessing keys without host trace matrices. Its 119 passing Rust
cases cover both layouts, exact CPU proof bytes, fresh-session reuse and
explicit debug CPU audits. Add `LATTICA_V2_GPU_WITNESS=1` to the device-only
pipeline to select those GPU traces in registered proving. The
[registered-witness checkpoint](dag-gpu-implementation-2026-10-17.md#920-registered-gpu-witness-selection-and-worker-reservations--2026-10-07)
adds immutable selection, additive worker memory reservations and actual
witness-stage reporting. Its 64 Rust cases and 40 Python resource tests pass,
including full/compact proofs, original CPU verification and rejection before
uploads. Worker profiles require explicit witness bounds; no existing profile
was enabled or relaxed. Randomness, salts, transcript/grinding and wallet
arithmetic remain on CPU. Strict GPU-only admission and throughput qualification
remain open.

The [GPU random-stream foundation](dag-gpu-implementation-2026-10-17.md#921-gpu-random-streams-and-hiding-buffer-handoff--2026-10-07)
now matches the reference ChaCha20 stream and exact Goldilocks rejection
sampling. Its private device buffers feed trace/lookup/quotient hiding
commitments without sample staging through host memory. All 28 Rust cases
pass, including 22 native checks.

The [randomization and retained-salt checkpoint](dag-gpu-implementation-2026-10-17.md#922-gpu-randomization-polynomials-and-retained-salts--2026-10-07)
now keeps those polynomials and private commitment/FRI salts in device storage,
with only final queried salt rows returned to the host. All 34 Rust cases pass,
including 28 native GPU checks across both AIR layouts and debug builds.
The [public-salt and RNG-snapshot checkpoint](dag-gpu-implementation-2026-10-17.md#923-trusted-public-gpu-salts-and-rng-snapshots--2026-10-07)
also adds trusted GPU salts for reusable preprocessing keys and explicit device
stream snapshots. Its 49 Rust cases include 29 native checks, with exact CPU
proof bytes and key reuse across fresh sessions. Registered proofs still use CPU
random generation. Complete private stream integration, immutable runtime
selection, stage reporting and worker reservations remain before activation.


## Native GPU wallet startup

The [Zig startup checkpoint](dag-gpu-implementation-2026-10-17.md#952-zig-gpu-startup-wallet-cli-and-real-node-delivery--2026-10-09)
wires the qualified native lifecycle into the CLI, FFI tests and real node. The
default CLI is a mock demonstration; build with `-Dgpu-prover=true` for real GPU
transfer proving. A strict request in a mock build rejects before producing a
transaction. Non-proving commands (`exchange`, `keygen`, `bench`) do not initialize
the GPU.

Build the release Rust library, then configure the complete GPU path before
starting the application. Replace `GPU-<device-uuid>` with the explicitly selected
device UUID reported by `nvidia-smi --query-gpu=uuid,name --format=csv,noheader`.

```sh
export CARGO_BUILD_JOBS=4 RAYON_NUM_THREADS=4
(cd lattica-prover-p3 && cargo build --offline --release --lib --features block-v2-wide-lanes)
scripts/with-toolchain.sh zig build -j4 -Doptimize=ReleaseSafe -Dgpu-prover=true

export LATTICA_GPU_DEVICE_UUID='GPU-<device-uuid>'
export LATTICA_V2_GPU_MANAGED_BYTES=1073741824
export LATTICA_PROVING_POLICY=gpu-required
export LATTICA_V2_QUOTIENT_FUSION=1
for gpu_stage in HASH RETAIN_TREES RESIDENT_LDE OPENINGS QUOTIENT_LDE \
    QUOTIENT_EVAL QUOTIENT_RESIDENT LOOKUP OPENING_EVAL FRI_RESIDENT \
    PCS_DEVICE_ONLY WITNESS RANDOMNESS TRANSCRIPT; do
    export "LATTICA_V2_GPU_${gpu_stage}=1"
done
./zig-out/bin/lattica-wallet demo
```

Use `-Dprover-library=/path/to/liblattica_prover_p3.a` to select a prebuilt library.
`zig build test-ffi -j4 -Doptimize=ReleaseSafe -Dgpu-prover=true` exercises the
same startup and verifies serialized proofs after shutdown. Its standalone test
binary is installed at `zig-out/bin/lattica-ffi-tests`.

With the same environment, `scripts/run-real-integration.sh` runs the standalone
C lifecycle harness and real node flow. `LATTICA_PROVER_LIBRARY` skips the Rust
build when using an existing matching library; `LATTICA_INTEGRATION_OUT` chooses
where its binaries are retained. `cpu-required` selects its CPU integration path.
GPU mode requires both `block-v2` and `gpu` library support; CPU-only, GPU-only and
debug-audited Rust libraries reject strict GPU startup.

The shared Zig runtime installs proving backends only after successful startup.
Join all proof work before drain/shutdown. Successful shutdown clears proving
registrations and retains CPU verification; a refused shutdown preserves the
live state for cleanup and retry. Public recursive-worker assignments remain
rejected for private wallet input. The separate local wallet assignment below
adds resource admission inside the wallet's privacy boundary.

Qualification passed 404 Zig test executions and 64 GPU-required proofs across
43 bounded checks on the desktop RTX 5080. Full/compact storage and wide/narrow
release libraries are covered. The [evidence](../evidence/gpu-zig-startup-2026-10-09.json)
records exact libraries and commands; it establishes correctness, not sustained
transaction throughput or other GPU backend performance.

## Wallet-owned local GPU workers (Linux/OpenCL)

The [local worker checkpoint](dag-gpu-implementation-2026-10-17.md#953-wallet-owned-local-gpu-worker-admission--2026-10-09)
adds a bounded process for an application that owns its wallet witnesses. The
assignment contains public resource metadata only. Public recursive workers
continue receiving completed proofs and statements.

After building the GPU-enabled wallet as above, launch it with:

```sh
python3 scripts/run-wallet-gpu-worker.py \
    --gpu-uuid 'GPU-<device-uuid>' \
    --state-dir "$PWD/lattica-prover-p3/benchmark-results/wallet-workers" \
    -- "$PWD/zig-out/bin/lattica-wallet" demo
```

Add `--storage compact` before `--` to select compact storage. The launcher
configures the complete GPU path and an owner-only JSON assignment, then waits
for a `lattica-wallet-*.service` user service. It uses 3 GiB host RAM, zero swap,
four CPU threads, a 4 GiB GPU context allowance and a 180-second runtime limit.
Managed GPU memory and host output both default to 1 GiB. Add
`--managed-gpu-gib 7 --host-output-gib 2` before `--` for larger allowances.
The supported ranges are 1–7 GiB managed GPU and 1–2 GiB host output; the host
process cap stays at 3 GiB. Stacks, mapped staging and retained heap need space
within that cap. The earlier [64-input native batch qualification](dag-gpu-implementation-2026-10-17.md#9164-large-batches-through-the-native-wallet-worker-2026-10-12)
used a 3 GiB output allowance on an older source; that allowance is now rejected.
The assignment file
is retained for inspection; it contains no witnesses or proof inputs. Use a
native application that initializes the prover before submitting local work.

`LATTICA_WALLET_WORKER_BUDGET` selects this assignment. Admission checks the
closed schema, file ownership/permissions, explicit GPU UUID, GPU-required
policy, environment budgets, actual Rayon pool size and actual cgroup v2
memory/swap/CPU limits. Startup pins the file identity and service identity;
proof admission revalidates them. Downgrading the policy, changing or removing
the assignment, or substituting another file rejects. The pin survives GPU
shutdown, so changing resources requires a new process. The public pool's
`LATTICA_V2_WORKER_BUDGET` cannot be combined with this mode.

Assigned startup requires Linux and the `stream` allocator. Assignment parsing
does not start Rayon. Before initializing GPU work, startup observes caller and
Rayon stack backing and installs immutable System and combined System/spill
request ceilings. At four threads under the 3 GiB process cap, these are
2,666,594,304 and 2,599,485,440 bytes respectively. Existing and in-flight Rust
requests count toward these limits; spill allocations charge their full backing.
Runtime admission errors and caught panics remain terminal for the process, even after
assignment removal. Allocation failures follow the caller's error handling;
infallible Rust allocations may terminate the worker. Caller/thread contracts,
foreign allocations and complete per-proof GPU/host reservations still require
separate lifetime accounting.

The [qualification evidence](../evidence/gpu-wallet-worker-2026-10-09.json) records
50 checks and 31 complete GPU proofs on the desktop RTX 5080: 17 in wallet-owned
services and 14 candidate-path regression proofs. Both storage modes, the C ABI,
Rust wallet entry points and the real Zig wallet CLI pass. Each proof has 15
OpenCL arithmetic observations, with CPU serialization and independent CPU
verification. This qualifies the wide-lane release build and small wallet/batch
fixtures; sustained throughput, larger recursion and multi-GPU scaling remain
open. No remote private-witness transport is introduced.

## Legacy tree GPU proving

The existing `lattica_prove_joinsplit_tree` C entry point and Zig
`ffi.proveJoinSplitTree` now use GPU leaf proving and root construction when
the GPU backend is selected. GPU startup installs the tree proving backend;
shutdown clears it. Tree verifier registration is a separate explicit choice.
The `LJSTREE1` format and CPU verifier are unchanged, and the container retains
all individual proofs. Wallet-owned local workers support this path without
transporting private witnesses into the public recursive pool.

The [qualification](../evidence/gpu-legacy-tree-2026-10-09.json) passed 42 checks,
2,167 complete GPU proofs, 3 CPU compatibility proofs and 14 complete GPU tree
containers. Complete C containers cover 1, 3, 4, 33 and 1,024 leaves in both
full and compact storage, with CPU verification after GPU shutdown and tamper
rejection. Root differential tests cover 18 counts per mode. The 16 successful
root-operation receipts are distinct from complete proof receipts. Root
construction reads back 32 public bytes and an 8-byte validity status, with
zero trace readback.

The 1,024-leaf runs took 151.838 seconds (full) and 151.557 seconds (compact)
to construct approximately 469 MB containers. Including CPU verification and
tamper checks, they took 170.145 and 169.801 seconds under the 180-second
service limit, with 1.1 GiB reported host peaks and zero swap. These synthetic
fixtures repeat dummy witnesses and do not establish sustained transactions
per hour, valid ledger throughput, recursive aggregation or multi-GPU scaling.
Legacy batch qualification remains limited to four padded tiles. See
[§9.54](dag-gpu-implementation-2026-10-17.md#954-legacy-tree-gpu-delivery--2026-10-09) for
the implementation boundary, admission limits and preserved attempt history.

## Quadratic and cubic GPU lookups

The owned LogUp path now supports both pinned extension fields. Expression
evaluation, denominators, batch inversion, fractions and prefix scans run on
GPU, with degree-specific memory admission. Quadratic generation returns a
16-byte terminal and 8-byte status; cubic generation returns a 24-byte terminal
and 8-byte status. Intermediate matrices stay on the device. Opening reduction
shares the same inversion kernel in both profiles.

The [qualification evidence](../evidence/gpu-quadratic-lookup-2026-10-09.json)
records 68 CPU/GPU lookup comparisons through 32,768 rows and 11 passing checks.
Full/compact regressions cover six registered cubic proofs and six complete
quadratic wallet proofs in two tree containers, with CPU verification after GPU
shutdown. Registered-proof receipts exclude public statement construction and
are counted separately from complete proof requests. This introduces no new
AIR/profile or consensus activation. Public recursive native delivery, owned
multi-AIR commitments, full-size recursion and sustained throughput remain open.
See [§9.55](dag-gpu-implementation-2026-10-17.md#955-quadratic-gpu-lookups-and-shared-opening-inversion--2026-10-09)
for resource bounds and preserved attempt history.

## Selected GPU pipeline implementation priority

The [execution DAG and GPU implementation plan](dag-gpu-implementation-2026-10-17.md)
makes candidate GPU arithmetic and data reuse the immediate acceleration work.
Start with transforms feeding commitments through retained device buffers, then
extend quotient/opening/FRI operations while preserving the exact transcript and
cubic profile. Build a minimal local proof DAG alongside it; qualify per-device
concurrency and remote subtree placement afterward. A complete remote CPU pool
is not a prerequisite for this work.

The plan defines device matrix ownership, tiling, memory/event lifetimes, CPU
verification and matched end-to-end gates. Candidate research now includes
resident LDE/commitment and tiled opening-reduction prototypes, not only hashing.
The [opening runner/controller checkpoint](../evidence/block-v2-gpu-openings-runner-2026-10-02.json)
records explicit default-off selection, bounded accounting and independently
reproduced full-size preprocessing keys. Host LDE readback, CPU barycentric
evaluation and upstream FRI work remain: this is not a fully resident prover.
A [complete opening-enabled count-eight trial](../evidence/block-v2-gpu-openings-recursive-2026-10-02.json)
now passes local pruning and independent CPU-only root audit in **686.046 seconds**,
with a **1,683,948-byte** root. The final merge took **92.427 seconds**; that is
not complete post-seal latency. The [fresh same-build retained-hashing control](../evidence/block-v2-gpu-openings-matched-pilot-2026-10-02.json)
passes in **607.112 seconds**, with a **71.812-second** final merge and the same
root size. The opening-enabled resident backend was **13.002% slower** in this
one pair, so it is not promoted. Repeated matched qualification remains open.
Historical legacy speedups below do not change production defaults.

The [local in-memory DAG](../evidence/block-v2-local-dag-2026-10-02.json) now has
validated dependency readiness, candidate/attempt fencing and aggregate
reservations. It does not yet dispatch real GPU workers, enforce device quotas
or provide durable recovery. Its synthetic scheduling tests are not GPU or
full-block performance evidence.

## Separate block-v2 hashing path

The cubic-extension block-v2 candidate uses a different, explicitly bounded
prove-side MMCS adapter. It shares the bit-exact Poseidon2 kernels, **not** the
legacy GPU PCS, DFT or thread-local allocation model described below. CPU remains
the default; compiling `gpu` alone does not select this candidate path.

Five full four-transaction/two-level trials passed in **23.396 minutes median,
24.488 minutes worst**, with roots below 2 MiB and CPU-only verification repeated
after all inner artifacts and shared wallet-proof fixtures were deleted. Sampled
process VRAM peaked at 1,222 MiB; this is not a hard physical VRAM quota. See the
[implementation, resource limits and reproduction instructions](bounded-execution-engine-2026-10-17.md#candidate-only-bounded-gpu-hashing)
and [dated evidence](bounded-execution-engine-2026-10-17.md#gpu-hashing-experiment-2026-09-30).
The older speedup numbers below are **not block-v2 measurements**. Those historical candidate
hashing runs retained CPU polynomial arithmetic. The newer research prototypes
above preserve strict CPU verification, with no production activation or
parameter reduction.

### Latest candidate measurement — 2026-10-01

Five matched retention-off/on pairs with serial transfers held fixed reduced
median four-transaction recursive proving time from **19.627 to 17.642 minutes**
(**10.114%**). The final-merge median changed from 170.902 to 167.426 seconds,
but its worst observed time increased from 187.451 to **201.993 seconds**.
Both variants exceeded three minutes for the final merge alone in two trials.
All ten roots plus the retained pilot passed fresh unchanged CPU verification
after shared wallet-proof pruning, with no inner proofs loaded.

Retention cut downloads from **39,728,434,880 to 7,297,536 bytes** per trial,
while uploads remained **328,028,118,272 bytes**. Managed GPU peak increased
from 1,006,633,672 to 7,449,083,816 bytes; sampled prover VRAM increased from
1,222 to 7,366 MiB. Allocation accounting and sampling are not a physical quota.
Keep retention experimental/opt-in; prefer it for bounded research when admission
succeeds. CPU defaults, strict CPU verification and security parameters remain
unchanged. Transfer overlap remains experimental; it was not enabled in this
retention comparison. Neither experiment qualifies full-block performance.

See the [completed measurement and decision](../evidence/block-v2-retention-matched-2026-10-01.json).
The polynomial/data-movement work now follows the primary pipeline sequence above;
grouped constructions retain their separate registration and security gates.
The earlier measurements above and legacy results below retain their original scope.

### Proposed multiple-GPU and remote-worker support

The [distributed proving roadmap](../distributed-proving.md) defines complete
public-proof jobs as the first distribution boundary. The current candidate
engine still has one mutex-protected engine and a per-user exclusive process
lease; a device selector does not provide concurrent multiple-GPU scheduling.
The proposed service uses per-device ownership, aggregate host admission and
independently verified results. Removing locks is not an implementation of it.
Intel/AMD backends also need correctness/performance qualification and a
replacement for the current NVIDIA-specific monitoring path. No distributed
or multiple-GPU speedup is claimed by the measurements above.

## Legacy GPU backend

`lattica-prover-p3` can offload the heavy proving steps — the low-degree extension (LDE), the Merkle
tree build, and the hiding PCS's quotient-randomization pipeline — to a GPU via OpenCL, for a
**measured ~4.6× speedup over an AVX2-optimized CPU** on the production (hiding) config, with the GPU
proof **verifying under the existing production verifier unchanged**. (The CPU baseline uses p3's
packed-Goldilocks SIMD — see *CPU SIMD* below.) It is
**opt-in and prove-only**: the default CPU proving path, the byte-exact wire format, and the C-ABI
verifier are untouched. All three GPU paths — `GpuDft` (LDE), `GpuHidingMerkleMmcs` (Merkle), and
`GpuHidingPcs` (quotient randomization) — are byte-compatible with the production `HidingFriPcs` +
`MerkleTreeHidingMmcs` stack, so a GPU-produced proof deserializes and verifies exactly like a CPU one
(accepted by `verify_bytes` / the C-ABI / the node).

## Enabling it

```bash
cargo build   --release --features gpu      # pulls the optional `ocl` dep + the GPU kernels
cargo test    --release --features gpu -- --ignored gpu_   # the GPU tests (need an OpenCL runtime + GPU)
```

Without `--features gpu`, nothing changes — `ocl` isn't even in the dependency tree.

**Runtime requirement:** an OpenCL 1.2+ runtime and a GPU (validated on an NVIDIA RTX 5080 via the
NVIDIA CUDA OpenCL platform; portable to AMD/Intel).

## What it does

`crate::gpu::GpuDft` implements p3's `TwoAdicSubgroupDft<Goldilocks>` with an OpenCL radix-2 DIT NTT.
p3 composes the whole coset-LDE from `dft_batch`, so dropping `GpuDft` into the PCS's `Dft` slot moves
the LDE onto the GPU. `crate::config::gpu::proof_to_bytes` proves with it:

```rust
#[cfg(feature = "gpu")]
let proof_bytes = lattica_prover_p3::config::gpu::proof_to_bytes(&JoinSplitAir, trace, &pis);
// verify with the STANDARD verifier — unchanged:
assert!(joinsplit_air::verify_bytes(&proof_bytes, &pis));
```

## Why it's safe (consensus)

- **The DFT is not in the wire or the verifier.** The `Dft` type never appears in `verify` or in the
  serialized `Proof`, so swapping `Radix2DitParallel → GpuDft` cannot change the wire.
- **The GPU MMCS is byte-compatible, not a new wire type.** `GpuHidingMerkleMmcs`'s `Commitment`
  (`MerkleCap<Val,[Val;4]>`) and `Proof` (`(salts, siblings)`) are the *identical* types as
  `MerkleTreeHidingMmcs`, and its GPU tree reproduces p3's tree bit-for-bit — so `Proof<GpuConfig>`
  serializes exactly like `Proof<MyConfig>` and the CPU verifier reconstructs the same caps/paths. GPU
  proofs are therefore accepted by the existing verifier and the Zig node unchanged.
- **Bit-exact kernels.** Every GPU primitive is validated bit-for-bit against p3: Goldilocks field, the
  NTT/coset-LDE (`GpuDft` matches `Radix2DitParallel` up to the real 2¹⁶ LDE), Poseidon2-8, the Merkle
  cap + sibling paths (`gpu_merkle_cap_matches_p3`, `gpu_hiding_mmcs_matches_p3`), F_p², the quotient
  selectors, and the FRI fold. The kernels reproduce p3's exact roots (`two_adic_generator`) and
  reduction; the serde encoding is canonical, so intermediate representation is irrelevant.
- **The correctness gate:**
  - *non-hiding* (deterministic) → a GPU proof is **byte-identical** to the CPU proof;
  - *production (hiding)* → salts are a fresh CSPRNG per proof, so full proofs differ CPU-vs-CPU too;
    the criterion is **"the standard verifier accepts it"** — the LDE-only path
    (`gpu_{joinsplit,htlc}_proof_verifies`) and the full LDE+Merkle path
    (`gpu_{joinsplit,htlc}_proof_verifies_hiding`).

## Status & performance

Three heavy proving steps run on the GPU: the **LDE** (`GpuDft`), the **Merkle tree build**
(`GpuHidingMerkleMmcs`), and the hiding PCS's **quotient-randomization pipeline** (`GpuHidingPcs`). All
are byte-compatible with the production **hiding** config, so GPU proofs verify under the standard
verifier.

### The 4.6× on the production (hiding) config (`gpu_hiding_benchmark`, join-split, best of 5)

Production `HidingFriPcs` + `is_zk` + salts + `CAP_HEIGHT = 6`, GPU vs CPU, **both verified under the
production `verify_bytes`**:

| config | LDE | Merkle | quotient LDEs | join-split prove |
|---|---|---|---|---:|
| CPU (AVX2 + LTO, production) | `Radix2DitParallel` | `MerkleTreeHidingMmcs` | CPU | **~785 ms** |
| GPU | `GpuDft` | `GpuHidingMerkleMmcs` | `GpuHidingPcs` | **~172 ms** (**~4.6×**) |

The killer test `gpu_{joinsplit,htlc}_proof_verifies_hiding` proves a circuit with the GPU hiding config
and asserts the **standard production verifier accepts it** — the whole FRI query/open/verify path over
the salted GPU tree round-trips. Of the ~172 ms: ~39 ms GPU NTT (51 calls), ~52 ms GPU Merkle
(7 commits), the rest CPU (FRI fold, challenger, opens, glue).

The 2.1× → 4.6× step came from three findings (2026-07-03):

1. **The NTT was launch- and transfer-bound, not butterfly-bound.** The per-stage kernel did `log h + 1`
   full global-memory round-trips; the `ntt_tile` kernel now runs ~8–12 stages per launch in a 32 KiB
   local-memory tile (rows `hi<<(s0+lt) | t<<s0 | lo` × up to 16 columns), with the stage-`s` twiddle
   split as `w_s^lo · w_k^(t mod 2^(k-1))` off p3's generator squaring chain — no twiddle tables. The
   bit-reversal is fused into the first group's load, the `1/h`/coset-shift/canonicalize tails into the
   last group's store, and the last group can emit rows **bit-reversed (p3's storage order) directly**,
   deleting the CPU `reverse_matrix_index_bits` pass per LDE. Stage generators are cached per
   `(log_h, inverse)`.
2. **Transfers ran at pageable speed (~3–6 GB/s) on a PCIe5 ×16 link that does 38–54 GB/s pinned.**
   `GpuCtx` now keeps pooled device scratch buffers and a persistently-mapped pinned
   (`CL_MEM_ALLOC_HOST_PTR`) staging window; every upload/download memcpys through it with the host-side
   copy parallelized (a fresh `Vec`'s cold-page single-threaded memcpy costs more than the DMA). Merkle
   commits marshal leaf rows **directly into the window** (`upload_rows`) instead of materializing the
   combined leaf matrix host-side — the 16-chunk quotient commit moves ~170 MB/proof through that path.
3. **p3's hiding quotient randomization was doing 16 full-size mostly-zero DFTs + ~48 host permutation
   passes per proof.** `HidingFriPcs::get_quotient_ldes` randomizes each quotient chunk with a coset-LDE
   plus a **full-size `dft_batch` whose input is ~94% zero rows**, materializes both natural-order on the
   host, adds them on the CPU, and re-bit-reverses. `get_quotient_ldes` is a `Pcs` *trait* method, so
   `gpu_pcs::GpuHidingPcs` wraps the production stack, delegates everything else (associated types are
   the inner's — the wire is untouched), and overrides just that one: same randomization math (draws,
   `get_zp_cis`, last-chunk adjustment), but per chunk the coset-LDE, the vanishing-poly NTT (only the
   `2h`-row nonzero coefficient prefix is uploaded; the GPU zero-pads), the elementwise add
   (`add_canon`), and the bit-reversed store run device-side with ONE download. **Gold gate**
   `gpu_quotient_ldes_match_p3`: with the same seed, the returned chunk LDEs are byte-identical to p3's.

(An isolated non-hiding micro-benchmark, `gpu_merkle_benchmark`, measures the LDE+Merkle offloads on a
small workload; the production number above is the one that matters.)

### How the Merkle offload works

`crate::gpu::GpuHidingMerkleMmcs` is a custom `p3_commit::Mmcs` byte-compatible with
`MerkleTreeHidingMmcs<…, 2, 4, 4>`: `commit` appends 4 salt columns per matrix (the exact p3 draw) and
runs the whole salted tree on the GPU (Poseidon2 `leaf_hash` → pairwise `compress_layer`, extracting the
`cap_height = 6` `MerkleCap`), while `open_batch`/`verify_batch` stay on the CPU using the **same**
exported Poseidon2 constants. Its `Commitment` (`MerkleCap<Val,[Val;4]>`) and `Proof`
(`(salts, siblings)`) are the *identical* types p3 uses, so a `Proof<GpuConfig>` serializes byte-for-byte
like `Proof<MyConfig>`. Validated at three levels: the GPU cap matches CPU `MerkleTreeMmcs` byte-for-byte
(`gpu_merkle_cap_matches_p3`); seeding both MMCS the same reproduces p3's salts and cap exactly and the
CPU verifier accepts the GPU opening (`gpu_hiding_mmcs_matches_p3`); and the full GPU-hiding proof
verifies under production `verify_bytes`. A custom MMCS was necessary because p3's `MerkleTree` internals
are `pub(crate)` and can't be reused. (`GpuMerkleMmcs`, the non-hiding `cap_height 0` variant, remains for
the isolated benchmark.)

### Quotient offload (done, but net-neutral)

The quotient evaluation is not behind a trait seam (it is inline in p3's `prove`), so it is offloaded by
`crate::quotient_gpu::prove_gpu` — a faithful fork of `prove` (preprocessed = None) that reuses every p3
public function and swaps only `quotient_values` for a GPU evaluator. The evaluator (`gpu_quotient_values`
+ the `quotient` kernel) flattens each AIR's `get_symbolic_constraints` DAG (~800–1300 nodes, `Arc`-CSE)
into an instruction stream and interprets it one-row-per-thread, folding the constraints with the F_p²
alpha powers × `inv_vanishing`. It is correct and **verifies under the production verifier** (all three
heavy steps now on GPU; `gpu_{joinsplit,htlc}_proof_verifies_hiding` + `gpu_quotient_verifies`).

**But it is net-neutral.** The kernel is fast (~10 ms/proof), yet marshalling the trace to `u64` buffers
on the CPU (~50 ms) offsets it — the quotient *constraint evaluation*'s cost is *data movement*, not
arithmetic. The fork + interpreters are kept as validated infrastructure, not wired into the default
path: a real win here needs the trace kept **on-GPU across LDE→quotient**. (Distinct from this, the
quotient *randomization/commit* pipeline — which profiling showed was the actual dominant cost — DID
move to the GPU via `GpuHidingPcs`; see above.)

### CPU SIMD (AVX2)

Rust's default `x86-64` target is SSE2-only, so p3-goldilocks's `target_feature`-gated AVX2 packed-field
module compiled out and all CPU field arithmetic ran scalar. `.cargo/config.toml` now pins
`target-cpu=x86-64-v3` (AVX2 + BMI2 + FMA; portable to all Haswell+/Zen+ CPUs, scoped to `x86_64` so
aarch64 NEON builds are unaffected). Measured **~10% faster CPU proving** (~940 → ~845 ms) — bit-identical
(packed field arithmetic equals scalar; fingerprints + verifier unchanged). The gain is modest because
p3 has **no hand-vectorized Poseidon2** (the speedup is from packed field ops only, capped by Poseidon2's
round dependencies and the NTT's memory-bound nature); a server with AVX-512 would additionally use p3's
8-lane `x86_64_avx512` path. **Runtime requirement:** x86_64 binaries now need a v3 CPU (2013+).

### GPU kernel tuning (done + learned)

- **NTT shared-memory tiling** (done, see above): the definitive fix for the per-stage global
  round-trips; superseded the earlier coalescing-only `ntt_stage` kernel.
- **Pinned staging** (done, see above): measure transfer paths before kernels — the "slow NTT" was
  mostly the driver staging pageable memory (probe: `gpu-smoke/xfer` in the session scratchpad).
- **Twiddle precompute in global memory** (tried, *reverted*): replacing the per-butterfly `gl_pow`
  with a master-table lookup made the NTT *slower*. `gl_pow` (pure compute) hides behind memory
  latency; a table adds global reads. The tiled kernel keeps computing twiddles.
- Parallelizing the host-side `u64` conversion is size-thresholded (`to_u64s`, ≥ 4 MiB): per-matrix
  `rayon` overhead loses on the many small quotient-chunk / FRI-layer matrices.

### What's next

- The Merkle **leaf-hashing** (~52 ms, the dominant GPU cost now) is *compute*-bound (~40 Poseidon2
  perms per wide quotient leaf) and near-optimal per-kernel; the remaining waste is re-uploading LDEs
  the GPU just produced — on-GPU LDE persistence across LDE→Merkle (device-resident matrix handles in
  the PCS) is the structural fix.
- The residual ~80 ms CPU tail is the FRI commit phase (ext-field folds + challenger) and the opens —
  p3's FRI prover is not behind a trait seam, so offloading it means forking `commit_phase` (the
  validated S4 fold kernel exists).
- A `_prove_gpu` C-ABI entry (or runtime GPU/CPU switch) + Zig-node wiring, once the node wants it.

### Owned multi-AIR GPU batches (2026-10-09)

The owned-input prover can now commit multiple AIRs and their quotient
partitions in one GPU batch. Machine setup generates and commits all public
preprocessing traces on the GPU, with combined witness/randomness admission
and unchanged CPU verification. Equal padded AIR heights are required; the
aggregate quotient admission bound is 256 matrices.

Qualification covers three 64-row AIRs, 48 quotient matrices, both instance
orders and full/compact storage. Sixteen batch proofs match CPU bytes and verify
after GPU shutdown; eight use GPU randomness/transcripts with complete
registered-proof arithmetic receipts. Separate component tests cover 50
quotient partitions. These are correctness fixtures, not throughput measurements
or proof of the maximum supported capacity.

See [implementation §9.56](dag-gpu-implementation-2026-10-17.md#956-owned-multi-air-gpu-batches-2026-10-09)
and [evidence](../evidence/gpu-multi-air-2026-10-09.json). Mixed-height trees, native
public worker delivery and full-size recursive/throughput qualification remain.

### Shared public worker admission (2026-10-09)

Linux grouped and typed GPU probes now share the library's
`block_v2::execution::gpu_admission::Admission`. It checks the existing
assignment against the current process's cgroup, CPU, GPU environment and
scratch filesystem before starting Rayon. Typed workload/FRI/workspace
checks use the same bounded assignment snapshot. Invalid CPU quota and range
encodings reject, and private wallet assignments remain separate.

This provides a reusable startup check for native public workers; it does
not initialize a GPU, approve a registry or add a native public proof API.
Worker/fleet memory must be capped and swap disabled by the enclosing
runtime. See [implementation §9.57](dag-gpu-implementation-2026-10-17.md#957-shared-public-gpu-worker-admission-2026-10-09)
and [evidence](../evidence/gpu-worker-admission-2026-10-09.json).

### Native public GPU startup (2026-10-09)

`lattica_gpu_public_worker_initialize_from_env` and Zig
`prover_runtime.PublicGpuWorker` now provide a separate startup route for an
assigned public worker. Build a release library with `block-v2`, `gpu` and
`stream`; configure `gpu-required`, the complete owned GPU switches and the
existing public worker assignment before startup. The runtime must enforce
the worker/fleet memory, zero-swap and CPU limits. An isolated fleet may use
`lattica-v2-multi-*.slice`, with exact assignment-to-parent matching.

Startup installs no wallet callbacks or verifier and approves no registry.
Use a fresh process for each public worker; an initialized Rayon pool cannot
be silently reused after shutdown. Existing drain/shutdown APIs apply.

Two complete 2,048-row empty proofs through this native startup pass unchanged
CPU verification after shutdown and have complete 16-stage OpenCL receipts.
Independent C/Zig lifecycle checks and wallet regressions also pass. These
fixtures do not qualify a full recursive registry, full-size proving or
throughput. The native service integration is qualified below.

See [implementation §9.58](dag-gpu-implementation-2026-10-17.md#958-native-public-gpu-worker-startup-2026-10-09)
and [evidence](../evidence/gpu-native-public-startup-2026-10-09.json).

### Native public GPU service (2026-10-09)

`lattica_gpu_public_worker_serve(socket_fd, bootstrap, bootstrap_len, completed_out)`
and Zig `prover_runtime.servePublicGpuWorker` perform startup, the existing typed
public-worker protocol and shutdown in one blocking call. Use a fresh process
without calling initialization first. The API duplicates the connected Unix
stream; the caller retains its descriptor. Success requires clean STOP and GPU
teardown. Exit the worker afterward so the supervisor can release reservations.

The host supplies an independently trusted, bounded
`execution::native_worker::Bootstrap` containing the registry/profile, chain,
executable fingerprint, launch directory and public policy context. Both sides
bind the complete resource assignment into the initial session identity. The
service shares the CLI's resource/cache interpretation, launch-token checks and
CPU verification contract. It grants no registry, wallet or verifier authority;
remote authentication remains a separate requirement.

A C worker completed two 2,048-row Empty jobs through `ProcessWorker`, including
an idle context update and preprocessing reuse. Both proofs pass independent CPU
verification and have complete 16-stage OpenCL receipts. Four rejected C sessions
retired the GPU while retaining journal reservations. Nineteen Rust tests, one
linked Zig test and compatibility checks pass. The archived fixture requires the
matching `block-v2-wide-lanes,gpu,stream` release profile.

The fixture contains only the Empty key and does not establish full-size proving
or transactions/hour. See [implementation §9.59](dag-gpu-implementation-2026-10-17.md#959-native-public-gpu-worker-service-2026-10-09)
and [evidence](../evidence/gpu-native-public-service-2026-10-09.json).

### Full-size admission limits (2026-10-09)

All twelve modes of the archived 262,144-row paired registry now have checked
witness/compiler geometry and matching Rust/Python resource bounds. A full
JoinSplit pair has an additive managed GPU bound of 11.82 GiB before context
headroom; retained salts and sampling account for about 5.84 GiB. The merge host
bound is 3.23 GiB, above the current 3 GiB worker cap. These are static bounds,
not measured proof peaks.

No full-size GPU proof was launched because the complete assignment did not fit
current resources. Salt replay is implemented in the checkpoint below.
Reduced source/compiler staging and sufficient complete-assignment headroom
are still needed before the added full-size pair-proof test against
the unchanged archived registry. See [implementation §9.60](dag-gpu-implementation-2026-10-17.md#960-full-size-recursive-geometry-and-admission-2026-10-09)
and [evidence](../evidence/gpu-full-size-admission-2026-10-09.json).

### Private GPU salt replay (2026-10-10)

Private commitment salts now retain bounded, session-owned replay records
and materialize one matrix at a time for commitment hashing and queries.
The exact random stream, cleanup and proof format are preserved. Public
preprocessing and FRI salts still remain resident. The initial sampling
pass and later replay add computation; no throughput improvement is claimed.

After memory and correctness checks, the Rust/Python full-size randomness
reservation falls from 5.84 GiB to 1.34 GiB. The JoinSplit pair's complete
managed bound is now 7.32 GiB, or 12.32 GiB with the current context reserve
and guard. The observed 11.69 GiB free remains insufficient for that
assignment, and merge source/compiler staging still exceeds the host cap.

Twenty-one Rust tests and 49 Python tests pass. Two complete 2,048-row Empty
proofs verify on CPU after shutdown with all 16 arithmetic stages on OpenCL;
component checks also cover quadratic/cubic PCS proofs and secret cleanup.
These qualify salt replay, not full-size proving or transactions/hour. See
[implementation §9.61](dag-gpu-implementation-2026-10-17.md#961-private-gpu-salt-replay-2026-10-10)
and [evidence](../evidence/gpu-salt-replay-2026-10-10.json).

### Full-size paired GPU proof and FRI salt replay (2026-10-10)

A 262,144-row, two-transaction JoinSplit pair now proves on the desktop
RTX 5080 against all twelve real archived registry keys. All 16 arithmetic
stages report OpenCL; CPU verification succeeds after GPU shutdown and
rejects an altered statement. The cold run takes 88.25 seconds, including
70.94 seconds of preprocessing and 16.03 seconds of registered proving.
Managed GPU memory peaks at 8.49 GiB under a 9 GiB cap; host memory is
reported as 1.5G with zero swap. This is one proof, not a sustained throughput
measurement.

FRI commitments now retain exact salt replay recipes after consuming their
original samples, saving another 512 MiB in the full-size randomness
reservation. Witness admission shares the compiler's actual metadata
layout. Nonempty statement summaries now perform and report real GPU
metadata validation, and device preprocessing uses its host staging checks
instead of the host LDE payload guard.

The earlier additive GPU totals are component sums: complete commitment/LDE
phases require additional temporary buffers. The observed peak exceeds
those sums. The bounded proof passes its enforced allocation limits, while
a full scheduler lifetime profile remains necessary. Full-size merge,
finalizer, other paired modes, AMD/Metal and sustained pool throughput are
still unqualified. See [implementation §9.62](dag-gpu-implementation-2026-10-17.md#962-fri-salt-replay-and-a-verified-full-size-paired-gpu-proof-2026-10-10)
and [evidence](../evidence/gpu-fri-replay-2026-10-10.json).

### Full-size recursive completion (2026-10-10)

The two-transaction pair now feeds a verified full-size merge and finalizer
under the same twelve-key registry. The merge uses a canonical Empty right
child and produces a level-2 node; the finalizer produces its depth-6 root.
All 16 arithmetic stages report OpenCL. Serialized proofs verify on CPU
after GPU shutdown and reject altered statements.

Cold wall times are 18.03 seconds for Empty, 124.73 seconds for merge and
71.54 seconds for finalization. Managed GPU peaks are 8.67, 8.70 and
8.95 GiB respectively, within the 9 GiB cap; all runs use less than the
3 GiB host cap and zero swap. The LDE planner uses spare assigned memory
for wider transform tiles, so these peaks depend on the chosen cap.

These are single cold runs with no cache hits. Two-nonempty-child merges,
other transaction kinds, larger blocks, complete scheduler phase profiles
and sustained throughput remain open. See [implementation §9.63](dag-gpu-implementation-2026-10-17.md#963-full-size-empty-merge-and-finalizer-proofs-2026-10-10)
and [evidence](../evidence/gpu-full-size-recursion-2026-10-10.json).

### Lower GPU cap and audited LDE plans (2026-10-10)

Full-size merge and finalizer proofs now pass under a **7 GiB managed GPU
cap**. Their measured peaks are 6.89 and 6.95 GiB respectively, with all
16 proving arithmetic stages on OpenCL and CPU verification after shutdown.
The same finalizer at 9 GiB peaks at 8.95 GiB: lowering its cap halves the
first three LDE column tiles and saves exactly 2 GiB of measured peak memory.
The single cold runs take 71.52 and 71.55 seconds; these do not establish
a sustained throughput change.

Versioned per-operation plan telemetry and a separate arithmetic audit now
explain the fixed and adaptive allocations. Complete scheduler admission
still needs a host lifetime model: current reservations combine compiler
storage with several legacy host-transfer buffers that the fully owned
GPU path does not materialize. See [implementation §9.64](dag-gpu-implementation-2026-10-17.md#964-audited-lde-plans-and-7-gib-recursive-proving-2026-10-10)
and [evidence](../evidence/gpu-lde-phase-plans-2026-10-10.json).

### GPU witness host memory and transfer accounting (2026-10-10)

The witness cache now releases uploaded host instructions and keeps only a
compact launch schedule. For the full-size merge, 621.7 MB of instruction
metadata becomes a 63 KB host schedule; the instruction allocation remains
on GPU. Host admission also stops charging lookup samples, FRI salts and
opening-vector transfers absent from the selected device path, while
preserving claims, query results, legacy transfers and GPU reservations.
Cache accounting explicitly includes an incoming source program alongside
retained entries.

The merge's combined extra host reservation falls from 4.32 GB to 2.92 GB.
Verified full-size merge and finalizer runs report host peaks of 1.8G and
1G, down from 2.1G and 1.2G. Both retain the 3 GiB host and 7 GiB managed
GPU caps, all 16 arithmetic stages on OpenCL, and independent CPU
verification after shutdown. GPU peaks and LDE plans are unchanged.

Fifty-two Python tests, ten native component cases, both full-size proofs
and CPU compatibility checks pass. Complete scheduler phase profiles,
full-size cache reuse, broader proof cases and sustained pool throughput
remain open. See [implementation §9.65](dag-gpu-implementation-2026-10-17.md#965-gpu-witness-host-retention-and-transfer-accounting-2026-10-10)
and [evidence](../evidence/gpu-witness-host-retention-2026-10-10.json).

### Full-size cached native GPU worker (2026-10-10)

Two distinct full-size finalizer jobs now pass through the independently
linked C worker with all 16 proving arithmetic stages on OpenCL. The cold
job takes 73.08 seconds and the warm job 18.27 seconds, with one preprocessing
setup and one cache hit. Both use the twelve actual archived registry keys
at height 262,144. The coordinator independently CPU-verifies both results,
rejects changed statements and re-verifies saved proofs after worker exit.

The worker stays within a 3 GiB host limit and a 7 GiB managed-GPU cap; its
measured host peak is 1.2132 GiB, with zero swap or OOM events. The C service
does not export an actual aggregate managed-GPU peak. Nine operative LDE
plans are audited, and the worker exits with all reservations released.

This closes the full-size cache-reuse qualification from §9.65 for these
finalizers. It does not measure sustained transactions per hour: both jobs
derive the same terminal statement through different verified dependencies.
Complete scheduler profiles, broader proof cases and sustained multi-GPU
throughput remain open. See [implementation §9.66](dag-gpu-implementation-2026-10-17.md#966-full-size-cached-native-worker-2026-10-10)
and [evidence](../evidence/gpu-full-size-cached-worker-2026-10-10.json).

### Native worker GPU memory accounting (2026-10-10)

The native C worker now reports each job's managed allocation peak, including
buffers freed before the job ends, and the bytes retained across idle periods.
Its full-size cold and warm finalizers peak at 6.9544 GiB under the 7 GiB cap.
They retain 1.8840 GiB between jobs, including a 536,870,880-byte preprocessing
tree; shutdown releases all managed allocations. These are allocator counters,
separate from driver/context VRAM and host memory.

Both full-size outputs remain independently CPU-verified with all 16 proving
arithmetic stages on OpenCL. Eleven native cases, the small C-worker
regression, malformed/disconnected service cleanup and CPU compatibility
pass. The measured times are 71.80 seconds cold and 17.36 seconds warm;
they are not sustained transactions-per-hour measurements. Scheduler profiles
must account for the idle cache and adaptive tile allocation before this
evidence can support broader admission. See [implementation §9.67](dag-gpu-implementation-2026-10-17.md#967-native-worker-gpu-memory-accounting-2026-10-10)
and [evidence](../evidence/gpu-worker-memory-windows-2026-10-10.json).

### Worker GPU allocation limits (2026-10-10)

The shared engine now enforces the public worker's assigned maximum buffer
size, including adaptive transform tiles. Previously the assignment specified
1 GiB while the engine used the device's roughly 3.89 GiB hardware limit;
the measured jobs happened to stay within 1 GiB. Startup now rejects invalid
limits, and an initialized engine cannot silently widen its allowance.

A real 8 MiB cap test checks tile sizing, rejection before allocation,
allocation at the exact limit and immutable engine configuration. Full-size
C-worker finalizers still pass with all 16 proving arithmetic stages on
OpenCL, independent CPU verification and the assigned 1 GiB buffer cap
enforced. Twenty-four native cases and CPU compatibility pass; shutdown
releases all managed memory and GPU leases. Complete scheduler lifetime
profiles and sustained throughput qualification remain open.

See [implementation §9.68](dag-gpu-implementation-2026-10-17.md#968-worker-gpu-allocation-limits-2026-10-10)
and [evidence](../evidence/gpu-worker-allocation-limit-2026-10-10.json).

### Raw trace and commitment geometry (2026-10-10)

GPU witness profiles now declare raw main and flattened lookup widths
separately from committed widths. Each nonempty private commitment adds four
hiding columns. This corrects a 16 MiB main-capture underestimate in the
full-size profile and increases its three-prefix reservation by 48 MiB.
Ambiguous profiles reject; conservative witness bounds and legacy profiles
remain supported.

All 169 related Python cases pass. The unchanged native C worker also proves
two full-size finalizers with the corrected assignment, all 16 arithmetic
stages on OpenCL, independent CPU verification and clean shutdown under the
same resource limits. Complete scheduler lifetime profiles and sustained
throughput qualification remain open.

See [implementation §9.69](dag-gpu-implementation-2026-10-17.md#969-raw-trace-and-committed-column-geometry-2026-10-10)
and [evidence](../evidence/gpu-worker-trace-geometry-2026-10-10.json).

### Program packing host lifetimes (2026-10-10)

Program packing now releases construction tables before allocating AIR rows
and requests final vector sizes. The full-size fixture retains 62.6 MiB less
program source; its measured worker host peak falls by 15.5%, from
1,310,605,312 to 1,107,386,368 bytes, under unchanged budgets.

Twenty native cases pass across both lane configurations, GPU witness/CPU
reference comparisons and two full-size C-worker finalizers. The original
registry, proof formats and all 16 GPU arithmetic stages are preserved.
Independent CPU verification and shutdown cleanup pass. Program construction
before packing and the complete scheduler lifetime profile still need bounds;
the measurements do not establish sustained transaction throughput.

See [implementation §9.70](dag-gpu-implementation-2026-10-17.md#970-program-packing-host-lifetimes-2026-10-10)
and [evidence](../evidence/gpu-program-packing-2026-10-10.json).

### Bounded program construction (2026-10-10)

Assigned GPU builders now enforce one allowance across interning tables,
operation buffers, hints and packing scratch. Buffer growth counts old and
replacement storage together. Oversized construction rejects before witness
setup; the native rejection test confirms GPU teardown while scheduler
reservations stay held after failure.

Thirty-five native cases pass across both lane configurations, resource
boundaries, GPU/CPU witness comparisons and C-worker tests. Both full-size
finalizers report a 508,066,244-byte construction/packing peak under the
existing 571,816,240-byte allowance. All 16 arithmetic stages per proof run on
OpenCL, with the original registry and independent CPU verification.
Cold/warm jobs take 71.8611 / 17.4176 seconds. Worker host peak is
1,099,972,608 bytes; GPU memory returns to zero after shutdown.

The construction counter covers requested builder storage. Complete caller
and compiler host lifetimes, scheduler profiles, broader proof cases and
sustained transaction throughput remain unfinished. These two proofs
finalize the same terminal statement; their timings are not transactions per
hour. Resource limits, proof formats and activation remain unchanged.

See [implementation §9.71](dag-gpu-implementation-2026-10-17.md#971-bounded-program-construction-2026-10-10)
and [evidence](../evidence/gpu-program-construction-2026-10-10.json).

### Compiler lifetime accounting (2026-10-10)

Program resource bounds now preserve construction requirements across cloning
and padding while keeping program identity unchanged. Merkle compilation
streams leaf fields, reuses an admitted cap buffer and checks hint storage
before evaluating its entry callback. Scratch shares the existing allowance
with table and operation growth.

Forty-eight native cases pass across both lane configurations, expanded
Merkle reference comparisons, allocation boundaries, GPU witness conformance
and C-worker proofs. Both full-size finalizers complete all 16 arithmetic
stages on OpenCL and pass independent CPU verification under the original
registry. Construction requires 508,066,252 bytes under the unchanged
571,816,240-byte allowance. Cold/warm jobs take 71.9828 / 18.4093 seconds;
worker host peak is 1,101,590,528 bytes, and GPU memory is zero after shutdown.

Manifest allocation lifetimes, remaining caller/compiler storage and complete
scheduler profiles remain open. Sustained transaction throughput, broader
proof cases, multiple GPUs and AMD/Metal still require qualification. Limits,
proof formats and activation are unchanged.

See [implementation §9.72](dag-gpu-implementation-2026-10-17.md#972-compiler-lifetime-accounting-2026-10-10)
and [evidence](../evidence/gpu-compiler-lifetimes-2026-10-10.json).


## Bounded manifest streaming (2026-10-10)

[Implementation checkpoint §9.73](dag-gpu-implementation-2026-10-17.md#973-bounded-manifest-streaming-2026-10-10)
removes complete program/identity vectors and row-operation clones from GPU
registration. Borrowed canonical fields feed the existing device public
hash through **32 KiB** host batches. The producer is validated before
allocation and checked again for canonical fields and exact length while
uploading. Failed producers return no digest, preserve reporting of completed
GPU work and release device buffers.

The symbolic fingerprint uses admitted fixed-capacity tables, fields and
roots within a **32 MiB** sub-budget of the existing compiler reserve. Its
DAG encoding and the original twelve-key registry remain unchanged.
**63 native cases** pass across standard/wide lanes and GPU public-hash
conformance, including allocation limits, malformed replay rejection and
two full-size proofs independently verified on CPU. Both proofs report all
**16 arithmetic stages on OpenCL**.

The measured identity contains **13,263,913 fields**, uploaded in **3,239
batches** without a full identity vector; the fingerprint retains a
**5,249,768-byte** buffer. Cold/warm jobs take **72.4365 / 17.4309 seconds**.
These qualification jobs finalize the same terminal statement through
distinct verified dependencies and do not measure transactions per hour.
Worker host peak is **1,101,000,704 bytes**, with zero swap/OOM; managed
GPU storage returns to zero at shutdown. Resource limits remain unchanged,
and cleanup confirms no workers or held GPU leases.

[Evidence](../evidence/gpu-manifest-lifetimes-2026-10-10.json) pins **375 source
files** and **117 root artifacts**. Complete host/compiler lifetime coverage,
scheduler phases, broader workloads, sustained pool throughput, multiple
GPUs and AMD/Metal qualification remain open. Proof formats, parameters and
activation are unchanged.


## Expression memo lifetimes (2026-10-10)

[Checkpoint §9.74](dag-gpu-implementation-2026-10-17.md#974-expression-memo-lifetimes-2026-10-10)
charges base and extension lowering tables to the same construction budget
as program operations and interning. Growth includes simultaneous old/new
arrays; quota failure latches rejection. Scope exit releases table storage
on success, error and unwind while preserving the construction peak.

**60 relevant native cases** pass, including four new memo cases per lane
configuration and two full-size proofs with all **16 arithmetic stages on
OpenCL**, independently verified on CPU. Each compilation releases
**640 KiB + 80 KiB** before packing. The required construction allowance
remains **508,066,252 bytes**, within the unchanged assignment. A frozen
reference lowerer verifies identical operations, wire IDs, canonical
manifests and evaluated values.

Cold/warm jobs take **73.9639 / 17.3971 seconds**; these qualification jobs
do not measure transactions per hour. Worker host peak is **1,101,426,688
bytes**, with zero swap/OOM, and managed GPU allocations return to zero at
shutdown. The registry, proof format, resource caps and activation remain
unchanged. [Evidence](../evidence/gpu-expression-lifetimes-2026-10-10.json) pins
**377 source files** and **108 root artifacts**. Complete compiler/caller
lifetimes, scheduler phases and sustained multi-GPU qualification remain
open.

## Proof input lifetimes (2026-10-10)

[Checkpoint §9.75](dag-gpu-implementation-2026-10-17.md#975-proof-input-lifetimes-2026-10-10)
checks whole base, extension and cap input groups before allocating wire
arrays or invoking callbacks. Retained values grow fallibly within the
declared input count; construction rejection stops further storage growth.
The old/new value-buffer overlap is covered by input staging, separately
from program construction.

**70 relevant native cases** pass, including five new input cases per lane
configuration and two full-size proofs with all **16 arithmetic stages on
OpenCL**, independently verified on CPU. Both compilations retain exactly
**211,083 values / 1,688,664 capacity bytes**; their largest growth overlap
is **2,737,240 bytes**. A frozen reference checks input order, wire IDs,
program identity, canonical manifests and evaluated values.

Cold/warm jobs take **72.8500 / 17.7219 seconds**; these qualification jobs
do not measure transactions per hour. Worker host peak is **1,102,733,312
bytes**, with zero swap/OOM and zero managed GPU storage after shutdown.
The registry, proof format, resource caps and activation remain unchanged.
[Evidence](../evidence/gpu-input-lifetimes-2026-10-10.json) pins **379 source
files** and **114 root artifacts**. Temporary wire vectors, other compiler
and caller lifetimes, scheduler phases and sustained multi-GPU qualification
remain open.

## PCS compiler scratch (2026-10-10)

[Checkpoint §9.76](dag-gpu-implementation-2026-10-17.md#976-pcs-compiler-scratch-2026-10-10)
removes PCS opening/cap copies and nested descriptor allocations. Fixed
arrays hold random additions, query reductions, cap/beta/row headers,
salts, siblings and FRI rows. The supported descriptor geometry is checked
before use. Cap and query-row payloads retain §9.75's bounded collectors.

**82 relevant native cases** pass, including frozen-compiler comparisons,
oversized-shape rejection, real uni/wallet/batch proof tampering tests and
two full-size proofs with all **16 arithmetic stages on OpenCL**. Independent
CPU verification confirms compatibility with the original registry.

Cold/warm jobs take **71.7660 / 17.4054 seconds**; these qualification jobs
do not measure transactions per hour. Worker host peak is **1,099,874,304
bytes**, with zero swap/OOM and zero managed GPU storage after shutdown.
The registry, proof format, resource caps and activation remain unchanged.
[Evidence](../evidence/gpu-pcs-scratch-2026-10-10.json) pins **381 source files**
and **135 root artifacts**, including the run stopped by a test-count mismatch. Evaluation
and other compiler/caller lifetimes, scheduler phases and sustained
multi-GPU qualification remain open.

## Evaluation lifetimes (2026-10-10)

[Checkpoint §9.77](dag-gpu-implementation-2026-10-17.md#977-evaluation-lifetimes-2026-10-10)
replaces repeated zero/challenge and copied public-value vectors with
borrowed views. Periodic/permutation results and ordered constraints use
scoped arrays admitted against the shared construction quota before
allocation. Storage and reservations release on success, error and unwind;
the peak remains recorded. Quotient vanishing values use fixed scratch.

**94 relevant native cases** pass, including new quota/release/indexing
checks, frozen reference comparisons, real proof tampering tests and two
full-size proofs with all **16 arithmetic stages on OpenCL**. Both preserve
the original registry and pass independent CPU verification. Each
compilation releases **13,664 + 816 bytes** after memo release and before
packing. The required construction allowance remains **508,066,252 bytes**.

Cold/warm jobs take **73.0221 / 17.4033 seconds**, without establishing
transactions per hour. Worker host peak is **1,103,405,056 bytes**, with
zero swap/OOM and zero managed GPU storage after shutdown. Resource caps,
proof format, parameters, registry and activation remain unchanged.
[Evidence](../evidence/gpu-evaluation-lifetimes-2026-10-10.json) pins **384
source files** and **123 root artifacts**. Remaining symbolic/caller lifetimes, scheduler phases and
sustained multi-GPU qualification remain open.

## Symbolic recording (2026-10-10)

[Checkpoint §9.78](dag-gpu-implementation-2026-10-17.md#978-symbolic-recording-2026-10-10)
admits recorder-owned expression nodes, layout arrays, constraint and
interaction vectors, and bus names before allocation against a **64 MiB
cumulative quota**. Discarded intermediates and old/new growth arrays retain
their admission. Shared row windows avoid repeated matrix copies. Depth
**512** is enforced before child-node allocation, and a latched failure
rejects the recording before normalization or GPU arithmetic.

**122 relevant native cases** pass, including CPU/GPU symbolic fingerprint
and lookup comparisons, recording failure paths and two full-size proofs
with all **16 arithmetic stages on OpenCL**. Both preserve the original
registry and pass independent CPU verification and altered-statement
rejection. Across **17 recording scopes**, maximum cumulative admission is
**946,879 bytes** and maximum raw depth is **189**. The program construction
requirement remains **508,066,252 bytes**.

Cold/warm jobs take **72.8812 / 17.3984 seconds**, without establishing
transactions per hour. Worker host peak is **1,099,341,824 bytes**, with
zero swap/OOM and zero managed GPU storage after shutdown. Resource caps,
proof format, parameters, registry and activation remain unchanged.
[Evidence](../evidence/gpu-symbolic-recording-2026-10-10.json) pins **386 source
files** and **132 root artifacts**. Normalization and caller-owned storage,
complete scheduler lifetime phases, broader workloads and sustained
multi-GPU/pool qualification remain open.

## Symbolic normalization (2026-10-10)

[Checkpoint §9.79](dag-gpu-implementation-2026-10-17.md#979-symbolic-normalization-2026-10-10)
admits normalization traversal, pointer-identity maps, expression nodes,
constraint/index arrays and lookup output storage before allocation against
a shared **64 MiB cumulative quota**. Growth accounts for old and new arrays;
discarded storage retains its admission. Exact output capacities, latched
failure and cleanup on error/unwind preserve bounded construction without
changing expression sharing or normalization order.

**144 relevant native cases** pass, including **24 symbolic cases per lane
configuration**, GPU fingerprint/rejection checks and two full-size proofs
with all **16 arithmetic stages on OpenCL**. Both proofs preserve the
original registry and pass independent CPU verification and tampering
checks. All arithmetic-stage operation counts match the previous checkpoint.
Across **17 normalization scopes**, maximum cumulative admission is
**4,154,832 bytes**. The program construction requirement remains
**508,066,252 bytes**.

Cold/warm jobs take **73.6916 / 18.6554 seconds**, without establishing
transactions per hour or a performance improvement. Worker host peak is
**1,106,968,576 bytes**, with zero swap/OOM and zero managed GPU storage
after shutdown. Resource caps, proof format, parameters, registry and
activation remain unchanged.
[Evidence](../evidence/gpu-symbolic-normalization-2026-10-10.json) pins **389
source files** and **128 root artifacts**. Lookup replay/packing, retained
output and caller lifetimes, complete scheduler phases and sustained
multi-GPU/pool qualification remain open.

## Bounded lookup packing (2026-10-10)

[Checkpoint §9.80](dag-gpu-implementation-2026-10-17.md#980-bounded-lookup-packing-2026-10-10)
replaces lookup AIR replay with packing admitted against a **64 MiB
cumulative quota**. A separate **64 MiB bound** covers retained vector
capacities, bus names and unique child Arcs, including inherited storage.
The pinned `p3-lookup 0.6.1` adds only a checked ownership-taking
constructor; its original packing and other algorithms remain unchanged.
The dependency archive and original package files are audited against
their registry hashes.

**160 relevant native cases** pass, including **32 symbolic cases per
lane configuration**, GPU rejection checks and two full-size proofs with
all **16 arithmetic stages on OpenCL**. Lookup order, degrees and weights,
the original registry and every arithmetic-stage operation count are
preserved. Independent CPU verification and tampering checks pass. Each
of **five packing scopes** admits **200,477 bytes** and retains **121,176
bytes** while packing **115 interactions into 16 lookups**.

Cold/warm jobs take **72.3207 / 18.2350 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,107,279,872 bytes**, with zero swap/OOM and zero managed GPU storage
after shutdown. Resource caps, proof format, parameters and activation
remain unchanged. [Evidence](../evidence/gpu-lookup-packing-2026-10-10.json)
pins **411 source files** and **131 root artifacts**. Enclosing caller and
retained-output lifetimes, complete scheduler phases, broader workloads
and sustained multi-GPU/pool qualification remain open.


## Lookup ownership transfer (2026-10-10)

[Checkpoint §9.81](dag-gpu-implementation-2026-10-17.md#981-lookup-ownership-transfer-2026-10-10)
transfers admitted packed lookups into cached proving metadata without
cloning nested vectors, bus names or child Arc references. Lookup layout
and constraint graphs now have separate ownership; registered setup drops
the constraints after canonical fingerprinting. Batch test setup releases
unused graphs before preparing the next AIR.

**166 relevant native cases** pass, including **three new ownership cases
per lane configuration** and two full-size proofs with all **16 arithmetic
stages on OpenCL**. The original registry and every arithmetic-stage
operation count are preserved, with independent CPU verification and
altered-statement rejection. Lookup-packing bounds and resource assignments
remain unchanged.

Cold/warm jobs take **71.7207 / 17.4025 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,108,316,160 bytes**, with zero swap/OOM and zero managed GPU storage
after shutdown. [Evidence](../evidence/gpu-lookup-ownership-2026-10-10.json)
pins **412 source files** and **144 root artifacts**, including the preserved
initial failed run and its source archive. Enclosing memory
lifetimes, complete scheduler phases, broader workloads and sustained
multi-GPU/pool qualification remain open. Proof formats, parameters,
registry identity and activation remain unchanged.

## Compiler constant storage (2026-10-10)

[Checkpoint §9.82](dag-gpu-implementation-2026-10-17.md#982-compiler-constant-storage-2026-10-10)
admits selector inverses/differences, periodic coefficients and quotient
constants before allocation or backend work. Both backends fill borrowed
output slices; quotient constants use one flat array, and returned selector
wires use fixed stack storage. Device readback uses fixed **16 KiB periodic /
8,448-byte constant** staging, with compile-time checks for coexistence with
the retained **8 KiB folding cache** inside the existing host allowance.

**178 relevant native cases** pass, including independent constant
identities, CPU/GPU compiler parity, periodic-verifier tamper checks and
quota rejection before arithmetic. Malformed output lengths preserve
sentinels and trigger no GPU allocation or transfers. Both full-size proofs
complete all **16 arithmetic stages on OpenCL**, preserve the registry and
every stage's operation count, pass independent CPU verification and reject
altered statements. GPU kernels and resource assignments are unchanged.

Cold/warm jobs take **72.1344 / 17.4311 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,110,142,976 bytes**, with zero swap/OOM and zero managed GPU storage
after shutdown. [Evidence](../evidence/gpu-compiler-constant-storage-2026-10-10.json)
pins **412 source files** and **146 root artifacts**, including the
preserved initial build failure and its source archive. Decoded inputs,
caller-owned sources, enclosing lifetimes, complete scheduler phases and
broader workload/pool qualification remain open. Proof formats, parameters,
registry identity and activation remain unchanged.

## Decoded input storage (2026-10-10)

[Checkpoint §9.83](dag-gpu-implementation-2026-10-17.md#983-decoded-input-storage-2026-10-10)
gives each typed worker request a cumulative **64 MiB** decoded-storage
quota, capped by assigned worker RAM. Every nested vector and canonical
encoding buffer is admitted before fallible allocation. Native proof
containers are constructed directly; extension coefficients use stack
storage. Wallet admission returns the proof it verified, eliminating a
second decode. The owner retains the allowance through input use and drops
proof values before releasing it, including error and unwind paths.

**234 relevant native cases** pass: **126** research/GPU and **108** CPU.
They cover wire parity, exact/undersized quotas, combined-input accounting,
malformed data, partial cleanup, unwind and real wallet admission. Both
full-size proofs preserve the registry and operation counts, complete all
**16 arithmetic stages on OpenCL**, pass independent CPU verification and
reject altered statements. Each request admits **3,778,172 bytes** of
decoded and canonical storage with no rejection.

Cold/warm jobs take **71.3881 / 17.5612 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,101,393,920 bytes**, with zero swap/OOM and zero managed GPU storage
after shutdown. [Evidence](../evidence/gpu-decoded-input-storage-2026-10-10.json)
pins **415 source files** and **185 root artifacts**, preserving corrected
compile, fixture and test-selection attempts. Raw packets, verifier
scratch, caller-owned sources, enclosing lifetimes, complete scheduler
phases and broader workload/pool qualification remain open. Proof formats,
parameters, registry identity and activation remain unchanged.

## Periodic source storage (2026-10-10)

[Checkpoint §9.84](dag-gpu-implementation-2026-10-17.md#984-periodic-source-storage-2026-10-10)
generates registered compiler periodic columns one at a time into borrowed
storage admitted by the construction budget. Source and coefficient
buffers share the allowance and release their storage before quota reuse.
JoinSplit, issuance and HTLC no longer construct entire source tables or
temporary row-index vectors in this compiler path. All **33 / 33 / 43
columns** match the unchanged AIR tables. The largest source column is
**32 KiB**, replacing table field payloads of **723,712 / 1,051,392 bytes**.

**244 relevant native cases** pass: **131** research/GPU and **113** CPU.
Coverage includes every source field, malformed buffers, admission before
callbacks/arithmetic, combined source/coefficient limits, cleanup on error
and unwind, CPU program parity and real uni-proof rejection. The GPU
periodic uni-verifier preserves the CPU program and witness. Both
full-size finalizers preserve the registry and operation counts, complete
all **16 arithmetic stages on OpenCL**, pass independent CPU verification
and reject altered statements. Those finalizers have no periodic columns;
GPU periodic consumption is exercised by the dedicated conformance case.

Cold/warm finalizers take **71.8015 / 17.4314 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,099,153,408 bytes**, with zero swap/OOM and zero managed GPU storage
after shutdown. [Evidence](../evidence/gpu-periodic-source-storage-2026-10-10.json)
pins **420 source files** and **166 root artifacts**, including preserved
compile and reporting corrections. Complete scheduler lifetimes, raw
packet/verifier storage, symbolic/AIR callback and cache overlaps, and
broader workload/pool qualification remain open. Proof formats, parameters,
registry identity and activation remain unchanged.

## Request storage (2026-10-10)

[Checkpoint §9.85](dag-gpu-implementation-2026-10-17.md#985-request-storage-2026-10-10)
borrows decoded proof bytes directly from the retained request packet.
Metadata and incoming frame vectors have bounded, fallible allocations;
request encoding reserves its exact size in advance. Launch and artifact
hashing stream the original framing with storage independent of payload
length, preserving digest identities against the unchanged slice reference.
Fixed permutation setup can still allocate round constants.

**357 qualification cases** pass: **186** research/GPU and **171** CPU.
They cover maximum-size packets, frames and digests, borrowed pointers,
capacity bounds, malformed data, launch fencing and worker lifecycle
behavior. Two CPU-only lifecycle cases were initially selected in the GPU
build; that failed run is preserved, and both pass in the CPU suite.
Both full-size finalizers borrow **1,683,948 proof bytes** with **200 bytes**
of metadata vector capacity. They preserve the archived registry and stage
operation counts, complete all **16 arithmetic stages on OpenCL**, pass
independent CPU verification and reject altered statements.

Cold/warm jobs take **68.0315 / 18.7212 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,099,542,528 bytes**, with zero swap/OOM and zero managed GPU storage
after shutdown. [Evidence](../evidence/gpu-request-storage-2026-10-10.json)
pins **421 source files** and **194 root artifacts**. The protocol storage
bounds still need enclosing scheduler lifetime reservations; result
serialization, coordinator copies, verifier scratch, callback/cache
overlaps, allocator/driver overhead and broader workload/pool qualification
remain open. Existing resource caps, proof parameters and activation remain
unchanged.

## Result storage (2026-10-10)

[Checkpoint §9.86](dag-gpu-implementation-2026-10-17.md#986-result-storage-2026-10-10)
serializes typed node proofs directly into a bounded result-packet buffer.
The coordinator compacts the received frame in place, retaining its original
capacity through proof use. Exact request binding avoids re-encoding the
request, and multipart dispatch avoids a temporary combined frame. Borrowed
compatibility APIs retain bounded copies; compaction still moves bytes.

**365 qualification cases** pass: **190** research/GPU and **175** CPU.
Coverage includes wire parity, buffer identity and capacity, maximum sizes,
truncation, original-request binding, multipart frames and worker lifecycle
behavior. Both full-size finalizers use one **2,097,333-byte** serialization
buffer. Their **1,684,129-byte** received frames become proof buffers without
a second result-buffer allocation. Both preserve the archived registry and
stage counts, complete all **16 arithmetic stages on OpenCL**, pass independent
CPU verification and reject altered statements.

Cold/warm jobs take **68.1174 / 17.7549 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,098,244,096 bytes**, with zero swap/OOM and zero managed GPU storage after
shutdown. [Evidence](../evidence/gpu-result-storage-2026-10-10.json) pins **421
source files** and **173 root artifacts**. Complete scheduler phases, native
proof/verifier storage, metadata and callback/cache lifetimes, allocator/driver
overhead and broader workload/pool qualification remain open. Existing caps,
proof parameters and activation remain unchanged.


## Verifier metadata (2026-10-10)

[Checkpoint §9.87](dag-gpu-implementation-2026-10-17.md#987-verifier-metadata-2026-10-10)
bounds trusted-cap CPU verification's symbolic recording, normalization and
lookup packing, then transfers lookup metadata by ownership. Each preparation
quota and the retained-output ceiling is **64 MiB**; the default graph
workspace ceiling is **192 MiB**. Descriptor vectors allocate exact capacities
fallibly and admit at most **256 instances**. These graph limits do not bound
all verifier scratch, callbacks or physical RSS.

**388 qualification cases** pass: **201** research/GPU and **187** CPU.
They include metadata parity with the upstream reference, quota rejection and
recovery, invalid caps, callback unwind cleanup, ownership, native proof
acceptance and tampering rejection. The first attempt is preserved after a
test-only invalid-cap fixture correction; run-02 passes. Both full-size
finalizers preserve the archived registry and operation counts, complete all
**16 proving arithmetic stages on OpenCL**, pass independent CPU verification
and reject altered statements. All **13 verifier metadata records** retain
**121,176 bytes** for **16 packed lookups** from **115 interactions**.

Cold/warm jobs take **70.3001 / 16.6938 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,098,969,088 bytes**, with zero swap/OOM and zero managed GPU storage after
shutdown. [Evidence](../evidence/gpu-verifier-metadata-2026-10-10.json) pins
**424 source files** and **215 root artifacts**. Complete scheduler phases,
native proof/verifier scratch, callback/cache lifetimes, allocator/driver
overhead and broader workload/pool qualification remain open. Existing caps,
proof parameters and activation are unchanged.


## FRI proof storage (2026-10-10)

[Checkpoint §9.88](dag-gpu-implementation-2026-10-17.md#988-fri-proof-storage-2026-10-10)
adds FRI query outputs and assembly arrays to the existing initial PCS query
allowance before folding, commitments or transcript changes. Exact fallible
vector capacities and sibling-buffer reuse preserve the bound for quadratic
and cubic proofs, including nonbinary folds and nonconstant final polynomials.

Each full-size finalizer admits **8,742,160 bytes** for this region: **7,069,696**
for initial queries, **1,276,928** for 19 FRI query batches and **395,536** for
caps, coefficients and assembly arrays. The existing **1 GiB** proof-query
ceiling remains unchanged. Engine/transcript storage, input ownership,
allocator overhead and whole-job scheduler phases remain separate concerns.

**397 qualification cases** pass: **210** research/GPU and **187** CPU.
GPU conformance covers 12 quadratic/cubic scenarios, rejects insufficient
storage without advancing device work or streams, matches upstream proof
bytes and verifies after shutdown. Both full-size finalizers preserve the
archived registry and operation counts, complete all **16 proving arithmetic
stages on OpenCL**, pass independent CPU verification and reject altered
statements.

Cold/warm jobs take **68.0657 / 16.6945 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,097,879,552 bytes**, with zero swap/OOM and zero managed GPU storage after
shutdown. [Evidence](../evidence/gpu-fri-proof-storage-2026-10-10.json) pins
**426 source files** and **176 root artifacts**. Complete worker admission,
native proof/verifier lifetimes and broader workload/pool qualification remain
open. Existing caps, proof parameters and activation are unchanged.


## Native opening handoff (2026-10-10)

[Checkpoint §9.89](dag-gpu-implementation-2026-10-17.md#989-native-opening-handoff-2026-10-10)
replaces opened-value cloning in batch and single-AIR GPU provers with
ownership transfers into the existing native proof types. Incoming capacities
and new metadata/descriptors are admitted together against the existing
host-output allowance. Each full-size finalizer accounts for **14,369 bytes**
for this handoff: **13,752** in existing capacities and **617** in new
descriptors. Admission occurs after opening, so complete proof and worker
lifetimes still require enclosing reservations.

**409 qualification cases** pass: **222** research/GPU and **187** CPU.
New unit checks establish ownership, capacity accounting, frozen encoding,
reference parity and rejection cleanup. Eighteen quadratic/cubic wallet and
multi-AIR proofs verify after GPU shutdown; seeded batches match CPU proof
bytes with and without device randomness/transcripts. Both full-size
finalizers preserve the archived registry and operation counts, complete all
**16 proving arithmetic stages on OpenCL**, pass independent CPU verification
and reject altered statements.

Cold/warm jobs take **68.7546 / 16.6694 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,099,255,808 bytes**, with zero swap/OOM and zero managed GPU storage after
shutdown. [Evidence](../evidence/gpu-opening-handoff-2026-10-10.json) pins
**428 source files** and **287 root artifacts**, preserving the corrected
compile and controller attempts. Complete scheduler phases, native
proof/verifier lifetimes and broader workload/pool qualification remain open.
Existing caps, proof parameters and activation are unchanged.


## Machine AIR degree contract (2026-10-10)

[Checkpoint §9.90](dag-gpu-implementation-2026-10-17.md#990-machine-air-degree-contract-2026-10-10)
removes repeated symbolic constraint graph construction from upstream release
verification. `MachineAir` declares its exact base degree of **8**, while
Plonky3 still includes lookup constraint degree separately. Numerical
verification and upstream verifier source remain unchanged. Debug assertions
retain their independent symbolic calculation.

Both **8-lane and 23-lane** layouts match the original no-hint inference over
all **65 supported public-value counts** and preserve packed/unpacked quotient
geometry. Native seeded proof bytes and tamper decisions match. Instrumented
release verification makes **one AIR callback instead of two**, eliminating
the symbolic inference callback while retaining numerical evaluation.

**420 qualification cases** pass: **225** research/GPU, **191** standard CPU
and **4** additional CPU-only wide-layout cases. Both full-size finalizers
preserve the archived registry and operation counts, complete all **16 proving
arithmetic stages on OpenCL**, pass independent CPU verification and reject
altered statements. Cold/warm jobs take **70.3267 / 17.3992 seconds**, without
establishing throughput or a performance gain. Worker host peak is
**1,098,616,832 bytes**, with zero swap/OOM and zero managed GPU storage after
shutdown.

[Evidence](../evidence/gpu-machine-degree-2026-10-10.json) pins **429 repository
source files**, **196 artifacts** and the unchanged upstream degree/verifier
sources against their package checksums. Full numerical verifier scratch,
native proof lifetimes, complete worker admission and sustained pool
qualification remain unfinished. Existing budgets, proof parameters and
activation are unchanged.

## Registered verifier shape admission (2026-10-10)

[Checkpoint §9.91](dag-gpu-implementation-2026-10-17.md#991-registered-verifier-shape-admission-2026-10-10)
adds an allocation-free shape check at both registered native verification entry
points, before configuration construction, public-value copies or upstream
proof-data cloning. Trusted machine and profile dimensions bound openings,
hiding values, commitments, queries, salts, authentication paths and FRI layers.

It also rejects unexpected next rows. A valid proof modified to contain an empty
optional preprocessing-next row otherwise reaches an upstream matrix-width
assertion after PCS verification. Both CPU layouts reproduce that assertion and
confirm the new error return. The upstream numerical verifier remains unchanged;
valid proofs and public-input/opening tamper decisions retain conformance.

All **440 qualification cases** pass: **231** research/GPU, **198** standard CPU
and **11** additional CPU-only wide-layout cases. Both full-size finalizers retain
registry identities and operation counts, complete all **16 proving arithmetic
stages on OpenCL**, pass independent CPU verification and reject altered
statements. Cold/warm jobs take **68.0736 / 16.6593 seconds**, without establishing
throughput or a performance gain. Worker host peak is **1,097,555,968 bytes**, with
zero swap/OOM and zero managed GPU storage after shutdown.

[Evidence](../evidence/gpu-verifier-envelope-2026-10-10.json) pins **431 source files**,
**377 artifacts** and **five source archives**, preserving the failed compile
fixture, failed CPU assumption and earlier passing GPU run. Original upstream
packages match their lockfile checksums. Complete numerical scratch accounting,
native proof lifetimes, worker admission and sustained pool qualification remain
unfinished. Existing budgets, proof parameters and activation are unchanged.

## Verifier inversion dispatch (2026-10-10)

[Checkpoint §9.92](dag-gpu-implementation-2026-10-17.md#992-verifier-inversion-dispatch-2026-10-10)
keeps `p3-field` inversions through **1,024 elements** on the calling thread,
avoiding lazy Rayon pool creation for binary FRI's two-element inversions. The
packed-prefix/scalar-tail arithmetic is unchanged, and larger inputs retain
parallel chunk scheduling. This pinned dependency patch applies to CPU builds
as well as GPU builds.

Three-field conformance covers **75 length/field combinations**, independent
elementwise inverses, proof-value encodings, capacities and zero-input failures.
Fresh child processes with thread creation disabled establish that the small
selected path needs no pool, while the original two-element path and selected
1,025-element path still require it. The archived-arithmetic oracle inlines an
unchanged private helper and skips a verified empty-tail no-op.

All **449 qualification cases** pass: **234** research/GPU, **201** standard CPU
and **14** additional CPU-only wide-layout cases. Default compilation, native
builds and C linking pass. Both full-size finalizers preserve registry identities
and operation counts, complete all **16 proving arithmetic stages on OpenCL**,
pass independent CPU verification after worker exit and reject altered
statements. Cold/warm jobs take **68.1004 / 16.6640 seconds**, without establishing
throughput or a performance gain. Worker host peak is **1,099,964,416 bytes**,
with zero swap/OOM and zero managed GPU storage after shutdown.

[Evidence](../evidence/gpu-verifier-inversions-2026-10-10.json) pins **468 source
files**, **219 artifacts** and **four source archives**, preserving failed
compile snapshots and the corrected oracle audit. Complete native numerical
scratch and proof lifetimes, scheduler admission, broader workloads and
sustained pool qualification remain unfinished. Existing budgets, proof
parameters, encodings and activation are unchanged.

## Native numerical verifier scratch (2026-10-10)

[Checkpoint §9.93](dag-gpu-implementation-2026-10-17.md#993-native-numerical-verifier-scratch-2026-10-10)
adds a checked cumulative allocation-request bound for registered single-machine
numerical verification on **release x86_64**. It runs after proof-shape admission
and before configuration construction or numerical work. The model covers batch
and lookup vectors, transcript storage, opening clones and growth, Merkle
verification and binary FRI scratch. It includes the named global wire bus's
hash table, cold seed allocation and lookup height-check integers. The fixed
**64 MiB ceiling** is a component limit; complete worker reservation remains
unfinished.

Both layouts cover **24 geometry templates** each. Maximum source-derived sums
are **26,636,073 / 27,379,865 bytes** for standard/wide layouts. Eight fresh small
proofs support **48 allocation-observed verification attempts**, including
public-input, opening and late-query tampering. Every request sum fits its
source-derived bound and verification decisions agree. Measurements do not set
the limits, and large-height templates do not qualify proving at those heights.

All **460 qualification cases** pass: **237** research/GPU, **205** standard CPU
and **18** additional CPU-only wide-layout cases. Default and non-stream CPU
compilation, native builds and C linking pass. Both full-size finalizers preserve
registry identities and operation counts, complete all **16 proving arithmetic
stages on OpenCL**, pass independent CPU verification after worker exit and
reject altered statements. Cold/warm jobs take **68.1159 / 17.8769 seconds**,
without establishing throughput or a performance gain. Worker host peak is
**1,099,563,008 bytes**, with zero swap/OOM and zero managed GPU storage after
shutdown.

[Evidence](../evidence/gpu-verifier-scratch-2026-10-10.json) pins **471 source
files**, **257 artifacts**, **six worktree archives**, **419 upstream package
files** and **101 Rust container files**. It preserves failed attempts and the
corrected global-bus model. The research test build passed with two code-generation
units after a timeout; the static library retains one. All service caps remain
unchanged. Configuration, caller capacities, full proof/result lifetimes,
scheduler admission, broader workloads and sustained pool qualification remain
unfinished. Proof parameters, encodings and activation are unchanged.

### Native verifier call storage checkpoint (2026-10-10)

The registered native verifier now admits both proof backing capacities and
combined temporary allocation requests before configuration setup or numerical
verification. Proof buffers and temporary requests each have a **64 MiB**
component ceiling. The temporary sum combines §9.93's numerical model with
fresh configuration storage, an exact-capacity public copy and a **1,024-byte**
diagnostic allowance. It is not a complete worker-memory reservation.

Fresh verifier configuration reads OS entropy directly instead of initializing
a thread-local RNG. Source-derived construction bounds are **3,584 bytes** for
non-stream CPU, **3,728 bytes** for streaming CPU and **5,424 bytes** for the
streaming GPU build; twelve observations agree exactly. Diagnostics use a fixed
UTF-8 stack buffer and one bounded String allocation. An allocation-free proof
traversal includes all Vec spare capacities. A read-only accessor in pinned
`p3-symmetric` **0.6.1** exposes the hidden Merkle-cap backing capacity without
changing encodings, hashing or arithmetic.

All **55 qualification cases** pass across research/GPU, standard CPU, wide CPU
and non-stream CPU builds. Tests cover 34 spare-capacity mutations, empty
optional buffers, exact limits, diagnostics, trusted templates and 18 complete
verification allocation observations. Default/research compilation, the native
library and C linking pass. Both full-size finalizers retain registry identities
and operation counts, complete all **16 proving arithmetic stages on OpenCL**,
pass independent CPU verification after worker exit and reject altered
statements. Cold/warm runs take **68.1281 / 16.5835 seconds**; these measurements
do not establish throughput or a performance gain. Worker peak is
**1,454,411,776 bytes**, with zero swap/OOM and zero managed GPU storage after
shutdown. Resource caps remain unchanged, and no services or GPU leases remain.

[Evidence](../evidence/gpu-verifier-call-storage-2026-10-10.json) pins **489 final
source files**, **147 artifacts** and **12 source archives**. It preserves the
failed non-stream test build and records the subsequent test-only System
allocator observer separately from the completed GPU qualification. Every
production source and existing test body is identical across those revisions.
The source audit adds eight dependency packages and 12 Rust library files.

The check cannot retroactively reserve a caller's proof allocation or inspect
the owner capacity behind a borrowed public slice. Complete worker/coordinator
lifetimes, cached metadata, callbacks, stacks and allocator/driver/OS overhead
remain open. Ordinary pool admission still rejects the incomplete phase plan.
Broader workloads, sustained throughput, multiple GPUs and AMD/Metal
qualification remain unfinished. Proof parameters, encodings and activation
are unchanged.

### Independent verifier lifetime checkpoint (2026-10-10)

The native registered verifier now checks a **257 MiB** component storage plan
before building its independent trusted metadata. Construction and verification
have separate phase bounds covering shape/cap storage, symbolic workspace,
retained metadata, one admitted proof and verification scratch. Cap backing
capacity is limited to **64 KiB**. Recursive verification checks proof backing
capacity before metadata construction. These checks preserve independent CPU
verification and cannot reserve caller allocations retroactively.

Rust and Python worker reservations now include this verifier once per serial
worker. The qualified finalizer's witness host reservation is **1,863,197,984
bytes**, and its combined additional host reserve is **2,167,682,336 bytes**,
within the unchanged **3 GiB** worker cap. Complete worker RSS admission remains
unfinished.

All **92 native cases** and **55 Python resource tests** pass across research/GPU,
standard CPU, wide CPU and non-stream CPU configurations. Both full-size proofs
on the desktop RTX 5080 complete all **16 proving arithmetic stages on OpenCL**,
retain registry identities and operation counts, pass independent CPU
verification after worker exit, and reject altered statements. Cold/warm jobs
take **68.1116 / 16.7032 seconds**, with **1,102,585,856 bytes** observed host peak
and zero swap/OOM. GPU peaks, idle storage and all assigned caps are unchanged;
shutdown releases all managed GPU storage. Cleanup finds no services or leases.
These timings do not establish sustained throughput.

[Evidence](../evidence/gpu-verifier-lifetimes-2026-10-10.json) pins **491 source files**,
**255 artifacts** and **18 source archives**, preserving two failed fixture
attempts and the final successful qualification. The audit reverifies **947
inherited dependency files** and **113 Rust library files**. The goal remains
incomplete: caller/cache/result ownership, full worker/coordinator lifetimes,
stacks and allocator/driver/OS overhead still require enclosing admission.
Ordinary pool admission continues to reject the incomplete phase plan. Broader
workloads, sustained throughput, multiple GPUs and AMD/Metal qualification
remain open. Proof parameters, encodings and activation are unchanged.

### Retained program source checkpoint (2026-10-10)

Worker resource plans now separate cached program source from construction
workspace. The retained bound counts the Arc allocation and all owned vector
capacities, including nested and spare storage. Rust and Python charge this
storage per cache entry while preserving the full construction allowance in
the transient phase. Historical omitted/zero retained bounds keep their exact
conservative behavior. Workers reject an understated retained bound even when
the construction allowance is larger.

For the full-size fixture, the explicit retained-storage assignment reduces the
witness host reservation from **1,863,197,984** to **1,828,252,656 bytes**, a
**33.33 MiB** reservation reduction. The construction allowance and all physical
RAM/GPU caps stay unchanged. This is more accurate admission accounting, not a
measured throughput gain or a complete process RSS bound.

All **27 native cases** and **57 Python tests** pass. Resource planning is tested
in both supported GPU lane layouts; standard, wide, non-stream and default CPU
compilation also pass. Both historical and explicit retained assignments produce
two independently verified full-size proofs on the desktop RTX 5080, with all
**16 proving arithmetic stages on OpenCL**, unchanged registry identities and
operation counts, rejection of altered statements, zero swap/OOM and complete
GPU storage release at shutdown. Cleanup finds no services or leases.

[Evidence](../evidence/gpu-program-cache-lifetimes-2026-10-10.json) pins **492 source
files**, **202 artifacts** and **10 source archives**, including the corrected
Python schema-gate attempt. It reverifies the inherited dependency and Rust
container sources. Complete compiler/cache and worker/coordinator lifetime
admission remains unfinished, and ordinary pool admission still rejects the
incomplete phase plan. Broader workloads, sustained throughput, multiple GPUs
and AMD/Metal qualification remain open. Proof parameters, encodings, arithmetic
and activation are unchanged.

### Retained witness schedule checkpoint (2026-10-10)

GPU worker plans now reserve cached launch schedules separately from released
compiler workspace. Rust and Python preserve historical omitted/zero bounds
and the full construction allowance. The schedule bound comes from the
operation count, and its actual copy is admitted before allocation or device
upload. The copy is fallible, uses exact capacity, and retains no instruction
words or source wave spare capacity.

The full-size fixture has a **21,025,984-byte** schedule bound, compared with the
previous **56,775,136-byte** compiler cache allowance. An explicit **24 MiB**
schedule assignment reduces its witness host reservation from **1,828,252,656**
to **1,796,643,344 bytes**—another **30.15 MiB** of reservation—while preserving
all physical RAM/GPU caps. The actual retained schedule remains **63,152 bytes**;
observations validate the source model and do not set its limits. This is an
admission improvement, not a measured throughput gain.

All **46 native cases** and **59 Python tests** pass, along with standard, wide,
non-stream and default CPU compilation. Tests cover a chain that reaches the
per-operation wave bound, exact allocation limits, compiler overlap, GPU trace conformance and rejection
before upload followed by session reuse. Both assignments produce two full-size
proofs with all **16 proving arithmetic stages on OpenCL**, independent CPU
verification, unchanged registry identities and operation counts, rejection of
altered statements, zero swap/OOM and complete GPU storage release. Cleanup
finds no services or leases.

[Evidence](../evidence/gpu-schedule-lifetimes-2026-10-10.json) pins **494 source files**,
**228 artifacts** and **13 source archives**. Complete cached prover metadata,
registry/request/result and worker/coordinator lifetime admission remains
unfinished; ordinary pool admission still rejects the incomplete phase plan.
Broader workloads, sustained throughput, multiple GPUs and AMD/Metal
qualification remain open. Proof parameters, encodings, arithmetic and
activation are unchanged.

### Cached lookup lifetime checkpoint (2026-10-10)

GPU worker admission now reserves **64 MiB per cached AIR** for packed lookup
arrays, names and shared expression graphs. The symbolic packer already enforces
this retained-output ceiling. Rust and Python now charge it independently of the
single **192 MiB** construction workspace, so cached output remains covered while
another job is constructed. Full source/compiler peaks, retained source and
schedule allowances, and independent CPU verification reservations are preserved.

The full-size fixture's witness host reservation increases from
**1,796,643,344 to 1,863,752,208 bytes**; combined additional host reservation is
**2,168,236,560 bytes**. Physical host/GPU caps and managed GPU reservations are
unchanged. Actual lookup storage remains **121,176 bytes**. This additional
reservation closes a lifetime-accounting gap; no throughput improvement is
claimed. Existing bound fields still decode, while stale under-reserved worker
descriptors must be regenerated.

Final qualification passes **64 native cases**, **60 Python tests**, and standard,
wide, non-stream and default CPU compile checks. Tests exercise cache entries
**1/3/12**, construction/verifier overlap, exact admission boundaries, stale
assignment rejection, spare capacity/shared Arc counting, and allocation-free
ownership transfer. Two fresh full-size proofs run all **16 proving arithmetic
stages on OpenCL**, pass independent CPU verification, and reject two altered
statements. Registry identities and operation counts are unchanged. The worker
cgroup peaks at **1,082,118,144 bytes**, with zero swap/OOM and zero managed GPU
storage at shutdown. Cleanup finds no running services or held leases.

[Evidence](../evidence/gpu-cached-lookup-lifetimes-2026-10-10.json) pins **495 source
files**, **194 artifacts** and **16 source archives**, including preliminary
fixture corrections. Complete cached PCS/prover/container storage and
worker/coordinator phase composition remain unfinished. Ordinary pool admission
still rejects the incomplete phase plan. Broader workloads, performance
comparisons, **24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal
qualification remain open. Verification remains on CPU; proof parameters and
encodings are unchanged.

### Cached PCS metadata checkpoint (2026-10-10)

GPU worker plans now reserve cached PCS/common/provenance storage per program.
The optional `pcs_retained_host_bytes` bound uses **1 MiB** for device-salt
metadata. Omitted/zero conservatively also reserves **1,024 bytes per trace row**
for compatible host salt matrices. The worker checks actual salt ownership and
backing capacities before publishing cached data. Source, schedules and lookup
graphs retain their separate allowances; shared engine/context/driver storage
still needs worker-level composition.

The full-size fixture retains **5,624 bytes** of counted metadata under the
**1 MiB** ceiling. Its explicit device-salt witness reservation is
**1,864,800,784 bytes**, with **2,169,285,136 bytes** of combined additional host
reservation. Compared with the newly conservative omitted-field assignment,
this avoids an unnecessary **256 MiB** host-salt reservation per cache entry.
Compared with §9.98, it adds the missing **1 MiB** metadata allowance. Physical
host/GPU limits are unchanged; no measured RSS or throughput improvement is
claimed. Stale worker descriptors must be regenerated.

Final qualification passes **78 native cases**, **61 Python tests**, and standard,
wide, non-stream and default CPU compile checks. Both salt modes reject excess
cap backing and allow restoration without changing device allocations/uploads.
Four fresh full-size proofs run all **16 proving arithmetic stages on OpenCL**,
pass independent CPU verification, and reject four altered statements. Registry
identities and operation counts are unchanged. Both runs have zero swap/OOM and
zero managed GPU storage at shutdown. Cleanup finds no services or leases.

[Evidence](../evidence/gpu-cached-pcs-lifetimes-2026-10-10.json) pins **497 source
files**, **335 artifacts**, and **17 source archives**, preserving preliminary
fixture corrections. The audit checks **1,044 dependency files** and **113 Rust
library files**. Cache-container capacity, shared contexts, registry/request/result
ownership and complete worker/coordinator phase accounting remain open. Ordinary
pool admission still rejects the incomplete phase profile. Broader workloads,
performance comparisons, **24 hours AND 150 completed roots**, multiple GPUs and
AMD/Metal qualification remain unfinished. Verification stays on CPU; proof
parameters and encodings are unchanged.


### Fixed typed-session storage (2026-10-10)

Typed sessions now retain fixed inline slots for every registered key, so unused
cache capacity is included in admission and cache reconfiguration cannot leave a
larger vector allocation behind. A separate **1 MiB** allowance covers the session
and its registry backing; the qualified 12-key census is **35,128 bytes**.
Registry admission counts cap capacities against **64 KiB** before hashing.
The typed worker uses the session's registry instead of keeping a duplicate.
Process configuration and sessions share the checked subtraction of session and
idle-cache reservations from active prover RAM.

Rust and Python witness reservations each increase by **1 MiB**, independently
of the selected live-cache count. The full-size explicit device assignment now
reserves **1,865,849,360 witness-host bytes** and **2,170,333,712 combined additional
host bytes**. Physical limits remain 3 GiB worker RAM, 4 GiB aggregate host RAM,
7 GiB managed GPU memory and 1 GiB per GPU allocation. This is logical storage
accounting; no throughput or RSS improvement is claimed.

Final qualification passes **104 native cases**, **61 Python tests**, four CPU
compatibility builds and **four fresh full-size proofs**. Every proof records
all **16 proving arithmetic stages on OpenCL**, passes independent CPU
verification after worker exit and rejects an altered statement. Cold/warm times
are **69.0508 / 16.7195** and **68.2209 / 17.4218 seconds**. Worker peaks are
**1,097,883,648 / 1,099,763,712 bytes**; shutdown GPU storage is zero.

See [implementation §9.100](dag-gpu-implementation-2026-10-17.md#9100-fixed-typed-session-storage-and-registry-ownership-2026-10-10)
and [the pinned evidence](../evidence/gpu-session-storage-2026-10-10.json).
Shared engine/context storage, the bootstrap configuration's separate registry,
request/result ownership and complete worker/coordinator phase composition
remain unqualified. Ordinary pool admission still rejects incomplete phase
profiles. Broader workloads, paired performance comparisons, **24 hours AND 150
completed roots**, multiple GPUs and AMD/Metal qualification remain open.
Verification remains on CPU.

### Retained OpenCL engine storage (2026-10-10)

OpenCL worker admission now includes a **72 MiB retained-engine host
component**: 8 MiB for engine metadata and 64 MiB for mapped staging. The
census counts shared accounting/lease allocations, selector backing,
timing-event storage and staging/workspace containers. Capacity limits and
fallible timing reservation prevent those containers from growing beyond
their envelope; admission runs before engine publication and at drain.
Rust and Python reservations agree. Historical descriptors must regenerate
the added reservation.

The historical/device-PCS assignments reserve **2,209,782,288 /
1,941,346,832 witness-host bytes** and **2,514,266,640 / 2,245,831,184
combined additional host bytes**. Physical limits remain 3 GiB worker RSS,
4 GiB aggregate host memory, 7 GiB managed GPU memory and 1 GiB per GPU
allocation. Retained ownership is a logical storage census; initialization,
per-job and opaque driver storage remain separate phases.

Validation passes **111 native cases**, **61 Python tests**, four CPU
compatibility builds and **four fresh full-size proofs** on the desktop
RTX 5080. Every proof records all **16 proving arithmetic stages on OpenCL**,
passes CPU verification after worker exit and rejects an altered statement.
Cold/warm times are **67.7518 / 16.4767** and **68.1666 / 17.5337 seconds**;
worker memory peaks are **1,061,007,360 / 1,097,637,888 bytes**. Swap and
shutdown GPU storage are zero. These runs do not establish a throughput gain.

See [implementation §9.101](dag-gpu-implementation-2026-10-17.md#9101-retained-opencl-engine-storage-2026-10-10)
and [the pinned evidence](../evidence/gpu-engine-retained-storage-2026-10-10.json).
Bootstrap configuration/request/result ownership and complete
worker/coordinator phase composition remain open. Ordinary pool admission
still rejects incomplete profiles. Broader workloads, paired comparisons,
**24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal qualification
remain required. The retained census is OpenCL-specific; verification stays
on CPU.

### Process configuration ownership (2026-10-10)

The typed-process child now moves its registry into the typed session;
the coordinator retains only a **248-byte descriptor** after preparing its
process reservation. This removes the unused bootstrap/coordinator registry
copies. Configuration and session records use fixed **248-byte / 312-byte
arrays**, preserving the existing wire format. Context rebinding updates the
policy digest without cloning or rehashing the registry.

The **12 process lifecycle tests** and **six CPU/GPU compile configurations**
pass. Registry backing moves intact, v1 wire positions remain unchanged, and
context rebinding preserves the assignment and reservation suffix. Cleanup
finds no running services or held GPU leases. See
[implementation §9.102](dag-gpu-implementation-2026-10-17.md#9102-process-configuration-ownership-and-fixed-records-2026-10-10)
and [the pinned evidence](../evidence/gpu-process-config-ownership-2026-10-10.json).

This change has no new GPU runtime or performance measurement; the four
full-size proofs in §9.101 precede it. Request/result and caller-owned storage,
engine initialization/per-job owners and complete worker/coordinator phase
composition remain open. Resource reservations and proof arithmetic are
unchanged, and ordinary pool admission still rejects incomplete profiles.

### Worker protocol storage admission (2026-10-10)

Typed workers now preserve an **8 MiB protocol allowance** outside session
and prover RAM. Python admission includes it for witness and hybrid profiles.
The allowance covers overlapping bounded request/result buffers and protocol
metadata; policy contexts use 64 fixed slots with no retained heap storage.
Context encoding and proof formats remain unchanged.

Combined additional host reservations are **2,522,655,248 /
2,254,219,792 bytes** for the historical/device-PCS assignments, each 8 MiB
above §9.101. Physical worker and aggregate host limits stay at 3 GiB and
4 GiB. This logical ownership bound does not complete a worker lifetime plan.

**129 native cases**, **62 Python tests**, four CPU compatibility builds and
**four fresh full-size GPU proofs** pass. Each proof reports all **16 proving
arithmetic stages on OpenCL**, passes CPU verification after worker exit and
rejects an altered statement. Worker memory peaks remain below 1.10 GB with
zero swap; GPU shutdown storage is zero. Cold/warm times are **67.0832 /
16.3150** and **67.1540 / 16.3056 seconds**. No throughput improvement is claimed.

See [implementation §9.103](dag-gpu-implementation-2026-10-17.md#9103-worker-protocol-storage-and-admission-2026-10-10)
and [the pinned evidence](../evidence/gpu-worker-protocol-storage-2026-10-10.json).
Coordinator ownership, remaining engine/runtime storage and complete phase
composition remain open. Ordinary pool admission still rejects incomplete
profiles; broader workload, sustained-run and hardware qualification remains
required.


### Coordinator job storage admission (2026-10-10)

Active typed coordinator jobs now reserve at least **337 MiB**: 16 MiB for
assignment/transport/publication storage, 64 MiB for bounded canonical decoding
and 257 MiB for the independent CPU verifier. The decoded proof is conservatively
counted twice. Actual exported vector capacities and shared proof backing are
checked before request encoding. The maximum packet overlap is **15,860,000
bytes**, within its 16 MiB allowance.

The shared budget floor is independent of Linux IPC and `stream`. Python planning
reserves coordinator capacity before worker RAM; the shared runner rejects an
insufficient fixed cap. Existing reservations remain held through CPU verification,
which now uses bounded proof decoding. Full coordinator/process RSS admission is
still incomplete, and ordinary pool admission still rejects incomplete profiles.

**654 native cases**, **132 Python tests**, all four CPU compatibility builds and
**four fresh full-size GPU proofs** pass with the final source. Every proof reports
all **16 proving arithmetic stages on OpenCL**, passes CPU verification after
worker exit and rejects an altered statement. Worker peaks are **1.442 / 1.098 GB**
with zero swap and no sampled OOM events; managed GPU storage returns to zero at
shutdown. Cold/warm times are **67.2150 / 16.3170** and **67.8157 / 18.3652 seconds**;
no throughput gain is claimed from these qualification runs.

See [implementation §9.104](dag-gpu-implementation-2026-10-17.md#9104-coordinator-job-storage-admission-2026-10-10)
and [the pinned evidence](../evidence/gpu-coordinator-job-storage-2026-10-10.json).
Global coordinator storage, remaining worker phase composition, broader workloads,
paired performance comparisons, the sustained-run gate, multiple GPUs and AMD/Metal
qualification remain open.


### Bounded coordinator persistence buffers (2026-10-10)

Snapshot serialization now measures and validates against the configured journal
limit before allocating one exact-capacity payload buffer. Journal checksums stream
their existing input framing, and reopening a journal reuses its frame allocation.
Journal and artifact reads reject file growth without expanding their admitted
buffers. All four snapshot versions and journal bytes remain unchanged.

With the CLI's 1 MiB snapshot limit, simultaneous snapshot/frame backing is bounded
at **2,097,204 bytes**. This excludes graph/index metadata, retained artifacts and
other coordinator owners, which still need complete budget composition. Worker
assignments and the 337 MiB per-job floor remain unchanged; ordinary pool admission
still rejects incomplete profiles.

**663 native cases**, all four CPU compatibility builds and **four fresh full-size
GPU proofs** pass. Each proof reports all **16 proving arithmetic stages on
OpenCL**, passes CPU verification after worker exit and rejects an altered
statement. Worker peaks are **1.118 / 1.107 GB**, with zero swap and no sampled OOM
events; managed GPU memory returns to zero at shutdown. These results qualify
correctness and bounded backing, not a throughput gain.

See [implementation §9.105](dag-gpu-implementation-2026-10-17.md#9105-bounded-coordinator-persistence-buffers-2026-10-10)
and [the pinned evidence](../evidence/gpu-coordinator-journal-storage-2026-10-10.json).
Full coordinator/worker phase composition, broader workloads, paired performance
comparisons, sustained operation, multiple GPUs and AMD/Metal qualification remain
open.


### Bounded retained coordinator state (2026-10-10)

The DAG now uses exact-capacity wallet/attempt handle vectors, preventing excess
caller capacity from becoming retained coordinator storage. A capacity census
and conservative Rust 1.96 BTree bound cover retained graph ownership. At CLI
limits, this component is **272,943,224 bytes**, including up to 256 MiB of proof
payloads. Artifact inventory owns exact-length names and its **1,531,656-byte**
refresh/prune bound includes both inventories and pruning's temporary owners.

**684 native cases**, four CPU compatibility configurations, **36 independent
allocator cases** and **four fresh full-size GPU proofs** pass. Every proof
reports all 16 proving arithmetic stages on OpenCL, passes CPU verification after
worker exit and rejects an altered statement. Worker peaks are 1.442 / 1.098 GB,
with zero swap and no sampled OOM events; managed GPU backing reaches zero at
shutdown. These measurements establish correctness and component bounds, not a
throughput gain.

See [implementation §9.106](dag-gpu-implementation-2026-10-17.md#9106-bounded-retained-coordinator-state-2026-10-10)
and [the pinned evidence](../evidence/gpu-coordinator-retained-storage-2026-10-10.json).
The component APIs do not yet compose a complete coordinator phase budget.
Transition/recovery owners, paths, fleet queues, external caller lifetimes and
allocator/OS costs remain separate; worker/coordinator caps and the 337 MiB
per-job floor are unchanged. Ordinary admission remains closed for incomplete
profiles. Full worker phase composition, broader workload and performance gates,
sustained operation, multiple GPUs and AMD/Metal qualification remain open.


### Snapshot and recovery metadata composition (2026-10-10)

Persistence reuses one exact-capacity job index across counting and writing;
attempts and launch bindings stream directly from their maps. Recovery uses
bounded descriptor/handle vectors, avoids bulk-collection scratch and releases
validation indexes before proof decoding and CPU verification.

`JournalLimits::graph_storage` combines retained graph backing, journal payload
buffers and both metadata phases, including their overlap during recovery
resume. Its CLI component bound is **275,976,236 bytes**. Durable/store owners,
transition scratch, supervisors, queues, callers, verification and allocator/OS
costs remain separate; this does not enable complete coordinator admission.

**694 final native cases**, all four CPU compatibility configurations and **13
snapshot byte-parity cases per suite** pass. A 64-input recovery case preserves
255 unresolved attempts and one workspace within the metadata bound. No fresh
GPU proofs ran in this checkpoint; the unchanged proving-path qualification from
§9.106 remains explicitly inherited. No throughput improvement is claimed.

See [implementation §9.107](dag-gpu-implementation-2026-10-17.md#9107-snapshot-and-recovery-metadata-composition-2026-10-10)
and [the evidence](../evidence/gpu-coordinator-snapshot-metadata-2026-10-10.json).
Physical caps and the 337 MiB per-job minimum are unchanged. Complete resource
composition and the broader workload, performance, sustained-run and hardware
qualification gates remain open.

### Durable shared-state storage composition (2026-10-10)

The shared coordinator component now includes graph persistence/recovery,
transition indexes, store inventory/read/path work and durable guard metadata.
It counts Arc allocations retained by expired Weak references, preserves
release fencing, and returns exact-capacity query lists with unchanged
scheduling order. The production CLI component is **280,819,148 bytes**;
production and test layouts agree. This is a requested-backing component,
not complete physical coordinator admission or an RSS bound.

Qualification passes **709 native cases**, four CPU compatibility builds,
36 BTree allocation-layout cases and four Arc cases. The source/archive audit
and cleanup pass. No GPU proofs or Python application tests were rerun;
their previously qualified evidence remains explicitly inherited. See
[implementation §9.108](dag-gpu-implementation-2026-10-17.md#9108-durable-shared-state-storage-composition-2026-10-10)
and [the evidence](../evidence/gpu-coordinator-durable-storage-2026-10-10.json).

Job construction, caller/registry lifetimes, supervisors, queues and opaque
runtime costs still require composition. Physical caps, the 337 MiB per-job
minimum and rejection of incomplete phase profiles are unchanged. No
throughput improvement is claimed; the broader acceptance gates remain open.

### Pool and scheduler storage composition (2026-10-10)

Pool job copies, candidate lists, failure messages, transition indexes and
scheduler history/scratch now have a composable storage allowance. Combined
with durable state, the CLI shared component is **312,855,004 bytes**. Scheduling
order and stop/retry fencing are preserved. P95 estimates use fixed scratch,
deadline indexes avoid bulk-collection scratch, and error messages are bounded
during formatting instead of after allocating the complete output string.

Qualification passes **718 native cases**, four CPU compatibility builds and
two example feature-gate checks. A 4,096-class/64-sample history stress test,
pool lifecycle tests, production-layout comparison, source audit and cleanup
pass. Final library sources are covered by all runtime suites; an example-only
gate correction was qualified separately. See
[implementation §9.109](dag-gpu-implementation-2026-10-17.md#9109-pool-and-scheduler-storage-composition-2026-10-10)
and [the evidence](../evidence/gpu-pool-bookkeeping-storage-2026-10-10.json).

Registry and concrete endpoint heaps, caller lifetimes, process supervisors and
runtime costs still need composition before complete physical admission. The
337 MiB per-job floor, physical caps and rejection of incomplete profiles are
unchanged. GPU proof evidence is inherited; no new throughput result is claimed.

### Registry and caller selection storage (2026-10-11)

Shared pool storage now includes its existing 64 KiB registry allowance.
Selection accounting covers retained proof sharing, construction, input
conversion and admission copies. Input conversion rejects Vec capacity above
8 MiB; the encoded proof limit stays at 2 MiB. The CLI shared pool plus one
selection component totals **461,890,204 bytes**, before remaining caller,
endpoint, supervisor and runtime owners.

Qualification passes **727 native cases**, four CPU compatibility builds and
three example build configurations. Tests cover 160 selection shapes, 64
separate maximum-size buffers and seven independently observed slice-Arc
allocation layouts. Production sizes match tests, and cleanup passes. See
[implementation §9.110](dag-gpu-implementation-2026-10-17.md#9110-registry-and-caller-selection-storage-2026-10-11)
and [the evidence](../evidence/gpu-coordinator-caller-storage-2026-10-11.json).

Complete physical admission and the broader GPU qualification gates remain open.
Physical caps, the 337 MiB per-job floor, proof formats and registry identities
are unchanged. GPU proof evidence is inherited; no new throughput measurement
was made.


### Local endpoint and launch storage (2026-10-11)

The persistent pool now has storage allowances for its shared launch inventory,
concrete local workers, owned service identities and sequential observation
work. The component is **17,312,012 bytes for one worker** and **18,362,552 bytes
for 16 workers**, before the separate shared pool/caller components. Inventory
refresh charges both old and new maps; argv matching avoids a split vector
while preserving exact process binding.

Qualification passes **742 regular host cases and two separately enabled
supervised lifecycle cases**, four CPU compatibility builds and three example
configurations. Production/test sizes agree; independent allocation observation
and cleanup pass. The supervised cases use bounded real services and IPC
without GPU proving. See
[implementation §9.111](dag-gpu-implementation-2026-10-17.md#9111-local-endpoint-and-launch-storage-2026-10-11)
and [the evidence](../evidence/gpu-local-endpoint-storage-2026-10-11.json).

These are requested-backing components, not complete physical admission or RSS
bounds. Remaining caller/preparation/result/runtime owners require composition,
and shared storage must be deducted before physical coordinator RAM is divided
among jobs. Physical caps, the 337 MiB per-job floor and rejection of incomplete
phase profiles remain unchanged. GPU proof evidence is inherited; no new
throughput measurement was made. The broader acceptance gates remain open.


### Pool result and service report storage (2026-10-11)

Returned pool results now have an explicit ownership component covering accepted
records, drained failures and a root copy. The service keeps bounded typed report
records, transfers failure strings without copying and limits JSON serialization
to the existing 128 KiB ceiling before buffer growth. One service report plus
returned outputs and JSON backing requires **2,773,000 bytes for one worker** or
**2,896,360 bytes for 16 workers**, before other coordinator components.

Qualification passes **757 fresh native cases**, four CPU compatibility builds
and three example configurations. The returned-output production layout matches
tests; report layouts are measured in binary tests. Cleanup and source/archive
checks pass. See
[implementation §9.112](dag-gpu-implementation-2026-10-17.md#9112-pool-result-and-service-report-storage-2026-10-11)
and [the evidence](../evidence/gpu-pool-result-storage-2026-10-11.json).

Remaining preparation/runtime owners and the shared-versus-job physical RAM
split are still open. These components do not establish an RSS bound or complete
admission. Physical caps, the 337 MiB per-job floor and rejection of incomplete
phase profiles remain unchanged. GPU proofs and supervised lifecycle evidence
are inherited; no new throughput measurement was made.


### Preparation input ownership and pool handoff (2026-10-11)

Pool submission now consumes preparation objects, releasing caller selections
and temporary registries before dispatch. Unused initial preparation fields and
published expectation metadata are also released earlier. Exact-capacity caller
input/policy lists and temporary registry metadata add an **82,856-byte**
component; shared proof backing remains in the selection allowance.

Qualification passes **832 fresh native cases**, four CPU compatibility builds
and three example configurations. A durable handoff test confirms that lease
inputs survive the loss of all caller proof owners and that cancellation retains
reservations until stop acknowledgement. Production/test layouts agree and
cleanup passes. See
[implementation §9.113](dag-gpu-implementation-2026-10-17.md#9113-preparation-input-ownership-and-pool-handoff-2026-10-11)
and [the evidence](../evidence/gpu-preparation-handoff-storage-2026-10-11.json).

Preparation parsing/verification/runtime accounting and the shared-versus-job
physical RAM split remain open. These components do not establish an RSS bound
or complete admission. Physical caps, the 337 MiB per-job floor and rejection of
incomplete profiles are unchanged. GPU proof evidence is inherited; no new
throughput measurement was made.


### Coordinator shared RAM partition (2026-10-11)

Shared fleet plans now reserve **512 MiB** for known coordinator owners before
splitting the existing physical cap into per-job allowances. The **337 MiB**
per-job minimum remains unchanged. Rust checks the compiled shared total
(**483,231,972 B** for 16 workers), matching plan/worker reservations, overflow
and fleet capacity. Schema-2 recovery preserves the partition; insufficient
existing caps fail admission.

Qualification passes **844 native cases**, **135 Python tests**, four CPU
compatibility builds, three example configurations and production layout parity.
Cleanup passes. See [implementation §9.114](dag-gpu-implementation-2026-10-17.md#9114-disjoint-coordinator-shared-and-job-reservations-2026-10-11)
and [the evidence](../evidence/gpu-coordinator-partition-2026-10-11.json).

The reservation covers known owners; preparation parsing/verification and runtime
lifetimes still need composition. Ordinary incomplete profiles remain rejected,
physical caps are unchanged, and no RSS or throughput improvement is claimed.
GPU proof evidence remains inherited from the desktop RTX 5080 runs in §9.106.


### Bounded preparation input payloads (2026-10-11)

Preparation now bounds JSON collections while decoding, rejects duplicate
authorizations, reads artifacts into exact-capacity buffers and restricts key
decoding to the existing 64-root shape. Task metadata uses fixed capacities and
an in-place sort with unchanged ordering for all 1–64 input counts.

The **2,156,002-byte** payload component is included in shared admission. The
16-worker known total is now **485,387,974 B**, within the unchanged 512 MiB floor.
Qualification passes **969 native cases** across all three CPU CLI proof families
and both GPU feature sets, plus compatibility and production-layout checks.
See [implementation §9.115](dag-gpu-implementation-2026-10-17.md#9115-bounded-preparation-input-payloads-2026-10-11)
and [the evidence](../evidence/gpu-preparation-ingress-2026-10-11.json).

Parser/runtime scratch and direct wallet verification remain separate accounting
work. Ordinary incomplete profiles remain rejected; GPU proof and Python suite
evidence remain inherited. No throughput or RSS claim is made.


### Wallet verifier input admission (2026-10-11)

Wallet verification now checks the Uni-STARK proof's nested shapes and spare
capacities before configuration construction or numerical verification. Admission
allocates nothing and caps owned proof backing at **64 MiB**. Public arguments
use a fixed array, and diagnostic output is bounded.

**905 native cases pass**, including four fresh CPU proofs covering JoinSplit,
HTLC redeem/refund and issuance, independent upstream verification and altered
context/public/opening rejection. See [implementation §9.116](dag-gpu-implementation-2026-10-17.md#9116-wallet-verifier-input-admission-2026-10-11)
and [the evidence](../evidence/gpu-wallet-verification-inputs-2026-10-11.json).

The input gate does not bound symbolic inference or numeric verifier scratch;
those phases and runtime composition remain open. Physical caps are unchanged,
ordinary incomplete profiles remain rejected, and no new GPU throughput or RSS
claim is made.


### Wallet verifier degree metadata (2026-10-11)

Release wallet verification now uses independently checked degree metadata for
JoinSplit, HTLC and issuance. Degree inference makes **zero heap requests**,
replacing 814–1,202 requests totaling 56–90 KB per call. Constraints, quotient
geometry, proof parameters and proving code are unchanged.

**19 fresh native cases** and four compatibility builds pass, including four
fresh CPU proofs verified against the original AIRs. See
[implementation §9.117](dag-gpu-implementation-2026-10-17.md#9117-wallet-verifier-degree-metadata-2026-10-11)
and [the evidence](../evidence/gpu-wallet-verifier-degree-2026-10-11.json).

Periodic/numeric verifier scratch and complete runtime budgets remain open.
Physical reservations are unchanged; no end-to-end throughput or RSS gain is
claimed, and ordinary incomplete lifetime profiles remain rejected.


### Registered verifier cap invariants (2026-10-11)

Registered CPU verification now rejects empty or irregular Merkle caps before
configuration construction or numerical verification. Ten malformed proof-cap
cases and two trusted-cap cases confirm early rejection without allocations.

**71 fresh native cases** and four compatibility builds pass, including existing
conformance tests that produce seven fresh CPU registered proofs. See
[implementation §9.118](dag-gpu-implementation-2026-10-17.md#9118-registered-verifier-cap-invariants-2026-10-11)
and [the evidence](../evidence/gpu-registered-cap-invariants-2026-10-11.json).

Proving code and resource floors remain unchanged. Complete wallet verifier and
runtime budgets, full workload qualification and throughput measurements remain
open; ordinary incomplete profiles continue to be rejected.


### Wallet verifier scratch and payload lifetimes (2026-10-11)

CPU wallet verification now checks source-derived temporary payload bounds,
including periodic interpolation allocations across all Rayon workers. The
largest admitted geometry stays below 28.71 MB of modeled temporary payload.
This is a component bound; allocator/runtime and enclosing lifetimes remain open.

**425 native test-case executions** and four CPU compatibility builds pass.
Four fresh wallet proofs pass unchanged CPU verification and reject all 16
mutations. Sixteen behavioral source archives and six final scheduling archives
differ only by three explicit serial-test attributes. See
[implementation §9.119](dag-gpu-implementation-2026-10-17.md#9119-wallet-verifier-scratch-and-payload-lifetimes-2026-10-11)
and [the evidence](../evidence/gpu-wallet-verifier-scratch-2026-10-11.json).

Physical resource floors and incomplete-profile rejection remain unchanged.
Full runtime admission, workload qualification and throughput remain open.


### Borrowed wallet registry approval (2026-10-11)

Candidate preparation now validates its immutable registry once and reuses that
approval for wallet intake. Every wallet still receives full CPU verification.
For the test registry, reuse avoids 18,480 allocation requests totaling about
3.0 MB per wallet; this is not a measured throughput gain.

**334 native test-case executions**, four CPU compatibility builds and two
GPU-feature driver builds pass. Fresh proofs preserve tickets and reject altered
inputs. See [implementation §9.120](dag-gpu-implementation-2026-10-17.md#9120-borrowed-wallet-registry-approval-2026-10-11)
and [the evidence](../evidence/gpu-wallet-registry-context-2026-10-11.json).

Complete lifetime admission and workload/throughput qualification remain open.
Resource floors and incomplete-profile rejection are unchanged.


### Wallet intake lifetime composition (2026-10-11)

The shared coordinator budget now includes sequential wallet decoding,
verification and summary payloads. A source-derived 8 MiB decoder quota covers
all admitted shapes and rejects oversized malformed nesting earlier. The largest
known shared payload is 517,051,158 bytes, below the unchanged 512 MiB floor.

**437 native test-case executions**, compatibility builds and three production
layout probes pass, including fresh wallet proof verification. See
[implementation §9.121](dag-gpu-implementation-2026-10-17.md#9121-wallet-intake-lifetime-composition-2026-10-11)
and [the evidence](../evidence/gpu-wallet-intake-lifetimes-2026-10-11.json).

Initial registry compilation, allocator/runtime lifetimes and full workload
qualification remain open. Incomplete profiles are still rejected; no throughput
gain or production activation is claimed.
