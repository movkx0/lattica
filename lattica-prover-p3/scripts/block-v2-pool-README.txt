Persistent local pool and delivered-throughput campaigns

Current combined-source checkpoint: integration checks (section 9.293)

The frozen combined source includes 877 source/support files, incorporating the
concurrent session's capacity and host/pool changes. 135 Rust tests, 205 Python
tests, four all-target checks and 25 GPU tests pass. The GPU tests produce 44
fresh proofs verified on CPU (33 wallet, three registered, eight public recursive
padding requests), plus 18 opening/FRI component cases and two tree operations.
GPU evidence uses default capacity; opt-in capacity 128 has CPU/compilation
coverage only. Two stale Python fixtures were corrected, with explicit capacity
root-selection and 65-transaction preflight boundary checks. Production code
was not changed by this checkpoint.

The audit verifies 877 sources, 40 source archives and 1053 artifacts. The final
snapshot differs from the Rust/GPU test snapshot only in those two Python test
files; their corrected suites pass. The shared source/support whitelist,
including newly added files, matched at packaging. This observation does not
freeze the concurrently edited checkout. Preserved unsuccessful selections and
fixture runs are excluded from accepted coverage.

Original limits remain: 3 GiB worker/build, 1 GiB auditor, four CPUs, zero swap,
150/180-second GPU work/service deadlines and 12288 MiB free GPU memory.
Accepted runs have no observed competing services or memory-limit/OOM events.
No native block or funded slot was consumed. Native Zig/ABI integration, complete
host/cache/output ownership, nonempty recursive requests, production images and
calibration, matched controls, long history, 24 hours AND 150 roots, multi-GPU,
AMD OpenCL and native Apple Metal/local Mac source integration remain open.
The full goal remains active; these checks establish no throughput claim.

Metadata/continuation (crate relative):
benchmark-results/gpu-combined-source-20261016/control/current-validation-01.json
benchmark-results/gpu-combined-source-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-combined-source-integration-2026-10-16.json

Preceding isolated checkpoint: public recursive requests (section 9.292)

Four existing GPU tests on the unchanged, verified section 9.291 source produce
eight fresh recursive padding proofs. The 3-, 5-, 6- and 12-key registries each
prove levels 0 and 5 at height 2048, with one cold setup and one warm preprocessing
hit. All 16 required request stages report completed OpenCL work, including
public-value construction. Each request completes statement, registry,
statement-check, preprocessing and proof slots. Cached preprocessing is explicitly
marked; it does not fabricate fresh device work. CPU verification after GPU
shutdown, CPU public-root comparison and altered expected/embedded public-value
rejection pass for every proof.

The independent audit pins 745 sources, eighteen inherited source archives and
78 new artifacts. No source or production image changes. GPU service peaks span
236.58-254.34 MiB with zero swap, no memory-limit/OOM events and no observed
competing services. Original resource limits and the 12288 MiB free-GPU gate
remain unchanged. No native block or funded slot is consumed.

Metadata/continuation (crate relative):
benchmark-results/gpu-recursive-entrypoint-inventory-20261016/control/current-validation-01.json
benchmark-results/gpu-recursive-entrypoint-inventory-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-recursive-request-qualification-2026-10-16.json

A bounded source scan collected 2981 textual candidates; selected call chains
were reviewed. This is not an exhaustive command/cfg/raw-arithmetic inventory.
Nonempty wrap/pair, merge and finalization qualification, complete host/cache
ownership, combined-checkout validation, fresh production images/calibration,
matched controls, long history, 24 hours AND 150 roots, multi-GPU, AMD OpenCL and
native Apple Metal/local Mac source integration remain open. The full goal is
active; these correctness samples establish no throughput claim.

Preceding isolated checkpoint: transcript/scalar host ownership (section 9.291)
Each proof session now owns a fixed 1 MiB atomic host quota shared by its clones
and transcript families. Retained states acquire their backing before allocation
and keep the charge through cleanup. Adapters reserve their complete transient
plan before allocation; nested GPU methods exclusively borrow that scope and
check its owner/capacity. Raw APIs reserve their own scopes. Concurrent operations
and future states therefore compose within the same allowance.

126 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
21 GPU test executions pass: nine wallet integrations produce 33 fresh proofs
and two tree operations; four opening/FRI tests cover 18 component cases; seven
transcript/scalar checks and one registered integration add three fresh proofs.
All 36 fresh proofs verify independently on CPU after GPU shutdown. Ownership
checks cover concurrent contention, rejection before GPU work, wrong-session
scopes, error/unwind cleanup and zero live charge after drop. Accepted services
record no observed overlap. An initial interleaved build and eleven tests, plus
the rejected GPU-memory preflight, remain preserved separately.

Known state backing is 424 bytes. Maximum tested scratch is 721952 bytes; two
registered states plus that scratch total 722800 bytes, below 1048576. Allocation
oracles confirm 768 bytes of temporary owners and 1256 bytes of session backing.
The original 3 GiB worker / 1 GiB auditor limits, zero swap, four CPUs and
12288 MiB free-GPU gate remain in force. Accepted build/test services peak at
1627.63 MiB; the registered integration peaks at 270.86 MiB. These are bounded
correctness samples; production images and throughput remain unqualified.

Evidence verifies 745 sources, eighteen current-source archives, one preserved
initial archive and 737 artifacts. The reviewed 946-line diff covers fifteen
paths, including two new modules. The verified section 9.290 snapshot plus this
overlay excludes 74 unrelated changed shared-checkout paths.
Isolated metadata/continuation (crate relative):
benchmark-results/gpu-transcript-host-ownership-20261016/control/current-source-validation-04.json
benchmark-results/gpu-transcript-host-ownership-20261016/control/continuation-04.json
Evidence (repository relative):
docs/evidence/gpu-transcript-host-ownership-2026-10-16.json

Escaped returned vectors, caller input, earlier construction, later output/export,
verifier/foreign allocations and allocator overhead remain separate;
whole_proof=false. Combined-checkout validation, public recursive request/cache
integration and full production/history/multi-GPU/AMD/Metal qualification remain
open. No native block or funded slot is consumed. The full all-GPU goal is active.

Preceding isolated checkpoint: transcript/scalar host storage (section 9.290)

The existing 1 MiB transcript host envelope now bounds observation, sampling,
scalar input/output, next-point conversion, lookup metadata/challenges and domain
splitting. Observation uses a fixed stack batch; other maintained buffers reserve
exact fallible capacity. Lookup IDs retain original encounter-order semantics.
Opening/FRI deducts the envelope alongside retained commitments/runtime storage.
The largest tested transient plan is 721880 bytes. Allocator oracles confirm
696 bytes for temporary owners and 229376 bytes for 4096-entry lookup metadata.

120 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
20 GPU test executions pass: nine wallet integrations produce 33 fresh proofs
and two tree operations; four opening/FRI tests cover 18 component cases; six
transcript/scalar checks and one registered integration add three fresh proofs.
All 36 fresh proofs verify independently on the CPU. Accepted test runs record
no observed service overlap. The initial interleaved build/tests and one
preflight idle-guard rejection are preserved separately.

Evidence verifies 743 sources, seventeen current-source archives, one preserved
initial archive and 704 artifacts. The reviewed 947-line diff covers thirteen
paths, including two new modules. The source is the verified section 9.289
snapshot plus the declared overlay; 73 unrelated changed paths are excluded.
Evidence packaging waited for the other session's benchmark to finish.
Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-transcript-host-storage-20261016/control/current-source-validation-04.json
  benchmark-results/gpu-transcript-host-storage-20261016/control/continuation-04.json
Evidence (repository relative):
  docs/evidence/gpu-transcript-host-storage-2026-10-16.json

Budget reconstruction links all 33 wallet and three registered proofs. Runtime
charges including scratch span 9471944-76548040 bytes. Build/test services peak
at 1620.61 MiB; wallet GPU services span 143.95-216.22 MiB; opening/FRI components
span 201.70-212.49 MiB. Six transcript/scalar services span 140.48-144.50 MiB;
the registered integration peaks at 1383.13 MiB. The separately retained initial
build peaks at 2847.14 MiB. No recorded service has memory-limit/OOM events.

Combined-checkout validation and full lifetime ownership remain open, including
concurrent calls whose host buffers are allocated outside the execution mutex.
whole_proof=false remains explicit. Original limits and the 12288 MiB free-GPU
gate are unchanged; no production timing approval transfers. This checkpoint
consumes no native block or funded slot. The full all-GPU goal remains active.

Preceding isolated checkpoint: retained runtime storage (section 9.289)

Device-only opening/FRI now charges the existing engine metadata envelope plus
actual mapped staging, shared session storage and current live GPU transcript
states. Commitments and runtime backing reduce the same configured allowance
before opening construction. Host/hybrid behavior, arithmetic, profiles, circuits,
entropy, encoding and verification remain unchanged. Transient transcript/scalar
vectors, future concurrent clones and enclosing lifetimes remain outside this
component; whole_proof=false stays explicit.

108 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
Nine wallet integrations produce 33 fresh CPU-verified proofs and two tree-root
operations; all 15 required wallet arithmetic stages report OpenCL. Four focused
GPU tests pass 18 component cases. Six PCS cases verify allocation-free runtime
census, snapshot counting, early exhausted-budget/wrong-session rejection and
explicit CPU-transcript compatibility. Allocator oracles confirm session storage
of 1208 bytes and two live transcript states of 784 bytes on this toolchain.

All 33 proofs link retained preparation, commitments, runtime backing and opening
work to the original request allowance. Observed runtime charges span
8423368-75499464 bytes. These are correctness samples, not throughput qualification.

Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-opening-runtime-storage-20261016/control/current-source-validation-04.json
  benchmark-results/gpu-opening-runtime-storage-20261016/control/continuation-04.json
Evidence (repository relative):
  docs/evidence/gpu-opening-runtime-storage-2026-10-16.json

Evidence verifies 741 sources, sixteen current-source archives, one preserved
initial archive and 581 artifacts. The reviewed 374-line diff covers nine paths.
Other-session edits remain preserved; 73 unrelated changed paths are excluded.
Combined-checkout validation is still pending. One successful initial build and
eleven tests overlapped another service and are preserved separately; the tests
were rerun. Accepted runs record no observed service overlap.

Qualified build/test peak is 1565.06 MiB; wallet GPU-service peaks are
144.20-214.19 MiB and component peaks 201.98-212.25 MiB. The initial build peaks at
2846.00 MiB. No recorded service has memory-limit/OOM events. Original limits and
the 12288 MiB free-GPU gate remain unchanged. No production approval transfers.
Next compose transient transcript/scalar buffers and concurrent clone ownership,
earlier construction and later export/verifier/foreign lifetimes. No native block
or funded slot is consumed. The full all-GPU goal remains active.

Preceding isolated checkpoint: retained commitment storage (section 9.288)

Device-only opening admission now charges retained inline prover descriptors,
private/public prefix capacities and allocation wrappers, all salt-store variants,
shared replay-stream/seed wrappers and tree caps. Shared owners and repeated
references are conservatively recounted without a deduplication allocation.
The charge reduces the allowance used by opening construction and the later
opening/FRI partition. Explicit host/hybrid representations keep their existing
path. Engine/session, transcript, device payload, driver, allocator overhead and
enclosing lifetimes remain separate; whole_proof=false stays in the report.

100 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
Nine wallet GPU integrations produce 33 fresh proofs (16 quadratic, 17 cubic),
plus two tree-root operations. All 15 required wallet arithmetic stages use
OpenCL; CPU verification after GPU shutdown and altered-public rejection pass.
Four focused tests pass 18 component cases. Six PCS cases independently observe
an allocation-free retained-data census and rejection before GPU work. Actual
Rust wrapper layouts are checked against allocator requests; the replay stream
and its seed wrappers require 312 bytes per conservatively counted occurrence.

All 33 successful proofs link the retained commitment charge to opening
construction, retained output, FRI and serialization under the configured budget.
Observed commitment charges span 19128-29368 bytes. These are correctness samples,
not maximum-size or throughput qualification. Other-session edits remain untouched;
the combined shared checkout still requires validation after concurrent work ends.

Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-opening-commitment-storage-20261016/control/current-source-validation-04.json
  benchmark-results/gpu-opening-commitment-storage-20261016/control/continuation-04.json
Evidence (repository relative):
  docs/evidence/gpu-opening-commitment-storage-2026-10-16.json

Evidence checks 738 sources, fifteen current-source archives and 511 artifacts.
The reviewed 415-line diff covers ten paths, including two new partition/test
modules. Host build/test peak is 2861.53 MiB; GPU wallet-service peaks are
141.81-213.45 MiB. No memory-limit/OOM events occur. Original resource limits and
the 12288 MiB free-GPU gate remain unchanged. No production timing approval
transfers. Next compose engine/session and transcript storage, earlier commitment
construction and later output/export lifetimes. No native block or funded slot
is consumed; the full all-GPU goal remains active.

Preceding isolated checkpoint: opening construction storage (section 9.287)

Opening construction now admits retained round capacities, exact nested opened
values, prepared descriptors, FRI output backing and the larger sequential
readback before normal construction allocation or opening arithmetic. Fixed stack
geometry, a height bitset and point/alpha word buffers replace growable metadata.
Output/descriptor vectors use fallible exact reservations. Runtime retained
capacities match the later opening/FRI partition; both proof fields, arithmetic
ordering, profiles and circuit fingerprints remain unchanged in the isolated source.

91 unit/policy tests and CPU/GPU all-target checks pass offline and locked. Nine
qualified wallet GPU integrations produce 33 fresh CPU-verified proofs, plus two
tree-root operations. All 15 required wallet arithmetic stages report OpenCL.
Four focused GPU tests pass 18 component cases, including exact capacity checks,
early insufficient-budget rejection, upstream byte parity and CPU verification
after shutdown. All 33 qualified proofs link construction, retained opening,
FRI and serialization admissions to the same configured operation allowance.

The first compile failure and a later inverted assertion failure are corrected
and preserved. One tree integration passed its proof checks but cleanup detected
another session's validation service; its six additional proofs and two operations
are recorded as superseded. Only that tree test was rerun, successfully. There are
thirteen qualified GPU tests across fourteen GPU attempts. The other session's
source edits remain untouched. Combined shared-checkout validation is still pending.

Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-opening-construction-storage-20261016/control/current-source-validation-04.json
  benchmark-results/gpu-opening-construction-storage-20261016/control/continuation-04.json
Evidence (repository relative):
  docs/evidence/gpu-opening-construction-storage-2026-10-16.json

Evidence checks 736 sources, fourteen current-source archives, fourteen preserved
initial archives and 701 artifacts. The reviewed 634-line diff covers four paths,
including two new planner/test modules. Build/test host peak is 2753.46 MiB;
qualified wallet GPU-service peaks are 199.96-222.38 MiB. No memory-limit/OOM events
occur. Two Cargo jobs run within the original four-CPU/3 GiB build allowance.
All remaining resource limits and the 12288 MiB free-GPU gate are unchanged.
Engine, transcript, borrowed commitment data, allocator overhead and stack remain
outside this component. Whole-proof ownership and production/throughput gates
remain open. No native block or funded slot is consumed; the all-GPU goal is active.

Preceding isolated checkpoint: opening/FRI host partition (section 9.286)

Opening evaluation now receives the actual configured operation allowance.
An allocation-free census deducts retained opening and round vector capacities,
device-input descriptors, the exact FRI reference array and pending exact hiding
output before FRI. FRI proof assembly, query gathering, salts and final-polynomial
readback receive the remainder, subject to existing local caps. Exact hiding
buffers preserve preprocessing order and encoded bytes.

84 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
Nine wallet GPU integrations produce 33 fresh proofs (16 quadratic, 17 cubic)
with all 15 required arithmetic stages on OpenCL and independent CPU verification
after GPU shutdown. Four focused GPU tests pass 18 component cases covering
both fields, early insufficient-allowance rejection, CPU byte parity and CPU
verification after shutdown. These component cases are operation coverage,
separate from the 33 complete wallet proofs. Every successful wallet proof links
its operation allowance, opening partition, FRI storage and serialization record.

The shared checkout is being edited by another session. The initial source guard
rejected unrelated changes before compilation. Validation therefore uses the
verified section 9.285 archive plus only the twelve declared opening/FRI paths,
with separate source, Cargo cache and target directories. No concurrent source
changes are overwritten or qualified. Combined shared-checkout validation remains
pending after that session finishes. The source below is not a production image.

Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-opening-host-partition-20261016/control/current-source-validation-02.json
  benchmark-results/gpu-opening-host-partition-20261016/control/continuation-02.json
Evidence (repository relative):
  docs/evidence/gpu-opening-host-partition-2026-10-16.json

Evidence checks 734 sources, thirteen archives and 460 artifacts; the full
781-line diff covers twelve paths. Host build/test peak is 2957.46 MiB;
wallet GPU-service peaks are 143.83-213.11 MiB. No memory-limit/OOM events occur.
Original resource limits, the 12288 MiB free-GPU gate, proof profiles and circuit
fingerprints remain unchanged in the isolated source. No production timing
approval transfers. This partition excludes borrowed prover data, engine,
transcript, configuration, other caller memory and allocator overhead; it retains
whole_proof=false and host_lifetime_admitted=false. Complete host/cross-stage/
export/recursive lifetimes and production/sustained qualification remain open.
No native block or funded slot is consumed. The all-GPU goal remains active.

Preceding source checkpoint: bounded wallet serialization (section 9.285)

Legacy single/batch and cubic JoinSplit, HTLC and issuance GPU proofs now admit
retained proof/public capacities plus a single final output against their actual
operation allowance. The allocation-free census includes spare capacity at every
nested level. Checked Postcard sizing precedes allocation; cubic envelopes serialize
directly into the final buffer. The existing cubic 2 MiB cap includes its 72-byte
header. CPU encoders/verifiers, proof parameters, circuits and entropy are unchanged.

The preceding preparation/operation partition remains enforced: the 1 GiB request
allowance splits into 203500104-205861128 preparation bytes and 867880696-870241720
operation bytes. Serialization is a late output boundary. Earlier construction,
cross-stage retained storage, caller/configuration/export/verifier/foreign memory,
diagnostics, stack and allocator overhead still need enclosing ownership. Reports
retain whole_proof=false and lattica-wallet-device-phase-v9 with
host_lifetime_admitted=false.

70 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
Seven new output tests independently match retained capacity with allocator
requests, mutate 30 nested capacity locations in each field, cover empty optional
buffers, accept exact limits, reject short limits without allocating, require one
output allocation, reject overflow and preserve Postcard/envelope bytes. The prior
63 tests retain their coverage; all five production fingerprints are unchanged.

Nine GPU integrations produce 33 fresh proofs (16 quadratic, 17 cubic), plus two
tree-root operations. All 15 required proving arithmetic stages use OpenCL. CPU
verification after shutdown, altered-public rejection, capacity/unwind and 21
private-input boundaries pass. Existing 22 resource rejections precede arithmetic.
There are 43 phase-admitted requests: 33 successes and ten later rejections.
69 preparation records and 34 configured operation partitions are checked; the
latter close as 33 successful proofs and one unsuccessful issuance request. All
33 successful proofs have serialization records linked to their actual partitions
and completed requests, independently reconstructed from raw logs. Proof/public/
output totals span 995769-1962352 bytes; encoded output spans 458009-875464 bytes.
These correctness samples do not qualify maximum-size proofs or throughput.

Source metadata/continuation (crate relative):
  benchmark-results/gpu-wallet-serialization-storage-20261016/control/current-source-validation-01.json
  benchmark-results/gpu-wallet-serialization-storage-20261016/control/continuation-01.json
Evidence (repository relative):
  docs/evidence/gpu-wallet-serialization-storage-2026-10-16.json

Independent verification checks 732 sources, ten current-source archives and
317 artifacts. The 715-line diff covers seven changed paths. Build/test host peak
is 2649.92 MiB; GPU-service peaks are 143.61-213.32 MiB. No memory-limit/OOM events
occur. Original 3 GiB worker/build,
1 GiB auditor, four CPUs, zero swap, 150/180-second GPU work/service limits and
12288 MiB free-GPU gate hold. Correctness images use opt-level 1, 64 codegen units
and no LTO; no production timing approval transfers.

Next complete construction and cross-stage retained-output ownership,
caller/export/verifier/foreign lifetimes, public recursive request/cache composition,
fresh production builds/calibration, matched controls and sustained/multi-device
qualification. No native block, funded-slot use or new throughput/speedup is claimed.

Accepted history remains eight blocks at height 17; next native slots 1152-1215,
qualification 9556-9559, unused slots 8288. At least 1312 more unused slots are needed
for a fresh 150-root campaign before controls/failures/qualification. Failed slots
896-959 remain terminal. The original all-GPU goal remains active, including 24 hours
AND 150 roots, multi-GPU, AMD OpenCL and native Apple Metal/local Mac integration.
