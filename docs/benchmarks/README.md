# Solving benchmark report

Open [index.html](index.html) directly in a current Chromium, Firefox or Safari.
It is a standalone HTML5 report: no server, package install, network connection
or original benchmark directory is needed.

The purpose is to measure useful transaction throughput and development against
the [P0–P5 engineering roadmap](../high-throughput-proving-plan.md#8-engineering-project-plan).
Apple silicon and Linux/OpenCL are development tracks. There is no hardware
leaderboard.

## Paused capacity checkpoint and Apple Silicon handoff — 2026-10-06

Workstation experiments are paused at the user's request. The
[capacity checkpoint JSON](../evidence/block-v2-vram16-capacity-paused-2026-10-06-r1.json)
retains the declared 16 → 32 → 64 campaign on the RTX 5080 Laptop GPU:

| Ordered inputs | Outcome | Complete recursive proving | Sampled GPU process peak |
| --- | --- | --- | --- |
| 16: 12 user + 4 issuance | Passed independent CPU root audit; 16 fresh proofs, zero reused | 527.590 s | 6.63 GiB |
| 32 | Interrupted at the user's request before a complete root or audit | Unqualified | Unqualified |
| 64 | Not started | Unqualified | Unqualified |

Direct host readback and opening-denominator caching were enabled for this
campaign. For count 16, actual reservations were 7 GiB managed VRAM plus
7.25 GiB driver/context allowance, 37.75 GiB worker RAM, 28.5 GiB tmpfs spill
charged to RAM, and 23 Rayon threads. Count 32 redetected 38.25 GiB worker RAM;
its separate budget is retained. These conservative reservations differ from
sampled usage. The observed peak is sampled at process checkpoints, not a
continuous maximum.

Cleanup verified 10 process identities and seven services were terminal. Six
accounting records contained zero memory-limit or OOM events. Original logs,
proofs, partial state, service journals, budgets and hashes remain retained.
The original count-32 summary still says `running`; the later pause and cleanup
records establish that it was stopped. The interruption is not a resource or
correctness failure. Maximum optimized capacity remains undetermined; 16 is
the largest completed size in this campaign. It used existing wallet proofs
and did not measure fresh wallet proving, native chain application or delivered
transaction throughput. Any later 32/64 attempts need a new declared revision
and fresh output directories.

The earlier
[partial native cache comparison](../evidence/block-v2-opening-cache-native-comparison-2026-10-06-partial-r1.json)
remains incomplete: four of five pairs completed, followed by an unpaired
baseline and a cache arm that failed host RAM/spill admission before proving.
Median paired pipeline reduction was **2.978%** (range **0.365–4.495%**).
Its nine completed arms, failed attempt and original evidence are unchanged;
the cache remains opt-in. The report retains these arms and the new capacity
checkpoint alongside 819 indexed records. The two-hour pilot has not started.

Use the [current-source Mac instructions](../../lattica-prover-p3/scripts/apple-current-benchmark-README.txt)
to fetch `v3`, create an isolated checkout and build a new package with
`--revision HEAD`. It freezes that exact commit and uses the public fixture in
Git. The Metal recipe runs correctness checks followed by nine measurements of
quotient control, deferred timing, and compact data with deferred timing.
Direct readback and denominator caching need a separate declared Metal
qualification before they enter that recipe. NVIDIA results do not establish
Apple Silicon performance or memory requirements. Keep failed attempts and
return the portable result archive for import. Apple execution remains pending.

The [r40 readiness snapshot](../evidence/block-v2-throughput-readiness-2026-10-06-r40.json)
records this pause. Full cold-start, post-seal timing and sustained delivered
throughput qualification remain open.

## Two-hour throughput pilot

The active [contract](../../lattica-prover-p3/scripts/block-v2-throughput-contract.json)
targets four useful user transactions/minute on this workstation. It retains
600 s cold full-64, 180 s complete post-seal finalization, depth six, the 2 MiB
root limit and the existing security parameters. Resource budgets follow the
actual GPUs, CPU capacity, host headroom and scratch filesystem.

The deterministic schedule contains 504 requests from four wallet participants:
4/min for minutes 0–48, 6/min for 48–60 and 4/min for 60–120. Four issuance
transactions per nominal cycle are an assumption; authoritative amounts and
issuance policy come from the host. Startup, failures and recovery remain inside
the two-hour window. Any subsequent drain has separate accounting.

Prepare the schedule and inspect every prerequisite:

```sh
python3 lattica-prover-p3/scripts/block-v2-multi-gpu-run.py \
  --config PATH_TO_QUALIFIED_CONFIG --plan > /tmp/lattica-resource-plan.json
python3 lattica-prover-p3/scripts/block-v2-throughput-pilot.py prepare \
  --resource-plan /tmp/lattica-resource-plan.json \
  --evidence docs/evidence/block-v2-throughput-readiness-2026-10-06-r40.json \
  --output /tmp/lattica-pilot-readiness.json
python3 lattica-prover-p3/scripts/block-v2-benchmark-report.py ingest \
  --input /tmp/lattica-pilot-readiness.json
```

Exit **2** means a qualification gate is blocked; exit **1** means invalid input.
Both `prepare` and `check` are read-only with respect to workers and chain state.
They cannot start a pilot. The current implementation provides readiness,
research proof APIs and campaign accounting. The native journal now accepts and independently replays candidates assembled
from current-head pending arrivals, including durable sealed intake receipts.
Deferred-arrival revalidation and independent-policy selection now pass for the
recorded count-four case. A staged count-four to count-eight run now qualifies
pre-seal subtree proving and CPU-verified reuse. Active proving recovery and
complete timing/capacity qualification remain required before an actual pilot run.
The report retains readiness in `qualifications/*.json` and displays each gate.
Immutable `campaigns/*.json` files hold actual lifecycle exports when available.
No successful pilot data is generated from the planned schedule. Apple-silicon
campaigns use the same import format with their own resource profile.

### Implementation and remaining work

1. Typed leaves, the twelve-key paired registry, independent CPU root replay and
   hardware-based admission are implemented. The [count matrix](../evidence/block-v2-typed-count-matrix-2026-10-05.json)
   passes all nine required counts on both GPUs: 16 new roots and 380 new
   recursive proofs, plus two retained roots containing eight prior proofs.
2. Five matched count-four fleet pairs remain qualified: median sequential and
   concurrent windows are 316.521 and 197.872 seconds, a 37.486% median within-pair
   reduction. Larger counts remain unqualified under the shared two-worker
   allocation; the completed matrix ran them one at a time. The new typed inline
   DAG binary separately passes one concurrent count-eight trial in 422.634 s
   with two CPU-audited roots, 16 fresh recursive proofs and zero memory events.
3. The [multi-height native qualification](../evidence/block-v2-native-delivery-2026-10-05.json)
   passes 41 checks with four audited roots across heights 10–12 and an alternate
   height-11 branch. Fresh-process recovery, exact accounting, reorg and stale
   result rejection pass. The earlier journal's 55 storage/fault checks remain
   retained. The [typed DAG qualification](../evidence/block-v2-typed-local-dag-2026-10-05.json)
   adds selection for 1–64 inputs, CPU checks of all nine count plans, and journal
   reopen of four retained roots (16 nodes). All 153 enabled execution tests and
   six paired-probe tests pass for that replay. The
   [typed GPU worker qualification](../evidence/block-v2-typed-worker-2026-10-05.json)
   adds typed packets, cached preprocessing, persistent reservations and six
   independently CPU-audited roots containing 40 fresh recursive proofs. Its 159
   execution tests, nine probe tests and 34 controller tests pass.
   [Completed GPU journal recovery](../evidence/block-v2-typed-recovery-2026-10-05.json)
   now passes in two fresh CPU processes at epochs 2 and 3. Each reverified eight
   cached nodes and returned the identical root in about 4.676 seconds with zero
   new proving jobs. Four invalid-input checks left the journal unchanged.
   The dedicated GPU input run added one audited root and eight fresh proofs;
   recovery added no new proofs or native blocks.
   [Persistent GPU child dispatch](../evidence/block-v2-typed-process-2026-10-05.json)
   first passed one eight-input laptop root in 250.478 seconds. Its failed
   initial trial and host-telemetry gap remain retained.
   [Desktop and concurrent qualification](../evidence/block-v2-typed-process-concurrent-2026-10-05.json)
   adds three audited roots and 24 fresh proofs with the same frozen binary:
   291.247 seconds on the standalone desktop GPU, and 303.486 / 342.703 seconds
   concurrently. Each root recorded four setups, four cache hits and confirmed
   child exit before workspace release. Both new monitor services completed;
   all worker and fleet memory-event counters were zero. This is one concurrent
   count-eight trial with independent DAG owners. The differing resource assignments do not establish matched speedup.
   [Shared-owner qualification](../evidence/block-v2-typed-shared-owner-2026-10-05.json)
   adds one eight-input root in **237.679 seconds**, a separate **0.144-second CPU
   audit**, and eight verified recursive proofs. One coordinator dispatched five
   proofs to the laptop GPU and three to the desktop GPU. All services exited
   cleanly; memory-event counters remained zero. Worker peaks were
   **15.644 / 15.559 GiB**, with **143.887 MiB** for the owner. This is one
   fixture trial. The native trials below extend application qualification;
   arrivals, active-worker/coordinator recovery, matched repetitions and larger
   shared counts remain open.

   [Native shared-owner application](../evidence/block-v2-native-shared-owner-2026-10-05.json)
   now passes two local native blocks at heights 10 and 11. Each contains four
   fresh synthetic transactions. Proving took **126.385 / 126.512 seconds**;
   native application took **3.621 / 3.755 seconds** after CPU root audit. Both
   published states passed independent replay, including a later fresh process.
   Stale preparation and resubmission of an applied root were rejected without
   changing the journal. This qualification applied six useful and two issuance
   transactions. That qualification covered prepared batches; the intake extension follows below.
   [Durable intake qualification](../evidence/block-v2-native-arrival-intake-2026-10-05.json)

   adds one native count-four application from a sealed intake selection. Proving
   took **126.861 seconds** with four fresh recursive proofs and a three/one GPU
   split. A separate process submitted one late transaction during proving; it
   was retained outside the applied candidate and needs head revalidation.
   Native application, intake receipts and fresh-process replay passed. This
   isolated journal used existing wallet proofs and applied three useful
   transactions plus one issuance. All memory-event counters were zero.
   The bounded observer now stays separate from worker admission limits.
   That trial used an explicitly prepared selection; pending-candidate assembly
   is qualified separately below. Pre-seal dispatch, active proving recovery
   and sustained throughput remain open.

   [Pending candidate qualification](../evidence/block-v2-native-pending-candidate-2026-10-05.json)
   adds FIFO assembly from stored transaction/proof bytes, native state and
   issuance-policy preflight, and portable CPU wallet verification. The
   prepare-and-seal command took **13.834 seconds**; its builder took
   **7.614 seconds**. Both intervals precede the GPU controller window.
   Four fresh recursive proofs took **129.986 seconds**, with a three/one GPU
   split. CPU audit, native application, durable receipts and fresh-process
   replay passed. This isolated application contains three useful transactions
   plus one issuance and reuses existing wallet proofs. Memory events were zero
   and all proving services exited. The report shows preparation as a separate
   stage and retains its manifest in the run JSON. The deferred-arrival extension
   follows below; Apple runtime validation is still pending.

   [Deferred-arrival qualification](../evidence/block-v2-native-deferred-arrivals-2026-10-05.json)
   revalidated two prior-head transactions, selected two current-head HTLCs, and
   moved an early issuance arrival into its independently authorized slot.
   Altered ciphertext, an old-height HTLC and a spent nullifier stayed outside
   the candidate. Their bytes remain retained. Original receipts and exact retry
   responses were unchanged. The prepare-and-seal command took **26.729 seconds**;
   the builder inside it took **21.094 seconds**. Four fresh recursive proofs
   took **126.801 seconds** across both GPUs. CPU audit, native application,
   intake publication and fresh-process replay passed. The height-10 setup root
   was reused and does not count as fresh proving. All memory-event counters
   were zero and all proving services exited. Pre-seal dispatch, active recovery,
   larger shared counts and sustained throughput remain open.

   [Pre-seal subtree qualification](../evidence/block-v2-native-preseal-arrivals-2026-10-05.json)
   produced three subtrees while another process submitted four later arrivals.
   The sealed eight-transaction candidate CPU-reverified and reused those proofs,
   generated five remaining proofs in **159.088 seconds**, and passed root
   audit, native application, receipt publication, and fresh replay. The successful
   path created eight proofs and one audited root, applying six useful transactions
   and two issuances from existing wallet proofs. Four invalid cache cases were
   rejected before GPU dispatch. The dashboard separates subtree audits, fresh
   proofs, and reuse, and retains the earlier failed controller attempt. Separate
   rejection trials and a continuation lie outside the final owner window;
   complete post-seal timing, active recovery, larger shared counts, sustained
   throughput, and repeated Apple runtime measurements remain open.

   [Active-worker failover](../evidence/block-v2-native-active-failover-2026-10-05.json)
   now passes for a four-transaction native candidate. The exact desktop worker
   was killed after the laptop's first subtree was accepted. The coordinator
   confirmed teardown before releasing its reservation, retained the accepted
   proof, and retried on the surviving GPU under its original assignment.
   Five dispatches produced four accepted proofs and one audited/applied root
   in **157.676 seconds** of proving, including the interrupted attempt and retry.
   All memory-limit/OOM counters stayed zero. The report retains both workers,
   their termination records and the failed worker's zero accepted proofs.
   Worker replacement, resource exhaustion and active reorg recovery remain
   unqualified. Later initialized startup/dispatch checks are described below.

   [Explicit coordinator restart](../evidence/block-v2-native-coordinator-recovery-2026-10-05.json)
   now passes after one subtree is accepted during active proving. Recovery resumes
   the original journal at epoch two with unchanged per-GPU limits, CPU-reverifies
   and reuses one proof, produces three more, independently audits the root and
   applies the native candidate once. Resumed proving took **115.032 seconds**;
   the full experiment took **267.566 seconds**, including initial proving,
   interruption, RAM admission waiting and replay. One idle GPU worker closed
   successfully. Every process exited and memory-limit/OOM counters stayed zero.
   The dashboard retains both failed recovery attempts and the successful resumed
   phase; original interruptions and admission rejections are pinned in the
   qualification evidence. Automatic supervision and broader interruption/OOM/reorg
   coverage remain open.

   [Cached-root continuation](../evidence/block-v2-native-cached-recovery-2026-10-05.json)
   now passes at epoch four after an incomplete-cache rejection, GPU continuation
   from that rejected epoch, and a second interruption after final-root acceptance.
   It reverifies four saved proofs and applies the native block once with **zero
   GPU workers and zero new proofs**. Cached recovery took **3.479 seconds** and
   the owner window **20.943 seconds**. The report identifies this as CPU-only
   recovery and suppresses its proving-throughput rate. Native-application and
   receipt-publication interruptions still need qualification. The original harness
   failure and continuation are retained; no accepted work was regenerated.
   [Native receipt recovery](../evidence/block-v2-native-application-recovery-2026-10-05.json)
   now passes crashes after native head publication and before/after intake
   commit. Recovery preserves one block and one intake application event, with
   four reused proofs, zero new proofs and zero GPU workers. Five native storage
   boundaries and fresh-process exact retries also pass. The final owner window
   is **24.280 seconds**, including **3.476 seconds** of proof-journal recovery.
   The report identifies recovery of existing receipts and records **zero fresh
   native blocks**. Other interruption/OOM/reorg and automatic supervision gates
   remain open.

   [Startup, dispatch and export recovery](../evidence/block-v2-native-startup-recovery-2026-10-06.json)
   now covers initialized worker startup before launch and readiness, coordinator
   interruption after dispatch, and an accepted-root export I/O failure. The
   final CPU-only phase restored four accepted proofs, started no GPU workers,
   and applied one isolated block. Its **18.589-second owner window** includes
   **3.903 seconds** of journal recovery. The “Cached export recovery” row pins
   the unexported root's internal artifact and journal and leaves transaction
   throughput blank. Resource exhaustion, reorg/all-worker failure, and automatic supervision remain
   open. Controller admission and recovery initialization are covered below.

   [New-candidate bootstrap recovery](../evidence/block-v2-native-bootstrap-recovery-2026-10-06.json)
   now passes four earlier coordinator crashes, including incomplete metadata
   and the interval before worker intents. The final resumed phase produced
   four recursive proofs and applied one block after another dispatch crash:
   **132.551 seconds** proving and **162.073 seconds** for the invocation.
   The report's owner rate describes that resumed phase. It excludes prior
   attempts and wallet/registry preparation. All partial journals, the failed
   launch-path attempt, source archives and accounting are retained. Resource exhaustion, reorg/all-worker failure, and automatic supervision remain
   open. Controller admission and recovery initialization are covered below.

   [Existing-journal recovery initialization](../evidence/block-v2-native-recovery-initialization-2026-10-06.json)
   now passes four interruptions before initialization completes. One accepted
   proof survived generations 2–5. The final continuation produced three more
   proofs, passed the CPU root audit and applied one block and one intake event;
   fresh-process replay and two retries preserved those counts. It took
   **114.515 seconds proving** and **143.117 seconds for the invocation**. Prior
   attempts and input preparation are outside this resumed measurement. Partial
   journals, checkpoint snapshots, the rejected routing attempt, binaries and
   source archives remain retained. Broader failure coverage and complete throughput qualification remain open;
   controller admission is covered below.

   [Controller admission and recovery](../evidence/block-v2-native-controller-admission-2026-10-06.json)
   now passes four interruptions before owner admission, one after handoff but
   before owner launch, and one after accepted proof work. The bound owner and
   workers stopped when only the controller was killed. Explicit recovery reused
   one proof, produced three more, passed CPU audit, and applied one block with
   three user transactions and one issuance. The final continuation took
   **114.635 seconds proving** and **145.858 seconds for the full invocation**.
   Earlier attempts and input preparation remain outside this measurement.

   A subsequent CPU-only controller continuation reused all four proofs, started
   no GPU workers, and added no native block or intake event. Its **46.072-second
   controller service window** excludes frontend pinning; its report row leaves
   transaction throughput blank. Independent replay confirmed one application.
   All 30 recorded processes exited and 31 services were terminal. Nine retained
   service accounts and fleet counters have zero memory events; eight killed
   controllers lack final accounts. Interrupted summaries, exit/drain receipts,
   failed test-hook/checker attempts, proofs, binaries, and source archives are
   retained. Resource exhaustion, reorg/all-worker failure, automatic supervision,
   and complete throughput remain open.

   [Worker OOM and all-worker loss](../evidence/block-v2-native-worker-failure-2026-10-06.json)
   now pass. After one accepted proof, a controlled 1 GiB cap caused the other
   worker's OOM. Its job was retried on the surviving GPU: **160.032 seconds
   proving**, **188.611 seconds for the invocation**, including failure and retry.
   Fleet memory events must exactly match the drained failed-worker counters.
   The report's OOM row retains those counts and the original resource assignment.

   A separate attempt lost both workers after one accepted proof and stopped
   without applying a block. Explicit recovery preserved the proof and produced
   three more: **114.700 seconds proving**, **145.907 seconds for the final
   invocation**, excluding the **67.208-second failed attempt**. Each isolated
   candidate applied one block containing three user transactions and one issuance.
   Independent replay and repeated application produced no duplicate block or
   intake event. All 25 recorded processes and 22 services stopped; all 16 service
   accounts were retained. The failed attempt is visible separately in the report.
   Earlier harness and accounting failures remain retained. Broader resource
   exhaustion, active reorg, automatic replacement, and full throughput remain open.

   [Active and late native reorg](../evidence/block-v2-native-reorg-cancellation-2026-10-06.json)
   now pass. The controller preserves accepted proofs, drains owner and workers,
   and cancels stale intake selections. An audited root is also rejected when the
   head changes immediately before native application. Partial and cached recovery
   reject before GPU dispatch. Revalidating four arrivals produced a replacement
   candidate in **131.788 seconds proving / 160.711 seconds invocation**. One block
   with three user transactions and one issuance applied; fresh-process replay and
   two exact retries caused no duplicates. All 28 recorded processes exited and
   24 services stopped; all 18 solver accounts have zero memory-limit/OOM events.
   The report retains the failed cleanup attempt and both stale candidates as
   failed rows, including the CPU audit of the late root. They contribute no
   throughput. The r33 catalog contained **774 runs, 355 CPU-audited records, and
   zero transaction campaigns**. VRAM/spill exhaustion, automatic supervision,
   complete timing boundaries, and the pilot remain unqualified.

   [Physical resource exhaustion](../evidence/block-v2-native-resource-exhaustion-2026-10-06.json)
now passes for a full private spill filesystem (SIGBUS) and bounded CUDA pressure
causing `CL_MEM_OBJECT_ALLOCATION_FAILURE`. Accepted proofs survived, the failed
worker drained, and the other GPU completed one native block in each case.
Fresh-process replay and two exact retries per case caused no duplicate
application. Spill proving / invocation took **160.718 / 191.343 seconds**;
VRAM exhaustion took **155.011 / 184.621 seconds**, including failure and retry.
The pressure allocation and CUDA context were released. All 25 recorded
processes exited, 26 services are terminal, and 12 solver accounts have zero
host memory-limit/OOM events. The report shows each fault and retains its source
pins. The r34 catalog contains **776 runs, 357 CPU-audited records, and zero
transaction campaigns**. Automatic supervision and worker replacement, matched
repetitions, larger counts, and complete timing boundaries remain open.

   [Automatic sealed-candidate supervision](../evidence/block-v2-native-supervision-2026-10-06.json)
   now passes two real native fault trials:

   | Fault | Full supervised invocation | Final owner attempt | Final proving interval |
   | --- | ---: | ---: | ---: |
   | Both GPU workers killed; replacement fleet | 234.063 s | 128.069 s | 113.478 s |
   | Supervisor killed; live controller adopted | 164.515 s | 144.431 s | 129.808 s |

   Fleet recovery reused one accepted proof and produced three fresh proofs.
   Supervisor restart kept both original workers running and produced four fresh
   proofs. Each case applied three user transactions and one issuance exactly once;
   independent CPU audits, fresh-process replay and two exact retries passed.
   Early stale rejection started no controller or GPU worker and changed no store.
   All 29 observed processes exited, 18 services are terminal, and 18 accounting
   records show zero host memory-limit/OOM events. Validation passed 148 Python tests.

   The r35 catalog retains **779 runs, 359 CPU-audited records and zero transaction
   campaigns**, including the failed original attempt. Per-run rates use full
   supervision time. Preparation, wallet proving and separate replay checks remain
   outside those intervals. The five required recovery cases now pass; current
   pilot admission still requires typed context calibration on both GPU UUIDs,
   all required geometries and complete cold/post-seal timing. Automatic cached
   root recovery and active reorg through the supervisor have not had separate
   real native fault trials. Supervision currently accepts sealed candidates only.

   The [five-cycle comparison](../evidence/block-v2-native-context-repetitions-2026-10-06.json)
   qualifies native eight-input candidates with **512 MiB context per GPU**.
   Twenty isolated arms use identical fixtures, 20.75 GiB RAM and 14.25 GiB spill
   per worker, Rayon 12/11, and 7/6 GiB managed VRAM. Single-GPU arms retain their
   share of the same allocation. Median times over five repetitions:

   | Scheduling arm | Final proving | Full candidate pipeline | Seal start to controller exit |
   | --- | ---: | ---: | ---: |
   | Laptop GPU only | 279.925 s | 341.331 s | 317.395 s |
   | Desktop GPU only | 355.958 s | 420.064 s | 396.238 s |
   | Shared owner, both GPUs | 227.187 s | 289.244 s | 265.270 s |
   | Staged prefix reuse, both GPUs | 161.066 s | 366.689 s | 198.038 s |

   The median within-cycle pipeline reduction is **16.049%** for shared execution
   versus the laptop GPU alone. Staging reduces seal-start-to-controller-exit time
   by **24.836%** versus shared execution, while increasing full pipeline time by
   **26.577%**. Each arm has monotonic and UTC stamps around durable sealing.
   Controller exit bounds host-ready time from above. Pipeline timing includes
   candidate preparation, staged prefix work, final proving, CPU audit, native
   application and controller cleanup. Wallet proving, arrival waiting and
   separate replay checks are excluded.

   All 20 roots passed CPU audit; fresh-process replay and two exact retries per
   arm passed without duplicate application. The campaign produced 160 fresh
   recursive proofs and reused 15, with zero fresh wallet proofs. Each journal
   applied the same six user transactions and two issuances. These are isolated
   native applications; sustained transaction throughput remains unmeasured.

   Cleanup checked 160 process records, 92 terminal services and 90 accounting
   records with zero memory-limit/OOM events. Context peaks were 209,713,424 bytes
   and 278,919,440 bytes. Current validation passes 219 Python tests and imports
   all ten complete single-GPU trials. The [opt-in denominator cache](../evidence/block-v2-opening-cache-native-qualification-2026-10-06-r1.json)
   now passes ten native roots and replay checks, with 80 fresh recursive proofs.
   Both modes qualify on each GPU and in shared execution with separately derived
   **512 MiB context allowances**. All 72 observed processes and 34 services exited;
   32 accounting records show zero memory-limit/OOM events. Each cache-enabled root
   avoided **27 GiB of uploads**, with a **192 MiB peak cache per worker** inside its
   managed VRAM allowance. These are resource qualifications; matched solving-time
   comparison qualification remains incomplete, as recorded above. The report preserves that distinction and passes
   76 focused report tests. Larger shared counts and complete cold/post-seal
   boundaries remain pending. The report retains **819 runs, 393 CPU-audited
   records and zero transaction campaigns**.

4. Count-64 worker times are 1,692.217 / 2,201.471 seconds, excluding wallet proving,
   registration and durable application. Complete cold-full-64 and post-seal
   measurements remain unqualified. Full-count profiles prioritize CPU quotient
   computation and GPU opening work; preprocessing is already reused by mode.
5. Portable event accounting, readiness checks, deterministic arrivals and offline
   report views are implemented. The retained native count-four shared-owner resource plan admits
   both workers. The prepared Mac package still awaits external execution.
6. After the arrival backend and all readiness gates are qualified, run the
   two-hour pilot. Retain source-pinned JSON, root audits, application
   events, backlog and resource measurements. No delivered-transaction campaign
   or sustained-service qualification has been completed.

## Historical evidence

The initial export includes 62 historical evidence documents, recognized worker
and controller runs, older paired runs, and diagnostics from the remaining
archives. The catalog reports exact run, event and sample counts. It also lists
unavailable historical references, pin mismatches and campaigns for which only
documentary evidence remains.

- `catalog.json` contains summaries, milestones, complete evidence documents,
  controller campaign summaries, comparison windows and provenance.
- `runs/*.json` retains full structured measurements, exact timestamp and counter
  values, configuration, accounting, proof durations, sources and limitations.
- `index.html` embeds gzip-compressed copies of the catalog and every run.
  Selecting a run decompresses its data. Downloads contain the complete JSON.
- [FORMAT.md](FORMAT.md) defines the portable version 1 import contract.

Full retention makes this a substantial dataset: approximately 380 MB including
the standalone HTML. Each JSON file is below GitHub's individual file limit.
Charts reduce drawing density; stored event and sample rows are not downsampled.
No proof payloads, wallet stores, keys, binaries or arbitrary log text are copied.
Structured source hashes remain available after `target/` and `/tmp` are removed.
Some original files had already disappeared before this export; their references
and remaining documentary results are retained.

## Read the metrics

The service target is **4 valid, unique user transactions durably applied to
canonical host-chain state per minute**. The full measurement window includes
outages and recovery. Payouts, duplicates, invalid transactions and failed or
abandoned candidates are excluded; reorg reversals are separate.

The current aggregation benchmark does not establish attainment of that target.
Its jobs consume **eight already-created non-issuance wallet proofs**, reuse the
same fixture, create seven recursive proofs and independently audit the root on
CPU. Wallet proving, network delivery and chain acceptance are outside its scope.

For the five-round multi-GPU campaign:

| Measure | Sequential | Concurrent |
|---|---:|---:|
| Aggregate fixture transactions/minute | 2.183540 | 2.710593 |
| Median pair makespan, seconds | 436.539051 | 325.456042 |
| Median individual job latency, seconds | 218.425103 | 315.584569 |

Aggregate rate is completed CPU-audited transaction inputs divided by the sum of
measured pair windows. Each concurrent window is counted once. A rate derived from
the median pair time is a different statistic. Failed work consumes time but adds
no successful transactions. Unknown transaction counts remain unknown.

Whole-job duration, recursive command time, stage duration and pair makespan are
different boundaries. Historical controller manifests often have recursive
command time but no whole-job duration. Registration and component diagnostics
are not treated as completed user transactions.

CPU/GPU phase totals and cumulative counters are non-additive. Separate processes
can reset counters. The report does not sum checkpoints or align OpenCL device
clocks to host clocks without recorded anchors. Configured reservations are not
observed peaks. Apple unified memory is one shared pool, not host RAM plus VRAM.
Dropped events, open profiling spans, missing samples and partial runs remain
visible.

## Commands

From the repository root, with Python 3.10 or newer:

```sh
# Import all surviving historical archives and evidence, then build HTML.
python3 lattica-prover-p3/scripts/block-v2-benchmark-report.py import-history

# Import a new controller archive, or one portable run JSON from another system.
python3 lattica-prover-p3/scripts/block-v2-benchmark-report.py ingest --input /path/to/archive
python3 lattica-prover-p3/scripts/block-v2-benchmark-report.py ingest --input /path/to/apple-run.json

# Rebuild using only the committed JSON; does not read target or probe hardware.
python3 lattica-prover-p3/scripts/block-v2-benchmark-report.py render

# Validate run schemas, source-independent dataset hashes and computed rates.
python3 lattica-prover-p3/scripts/block-v2-benchmark-report.py check

# Reporting unit tests; no benchmark workers are started.
python3 lattica-prover-p3/scripts/test-block-v2-benchmark-report.py
```

`--output /path/to/report` uses another dataset directory. `--root /path/to/repo`
changes historical discovery and the default output location.

Portable run IDs are immutable. Importing identical content again is harmless;
different content with the same ID is rejected. Use a new ID for a new run.
Historical adapters use source identity so partial archive exports can be
refreshed when a controller finishes. Writes use temporary files and atomic
replacement. A directory lock serializes dataset writers; after an interrupted
export, confirm the exporting process has stopped before removing `.export-lock`,
then repeat the export. Run `check` before committing.

Optional browser QA uses an externally installed Playwright:

```sh
node lattica-prover-p3/scripts/test-block-v2-benchmark-browser.mjs
```

Set `PLAYWRIGHT_MODULE` to an absolute Playwright module path if it is not on the
normal Node module search path, and `CHROMIUM` to the browser executable if needed.
The check opens the actual HTML with networking disabled, exercises filters,
downloads, a large timeline, keyboard-accessible zoom controls, mobile layout and
print styles, and saves screenshots in a temporary directory.

## Automatic export

The current multi-GPU runner, multi-GPU comparison runner and scratch benchmark
suite export after measured work and cleanup. Generated pipeline and GPU-default
launchers inherit the scratch-suite hook. Existing frozen controllers are
unchanged.

The comparison controller sets `LATTICA_BENCHMARK_REPORT_DEFER=1` in its child
runner environment. Only the outer comparison exports, after pair timing has
finished. Export errors print a retry command and preserve the benchmark result
and raw evidence. No export starts proving or performs Git operations.

For a new enclosing harness that times one of these controllers, set the same
environment variable for its timed child and export its archive after all timing
ends. An interrupted/failing comparison records its elapsed pair window before
the export hook runs.

New worker configurations may provide `benchmark_workload`, using the workload
object described in FORMAT.md. Include a public count-evidence reference and an
explicit fixture-reuse flag. Otherwise transaction counts remain unavailable.

Future results are written under `docs/benchmarks/` for the normal Git workflow:

```sh
git add docs/benchmarks
git commit -m "docs: retain solving benchmark results"
```

Do not edit generated HTML or normalized measurements to change a result.
Update the importer, template or documentary interpretation, then regenerate and
review the diff. Milestone statuses are conservative editorial assessments;
benchmark success alone does not mark an entire engineering phase achieved.


Paired typed candidate — 2026-10-05
----------------------------------

The [first paired GPU qualification](../evidence/block-v2-typed-paired-gpu-2026-10-05.json)
passed on the laptop GPU: four fresh proofs in 133.268 seconds, a 1,683,948-byte
root, an independent CPU root audit and seven rejected mutations. It uses a
separate twelve-key registry.

[Five alternating matched pairs](../evidence/block-v2-typed-paired-comparison-2026-10-05.json)
now pass: **10 CPU-audited roots, 60 fresh proofs**, and zero worker memory events.
Median worker time was **238.312 seconds for finalizer / 135.675 seconds for paired**.
The median reduction within pairs was **43.068%** (42.357–43.418%), with paired
proving faster in all five pairs. The fixed assignment was 23 Rayon threads,
35 GiB worker RAM, 25.75 GiB spill, 7 GiB managed GPU memory and the provisional
7.25 GiB context allowance.

The report's matched campaign table now includes these construction comparisons.
Rates use each worker window once: **0.756 / 1.326 useful fixture inputs per minute**.
They exclude issuance, wallet proving, registry preparation and durable host
application. Incomplete trials, changed source pins or missing run mappings
withhold both comparison rates.

[The desktop paired qualification and per-device calibration](../evidence/block-v2-typed-paired-calibration-2026-10-05.json)
now pass. The desktop run produced four fresh proofs in 171.875 seconds, passed
its CPU audit, and had zero memory events. It used 6 GiB managed GPU memory;
the laptop observations used 7 GiB. Fresh measured context peaks of 200 / 266 MiB
support the policy's 512 MiB minimum allowance on each GPU. The new fleet
assignment retains 18 GiB RAM and 14.25 GiB spill per worker, with 12 / 11 Rayon
threads. [Five alternating sequential/concurrent pairs](../evidence/block-v2-typed-paired-repetitions-2026-10-05.json)
completed with **20 CPU-audited roots and 80 fresh proofs**, with zero worker or
parent memory events. Median two-root elapsed time was **316.521 seconds
sequential / 197.872 seconds concurrent**. The median reduction within pairs was
**37.486%** (36.249–37.855%), with concurrent execution faster in all five pairs.
Useful fixture throughput was **1.138 / 1.813 inputs per minute**. These rates
exclude issuance, wallet proving, registration and durable host application.
Each GPU proves an independent root. Other mixed counts remain pending.

Query readback experiment — 2026-10-05
-------------------------------------

[Five matched row/gather pairs](../evidence/block-v2-query-gather-comparison-2026-10-05.json)
passed **10 independent CPU root audits and 40 fresh proofs**, with no memory
events. Median worker time was **133.599 / 133.298 seconds**. The median change
within pairs was **0.225% faster with gather**, with a range of **−0.668% to
0.918%**; gather was faster in three of five pairs. The same binary, public
fixture, GPU and resource limits were used in both arms.

Useful fixture throughput was **1.348 / 1.350 inputs per minute**. These rates
exclude issuance, wallet proving, registration and durable application. Gather
reduced downloads from **15,360 to 120** per root, but the median reconstruction
span remained **10.869 / 10.878 seconds**. Row readback remains the default
because this series did not establish a consistent solving-time improvement.
The gather path is opt-in and its Metal implementation still needs Mac validation.

The report includes the query mode in each run and retains matched comparison
windows. Changed binary, fixture, profile or resource pins, missing audits,
invalid timings and incomplete run mappings withhold both rates. The
[count-matrix controller](../evidence/block-v2-typed-count-matrix-tooling-2026-10-05.json)
is ready for the remaining mixed counts with conservative per-device admission.
Instructions are in [`typed-benchmark-README.txt`](../../lattica-prover-p3/scripts/typed-benchmark-README.txt).
