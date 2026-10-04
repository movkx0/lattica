# Solving benchmark report

Open [index.html](index.html) directly in a current Chromium, Firefox or Safari.
It is a standalone HTML5 report: no server, package install, network connection
or original benchmark directory is needed.

The purpose is to measure useful transaction throughput and development against
the [P0–P5 engineering roadmap](../high-throughput-proving-plan.md#8-engineering-project-plan).
Apple silicon and Linux/OpenCL are development tracks. There is no hardware
leaderboard.

## Retained evidence

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
