# Completed 16 GB capacity validation — 2026-10-06 (r41)

The requested 16 → 32 → 64 sequence passed on one RTX 5080 Laptop GPU.
64 ordered inputs is the largest validated size within the requested/protocol
limit; an intrinsic GPU limit above that range was not tested.

- Three complete depth-six roots passed independent CPU audits. They contained
  16, 32 and 63 fresh recursive proofs respectively, with zero reused proofs.
- Recursive proving took 527.589715 s, 1,076.566615 s and 2,112.215279 s. Each
  job's sampled GPU process peak was 7,121,928,192 bytes (6.63 GiB).
- All three roots were 1,683,948 bytes, below the 2 MiB bound. The 64-input
  fixture contained 48 user transactions and 16 issuance inputs.
- The final audit rechecked binary hashes, all 185 compiled-input hashes,
  retained source hashes, per-count budgets, proof plans, fresh-node events,
  GPU identities, root hashes, CPU audit logs and non-overlapping invocation
  intervals. The successful 16-input result was retained across the pause;
  the resumed 32/64 attempts used fresh directories.
- Resumed-campaign cleanup checked 10 process records, seven terminal services
  and six accounting records, with zero memory-limit or OOM events. The earlier
  campaign's cleanup and interrupted attempt remain retained separately.
- The initial resumed observer launch failed before proving because the
  interpreter was omitted. Its terminal status and journal remain retained.
- 37 Python checks passed: four capacity-harness checks, seven Apple-package
  checks, and 26 report checks.
- The standalone report check passed with 819 indexed records and 298 evidence
  documents. The three capacity roots remain documentary results outside the
  indexed delivered-throughput totals.
- Offline Chromium checks passed at 1440 px and 390 px widths. There were no
  external requests, page errors or page overflow. The capacity table scrolls
  within its panel on narrow screens. Desktop and mobile screenshots were
  visually inspected, and the downloaded JSON matched the exact browser
  representation, preserving nanosecond integers as strings.

The [capacity qualification JSON](../evidence/block-v2-vram16-capacity-qualification-2026-10-06-r1.json)
and [r41 report QA](../evidence/block-v2-throughput-report-qa-2026-10-06-r41.json)
retain the results, scope, hashes and validation. Historical report snapshots
remain retained. Complete cold-start, post-seal and delivered-throughput gates
remain open; this publication started no new proving campaign.

---

# Capacity pause checkpoint validation — 2026-10-06 (r40)

The capacity campaign was stopped at the user's request. No new proving trial
was started while preparing this publication.

- Count 16 passed its independent CPU root audit: 16 fresh recursive proofs,
  527.589715 s proving, and a 7,121,928,192-byte sampled GPU process peak.
- Count 32 was interrupted before a complete root or audit; count 64 was not
  started. Maximum capacity remains undetermined.
- Cleanup verified 10 process identities, seven terminal services and six
  accounting records, with zero memory-limit/OOM events.
- All 214 frozen runtime files and 245 completed-run source references matched
  their retained sizes and SHA-256 hashes.
- 37 Python checks passed: four capacity-harness checks, seven Apple-package
  checks, and 26 report checks.
- The standalone report check passed with 819 indexed records and 291 evidence
  documents. The capacity result is retained as a separate documentary
  checkpoint; it is not added to the indexed delivered-throughput totals.
- Offline Chromium checks passed at 1440 px and 390 px widths, with no external
  requests, page errors or page overflow. The capacity table scrolls on narrow
  screens. The downloaded checkpoint JSON preserves nanosecond integers as
  strings, following the report's existing precision policy.
- Desktop and mobile screenshots were visually inspected. The existing
  four-of-five cache comparison and blocked pilot qualification remain visible.

The [r40 QA record](../evidence/block-v2-throughput-report-qa-2026-10-06-r40.json)
retains report, catalog, evidence and validation hashes. Older snapshots remain
unchanged. The current-source Apple Silicon instructions create unique package
and result directories, pin the fetched commit and retain failed attempts.
Actual Apple Silicon measurements remain pending external execution.

---

# Initial report validation — 2026-10-04

No new proving campaign was started to build this report.

## Dataset

- 62 historical evidence documents.
- 255 run and diagnostic records; 93 explicitly record a CPU audit.
- 3,760,823 host timeline intervals and 837,168 GPU timeline intervals.
- 167,369 resource samples.
- 38 unavailable historical references are listed in the catalog. Remaining
  documentary results are retained; missing originals are not reconstructed.

An independent scan of retained, non-alias log sources counted **4,597,991**
timeline intervals, exactly matching the normalized dataset. All run schemas,
summary values, JSON hashes and computed comparison rates passed the report
check command. There are no unreferenced JSON run files.

The five-round comparison recomputes to **2.183540461929761** sequential and
**2.7105934746929763** concurrent fixture transactions/minute. These are rates
for aggregation of already-created wallet proofs, not canonical chain throughput.

## Checks

- 26 report tests: transaction counting, concurrent/failed windows, unknown
  counts, audit requirements, exact integers, mixed dictionaries, counter resets,
  clock domains, malformed samples, pin gaps, legacy adapters, atomic writes,
  immutable portable imports, safe HTML embedding and export timing.
- 17 existing multi-GPU scheduler tests.
- 13 existing scratch benchmark tests.
- 7 existing pipeline benchmark tests.
- Offline Chromium: filters, full JSON download, large timeline and zoom,
  responsive desktop/mobile layouts and print styles. No JavaScript errors or
  HTTP/network requests; no mobile horizontal overflow.
- Visual inspection of desktop, mobile and timeline screenshots.

A separate temporary repository containing only the reporting code and retained
JSON regenerated byte-identical HTML without an original evidence directory or
target directory. The standalone HTML SHA-256 was:

    1ea4d14a04ec3ff428f54651d004cc94ad26ab56ff0ae2a376fd81d45c056d9c

This validates the reporting implementation and retention. It does not change
the production, recursive-security or four-wallet activation gates.
