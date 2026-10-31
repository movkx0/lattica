# Same-private-note CPU/GPU comparison

`note_workflow_report.py` is a read-only report proposal. It accepts either two
chronological guard records for a single screen, or six chronological records
for three strictly alternating CPU/GPU repetitions. Each record must select the
exact C020/C021 seven-case ignored test. It launches no process and performs no
proving, resource admission, adoption decision or production acceptance.

Example after the coordinator has completed and audited all six workers:

```text
python3 research/pq-direct-spend/tools/note_workflow_report.py \
  /absolute/runs/cpu-1.json /absolute/runs/gpu-1.json \
  /absolute/runs/cpu-2.json /absolute/runs/gpu-2.json \
  /absolute/runs/cpu-3.json /absolute/runs/gpu-3.json
```

GPU-first order is also accepted. Mixed order, overlapping intervals, reused
records, changed source snapshots, changed executables/build records, changed
guard limits, or changed environments within a backend are rejected. CPU/GPU
environments are each validated against their separately fixed policy. Their
common base and paths are fixed by the same executable path. The CPU worker
has no GPU selectors. The GPU worker fixes the device-tree baseline, eight
Rayon threads, 8 GiB managed device, 4 GiB context reserve and 24 GiB native/output
allowance. Worker source reservations must remain within 32 GiB; external
process limits remain at most 47 GiB with zero swap. Build records retain their
separate 200% CPU quota; workflow workers require 800%.

CPU receipt data must appear in `note_cpu_environment`; GPU receipt data must
appear in `note_startup_environment`. All three guard mode fields must be
present, and the unused note receipt and `owned_runtime_environment` must be
explicitly `null`. Mixed note/runtime receipts are rejected. The focused test
derives both backend plans from the current guard's actual `build_plan` function
and checks complete synthetic evidence using those receipts and environments.
It never calls the guard's execution entry point or queries a device.

The parser checks raw workflow and build log hashes, source/executable/build
provenance, guard terminal status and cleanup, and the recorded env-clear
service command. It accepts only the reviewed C020/C021 proof/profile/report
source pins embedded in the script. Revisions require deliberate re-review and
pin updates. It does not need to execute the binary or hash a subsequently
rebuilt binary to replay historical evidence. This binds the captured evidence;
it does not authenticate arbitrary fabricated guard files. The coordinator
retains the original recorded-build and terminal audits.

Each run must contain exactly seven ordered case records, identity records,
and managed-memory records, followed by one workflow and cleanup record. The
seven distinct public-statement digests must match across every run. All
randomized canonical packet hashes must remain distinct across the full
comparison. Counts, 2560 active/4096 padded rows, fresh preparations, two CPU
verifications per case, canonical roundtrips and original-owner destruction are
checked. CPU substage intervals, GPU reported proof intervals and disjoint
case intervals must fit their enclosing complete intervals.

GPU evidence additionally requires seven matching RTX 5080 identities and
seven successful GPU-required native stage reports. All fifteen required
cryptographic stages need completed device observations; CPU serialization is
reported separately. CPU runs reject GPU identities or native wrapper reports.
Managed Engine peaks are positive and at most 8 GiB, and the workflow value must
be their maximum. CPU managed peaks are absent. Neither value is called total
process device memory. External cgroup host peaks and source reservation peaks
remain separate fields. Total process device peak remains unavailable.

The output schema is `private-note-same-profile-cpu-gpu-comparison-v1`:

| Field | Meaning |
| --- | --- |
| `comparison` | Always `same_private_note_construction_cpu_versus_gpu`. |
| `stage` | `single_screen_pair` or `three_alternating_pairs`. |
| `cpu_median_complete_note_research_workflow_ns` | Median of complete CPU intervals, including fixture generation/admission, proof work, independent verification/roundtrip and cleanup. |
| `gpu_median_complete_note_research_workflow_ns` | Median of the identical GPU workflow boundary. |
| `cpu_over_gpu_complete_workflow_ratio` | CPU median divided by GPU median. This is only an execution-backend comparison for the same construction. |
| `case_medians` | All seven stable statement digests, CPU/GPU complete case medians, stage medians and case ratios. Fixture generation is separate from complete case intervals and included in the complete workflow. |
| `runs` | All raw stage/count/memory observations and record/log/build hashes, environment, source-snapshot hash, timestamps and external cgroup peak. |
| `actual_process_device_peak_bytes` | Always absent (`null`); no total device-memory observation exists. |

The complete RingCT, faithful RingCT qualification, protocol-redesign speedup,
research adoption, production acceptance and performance promotion flags are
always false. Even a ratio above 2 does not satisfy protocol-redesign adoption
criteria: that needs a separate matched faithful RingCT complete-workflow
baseline and semantic/security review. Mutation qualification stays separate
from these timing intervals. Inclusive native timings are never added to
complete case/workflow durations. Guard process wall time is retained as a
different metric.

The proposed focused tests use synthetic logs and temporary evidence files.
They cover exact identities, chronology, provenance, policy, cleanup, hash
binding, numerical types, median boundaries, native GPU coverage and memory
scope. They never create an executable or start a worker. No test or report
execution was performed by Agent C while preparing this proposal.
