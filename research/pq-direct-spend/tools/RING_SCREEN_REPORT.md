# Seven-case direct-ring evidence audit

`ring_screen_report.py RECORD.json` reads the coordinator's completed exact-test
record and prints a JSON evidence report. It never launches a worker, writes the
evidence directory, executes a proof verifier, or qualifies performance. Run the
script and its focused tests only through the coordinator's serialized queue.

The accepted producer is C023 with its C023-r2 terminal-scope correction:
`ring_screen::tests::gpu_seven_distinct_ring_workflows_verify_roundtrips_and_retire`.
It requires the exact baseline public-hash, host-tree `direct-full` environment
and a physical GPU UUID. The service retains the existing 45 GiB process maximum,
43 GiB high watermark, 47 GiB fresh-memory admission, zero swap, eight-thread CPU
quota, 8 GiB managed device allowance, 4 GiB context reserve, 32 GiB worker host
allowance, and at most 24 GiB native host allowance.

The audit checks guard and build completion, full matching source snapshots,
reviewed relation/compiler/artifact/screen source pins, recorded executable hash,
log hashes, the actual env-clear service command, and terminal process cleanup.
It does not require the old executable to remain on disk: the completed guard's
recorded before/after executable hash is the historical evidence. Current audit
helper sources are pinned separately and their hashes appear in the result.

The output directory must contain exactly `screen.json`, `preflight.json`, and
seven case directories. Each case contains exactly `workflow.json`, `proving.json`,
`verification.json`, and `proof.bin`. Readers and directory inventories are
bounded; symlinked evidence entries, extra/failure files, duplicate JSON keys,
and nonfinite numbers are rejected.

All seven preflight statements, fourteen serials, and seven fresh artifact hashes
must be distinct. Case ordering, preflight identities, case reports, disk suite,
and the single stdout summary must agree. Artifact SHA3, profile/context/manifest/
registration header fields, canonical public bindings, exact compiler capacities,
complete numerical host/device phase bounds, native OpenCL stage receipts, fixed
physical identity, and the public-hash observations are checked. The seven prover
sessions must claim completed proofs; the seven independent preprocessing sessions
must report `completion_claimed=false`. Both kinds must retire and drain cleanly.
Independent CPU verification and two cryptographic mutation rejections per case
remain reported evidence from the pinned executable, not new verification by this
Python script.

The report retains active/padded rows, setup/proving/reconstruction/CPU verification
and mutation timings, whole-case and suite times, admitted host partitions,
managed GPU peaks and the guard's cgroup host peak. It checks all reported nested
lifecycle times fit their enclosing phases. The suite timer includes preflight,
seven complete case lifecycles, owner destruction and case-report writes; final
summary serialization and process launch remain excluded and the guard wall time
is separately reported. Actual process device peak is unavailable and stays null.

Seven direct relation proofs are research evidence only. Recursive proof count
is zero. Faithful RingCT workflow, N3/N4 aggregation, protocol-redesign 2x speedup,
cryptographic security review and production adoption remain false. This tool
makes no comparison against a different protocol or the historical throughput.

`test_ring_screen_report.py` uses the existing synthetic direct-artifact and note
guard fixture factories. Its bytes are deliberately not valid proofs. Positive
cases test consistency acceptance; negative cases exercise missing/reordered or
duplicate identities, serials or artifacts, altered/rehashed headers, wrong
terminal completion scope, native-stage failures, changed resource bounds,
incomplete timers, extra/symlinked evidence, duplicate stdout/JSON, source/build/
executable/log/environment drift, and incomplete cleanup. Passing these tests is
parser validation only. No test here launches a worker or creates GPU evidence.
