# Exact identity experiment guard and independent audit

Use `gpu-identity-reuse-experiment` in the recorded release lib-test build.
Run exactly one selector with `--exact --ignored --test-threads=1 --nocapture`:

- `ring_screen::identity_experiment::tests::gpu_direct_ring_identity_cold_baseline`
- `ring_screen::identity_experiment::tests::gpu_direct_ring_identity_receipt_cross_session`

Both require `LATTICA_DIRECT_RING_IDENTITY_QUALIFICATION=1` and a fresh exact
`LATTICA_DIRECT_RING_IDENTITY_OUTPUT_DIR`. The first requires
`LATTICA_DIRECT_RING_IDENTITY_MODE=baseline`, the second `receipt-v1`.
All remaining environment/physical-device/process controls match the existing
direct-full baseline-public-hash host-tree seven-ring guard. In particular,
managed GPU is 8 GiB, context 4 GiB, worker host 32 GiB, host trees 8 GiB and
direct machine HOST_OUTPUT is 32 GiB; this path has no separate native child.
The standalone 24 GiB native-stage allowance is not the launch HOST_OUTPUT.
Zero swap, 8 threads, row limit, fresh-memory/process caps remain unchanged.
The screen flag, public-hash candidate, unrelated owned modes and extra test
selectors must not be mixed into this profile. Do not relax baseline-only C024.

Output is exactly one `DIRECT_RING_IDENTITY_SCREEN ` JSON stdout record equal
to `identity-screen.json`, plus `preflight.json` and one `case-0` directory.
The case contains `proving.json`, `proof.bin`, `verification.json`, and
`workflow.json`; no failure report may be accepted. Bind raw-log, saved JSON,
proof bytes, executable/build/source records and terminal process/GPU evidence.
Require one actual passed exact ignored test and the original command/environment.

Root schema: `lattica-research-direct-ring-identity-screen-v1`. Both modes require
research_only=true, case_count=1, fresh_preprocessing_cap=true, original_shared_
ledger_receipt=false, complete_faithful_ringct_workflow=false, protocol_redesign_
twofold_qualified=false and production_acceptance_changed=false. Root counters:
validated_gpu_registration_receipts=2, validated_gpu_proof_receipts=1,
retired_gpu_sessions=2, independent_cpu_acceptances=1, mutation_rejections=2.
The nested workflow must equal saved workflow.json. Compare all numeric setup,
proving, verification, mutation and terminal fields to their original reports.
Require complete workflow time to cover all disjoint subphase boundaries,
complete screen >= workflow and guard wall >= screen; do not sum overlapping
native inclusive/device timers or mistake complete-screen time for a sum of
only proof/aggregation stages. Preserve source-derived caller/metadata limits.

Baseline: public_preprocessing_reused=false, reused_preprocessing_part="none",
identity_receipt_hits=0, full_gpu_identity_hashes_required=2. Workflow and
verification use their existing baseline schemas and reused_prover_state=false;
identity_reuse/profile fields must be absent. Exactly two full raw
bounded_gpu_program_identity markers and two miss markers with hint_present=false
must occur. Prover/verifier public_hash are equal actual baseline observations.

Receipt-v1: public_preprocessing_reused=true, reused_preprocessing_part=
"protocol-program-identity-only", identity_receipt_hits=1,
full_gpu_identity_hashes_required=1. Workflow schema is
`lattica-research-direct-ring-identity-reuse-workflow-v1`, profile is
`direct-ring-cross-session-identity-receipt-v1`, reused_prover_state=true.
Verification schema is `lattica-research-direct-ring-identity-reuse-verification-v1`.
Exactly one full hash, one cold miss without a hint and one real hit with
full_stream_checked=true must occur, in that order. Field counts/receipt byte
counts must match across cold and hit markers. Reject unexpected additional
identity markers, misses, retries, CPU replacement or missing markers.

Candidate verification.identity_reuse must be present with matching profile,
identity_hint_hit/full_identity_stream_checked/public_preprocessing_reused/
fresh_preprocessing_cap/prover_session_retired_before_verifier_start/
expected_statement_reconstructed=true. prepared_program_reused/proof_reused/
fresh_identity_gpu_hash=false. reused_part, lookup_digest and numerical ID must
match the source specification/independently rebuilt descriptor; receipt
payload equals the actual raw marker, receipt_sublimit=1048576,
combined_metadata_limit=67108864, idle_device_bytes=0,
receipt_retained_after_setup_bytes=0 and reuse_distance_registrations=0.
source_admitted_host_bytes is bounded by both limits and existing caller memory.
source_public_hash equals the prover's real observation.
verifier_fresh_public_hash equals verification.public_hash, which may be null
only on this actual hit. Never synthesize a fresh hash observation from source
provenance. Each native report must independently satisfy its actual scope;
registration reports are fresh cap setup and must not claim a fresh proof.

Artifact identity checks may reuse C024's bounded byte/header/descriptor/profile
parsing helpers and terminal validators where their input contracts match.
Do not invoke or broaden its baseline-only top-level acceptance or its helper
which requires identical fresh public-hash observations. Rebind actual proof.bin
hash/length/header to saved descriptor, expected fixture-0 public binding,
context 0x73, profile digest, active/padded rows and all public identities.
Use the existing strict native-receipt checker separately for the two setup
and one proof receipts. This specification supplies no audit PASS by itself.
