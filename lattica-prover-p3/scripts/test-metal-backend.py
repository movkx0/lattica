#!/usr/bin/env python3
"""Run bounded Apple GPU qualification, preserving each test's log and result."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

TESTS = [
    "chunked_transfers_preserve_individual_gpu_intervals",
    "arithmetic_matches_full_width_integer_oracle_in_both_memory_modes",
    "gpu_resident_lde_columns_caps_and_paths_match_cpu",
    "gpu_resident_lde_multigroup_ntt_and_unequal_input_heights_match_cpu",
    "gpu_opening_reduction_matches_cpu_all_points_and_unequal_heights",
    "gpu_opening_pinned_partial_chunks_match_pageable_and_cpu_without_extra_allocations",
    "gpu_compact_openings_match_original_and_cpu_for_real_ldes_and_all_points",
    "gpu_resident_matches_all_cpu_commitment_streams_across_active_clones",
    "gpu_resident_admission_errors_do_not_consume_masks_or_salts",
    "gpu_resident_research_switch_only_selects_explicit_proving_configs",
    "gpu_resident_full_strength_cubic_proofs_replay_through_original_cpu_pcs",
    "gpu_openings_full_strength_cubic_proofs_replay_through_original_cpu_pcs",
    "gpu_openings_match_reference_transcript_and_preprocessing",
    "gpu_quotient_pipeline_matches_cpu_matrices_caps_and_openings",
    "gpu_quotient_pipeline_proof_matches_upstream_and_cpu_verifies",
    "gpu_compact_prefix_readback_reconstructs_original_rows_salts_and_paths",
    "gpu_compact_prover_data_preserves_fixed_seed_proof_bytes_and_challenger",
    "gpu_compact_quotient_pipeline_preserves_full_proof_bytes",
    "gpu_lde_error_and_unwind_drain_before_transform_reservations_release",
    "gpu_opening_error_and_unwind_drain_before_allocations_release",
    "gpu_compact_opening_compression_and_ntt_failures_drain_before_release",
    "gpu_retained_copy_error_and_unwind_release_reservations",
    "gpu_retained_query_error_drains_pending_kernel_and_preserves_tree",
    "gpu_retained_admission_rejects_live_trees_and_recovers_after_drop",
    "gpu_failed_drain_aborts_worker_and_releases_job_lease",
    "gpu_commitments_openings_salts_order_caps_and_tiles_match_cpu",
    "gpu_retained_trees_keep_context_alive_and_survive_workspace_reuse",
    "gpu_process_death_releases_job_lease",
    "gpu_spill_backed_bit_reversed_inputs_match_resident_cpu_openings",
    "gpu_cubic_wallet_proof_cross_verifies_with_unmodified_cpu_types",
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--filter", default="")
    args = parser.parse_args()
    binary = args.binary.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    listing = subprocess.check_output([binary, "--list"], text=True)
    names = [line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")]
    selected_tests = []
    for suffix in TESTS:
        if args.filter and args.filter not in suffix:
            continue
        selected = [name for name in names if name.endswith("::" + suffix)]
        if len(selected) != 1:
            raise RuntimeError("missing/ambiguous test: " + suffix)
        selected_tests.append((suffix, selected[0]))
    report = {"status": "RUNNING", "binary": str(binary),
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "git_base": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "controller_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "tests": [], "rss_limit_bytes": 3 << 30, "test_timeout_seconds": 180}
    def save():
        temp = args.out / "result.json.new"
        temp.write_text(json.dumps(report, indent=2) + "\n")
        temp.replace(args.out / "result.json")
    save()
    for mode in ("shared", "copy"):
        for suffix, selected in selected_tests:
            path = args.out / (mode + "-" + suffix + ".log")
            env = {**os.environ, "RAYON_NUM_THREADS": "4", "LATTICA_V2_METAL_MEMORY": mode,
                   "LATTICA_V2_GPU_RETAIN_TREES": "1", "LATTICA_V2_GPU_PIPELINE": "0",
                   "LATTICA_SPILL_BACKING": "memory", "LATTICA_SPILL_MAX_BYTES": str(1 << 30),
                   "LATTICA_V2_GPU_OPENING_COMPACT": "1" if suffix in {
                       "gpu_compact_prover_data_preserves_fixed_seed_proof_bytes_and_challenger",
                       "gpu_compact_quotient_pipeline_preserves_full_proof_bytes",
                   } else "0",
                   "LATTICA_V2_GPU_PARALLEL_READBACK": "1" if "quotient_pipeline_matches" in suffix else "0"}
            command = [str(binary), selected, "--exact", "--ignored", "--nocapture", "--test-threads=1"]
            started = time.monotonic()
            reason = None
            print("START", mode, suffix, flush=True)
            with path.open("w") as log:
                child = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                while True:
                    pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                    if pid:
                        child.returncode = os.waitstatus_to_exitcode(status)
                        break
                    if time.monotonic() - started > 180:
                        reason = "test timeout"
                    sample = subprocess.run(["/bin/ps", "-o", "rss=", "-p", str(child.pid)], capture_output=True, text=True)
                    if sample.returncode == 0 and sample.stdout.strip() and int(sample.stdout) * 1024 > 3 << 30:
                        reason = "3 GiB RSS limit exceeded"
                    if reason:
                        os.killpg(child.pid, signal.SIGKILL)
                    time.sleep(0.2)
            entry = {"test": selected, "memory": mode, "exit_code": child.returncode,
                     "stop_reason": reason, "wall_seconds": time.monotonic() - started,
                     "maximum_resident_bytes": usage.ru_maxrss, "log": str(path),
                     "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            entry["passed"] = child.returncode == 0 and reason is None and "1 passed; 0 failed" in path.read_text()
            report["tests"].append(entry)
            save()
            print("PASS" if entry["passed"] else "FAIL", mode, suffix, flush=True)
    report["status"] = "PASS" if report["tests"] and all(t["passed"] for t in report["tests"]) else "FAIL"
    save()
    raise SystemExit(0 if report["status"] == "PASS" else 1)

if __name__ == "__main__":
    main()
