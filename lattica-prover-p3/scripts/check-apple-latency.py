#!/usr/bin/env python3
"""Qualify merged readback, opening-cache and query-gather paths on Apple Silicon."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("resident_checks", ROOT / "scripts/check-apple-resident.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    env = {k: v for k, v in os.environ.items() if not k.startswith("LATTICA_")}
    env.update(RAYON_NUM_THREADS="2", LATTICA_V2_GPU_RETAIN_TREES="1",
               LATTICA_V2_GPU_PIPELINE="0", LATTICA_V2_METAL_PIPELINE="reference",
               LATTICA_V2_METAL_MEMORY="shared", LATTICA_V2_METAL_KERNEL_VARIANT="reference",
               LATTICA_V2_METAL_WORKGROUP="256", LATTICA_V2_METAL_BATCH="1",
               LATTICA_V2_METAL_POSEIDON_DIAGONAL="specialized", LATTICA_V2_METAL_NTT_TABLES="on",
               LATTICA_V2_METAL_NTT_TILE_LOG2="12", LATTICA_V2_METAL_QUOTIENT="cpu",
               LATTICA_V2_METAL_PREFIX_STORE="separate", LATTICA_V2_METAL_DEFER_TIMING="1",
               LATTICA_SPILL_BACKING="memory", LATTICA_V2_GPU_OPENING_COMPACT="1",
               LATTICA_V2_GPU_DIRECT_READBACK="1", LATTICA_V2_GPU_QUERY_GATHER="0",
               LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE="0")
    cases = [
        ("salt-replay", "compact_salts_replay", False, {}),
        ("salt-proof", "gpu_compact_quotient_pipeline_preserves_full_proof_bytes", True, {"LATTICA_APPLE_COMPACT_SALTS": "1", "LATTICA_V2_GPU_QUERY_GATHER": "1", "LATTICA_APPLE_QUERY_SCRATCH_BYTES": "65536"}),
        ("query-unwind", "gpu_apple_query_reconstruction_error_and_unwind_release_permit", True, {}),
        ("phase-permits", "apple_phase_permits", False, {}),
        ("shared-prefix", "shared_prefix_publication_validation", False, {}),
        ("queue-retirement", "pending_command_retention_is_bounded_and_fully_accounted", True, {}),
        ("shared-preprocessing-proof", "gpu_apple_shared_preprocessing_preserves_proofs_and_private_randomness", True, {}),
        ("query-phase-proof", "gpu_apple_shared_preprocessing_preserves_proofs_and_private_randomness", True, {}),
        ("direct-layout", "direct_layout", False, {}),
        ("direct-field-edges", "direct_parallel_decode", False, {}),
        ("cache-planner", "denominator_cache::tests", False, {}),
        ("gather-planner", "query_reconstruct::tests", False, {}),
        ("opening-weights", "opening_compact_weights", False, {}),
        ("scratch-retirement", "gpu_apple_transient_retirement", True, {"LATTICA_APPLE_MEMORY_RECLAIM": "1"}),
        ("headroom-proof", "gpu_compact_quotient_pipeline_preserves_full_proof_bytes", True,
         {"LATTICA_V2_GPU_QUERY_GATHER": "1", "LATTICA_APPLE_MEMORY_RECLAIM": "1", "LATTICA_APPLE_QUERY_SCRATCH_BYTES": "65536"}),
        ("unwind-opening", "gpu_compact_opening_compression_and_ntt_failures_drain_before_release", True,
         {"LATTICA_APPLE_MEMORY_RECLAIM": "1"}),
        ("arithmetic", "arithmetic_matches_full_width_integer_oracle_in_both_memory_modes", True, {}),
        ("poseidon", "diagonal_and_poseidon_match_cpu_for_redundant_representatives", True, {}),
        ("ntt-direct", "gpu_resident_lde_multigroup_ntt_and_unequal_input_heights_match_cpu", True, {}),
        ("wide-lde-tiles", "gpu_wide_lde_tiles_preserve_columns_caps_and_paths", True, {}),
        ("large-buffer-fill", "large_buffer_shader_offsets_and_zero_fill_cover_full_ranges", True, {}),
        ("opening-cache", "gpu_compact_openings_match_original_and_cpu_for_real_ldes_and_all_points", True, {}),
        ("query-gather", "gpu_compact_prefix_readback_reconstructs_original_rows_salts_and_paths", True,
         {"LATTICA_V2_GPU_QUERY_GATHER": "1", "LATTICA_APPLE_COMPACT_SALTS": "1"}),
        ("proof-direct", "gpu_compact_quotient_pipeline_preserves_full_proof_bytes", True, {}),
        ("proof-direct-gather", "gpu_compact_quotient_pipeline_preserves_full_proof_bytes", True,
         {"LATTICA_V2_GPU_QUERY_GATHER": "1"}),
        ("proof-banded-gather", "gpu_compact_quotient_pipeline_preserves_full_proof_bytes", True,
         {"LATTICA_V2_GPU_QUERY_GATHER": "1", "LATTICA_V2_GPU_DIRECT_READBACK": "0"}),
        ("unwind-direct", "gpu_lde_error_and_unwind_drain_before_transform_reservations_release", True, {}),
    ]
    report = {"schema": "apple-latency-qualification-v1", "status": "RUNNING",
              "proof_source_sha256": checks.hashes(), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "environment": {k: v for k, v in env.items() if k.startswith("LATTICA_") or k == "RAYON_NUM_THREADS"},
              "full_benchmark_jobs": 0, "tests": []}
    def save():
        (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    save()
    try:
        for label, selected, ignored, options in cases:
            path = args.out / (label + ".log")
            started = time.monotonic()
            command = [str(binary), selected, *(["--ignored"] if ignored else []), "--test-threads=1", "--nocapture"]
            with path.open("w") as log:
                result = subprocess.run(command, env={**env, **options}, stdout=log, stderr=subprocess.STDOUT)
            contents = path.read_text()
            summaries = re.findall(r"test result: ok\. (\d+) passed; 0 failed", contents)
            passed = result.returncode == 0 and summaries and int(summaries[-1]) > 0
            row = {"label": label, "selection": selected, "status": "PASS" if passed else "FAIL",
                   "tests_passed": int(summaries[-1]) if passed else 0, "command": command, "environment": options,
                   "seconds": time.monotonic() - started, "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            report["tests"].append(row)
            save()
            print(label, row["status"], f'{row["seconds"]:.2f}s', flush=True)
            if not passed:
                raise RuntimeError(contents[-4000:])
        if checks.hashes() != report["proof_source_sha256"]:
            raise RuntimeError("proof sources changed during qualification")
        report["status"] = "PASS"
    except BaseException as error:
        report.update(status="FAIL", failure=str(error))
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
