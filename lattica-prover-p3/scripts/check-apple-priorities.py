#!/usr/bin/env python3
"""Focused correctness checks and short component comparisons; no full proofs of the benchmark fixture."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("resident_checks", ROOT / "scripts/check-apple-resident.py")
CHECKS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECKS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    env = {**os.environ, "RAYON_NUM_THREADS": "2", "LATTICA_V2_GPU_RETAIN_TREES": "1",
           "LATTICA_V2_GPU_PIPELINE": "0", "LATTICA_V2_METAL_PIPELINE": "reference",
           "LATTICA_V2_METAL_MEMORY": "shared", "LATTICA_V2_METAL_KERNEL_VARIANT": "reference",
           "LATTICA_V2_METAL_WORKGROUP": "256", "LATTICA_V2_METAL_BATCH": "1",
           "LATTICA_V2_METAL_POSEIDON_DIAGONAL": "reference", "LATTICA_V2_METAL_NTT_TABLES": "off",
           "LATTICA_V2_METAL_NTT_TILE_LOG2": "12", "LATTICA_V2_METAL_QUOTIENT": "cpu",
           "LATTICA_V2_METAL_PREFIX_STORE": "separate", "LATTICA_PROFILE_TIMELINE": "0",
           "LATTICA_V2_METAL_DEFER_TIMING": "1", "LATTICA_V2_GPU_OPENING_COMPACT": "1",
           "LATTICA_SPILL_BACKING": "memory", "LATTICA_V2_GPU_PARALLEL_READBACK": "0"}
    env.pop("LATTICA_SPILL_MAX_BYTES", None)
    specialized = {"LATTICA_V2_METAL_POSEIDON_DIAGONAL": "specialized"}
    cached = {**specialized, "LATTICA_V2_METAL_NTT_TABLES": "on"}
    resident = {**cached, "LATTICA_V2_METAL_PIPELINE": "resident", "LATTICA_V2_METAL_BATCH": "8"}
    fused = {**resident, "LATTICA_V2_METAL_PREFIX_STORE": "fused"}
    cases = [
        ("diagonal", "diagonal_and_poseidon_match_cpu_for_redundant_representatives", specialized, True),
        ("diagonal-unrolled", "diagonal_and_poseidon_match_cpu_for_redundant_representatives", {**specialized, "LATTICA_V2_METAL_KERNEL_VARIANT": "optimized"}, True),
        ("ntt-schedule", "ntt_schedule_covers_every_stage_with_bounded_local_storage", {}, False),
        ("ntt-cached", "gpu_resident_lde_multigroup_ntt_and_unequal_input_heights_match_cpu", {**cached, "LATTICA_V2_METAL_NTT_TILE_LOG2": "11"}, True),
        ("prefix-fused", "gpu_compact_prefix_readback_reconstructs_original_rows_salts_and_paths", {**fused, "LATTICA_V2_METAL_NTT_TABLES": "off"}, True),
        ("prefix-fused-cached", "gpu_compact_prefix_readback_reconstructs_original_rows_salts_and_paths", fused, True),
        ("proof-reference", "gpu_compact_quotient_pipeline_preserves_full_proof_bytes", specialized, True),
        ("proof-hybrid", "gpu_compact_quotient_pipeline_preserves_full_proof_bytes", fused, True),
        ("proof-typed-gpu", "gpu_compact_quotient_pipeline_preserves_full_proof_bytes", {**fused, "LATTICA_V2_METAL_QUOTIENT": "gpu"}, True),
        ("unwind", "gpu_lde_error_and_unwind_drain_before_transform_reservations_release", fused, True),
    ]
    report = {"schema": "apple-priority-components-v1", "status": "RUNNING", "tests": [], "components": [],
              "proof_source_sha256": CHECKS.hashes(), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "full_benchmark_jobs": 0, "notes": ["Small correctness proofs are distinct from the full seven-proof aggregation fixture.",
              "Two component shapes, one untimed warm-up and three samples each; five controlled configurations, no thread matrix.",
              "GPU stage counters overlap wall time; do not add them to wall time. These are not end-to-end speedups."]}
    def save():
        (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    def run(label, suffix, options, ignored):
        path = args.out / (label + ".log")
        started = time.monotonic()
        with path.open("w") as log:
            result = subprocess.run([str(binary), suffix, *( ["--ignored"] if ignored else []), "--test-threads=1", "--nocapture"],
                                    env={**env, **options}, stdout=log, stderr=subprocess.STDOUT)
        contents = path.read_text()
        passed = result.returncode == 0 and "1 passed; 0 failed" in contents
        row = {"label": label, "test": suffix, "options": options, "status": "PASS" if passed else "FAIL",
               "seconds": time.monotonic() - started, "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        print(label, row["status"], f'{row["seconds"]:.2f}s', flush=True)
        if not passed:
            report["tests"].append(row)
            raise RuntimeError(contents[-4500:])
        return row, contents
    try:
        for case in cases:
            row, _ = run(*case)
            report["tests"].append(row)
            save()
        for label, options in [("reference", {}), ("diagonal", specialized), ("cached", cached),
                               ("resident-separate", resident), ("resident-fused", fused)]:
            row, contents = run("component-" + label, "metal_priority_components", options, True)
            samples = [json.loads(line.split(" ", 1)[1]) for line in contents.splitlines() if line.startswith("metal_priority_sample ")]
            if len(samples) != 6:
                raise RuntimeError("Missing component samples")
            row.update(configuration=label, samples=samples, medians={})
            for shape in sorted({s["output_rows"] for s in samples}):
                chosen = [s for s in samples if s["output_rows"] == shape]
                row["medians"][str(shape)] = {key: statistics.median(s[key] for s in chosen)
                    for key in ("wall_seconds", "ntt_gpu_seconds", "sponge_gpu_seconds")}
            report["components"].append(row)
            save()
        if CHECKS.hashes() != report["proof_source_sha256"]:
            raise RuntimeError("Sources changed during checks")
        report["status"] = "PASS"
    except BaseException as error:
        report.update(status="FAIL", failure=str(error))
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
