#!/usr/bin/env python3
"""Actual executable rejection gates; never initializes a GPU or proves anything.

Invoke under the bounded native-validation guard. Every GPU invocation has an
intentionally wrong accounting-unit binding, independently of the tested gate.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gpu-worker", type=Path, required=True)
    parser.add_argument("--cpu-gpu-build", type=Path, required=True)
    parser.add_argument("--cpu-only", type=Path, required=True)
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix="lattica-gpu-entrypoint-") as root:
        job = str(Path(root) / "must-not-be-created")
        base = {key: value for key, value in os.environ.items() if not key.startswith(("LATTICA_", "OCL_"))}
        base.update(LATTICA_V2_GPU_HASH="1", LATTICA_V2_GPU_RETAIN_TREES="1", LATTICA_V2_GPU_PIPELINE="0",
                    LATTICA_V2_GPU_RESIDENT_LDE="0", LATTICA_V2_GPU_DEVICE="4294967295",
                    LATTICA_V2_QUOTIENT_FUSION="0", LATTICA_V2_GPU_OPENINGS="0",
                    LATTICA_V2_ACCOUNTING_UNIT="lattica-v2-gpu-grouped-intentionally-wrong-binding.service")

        def reject(name, binary, arguments, message, changes=None):
            env = {**base, **(changes or {})}
            result = subprocess.run([str(binary), *arguments], env=env, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
            if result.returncode != 1 or message not in output:
                raise ValueError(f"entrypoint gate {name} failed: code={result.returncode}, output={output!r}")
            if any(marker in output for marker in ("bounded_gpu_initialized", "gpu_grouped_research", "grouped_key_generated", "grouped_node_complete")):
                raise ValueError(f"entrypoint {name} performed work before rejection")
            if Path(job).exists():
                raise ValueError("entrypoint gate created a job")
            results.append({"name": name, "exit_code": result.returncode, "output": output})

        reject("cpu_gpu_build_rejected", args.cpu_gpu_build, ["not-an-operation", job], "CPU-only build without the gpu feature")
        for value in ("1", "true", "2", ""):
            reject("cpu_resident_" + repr(value), args.cpu_only, ["not-an-operation", job],
                   "cannot select resident GPU proving", {"LATTICA_V2_GPU_RESIDENT_LDE": value})
        reject("cpu_zero_resident_reaches_parser_without_gpu", args.cpu_only, ["not-an-operation", job], "Unapproved preparation only:")
        reject("gpu_preparation_rejected", args.gpu_worker, ["prepare", job], "supports register/wrap-pair/wrap-all/merge/merge-all only")
        external = ["00" * 32] * 3
        for operation in ("check-registered", "remove-inners", "verify-root"):
            reject("gpu_cpu_stage_" + operation, args.gpu_worker, [operation, job, *external],
                   "supports register/wrap-pair/wrap-all/merge/merge-all only")
        for key, value in (("LATTICA_V2_GPU_HASH", "0"), ("LATTICA_V2_GPU_RETAIN_TREES", "0"),
                           ("LATTICA_V2_GPU_PIPELINE", "1")):
            reject("gpu_explicit_" + key, args.gpu_worker, ["register", job, "1"], "requires explicit GPU_HASH=1", {key: value})
        for value in ("", "true", "2"):
            reject("gpu_resident_" + repr(value), args.gpu_worker, ["register", job, "1"],
                   "requires explicit LATTICA_V2_GPU_RESIDENT_LDE=0 or 1", {"LATTICA_V2_GPU_RESIDENT_LDE": value})
        for value in ("", "true", "01", "2"):
            reject("gpu_openings_" + repr(value), args.gpu_worker, ["register", job, "1"],
                   "requires explicit LATTICA_V2_GPU_OPENINGS=0 or 1", {"LATTICA_V2_GPU_OPENINGS": value})
        reject("gpu_openings_without_resident", args.gpu_worker, ["register", job, "1"],
               "GPU openings require the resident grouped backend", {"LATTICA_V2_GPU_OPENINGS": "1"})
        for value in ("0", "1"):
            reject("gpu_cgroup_binding_" + value, args.gpu_worker, ["register", job, "1"],
                   "requires its named accounting-bound service", {"LATTICA_V2_GPU_RESIDENT_LDE": value})
        reject("gpu_openings_cgroup_binding", args.gpu_worker, ["register", job, "1"],
               "requires its named accounting-bound service", {"LATTICA_V2_GPU_RESIDENT_LDE": "1", "LATTICA_V2_GPU_OPENINGS": "1"})
    pins = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in vars(args).items()}
    print(json.dumps({"schema": "gpu-grouped-entrypoint-gates-v1", "status": "PASS", "production_ready": False,
                      "scope": "actual executable rejection paths only; no GPU initialization or proof", "pins": pins,
                      "tests": results}, sort_keys=True))


if __name__ == "__main__":
    main()
