#!/usr/bin/env python3
"""Freeze one 24-thread RAM-scratch follow-up without altering the prior suite."""
import ast
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "lattica-prover-p3/target"
SOURCE = ROOT / "lattica-prover-p3/scripts/block-v2-scratch-bench.py"
SOURCE_SHA = "4ad9d60de7a33d2fbce0d0ff4d2ac05eda860aa68481702378907687466f1117"
PREVIOUS = TARGET / "block-v2-scratch-bench-20261002"
OUT = TARGET / "block-v2-max-threads-20261002-a"
LAUNCHER = TARGET / "block-v2-max-threads-20261002-a-launcher.py"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    os.umask(0o077)
    if sha(SOURCE) != SOURCE_SHA:
        raise ValueError("completed-suite launcher changed; review before deriving")
    if OUT.exists() or LAUNCHER.exists():
        raise ValueError("follow-up already prepared; inspect it instead of overwriting")
    state = json.loads((PREVIOUS / "run-state.json").read_text())
    if state["status"] != "COMPLETE_RESEARCH_ONLY":
        raise ValueError("previous suite must be complete")
    if os.cpu_count() != 24 or len(os.sched_getaffinity(0)) != 24:
        raise ValueError("this follow-up requires all 24 host hardware threads")
    original = SOURCE.read_text()
    source = original
    changes = []

    def change(before, after):
        nonlocal source
        if source.count(before) != 1:
            raise ValueError("launcher template drift: " + before[:100])
        source = source.replace(before, after, 1)
        changes.append({"before": before, "after": after})

    change('ROOT = Path(__file__).resolve().parents[2]', f'ROOT = Path({str(ROOT)!r})')
    change('DEFAULT_PLAN = TARGET / "block-v2-scratch-bench-20261002"',
           f'DEFAULT_PLAN = Path({str(OUT)!r})\nPREVIOUS = Path({str(PREVIOUS)!r})')
    change('ARMS = ("disk8", "ram8", "ram16", "disk16")', 'ARMS = ("ram24",)')
    change('SCHEMA = "post-reboot-scratch-bench-v1"', 'SCHEMA = "max-hardware-threads-bench-v1"')
    change('require(threads in (8, 16), "unsupported thread count")',
           'require(threads == 24, "this follow-up requires 24 threads")')
    change('require(1 <= repeats <= 3, "choose one to three repeats per arm")',
           'require(repeats == 1, "this follow-up measures exactly one run")')
    change('threads = 16 if arm.endswith("16") else 8', 'threads = 24')
    change('"baseline_manifest": str(BASELINE), "source_artifacts": baseline["source_artifacts"],',
           '"baseline_manifest": str(BASELINE), "source_artifacts": baseline["source_artifacts"],\n'
           '            "previous_suite": str(PREVIOUS), "maximum_hardware_threads": 24,')
    change('pinned = [Path(__file__).resolve(), BASELINE, *support.iterdir()]',
           f'pinned = [Path(__file__).resolve(), BASELINE, *support.iterdir(),\n'
           f'              PREVIOUS / "plan.json", PREVIOUS / "run-state.json",\n'
           f'              PREVIOUS / "summary.json", Path({str(SOURCE)!r})]')
    change('"measured_runs": repeats * 4,', '"measured_runs": repeats * len(ARMS),')
    change('"proofs_started": 0, "requires_new_boot": True',
           '"proofs_started": 0, "requires_new_boot": False')
    change('require(boot_id() != plan["prepared_boot_id"], "reboot has not happened; preparation never starts proving")',
           'require(os.cpu_count() == 24 and len(os.sched_getaffinity(0)) == 24,\n'
           '            "all 24 hardware threads must be available")\n'
           '    require(json.loads((PREVIOUS / "run-state.json").read_text())["status"] == "COMPLETE_RESEARCH_ONLY",\n'
           '            "previous benchmark suite must be complete")')
    change('parser.add_argument("--repeats", type=int, default=3)',
           'parser.add_argument("--repeats", type=int, default=1)')
    ast.parse(source)
    with LAUNCHER.open("x") as stream:
        stream.write(source)

    # Exercise the actual generated worker command without starting any worker.
    spec = importlib.util.spec_from_file_location("max_threads_followup", LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    derived = module.derive_controller(module.TEMPLATE.read_text(), 24, Path("/tmp/validate-ram24"))
    controller = types.ModuleType("max_threads_controller")
    controller.__file__ = str(module.TEMPLATE)
    exec(compile(derived, str(module.TEMPLATE), "exec"), controller.__dict__)
    cfg = json.loads((PREVIOUS / "plan.json").read_text())["config"]
    cfg.update(job="/tmp/validate-job", evidence="/tmp/validate-evidence", scratch_dir="/tmp/validate-ram24")
    argv = controller.stage_command(cfg, "lattica-v2-validation.service", "worker.service", "pairs", ["wrap-all"])
    required = ("--setenv=RAYON_NUM_THREADS=24", "--property=MemoryMax=44G", "--property=MemorySwapMax=0",
                f"--setenv=LATTICA_SPILL_MAX_BYTES={34 * (1 << 30)}", "--setenv=LATTICA_V2_GPU_OPENING_COMPACT=1")
    if not all(arg in argv for arg in required):
        raise ValueError("derived worker command changed settings")
    if module.steps({"repeat_blocks": [["ram24"]]}) != [
            ("ram24", "register-ram24", True), ("ram24", "round-1-ram24", False)]:
        raise ValueError("unexpected follow-up run count")
    with patch.object(module.os, "sched_getaffinity", return_value=set(range(23))):
        try:
            module.preflight(OUT, {}, None)
        except ValueError as error:
            if "24 hardware threads" not in str(error):
                raise
        else:
            raise ValueError("reduced CPU availability was accepted")

    subprocess.run([sys.executable, "-B", str(LAUNCHER), "prepare"], check=True)
    (OUT / "launcher.diff").write_text("".join(difflib.unified_diff(
        original.splitlines(keepends=True), source.splitlines(keepends=True),
        fromfile=str(SOURCE), tofile=str(LAUNCHER))))
    (OUT / "derivation.json").write_text(json.dumps({
        "source": str(SOURCE), "source_sha256": SOURCE_SHA,
        "launcher": str(LAUNCHER), "launcher_sha256": sha(LAUNCHER),
        "changes": changes, "validation": ["derived controller compiles", "24-thread worker flags and memory bounds",
                                              "one registration and one measured run", "reject fewer than 24 available threads"],
        "production_ready": False, "proofs_started_by_preparation": 0,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
