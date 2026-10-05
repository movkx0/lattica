#!/usr/bin/env python3
"""Report the pinned standalone pilot without changing or restarting its prover."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shlex

SPEC = importlib.util.spec_from_file_location("scalability", Path(__file__).with_name("block-v2-scalability.py"))
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


def separate_controller_snapshot(raw, controller_unit):
    BENCH.require(re.fullmatch(r"lattica-v2-[\w-]+\.service", controller_unit), "invalid controller unit")
    lines = raw.splitlines(keepends=True)
    completions = [i for i, line in enumerate(lines) if line.strip() == "bounded_gpu_recursive_trial=PASS"]
    BENCH.require(len(completions) == 1, "pilot must contain exactly one successful completion")
    split = completions[0] + 1
    suffix = "".join(lines[split:]).strip().splitlines()
    BENCH.require(len(suffix) == 1 and suffix[0].startswith("stage_cgroup_accounting "),
                  "unexpected standalone controller log suffix")
    tokens = shlex.split(suffix[0])
    BENCH.require(tokens[0] == "stage_cgroup_accounting" and all("=" in token for token in tokens[1:]),
                  "unexpected controller accounting token")
    pairs = [token.split("=", 1) for token in tokens[1:]]
    BENCH.require(len({key for key, _ in pairs}) == len(pairs), "duplicate controller accounting field")
    f = dict(pairs)
    numeric = ("memory_peak", "memory_swap_peak", "memory_max", "memory_swap_max", "cpu_usage_usec")
    BENCH.require(set(f) == {"unit", "scope", *numeric} and f["unit"] == controller_unit
                  and f["scope"] == "exec_stop_post_snapshot", "misbound controller accounting")
    values = {key: int(f[key]) for key in numeric}
    BENCH.require(all(value >= 0 for value in values.values()), "negative controller accounting")
    BENCH.require(0 < values["memory_max"] <= 3 * 2**30
                  and values["memory_peak"] <= values["memory_max"]
                  and values["memory_swap_peak"] == values["memory_swap_max"] == 0,
                  "controller resource gate failed")
    return "".join(lines[:split]), dict(unit=controller_unit, scope=f["scope"], **values)


def report(manifest_path, repository):
    reporting_code = {str(path): BENCH.digest(path)
                      for path in (Path(__file__).resolve(), Path(BENCH.__file__).resolve())}
    manifest = json.loads(manifest_path.read_text())
    BENCH.require(manifest["kind"] == "full_size_retained_tree_serial_transfer_pilot_not_repeat_qualification",
                  "wrong pilot manifest kind")
    BENCH.require(manifest["gpu_pipeline"] is False and manifest["gpu_retain_trees"] is True,
                  "unexpected pilot configuration")
    BENCH.require(all(BENCH.digest(repository / path) == expected for path, expected in manifest["sha256"].items()),
                  "pinned pilot source, executable, archive or fixture changed")
    raw_path = Path(manifest["log"])
    raw_hash = BENCH.digest(raw_path)
    proving, controller = separate_controller_snapshot(raw_path.read_text(), manifest["unit"])
    path = manifest_path.parent / "proving-only.log"
    if path.exists():
        BENCH.require(path.read_text() == proving, "existing proving-only log differs; preserve evidence")
    else:
        with path.open("x") as output:
            output.write(proving)
    result = BENCH.collect_result(path, Path(manifest["job_directory"]), 0, "retained-serial-pilot", True, False)
    BENCH.require(result["resource_telemetry_complete"], "pilot lacks proving/helper accounting")
    BENCH.require(BENCH.digest(raw_path) == raw_hash, "raw log changed during reporting")
    BENCH.require(all(BENCH.digest(path) == expected for path, expected in reporting_code.items()),
                  "reporting source changed while collecting pilot evidence")
    result.update(kind=manifest["kind"], raw_log_sha256=raw_hash,
                  controller_cgroup_snapshot=controller,
                  controller_accounting_excludes_later_cleanup=True,
                  source_pins_checked=True, reporting_code_sha256=reporting_code,
                  repeat_qualified=False, production_ready=False)
    BENCH.save_verified_report(manifest_path.parent / "result.json", result,
                               ("root_sha256", "log_sha256", "raw_log_sha256"))
    print(json.dumps({key: result[key] for key in ("recursive_command_ms", "final_merge_ms", "root_bytes",
                                                  "root_sha256", "resource_telemetry_complete", "vram")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("repository", type=Path)
    args = parser.parse_args()
    report(args.manifest, args.repository)
