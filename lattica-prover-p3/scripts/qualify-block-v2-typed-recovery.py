#!/usr/bin/env python3
"""Qualify fresh CPU-process recovery of a new, completed typed GPU journal.

This advances the ORIGINAL journal to epochs two and three. Use a dedicated
trial whose mutable journal has not been published in another pinned record.
Every pre/post state is archived; existing benchmark journals are left alone.
No proving worker or native chain update is started by this controller.
"""
import argparse
import copy
from decimal import Decimal
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

SPEC = importlib.util.spec_from_file_location("typed_recovery_fleet", Path(__file__).with_name("block-v2-typed-multi-gpu-run.py"))
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
T, G = F.T, F.G
MAX_RUNTIME_BYTES = 1 << 30
MAX_RUNTIME_FILES = 8192


def inventory(runtime):
    """Content and inode inventory, excluding mutable read/access timestamps."""
    if runtime.is_symlink() or not runtime.is_dir():
        raise ValueError("runtime archive requires a nonsymlink directory")
    files, total = [], 0
    for path in sorted(runtime.rglob("*")):
        if path.is_symlink():
            raise ValueError("runtime archive refuses symlinks")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("runtime archive requires regular files")
        stat = path.stat()
        total += stat.st_size
        if total > MAX_RUNTIME_BYTES or len(files) >= MAX_RUNTIME_FILES:
            raise ValueError("runtime archive exceeds retention bound")
        files.append({"member": str(path.relative_to(runtime)), "bytes": stat.st_size,
                      "sha256": G.digest(path), "device": stat.st_dev, "inode": stat.st_ino})
    if not files:
        raise ValueError("runtime archive is empty")
    return files


def archive(runtime, destination):
    before = inventory(runtime)
    with tarfile.open(destination, "x:gz") as stream:
        for item in before:
            stream.add(runtime / item["member"], arcname=item["member"], recursive=False)
    if inventory(runtime) != before:
        raise ValueError("runtime changed during archival")
    return {"archive": F.C.pin(destination), "members": before}


def assert_unchanged(runtime, before):
    if inventory(runtime) != before:
        raise ValueError("rejected recovery mutated the original GPU journal")


def checked_result(directory, root, count, epoch, expected_nodes):
    result = json.loads((directory / "summary.json").read_text())
    if (result.get("record_type") != "typed_gpu_journal_recovery"
            or result.get("status") != "succeeded" or result.get("recovery_epoch") != epoch
            or result.get("count") != count or result.get("verified_cached_nodes") != expected_nodes
            or result.get("root_bytes") != root.stat().st_size):
        raise ValueError("recovery result identity/count differs")
    for key in ("cpu_audited_root", "original_gpu_journal", "root_identical", "wrong_head_rejected", "resources_released"):
        if result.get(key) is not True:
            raise ValueError("recovery result lacks " + key)
    for key in ("unresolved_attempts", "unresolved_workspaces", "prover_jobs_started", "fresh_recursive_proofs", "native_blocks_applied"):
        if type(result.get(key)) is not int or result[key] != 0:
            raise ValueError("recovery started work or retained unresolved resources: " + key)
    if G.digest(directory / "recovered-root") != G.digest(root):
        raise ValueError("recovered root bytes changed")
    if result.get("production_ready") is not False or result.get("arrival_backend_integrated") is not False:
        raise ValueError("recovery result exceeds its qualified scope")
    return result


def execute(command, directory, env, should_pass):
    directory.mkdir()
    G.durable(directory / "command.json", [str(value) for value in command], True)
    started = time.time_ns()
    with (directory / "process.log").open("wb") as output:
        process = subprocess.Popen([str(value) for value in command], env=env,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        timed_out = False
        try:
            code = process.wait(timeout=180)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            code = process.wait()
    observation = {"pid": process.pid, "started_ns": started, "finished_ns": time.time_ns(),
                   "exit_code": code, "timed_out": timed_out, "expected_success": should_pass}
    G.durable(directory / "process.json", observation, True)
    if timed_out or (code == 0) != should_pass:
        raise ValueError("CPU recovery exit differs from expectation: " + str(directory))
    return observation


def negative_cases(out, budget, budget_path, root, head):
    """Retain mutated inputs separately from each child process's directory."""
    bad_budget = copy.deepcopy(budget)
    bad_budget["host"]["worker_bytes"] -= 1
    bad_budget_path = out / "wrong-budget.json"
    G.durable(bad_budget_path, bad_budget, True)
    head_bytes = bytes.fromhex(head)
    wrong_head = (bytes([head_bytes[0] ^ 1]) + head_bytes[1:]).hex()
    corrupt_root = out / "corrupt-root.proof"
    altered = bytearray(root.read_bytes())
    altered[len(altered) // 2] ^= 1
    with corrupt_root.open("xb") as stream:
        stream.write(altered)
    return [("wrong-budget", bad_budget_path, root, head, 2),
            ("wrong-head", budget_path, root, wrong_head, 2),
            ("old-epoch", budget_path, root, head, 1),
            ("corrupt-root", budget_path, corrupt_root, head, 2)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trial", type=Path, required=True)
    parser.add_argument("--cpu-binary", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "record_type": "typed_gpu_journal_recovery_qualification",
              "status": "preparing", "processes": [], "recovered": [], "states": [],
              "fresh_recursive_proofs": 0, "prover_jobs_started": 0, "native_blocks_applied": 0,
              "production_ready": False, "arrival_backend_integrated": False,
              "active_worker_recovery_qualified": False}
    locks = []
    try:
        locks = G.lock_fleet()
        if json.loads(G.systemctl("list-units", "lattica-v2-multi-*.service",
                                 "--state=active,activating,deactivating", "--output=json", "--no-pager")):
            raise ValueError("a proving worker is active")
        trial = args.trial.resolve(strict=True)
        cpu, fixture = args.cpu_binary.resolve(strict=True), args.fixture.resolve(strict=True)
        config = json.loads((trial / "config.json").read_text())
        result = json.loads((trial / "001-typed/result.json").read_text())
        if config.get("execution_backend") != "typed-dag" or config.get("construction") != "paired":
            raise ValueError("recovery requires a completed paired typed-DAG trial")
        T.check_pins(config["pins"])
        F.validate_backend_result(config, result)
        assignment, assignment_sha, _ = F.calibration_assignment(trial, config, result)
        checked = F.C.checked_trial(trial, "paired", config["count"], assignment, assignment_sha,
                                   config["pins"][config["gpu_binary"]])
        if fixture != Path(config["fixture"]):
            raise ValueError("independently supplied fixture differs from pinned trial")
        runtime = trial / "001-typed/proofs/execution"
        root = trial / "001-typed/root-only/node.6.0"
        expected = trial / "expected.json"
        expected_data = json.loads(expected.read_text())
        head = bytes(expected_data["profile"]).hex()
        budget_path = trial / "001-typed/budget.json"
        cpu_host = F.R.detect_host("/tmp")
        threads = max(1, min(result["budget"]["cpu"]["rayon_threads"], int(Decimal(cpu_host["cpu_capacity"]))))
        env = {**T.clean_environment(), "RAYON_NUM_THREADS": str(threads)}
        pins = {**config["pins"], **dict(T.pin(p) for p in (cpu, budget_path, root, expected,
            Path(__file__), Path(F.__file__), Path(F.C.__file__), Path(T.__file__), Path(G.__file__), Path(F.R.__file__)))}
        report.update(status="running", source_trial=checked, pins=pins,
                      cpu_host=cpu_host, rayon_threads=threads, runtime=str(runtime))
        report["states"].append(archive(runtime, out / "original-runtime.tar.gz"))
        before = inventory(runtime)
        negative = negative_cases(out, result["budget"], budget_path, root, head)
        for name, budget, proof, current_head, epoch in negative:
            directory = out / name
            command = [cpu, "execution-recover", fixture, expected, runtime, budget, proof,
                       current_head, epoch, directory / "recovery"]
            observation = execute(command, directory, env, False)
            assert_unchanged(runtime, before)
            report["processes"].append({"name": name, **observation, "runtime_unchanged": True})
            G.durable(out / "summary.json", report)
        for epoch in (2, 3):
            directory = out / f"epoch-{epoch}"
            command = [cpu, "execution-recover", fixture, expected, runtime, budget_path, root,
                       head, epoch, directory / "recovery"]
            observation = execute(command, directory, env, True)
            recovered = checked_result(directory / "recovery", root, config["count"], epoch,
                                       checked["fresh_proofs"])
            report["processes"].append({"name": f"epoch-{epoch}", **observation})
            report["recovered"].append(recovered)
            report["states"].append(archive(runtime, out / f"epoch-{epoch}-runtime.tar.gz"))
            T.check_pins(pins)
            G.durable(out / "summary.json", report)
        report.update(status="succeeded", rejected_mutations=len(negative),
                      fresh_cpu_recovery_processes=len(report["recovered"]),
                      exact_root_reused=True, current_runtime_files=inventory(runtime))
    except BaseException as error:
        report.update(status="failed", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        G.durable(out / "summary.json", report)
        for lock in locks:
            os.close(lock)
    print(json.dumps({"status": report["status"], "fresh_cpu_recovery_processes": len(report["recovered"]),
                      "rejected_mutations": report["rejected_mutations"], "fresh_recursive_proofs": 0}))


if __name__ == "__main__":
    main()
