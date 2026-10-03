#!/usr/bin/env python3
"""Opt-in real systemd/cgroup lifecycle check. No cryptography or proving.

Run with --run in an idle user manager after linking the grouped slice. Creates
only uniquely named test units; cleanup never stops unrelated services. Runtime
artifacts are emitted into a new directory supplied by the caller.
"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location("grouped_trial", HERE.with_name("block-v2-grouped-trial.py"))
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def wait_for(check, description, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise RuntimeError("timeout: " + description)


def properties(unit):
    result = subprocess.run(["systemctl", "--user", "show", unit,
                             "--property=LoadState,ActiveState,MainPID,ControlGroup",
                             "--no-pager"], text=True, capture_output=True, timeout=10)
    if result.returncode:
        raise RuntimeError("cannot observe unit: " + result.stderr)
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def terminal(unit):
    value = properties(unit)
    return value if (value.get("LoadState") == "not-found" or
                     value.get("ActiveState") in {"inactive", "failed"}) and value.get("MainPID", "0") == "0" else None


def service(unit, mode, directory):
    return ["systemd-run", "--user", "--wait", "--pipe", "--collect",
            "--expand-environment=no", "--unit=" + unit,
            "--slice=" + trial.RESOURCE_SLICE,
            "--property=MemoryAccounting=yes", "--property=MemoryMax=3G",
            "--property=MemorySwapMax=0", "--property=RuntimeMaxSec=90",
            "--property=LimitCORE=0", "--", sys.executable, "-B", str(HERE),
            mode, str(directory)]


def cgroup_limits():
    rows = [line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
            if line.startswith("0::")]
    trial.require(len(rows) == 1, "unified cgroup required")
    group = Path("/sys/fs/cgroup") / rows[0].lstrip("/")
    return {"control_group": rows[0], "parent": group.parent.name,
            "memory_max": int((group / "memory.max").read_text()),
            "swap_max": int((group / "memory.swap.max").read_text()),
            "aggregate_memory_max": int((group.parent / "memory.max").read_text()),
            "aggregate_swap_max": int((group.parent / "memory.swap.max").read_text())}


def controller(directory):
    name = trial.require_controller()
    lease = trial.shared_lease_path()
    lease.mkdir(mode=0o700, exist_ok=True)
    trial.private_directory(lease)
    with trial.exclusive(lease / "exclusive.lock"):
        trial.require_no_other_work(name)
        write_json(directory / "controller.json", cgroup_limits())
        worker = (directory / "worker-unit").read_text().strip()
        config = {"accounting": str(HERE.with_name("block-v2-accounting.py")),
                  "runner": sys.executable, "job": str(directory), "mode": "prepare"}
        command = trial.stage_command(config, name, worker, "prepare", ["prepare"])
        # Exercise the actual stage resource/lifecycle flags with a tiny worker.
        # It cannot invoke a prover, generate keys, or read any proof artifact.
        command = command[:command.index("--") + 1] + [sys.executable, "-B", str(HERE), "worker", str(directory)]
        with (directory / "worker.log").open("x") as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            code = process.wait(timeout=60)
        raise RuntimeError("worker exited before controller kill: " + str(code))


def worker(directory):
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(time.monotonic()))
    write_json(directory / "worker.json", cgroup_limits())
    active = directory / "worker-active"
    active.touch(exist_ok=False)
    try:
        deadline = time.monotonic() + 60
        while not stopping and time.monotonic() < deadline:
            time.sleep(0.05)
        trial.require(stopping, "worker was not stopped by controller dependency")
        write_json(directory / "worker-stopping.json", {"received_sigterm": True})
        # Model asynchronous cleanup, retaining a real stopping service long
        # enough to test admission while the dead controller's lock is released.
        time.sleep(5)
    finally:
        active.unlink()
    write_json(directory / "worker-cleaned.json", {"cleanup_complete": True})


def admission(directory, expect_busy):
    output = directory / ("refusal.json" if expect_busy else "fresh-admission.json")
    try:
        controller_name = trial.require_controller()
    except ValueError as error:
        trial.require(expect_busy and "other experiment services remain live" in str(error),
                      "unexpected admission error: " + str(error))
        write_json(output, {"refused": True, "reason": str(error)})
        return
    trial.require(not expect_busy, "admitted new controller while old worker was live")
    trial.require_no_other_work(controller_name)
    write_json(output, {"admitted": True, "limits": cgroup_limits()})


def run(directory):
    trial.require(not directory.exists(), "requires a new evidence directory")
    directory.mkdir(mode=0o700)
    suffix = str(os.getpid())
    base = "lattica-v2-grouped-lifecycle-" + suffix
    units = {role: base + "-" + role + ".service" for role in ("controller", "worker", "retry", "fresh")}
    (directory / "worker-unit").write_text(units["worker"])
    processes = []
    started = time.monotonic()
    try:
        with (directory / "controller.log").open("x") as output:
            process = subprocess.Popen(service(units["controller"], "controller", directory),
                                       stdout=output, stderr=subprocess.STDOUT)
            processes.append(process)
            wait_for(lambda: (directory / "worker-active").exists(), "worker start")
            limits = json.loads((directory / "worker.json").read_text())
            trial.require(limits["memory_max"] == 44 * trial.GIB and limits["swap_max"] == 0
                          and limits["aggregate_memory_max"] == 48 * trial.GIB
                          and limits["aggregate_swap_max"] == 0
                          and limits["parent"] == trial.RESOURCE_SLICE, "actual worker limits")
            subprocess.run(["systemctl", "--user", "kill", "--signal=SIGKILL", "--kill-whom=main",
                            units["controller"]], check=True, timeout=10)
            wait_for(lambda: terminal(units["controller"]), "controller terminal")
            wait_for(lambda: (directory / "worker-stopping.json").exists(), "dependent worker stop")
            trial.require(properties(units["worker"])["ActiveState"] == "deactivating", "worker stop interval missing")
            # Confirm the motivating race: lock available, old worker still live.
            with trial.exclusive(trial.shared_lease_path() / "exclusive.lock"):
                pass
            retry = subprocess.run(service(units["retry"], "refuse", directory),
                                   text=True, capture_output=True, timeout=20)
            (directory / "retry.log").write_text(retry.stdout + retry.stderr)
            trial.require(retry.returncode == 0 and (directory / "refusal.json").exists(), "live overlap refusal")
            wait_for(lambda: terminal(units["worker"]), "worker terminal")
            trial.require((directory / "worker-cleaned.json").exists()
                          and not (directory / "worker-active").exists(), "worker cleanup incomplete")
            process.wait(timeout=10)
        fresh = subprocess.run(service(units["fresh"], "admit", directory),
                               text=True, capture_output=True, timeout=20)
        (directory / "fresh.log").write_text(fresh.stdout + fresh.stderr)
        trial.require(fresh.returncode == 0 and (directory / "fresh-admission.json").exists(), "fresh admission failed")
        report = {"status": "REAL_NON_PROVING_LIFECYCLE_PASSED", "units": units,
                  "worker_limits": limits, "abrupt_controller_death": True,
                  "released_lock_with_stopping_worker_observed": True,
                  "overlap_refused": True, "cleanup_observed": True, "fresh_admission_passed": True,
                  "wall_seconds": time.monotonic() - started, "real_proofs": False,
                  "production_ready": False}
        write_json(directory / "result.json", report)
        print(json.dumps(report))
    finally:
        # These exact units were created by this invocation. Never wildcard-stop.
        for unit in units.values():
            subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=15)
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


if __name__ == "__main__":
    trial.require(len(sys.argv) == 3, "usage: test-block-v2-grouped-lifecycle.py --run NEW_EVIDENCE_DIR")
    mode, path = sys.argv[1], Path(sys.argv[2]).resolve()
    if mode == "--run":
        run(path)
    elif mode == "controller":
        controller(path)
    elif mode == "worker":
        worker(path)
    elif mode in {"refuse", "admit"}:
        admission(path, mode == "refuse")
    else:
        raise ValueError("unknown mode")
