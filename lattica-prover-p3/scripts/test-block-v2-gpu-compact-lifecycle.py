#!/usr/bin/env python3
"""Bounded synthetic service lifecycle checks; no GPU, prover, or proof benchmark.

Run the driver in a <=3 GiB, no-swap lattica-v2 controller service in the
48 GiB grouped slice. The complete trial owns the normal exclusive lease.
Only the new controller's worker command and VRAM observer are substituted;
the frozen helper's resource, inventory, lease, and persistence policy is used
unchanged. A fresh evidence directory is mandatory; failures are not retried.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("gpu_compact_lifecycle_controller", Path(__file__).with_name("block-v2-gpu-compact-trial.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
H = M.H
UUID = "GPU-00000000-0000-0000-0000-000000000000"
LIVE = {"active", "activating", "deactivating", "reloading"}


def properties(unit):
    result = subprocess.run(["systemctl", "--user", "show", unit,
                             "--property=LoadState,ActiveState,SubState,MainPID", "--no-pager"],
                            capture_output=True, text=True, timeout=10, check=True)
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    H.require("ActiveState" in values and "LoadState" in values, "service observation incomplete")
    return values


def wait_for(unit, active, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = properties(unit)
        if active and observed["ActiveState"] == "active" and int(observed.get("MainPID", "0")) > 0:
            return observed
        if not active and observed["ActiveState"] not in LIVE:
            return observed
        time.sleep(0.05)
    raise TimeoutError(f"service did not reach requested {'active' if active else 'terminal'} state: {unit}")


def service(unit, controller, command, wait=True, memory="44G"):
    return ["systemd-run", "--user", "--collect", "--expand-environment=no", f"--unit={unit}",
            f"--slice={H.RESOURCE_SLICE}", "--property=MemoryAccounting=yes", f"--property=MemoryMax={memory}",
            "--property=MemorySwapMax=0", "--property=RuntimeMaxSec=60", "--property=KillMode=control-group",
            "--property=LimitCORE=0", "--property=UMask=0077", f"--property=BindsTo={controller}",
            f"--property=After={controller}", *( ["--wait", "--pipe"] if wait else ["--no-block"] ),
            "--", *command]


def sleeper():
    return [sys.executable, "-B", "-u", "-c", "import time; print('synthetic_worker_started', flush=True); time.sleep(50)"]


class NoGpuObserver:
    def __init__(self):
        self.samples = 0

    def sample(self):
        self.samples += 1


class FailAfterActive(M.VramMonitor):
    instances = []

    def __init__(self, unit, uuid, path):
        super().__init__(unit, uuid, path)
        self.unit = unit
        self.observed_active = False
        self.deadline = time.monotonic() + 20
        self.instances.append(self)

    def sample(self):
        H.require(time.monotonic() < self.deadline, "synthetic worker never became active")
        if properties(self.unit)["ActiveState"] == "active":
            self.observed_active = True
            raise RuntimeError("injected observer failure after worker activation")


def capture_exit(controller, evidence):
    unit = f"lattica-v2-gpu-grouped-lifecycle-{M.os.getpid()}-exit.service"
    observer = NoGpuObserver()
    log = evidence / "capture-exit.log"
    code = M.capture_gpu_stage(service(unit, controller,
                                      [sys.executable, "-B", "-c", "print('synthetic_capture_marker'); raise SystemExit(7)"]),
                               log, observer, timeout=30)
    H.require(code == 7 and b"synthetic_capture_marker" in H.regular_bytes(log), "capture lost output or service exit code")
    terminal = wait_for(unit, False)
    H.require(observer.samples > 0, "capture did not invoke observer")
    H.require_no_other_work(controller)
    return {"unit": unit, "exit_code": code, "terminal": terminal, "log_sha256": H.digest(log), "samples": observer.samples}


def observer_failure(controller, evidence):
    directory = evidence / "observer-failure"
    directory.mkdir(mode=0o700)
    config = {"mode": "register", "backend": "resident", "job": str(evidence / "unused-job"),
              "gpu_uuid": UUID, "gpu_index": 0, "gpu_openings": 1, "gpu_compact": 1}
    state = {"source_artifacts": {}, "artifacts": None, "attempts": [], "status": "RUNNING"}
    manifest = directory / "manifest.json"
    FailAfterActive.instances.clear()
    with patch.object(M, "VramMonitor", FailAfterActive), \
            patch.object(M, "stage_command", side_effect=lambda c, parent, unit, name, action: service(unit, parent, sleeper())):
        try:
            M.run_stage(config, controller, "key-1", ["register", "1"], directory, state, manifest)
        except RuntimeError as error:
            H.require(str(error) == "injected observer failure after worker activation", "unexpected failure injection")
        else:
            raise ValueError("injected observation failure was accepted")
    saved = json.loads(H.regular_bytes(manifest))
    record = saved["attempts"][0]
    H.require(saved["status"] == "FAILED_OR_INTERRUPTED" and record["status"] == "failed_or_interrupted"
              and record["cleanup_no_active_worker"] is True, "failure/cleanup evidence is incomplete")
    H.require(len(FailAfterActive.instances) == 1 and FailAfterActive.instances[0].observed_active
              and FailAfterActive.instances[0].output.closed, "worker was not observed active or observer was not closed")
    try:
        H.validate_prefix(saved, [("key-1", [])])
    except ValueError:
        pass
    else:
        raise ValueError("failed stage was resumable")
    terminal = wait_for(record["unit"], False)
    H.require_no_other_work(controller)
    return {"unit": record["unit"], "terminal": terminal, "manifest_sha256": H.digest(manifest),
            "failed_attempt_not_resumable": True, "observer_closed": True}


def controller_death(controller, evidence):
    parent = f"lattica-v2-gpu-lifecycle-parent-{M.os.getpid()}.service"
    worker = f"lattica-v2-gpu-grouped-lifecycle-{M.os.getpid()}-orphan.service"
    try:
        subprocess.run(service(parent, controller, [sys.executable, "-B", str(Path(__file__).resolve()),
                                                     "sentinel", parent, worker], wait=False, memory="64M"),
                       check=True, timeout=10)
        wait_for(parent, True)
        live_worker = wait_for(worker, True)
        subprocess.run(["systemctl", "--user", "kill", "--kill-whom=main", "--signal=SIGKILL", parent],
                       check=True, timeout=10)
        parent_terminal = wait_for(parent, False)
        worker_terminal = wait_for(worker, False)
        H.require_no_other_work(controller)
        return {"controller": parent, "worker": worker, "worker_observed_active": live_worker,
                "controller_terminal": parent_terminal, "worker_terminal": worker_terminal}
    finally:
        subprocess.run(["systemctl", "--user", "stop", parent, worker], timeout=30, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def driver(evidence):
    controller = H.require_controller()
    lease = H.shared_lease_path()
    H.private_directory(lease)
    with H.exclusive(lease / "exclusive.lock"):
        H.require_no_other_work(controller)
        evidence.mkdir(mode=0o700)
        state = {"schema": "gpu-compact-synthetic-lifecycle-v1", "status": "RUNNING", "production_ready": False,
                 "scope": "synthetic processes only; no GPU/prover/full-size qualification", "tests": [],
                 "pins": {"controller": H.digest(Path(M.__file__)), "lifecycle": H.digest(Path(__file__)),
                          "helpers": H.digest(M.HELPER_PATH)}}
        manifest = evidence / "manifest.json"
        for test in (capture_exit, observer_failure, controller_death):
            record = {"name": test.__name__, "status": "attempted"}
            state["tests"].append(record)
            H.save(manifest, state)
            try:
                record["result"] = test(controller, evidence)
                record["status"] = "PASS"
            except BaseException as error:
                record.update(status="FAILED_OR_INTERRUPTED", error=str(error))
                state["status"] = "FAILED_OR_INTERRUPTED"
                H.save(manifest, state)
                raise
            H.save(manifest, state)
        H.require_no_other_work(controller)
        state["status"] = "PASS"
        H.save(manifest, state)
        print(json.dumps({"status": "PASS", "synthetic_lifecycle_tests": len(state["tests"]), "production_ready": False}))


if __name__ == "__main__":
    M.os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("driver").add_argument("evidence", type=Path)
    sentinel = sub.add_parser("sentinel")
    sentinel.add_argument("controller")
    sentinel.add_argument("worker")
    args = parser.parse_args()
    if args.mode == "driver":
        driver(args.evidence.resolve())
    else:
        # Deliberately no lease acquisition: this is a child of the driver's
        # already-leased synthetic test, never a stand-alone proof controller.
        raise SystemExit(subprocess.run(service(args.worker, args.controller, sleeper()), check=False).returncode)
