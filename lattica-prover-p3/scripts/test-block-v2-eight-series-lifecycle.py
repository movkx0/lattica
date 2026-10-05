#!/usr/bin/env python3
"""Opt-in real service/journal lifecycle test for the repeated-series controller.

No proof, wallet fixture, key, or existing evidence is consumed or modified.
Series.advance/validate_completed/prefix, the durable journal, controller
admission, and worker resource/dependency flags are real. Expensive fixture and
proof checks are explicit stubs, so this is NOT cryptographic validation or a
complete test of the series CLI. Run only after the pinned pilot is terminal.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

import importlib.util

spec = importlib.util.spec_from_file_location(
    "eight_series", Path(__file__).with_name("block-v2-eight-series.py"))
series_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(series_module)


HERE = Path(__file__).resolve()
SCRIPTS = HERE.parent
GROUPED = SCRIPTS / "block-v2-grouped-trial.py"
GROUPED_SHA = "8bd17f9e084bb95119829b2c356e6f2968539e14011955d8ed623cb29c5e489e"
ACCOUNTING = SCRIPTS / "block-v2-accounting.py"
ACCOUNTING_SHA = "f9b665c3210ec602799acf5ada2338084063677d42d48065324f23f31bdd1ad0"
trial = series_module.load_helper(GROUPED, GROUPED_SHA)


def source_pins():
    paths = (HERE, Path(series_module.__file__).resolve(), GROUPED, ACCOUNTING)
    pins = {str(path): trial.digest(path) for path in paths}
    trial.require(pins[str(GROUPED)] == GROUPED_SHA, "grouped controller changed")
    trial.require(pins[str(ACCOUNTING)] == ACCOUNTING_SHA, "accounting changed")
    return pins


def record(directory, name, value):
    path = directory / name
    trial.require(not path.exists() and not path.is_symlink(), "refuse existing test record")
    trial.save(path, value)


def properties(unit):
    result = subprocess.run(
        ["systemctl", "--user", "show", unit,
         "--property=LoadState,ActiveState,MainPID,ControlGroup", "--no-pager"],
        text=True, capture_output=True, timeout=10,
    )
    trial.require(result.returncode == 0, "cannot observe unit: " + result.stderr)
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def terminal(unit):
    value = properties(unit)
    return value if (value.get("LoadState") == "not-found" or
                     value.get("ActiveState") in {"inactive", "failed"}) and value.get("MainPID", "0") == "0" else None


def wait_for(check, description, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise RuntimeError("timeout: " + description)


def limits():
    rows = [line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
            if line.startswith("0::")]
    trial.require(len(rows) == 1, "unified cgroup required")
    group = Path("/sys/fs/cgroup") / rows[0].lstrip("/")
    return {
        "control_group": rows[0], "parent": group.parent.name,
        "memory_max": int((group / "memory.max").read_text()),
        "memory_high": (group / "memory.high").read_text().strip(),
        "swap_max": int((group / "memory.swap.max").read_text()),
        "aggregate_memory_max": int((group.parent / "memory.max").read_text()),
        "aggregate_swap_max": int((group.parent / "memory.swap.max").read_text()),
    }


def service(unit, mode, directory):
    return [
        "systemd-run", "--user", "--wait", "--pipe", "--collect",
        "--expand-environment=no", "--unit=" + unit, "--slice=" + trial.RESOURCE_SLICE,
        "--property=MemoryAccounting=yes", "--property=MemoryMax=3G",
        "--property=MemorySwapMax=0", "--property=RuntimeMaxSec=90",
        "--property=LimitCORE=0", "--", sys.executable, "-B", str(HERE),
        mode, str(directory),
    ]


def new_state(config):
    return {
        "schema": 1, "config": config, "status": "READY_FOR_NEXT_TRIAL",
        "attempts": [], "prune": None, "replays": [],
        "shared_fixture_pruned": False, "repeat_qualified": False,
        "production_ready": False, "kind": "NON_PROVING_LIFECYCLE_TEST_ONLY",
    }


def fixture(directory, controller):
    """Real orchestration methods with explicitly non-cryptographic boundaries."""
    instance = series_module.Series.__new__(series_module.Series)
    instance.module = trial
    instance.config = {"pairs": 5, "lifecycle_test": True}
    instance.output = directory
    instance.path = directory / "series-manifest.json"
    instance.validate_source_archive = lambda: None
    instance.validate_pilot = lambda: None
    instance.validate_pins = lambda shared_required=True: None
    instance.trial_config = lambda pair, variant: {"pair": pair, "variant": variant}

    def create_job(config, variant):
        saved = json.loads(trial.regular_bytes(instance.path))
        trial.require(saved["attempts"][-1]["status"] == "attempted" and
                      saved["attempts"][-1]["config"] == config,
                      "trial was not durably journaled before fixture creation")
        record(directory, "synthetic-job-created.json", {"variant": variant, "config": config})

    def run_trial(config, resume):
        trial.require(not resume, "unexpected child resume")
        worker = json.loads(trial.regular_bytes(directory / "units.json"))["worker"]
        stub_config = {"mode": "prepare", "job": str(directory),
                       "accounting": str(ACCOUNTING), "runner": sys.executable}
        command = trial.stage_command(stub_config, controller, worker, "prepare", ["prepare"])
        # Preserve real systemd flags; replace only the executable payload.
        command = command[:command.index("--") + 1] + [
            sys.executable, "-B", str(HERE), "worker", str(directory)]
        with (directory / "worker.log").open("x") as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            process.wait(timeout=60)
        raise RuntimeError("test worker exited before abrupt controller death")

    def must_not_verify(*_):
        raise AssertionError("non-proving lifecycle test cannot claim a proof result")

    instance.create_job = create_job
    stub = SimpleNamespace(run=run_trial)
    instance.helper = SimpleNamespace(SINGLE=stub, GROUPED=stub,
                                      verify_completed_trial=must_not_verify)
    return instance


def controller(directory):
    name = trial.require_controller()
    lease = trial.shared_lease_path()
    lease.mkdir(mode=0o700, exist_ok=True)
    trial.private_directory(lease)
    with trial.exclusive(lease / "exclusive.lock"):
        trial.require_no_other_work(name)
        record(directory, "controller.json", limits())
        instance = fixture(directory, name)
        trial.save(instance.path, new_state(instance.config))
        with trial.exclusive(directory / "series.lock"):
            instance.advance(json.loads(trial.regular_bytes(instance.path)), name)
    raise AssertionError("controller unexpectedly survived")


def worker(directory):
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(time.monotonic()))
    record(directory, "worker.json", limits())
    record(directory, "worker-active.json", {"active": True})
    deadline = time.monotonic() + 60
    while not stopping and time.monotonic() < deadline:
        time.sleep(0.05)
    trial.require(stopping, "worker was not stopped by controller dependency")
    record(directory, "worker-stopping.json", {"received_sigterm": True})
    # Observe the released-lock/live-worker race while cleanup is in progress.
    time.sleep(5)
    (directory / "worker-active.json").unlink()
    record(directory, "worker-cleaned.json", {"cleanup_complete": True})


def refuse_live_overlap(directory):
    try:
        trial.require_controller()
    except ValueError as error:
        trial.require("other experiment services remain live" in str(error),
                      "unexpected admission error: " + str(error))
        record(directory, "overlap-refused.json", {"refused": True, "reason": str(error)})
        return
    raise AssertionError("admitted overlapping test while old worker was stopping")


def recover(directory):
    name = trial.require_controller()
    instance = fixture(directory, name)
    with trial.exclusive(directory / "series.lock"):
        before = trial.regular_bytes(instance.path)
        state = json.loads(before)
        trial.require(len(state["attempts"]) == 1 and
                      state["attempts"][0]["status"] == "attempted", "lost interrupted attempt")
        try:
            instance.advance(state, name)
        except ValueError as error:
            trial.require("uncertain attempt" in str(error), "unexpected recovery refusal")
        else:
            raise AssertionError("uncertain trial was automatically rerun")
        trial.require(trial.regular_bytes(instance.path) == before, "recovery rewrote the journal")
    record(directory, "recovery-refused.json", {
        "fresh_controller_admitted": True, "uncertain_trial_refused": True,
        "journal_unchanged": True, "journal_sha256": hashlib.sha256(before).hexdigest(),
    })


def require_idle_manager():
    # This check runs OUTSIDE a controller service. The shared controller
    # validator deliberately requires its own live unit and cannot accept an
    # empty controller name. Any live research service blocks this test.
    output = subprocess.check_output(
        ["systemctl", "--user", "list-units", "--all", "--type=service",
         "--state=active,activating,deactivating,reloading", "--plain",
         "--no-legend", "--no-pager", "lattica-v2-*.service"],
        text=True, timeout=10, env={**os.environ, "SYSTEMD_COLORS": "0"},
    )
    trial.require(not output.strip(), "live experiment services; lifecycle test refused")


def run(directory):
    # Fail before creating anything if the pilot, another series, or worker is live.
    require_idle_manager()
    trial.require(not directory.exists() and not directory.is_symlink(), "new evidence directory required")
    pins = source_pins()
    directory.mkdir(mode=0o700)
    record(directory, "source-pins.json", pins)
    suffix = uuid.uuid4().hex[:16]
    units = {role: f"lattica-v2-eight-series-lifecycle-{suffix}-{role}.service"
             for role in ("controller", "worker", "retry", "recover")}
    for unit in units.values():
        trial.require(properties(unit).get("LoadState") == "not-found", "test unit already exists")
    record(directory, "units.json", units)
    started_units, processes = [], []
    started = time.monotonic()
    try:
        with (directory / "controller.log").open("x") as output:
            # The worker is created by this controller using the recorded unique name.
            started_units.extend((units["controller"], units["worker"]))
            process = subprocess.Popen(service(units["controller"], "controller", directory),
                                       stdout=output, stderr=subprocess.STDOUT)
            processes.append(process)
            wait_for(lambda: (directory / "worker-active.json").exists(), "worker start")
            worker_limits = json.loads(trial.regular_bytes(directory / "worker.json"))
            controller_limits = json.loads(trial.regular_bytes(directory / "controller.json"))
            trial.require(worker_limits["memory_max"] == 44 * trial.GIB and
                          worker_limits["memory_high"] == str(40 * trial.GIB) and
                          worker_limits["swap_max"] == 0 and
                          worker_limits["aggregate_memory_max"] == 48 * trial.GIB and
                          worker_limits["aggregate_swap_max"] == 0 and
                          worker_limits["parent"] == trial.RESOURCE_SLICE, "worker limits differ")
            trial.require(controller_limits["memory_max"] == 3 * trial.GIB and
                          controller_limits["swap_max"] == 0, "controller limits differ")
            journal = directory / "series-manifest.json"
            before = trial.regular_bytes(journal)
            trial.require(json.loads(before)["attempts"][0]["status"] == "attempted",
                          "missing durable attempted record")
            subprocess.run(["systemctl", "--user", "kill", "--signal=SIGKILL", "--kill-whom=main",
                            units["controller"]], check=True, timeout=10)
            wait_for(lambda: terminal(units["controller"]), "controller terminal")
            wait_for(lambda: (directory / "worker-stopping.json").exists(), "dependent worker stop")
            trial.require(properties(units["worker"])["ActiveState"] == "deactivating", "stop interval missing")
            with trial.exclusive(directory / "series.lock"):
                pass
            with trial.exclusive(trial.shared_lease_path() / "exclusive.lock"):
                pass
            started_units.append(units["retry"])
            retry = subprocess.run(service(units["retry"], "refuse", directory),
                                   text=True, capture_output=True, timeout=20)
            record(directory, "retry-output.json", {"stdout": retry.stdout, "stderr": retry.stderr})
            trial.require(retry.returncode == 0 and (directory / "overlap-refused.json").exists(),
                          "live-worker overlap was not refused")
            wait_for(lambda: terminal(units["worker"]), "worker terminal")
            trial.require((directory / "worker-cleaned.json").exists() and
                          not (directory / "worker-active.json").exists(), "cleanup incomplete")
            process.wait(timeout=10)
        started_units.append(units["recover"])
        recovered = subprocess.run(service(units["recover"], "recover", directory),
                                   text=True, capture_output=True, timeout=20)
        record(directory, "recover-output.json", {"stdout": recovered.stdout, "stderr": recovered.stderr})
        trial.require(recovered.returncode == 0 and (directory / "recovery-refused.json").exists(),
                      "uncertain trial recovery was not refused")
        trial.require(trial.regular_bytes(journal) == before, "interrupted journal changed")
        trial.require(source_pins() == pins, "test source changed while running")
        report = {
            "status": "REAL_SERIES_JOURNAL_SERVICE_LIFECYCLE_PASSED", "units": units,
            "source_pins": pins, "worker_limits": worker_limits, "controller_limits": controller_limits,
            "abrupt_controller_death": True, "released_locks_with_stopping_worker_observed": True,
            "live_overlap_refused": True, "worker_cleanup_observed": True,
            "uncertain_trial_not_rerun": True, "journal_sha256": hashlib.sha256(before).hexdigest(),
            "wall_seconds": time.monotonic() - started, "real_proofs": False,
            "complete_cli_test": False, "fixture_and_crypto_checks_stubbed": True,
            "production_ready": False,
        }
        record(directory, "result.json", report)
        print(json.dumps(report))
    finally:
        # Only the exact unique units assigned to this test. Never wildcard-stop.
        for unit in started_units:
            subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=15)
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "controller", "worker", "refuse", "recover"))
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    directory = args.evidence.resolve()
    if args.mode == "run":
        run(directory)
        return
    trial.private_directory(directory)
    trial.require(source_pins() == json.loads(trial.regular_bytes(directory / "source-pins.json")),
                  "test source pins changed")
    {"controller": controller, "worker": worker, "refuse": refuse_live_overlap,
     "recover": recover}[args.mode](directory)


if __name__ == "__main__":
    main()
