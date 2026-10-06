#!/usr/bin/env python3
"""Prepare public typed fixtures and CPU verifier keys inside a bounded cgroup."""
import argparse
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location("typed_controller", Path(__file__).with_name("block-v2-typed-gpu-run.py"))
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)
G, R = T.G, T.R


def leaf_files(source):
    paths = [source / name for name in ("body.json", *(f"wallet.{i}" for i in range(64)))]
    if any(not p.is_file() or p.is_symlink() or not 0 < p.stat().st_size <= (128 * 1024 if p.name == "body.json" else 2 * R.MIB) for p in paths):
        raise ValueError("public fixture must contain 64 nonsymlink leaf artifacts and its body")
    return paths


def worker(packet_path):
    packet = json.loads(packet_path.read_text())
    out = packet_path.parent
    config, budget = packet["config"], packet["budget"]
    construction = config.get("construction", "reference")
    spec = T.construction_spec(construction)
    T.check_pins(config["pins"])
    fixture = out / "fixture"
    binary = config["cpu_binary"]
    env = {**T.clean_environment(), "RAYON_NUM_THREADS": str(budget["cpu"]["rayon_threads"]),
           "LATTICA_PROFILE": "1", "LATTICA_PROFILE_TIMELINE": "0"}
    commands = [] if config.get("public_fixture") else [("fixture", [binary, "fixture", fixture])]
    commands += [("geometry", [binary, "geometry", fixture])]
    commands += [(f"register-{mode}", [binary, "register", fixture, mode, budget["host"]["worker_bytes"]]) for mode in range(1, spec["keys"] + 1)]
    result = {"schema": "lattica-typed-cpu-preparation-v1", "status": "running", "stages": [],
              "recursive_root_produced": False, "production_ready": False, "construction": construction, "registry_keys": spec["keys"], "fixture_reuse": bool(config.get("public_fixture"))}
    G.durable(out / "worker-result.json", result, True)
    started = time.monotonic()
    try:
        if config.get("public_fixture"):
            before = time.monotonic()
            fixture.mkdir(mode=0o700)
            for source in leaf_files(Path(config["public_fixture"])):
                shutil.copyfile(source, fixture / source.name)
                if G.digest(fixture / source.name) != config["pins"][str(source)]:
                    raise ValueError("copied public fixture differs from pinned source")
            result["stages"].append({"name": "copy-public-fixture", "status": "succeeded",
                                     "elapsed_seconds": time.monotonic() - before})
        for name, command in commands:
            stage = {"name": name, "command": list(map(str, command)), "status": "running"}
            result["stages"].append(stage)
            G.durable(out / "worker-result.json", result)
            before = time.monotonic()
            T.execute_logged(command, out / (name + ".log"), env)
            stage.update(status="succeeded", elapsed_seconds=time.monotonic() - before)
            T.check_pins(config["pins"])
            G.durable(out / "worker-result.json", result)
            if name == "geometry":
                if json.loads((fixture / "height.json").read_text()) != 262144:
                    raise ValueError("typed CPU geometry is outside the GPU bootstrap model")
                geometry = T.public_events(out / "geometry.log", "typed_geometry")
                if len(geometry) != 1:
                    raise ValueError("missing typed geometry identity")
                T.validate_plan(geometry[0], construction)
            print("PASS", name, stage["elapsed_seconds"], flush=True)
        files = T.fixture_files(fixture, 64, construction)
        result.update(status="succeeded", cpu_registered=True, elapsed_seconds=time.monotonic() - started,
                      artifacts=dict(T.pin(path) for path in files))
    except BaseException as error:
        result.update(status="failed", failure=f"{type(error).__name__}: {error}")
        if result["stages"]:
            result["stages"][-1]["status"] = "failed"
        raise
    finally:
        G.durable(out / "worker-result.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--construction", choices=T.CONSTRUCTIONS, default="reference")
    parser.add_argument("--public-fixture", type=Path)
    parser.add_argument("--cpu-binary", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--worker", type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker)
        return
    if args.cpu_binary is None or args.evidence is None:
        parser.error("cpu-binary and evidence are required")
    os.umask(0o077)
    binary = args.cpu_binary.resolve(strict=True)
    sources = [binary, Path(__file__), Path(T.__file__), Path(G.__file__), Path(R.__file__)]
    config = {"cpu_binary": str(binary), "construction": args.construction}
    if args.public_fixture:
        source = args.public_fixture.resolve(strict=True)
        sources += leaf_files(source)
        config["public_fixture"] = str(source)
    config["pins"] = dict(map(T.pin, sources))
    out = args.evidence.resolve()
    locks = G.lock_fleet()
    created = launched = False
    unit = f"lattica-v2-multi-{os.getpid()}-typed-cpu.service"
    report = {"schema": "lattica-typed-cpu-preparation-v1", "status": "preparing", "unit": unit,
              "recursive_root_produced": False, "production_ready": False, "construction": args.construction}
    try:
        if json.loads(G.systemctl("list-units", "lattica-v2-multi-*.service", "--state=active,activating,deactivating", "--output=json", "--no-pager")):
            raise ValueError("another benchmark worker is active")
        out.mkdir(parents=True, exist_ok=False)
        created = True
        G.durable(out / "summary.json", report, True)
        G.systemctl("start", G.SLICE)
        host = G.detect_worker_host("/tmp")
        budget = R.shared_budgets(host, ["typed-cpu-preparation"])["typed-cpu-preparation"]
        if budget["host"]["worker_bytes"] < 31675383808:
            raise ValueError("typed CPU preparation exceeds available worker memory")
        G.durable(out / "admission.json", {"host": host, "budget": budget}, True)
        packet = out / "packet.json"
        G.durable(packet, {"config": config, "budget": budget}, True)
        G.systemctl("set-property", "--runtime", G.SLICE, f"MemoryMax={budget['host']['fleet_bytes']}",
                    "MemorySwapMax=0", "MemoryAccounting=yes")
        command = ["systemd-run", "--user", "--wait", "--pipe", "--expand-environment=no", "--unit=" + unit,
                   "--slice=" + G.SLICE, "--property=MemoryAccounting=yes",
                   "--property=MemoryMax=" + str(budget["host"]["worker_bytes"]), "--property=MemorySwapMax=0",
                   "--property=CPUQuota=" + budget["cpu"]["quota_percent"],
                   "--property=AllowedCPUs=" + ",".join(map(str, budget["cpu"]["allowed_cpus"])),
                   "--property=RuntimeMaxSec=3600", "--property=KillMode=control-group", "--property=LimitCORE=0",
                   "--property=UMask=0077",
                   "--property=ExecStopPost=" + " ".join([sys.executable, str(Path(G.__file__).resolve()), "--accounting", str(out)]),
                   sys.executable, str(Path(__file__).resolve()), "--worker", str(packet)]
        report["status"] = "running"
        G.durable(out / "summary.json", report)
        launched = True
        with (out / "controller.log").open("x") as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
        result = json.loads((out / "worker-result.json").read_text())
        if result.get("status") != "succeeded" or result.get("cpu_registered") is not True:
            raise ValueError("CPU preparation did not finish every selected registration")
        accounting = json.loads((out / "accounting.json").read_text())
        T.validate_accounting(accounting, budget)
        T.check_pins(result["artifacts"])
        report.update(status="succeeded", result=result, accounting=accounting)
    except BaseException as error:
        report.update(status="failed", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        try:
            if launched and not G.terminated(G.unit_state(unit)):
                G.systemctl("stop", unit)
                if not G.terminated(G.unit_state(unit)):
                    raise ValueError("typed CPU worker did not stop")
        except BaseException as error:
            report.update(status="failed", cleanup_failure=f"{type(error).__name__}: {error}")
            raise
        finally:
            if created:
                G.durable(out / "summary.json", report)
            for lock in locks:
                os.close(lock)
    print(json.dumps({"status": report["status"], "fixture": str(out / "fixture")}), flush=True)


if __name__ == "__main__":
    main()
