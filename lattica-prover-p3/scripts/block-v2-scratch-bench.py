#!/usr/bin/env python3
"""Prepare/run the post-reboot compact-opening scratch and Rayon comparison.

Preparation and unit tests do not start a prover. Four frozen controllers are
derived from the qualified controller, leaving it and its evidence unchanged.
The same binaries/public inputs are used in every arm; fresh CPU-equivalent key
registration and independent root audit remain mandatory. No production use.
"""
import argparse
import ast
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "lattica-prover-p3/scripts"
TARGET = ROOT / "lattica-prover-p3/target"
DEFAULT_PLAN = TARGET / "block-v2-scratch-bench-20261002"
BASELINE = TARGET / "block-v2-gpu-compact-proof-20261002-a-evidence/manifest.json"
TEMPLATE = SCRIPTS / "block-v2-gpu-compact-trial.py"
TEMPLATE_SHA = "f294ce1abda041306bf3b6f4d74df8843495c7cfec571fdb9a5361b6bace7953"
GIB = 1 << 30
ARMS = ("disk8", "ram8", "ram16", "disk16")
SLICE = "lattica-v2-grouped.slice"
SCHEMA = "post-reboot-scratch-bench-v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def memory_available():
    return next(int(line.split()[1]) * 1024 for line in
                Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:"))


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_module(path):
    module = types.ModuleType("scratch_bench_frozen_helper")
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def replace_once(source, before, after):
    require(source.count(before) == 1, "controller template drift: " + before[:100])
    return source.replace(before, after, 1)


# Included in each derived controller; sampled alongside existing GPU telemetry.
HOST_MONITOR = '''
def sample_bench_host(group, scratch):
    root = Path("/sys/fs/cgroup") / group.lstrip("/")
    row = {"utc_ns": time.time_ns(), "cgroup": group}
    for name in ("memory.current", "memory.peak", "memory.stat", "memory.events",
                 "memory.pressure", "cpu.stat", "io.stat", "io.pressure"):
        try:
            raw = (root / name).read_text()
        except FileNotFoundError:
            row[name] = None  # Worker startup/exit, not a zero observation.
            continue
        if name in ("memory.current", "memory.peak"):
            row[name] = int(raw.strip())
        elif name in ("memory.stat", "memory.events", "cpu.stat"):
            values = dict(line.split() for line in raw.splitlines())
            if name == "memory.stat":
                keys = ("anon", "file", "shmem", "file_dirty", "file_writeback",
                        "kernel", "pagetables", "pgfault", "pgmajfault")
                values = {key: values[key] for key in keys if key in values}
            row[name] = {key: int(value) for key, value in values.items()}
        else:
            row[name] = raw.strip()
    row["host_mem_available_bytes"] = next(int(line.split()[1]) * 1024 for line in
        Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
    fs = os.statvfs(scratch)
    row["scratch_filesystem_available_bytes"] = fs.f_bavail * fs.f_frsize
    row["scope"] = "sampled worker cgroup; io.stat is block-device accounting, not NAND writes"
    return row
'''


def derive_controller(source, threads, scratch):
    """Keep bounded workers, pin checks, GPU telemetry and CPU audit unchanged."""
    require(threads in (8, 16), "unsupported thread count")
    source = replace_once(source, 'SCHEMA = "gpu-compact-eight-v1"',
                          'SCHEMA = "gpu-scratch-eight-v1"\n' + HOST_MONITOR)
    source = replace_once(source, '"--setenv=RAYON_NUM_THREADS=8"',
                          f'"--setenv=RAYON_NUM_THREADS={threads}"')
    source = replace_once(source, 'f"--setenv=LATTICA_SPILL_DIR={config[\'job\']}/scratch"',
                          'f"--setenv=LATTICA_SPILL_DIR={config[\'scratch_dir\']}"')
    source = source.replace("128849018880", str(34 * GIB))
    require(source.count("120 * GIB") == 2, "unexpected spill gate/manifest")
    source = source.replace("120 * GIB", "34 * GIB")
    source = replace_once(source, '"aggregate_scratch_bytes": 128 * GIB',
                          '"aggregate_scratch_bytes": 36 * GIB')
    source = replace_once(source, '    config["external"] =',
                          f'    config["scratch_dir"] = {str(scratch)!r}\n'
                          f'    config["rayon_threads"] = {threads}\n'
                          f'    config["scratch_limit_bytes"] = {34 * GIB}\n'
                          '    config["external"] =')
    source = replace_once(source, '    validate_configuration(config)\n',
                          '    validate_configuration(config)\n'
                          '    H.private_directory(Path(config["scratch_dir"]))\n'
                          '    require(not any(Path(config["scratch_dir"]).iterdir()), "scratch not empty")\n')
    # Same cadence as VRAM samples; bounded persistent logs outside tmpfs.
    source = replace_once(source, '        self.output = path.open("xb")',
                          '        self.output = path.open("xb")\n'
                          '        self.host_path = path.with_name(path.stem + "-host.jsonl")\n'
                          '        self.host_output = self.host_path.open("xb")\n'
                          '        self.host_bytes = 0')
    source = replace_once(source, '        self.next_sample = time.monotonic() + 0.5',
                          '        self.next_sample = time.monotonic() + 0.5\n'
                          f'        host = sample_bench_host(self.group, {str(scratch)!r})\n'
                          '        data = (json.dumps(host, sort_keys=True) + "\\n").encode()\n'
                          '        self.host_bytes += len(data)\n'
                          '        require(self.host_bytes <= 32 * 2**20, "host telemetry exceeds log bound")\n'
                          '        self.host_output.write(data)')
    source = replace_once(source, '            self.output.close()\n',
                          '            self.output.close()\n'
                          '            self.host_output.flush()\n'
                          '            os.fsync(self.host_output.fileno())\n'
                          '            self.host_output.close()\n')
    source = replace_once(source, '                record["vram"] = monitor.result()',
                          '                record["host_log"] = monitor.host_path.name\n'
                          '                record["host_log_sha256"] = H.digest(monitor.host_path)\n'
                          '                record["vram"] = monitor.result()')
    source = replace_once(source, '            require(summarize_vram(path) == record["vram"], "saved VRAM summary differs from samples")',
                          '            require(summarize_vram(path) == record["vram"], "saved VRAM summary differs from samples")\n'
                          '            host = evidence / record["host_log"]\n'
                          '            H.regular_bytes(host, 32 * 2**20)\n'
                          '            require(H.digest(host) == record["host_log_sha256"], "host telemetry changed")')
    ast.parse(source)
    return source


def prepare(out, repeats):
    require(1 <= repeats <= 3, "choose one to three repeats per arm")
    require(not out.exists(), "plan directory already exists; use check/start or a new --plan")
    require(digest(TEMPLATE) == TEMPLATE_SHA, "qualified controller changed; review before deriving")
    baseline = json.loads(BASELINE.read_text())
    require(baseline["status"] == "GPU_PROOF_VERIFIED_RESEARCH_ONLY", "baseline incomplete")
    cfg = baseline["config"]
    require((cfg["backend"], cfg["gpu_openings"], cfg["gpu_compact"], cfg["quotient_fusion"])
            == ("resident", 1, 1, 0), "unexpected baseline modes")
    for key in ("gpu_runner", "cpu_runner", "auditor", "accounting", "source_archive"):
        require(digest(cfg[key]) == baseline["pins"][key], "baseline pin changed: " + key)
    helper = load_module(SCRIPTS / "block-v2-grouped-trial.py")
    require(helper.snapshot(Path(cfg["reference"])) == baseline["source_artifacts"],
            "reference fixtures changed")
    out.mkdir(mode=0o700)
    (out / "reference").mkdir(mode=0o700)
    (out / "reference/scratch").mkdir(mode=0o700)
    for name in baseline["source_artifacts"]:
        shutil.copyfile(Path(cfg["reference"]) / name, out / "reference" / name)
    require(helper.snapshot(out / "reference") == baseline["source_artifacts"], "fixture copy differs")
    support = out / "controllers"
    support.mkdir(mode=0o700)
    for name, pin in (("block-v2-grouped-trial.py", "helpers"),
                      ("block-v2-gpu-grouped-trial.py", "predecessor"),
                      ("block-v2-accounting.py", "accounting")):
        require(digest(SCRIPTS / name) == baseline["pins"][pin], "support pin changed")
        shutil.copyfile(SCRIPTS / name, support / name)
    shutil.copyfile(TEMPLATE, support / "qualified-compact-controller.py")
    tag = hashlib.sha256(str(out).encode()).hexdigest()[:12]
    scratch_root = Path(f"/tmp/lattica-scratch-bench-{os.getuid()}-{tag}")
    arms = {}
    source = TEMPLATE.read_text()
    for arm in ARMS:
        threads = 16 if arm.endswith("16") else 8
        scratch = (scratch_root if arm.startswith("ram") else out / "disk-scratch") / arm
        controller = support / f"scratch-{arm}.py"
        controller.write_text(derive_controller(source, threads, scratch))
        arms[arm] = {"threads": threads, "backing": "tmpfs" if arm.startswith("ram") else "disk",
                     "scratch": str(scratch), "controller": str(controller)}
    for name in ("jobs", "evidence", "logs", "disk-scratch"):
        (out / name).mkdir(mode=0o700)
    cfg = {key: value for key, value in cfg.items() if key not in ("mode", "job", "evidence", "registration")}
    cfg["reference"] = str(out / "reference")
    cfg["accounting"] = str(support / "block-v2-accounting.py")
    plan = {"schema": SCHEMA, "prepared_boot_id": boot_id(), "prepared_utc": time.time(),
            "production_ready": False, "config": cfg, "arms": arms,
            "scratch_root": str(scratch_root), "unit": f"lattica-v2-scratch-bench-{tag}.service",
            "minimum_available_ram_bytes": 46 * GIB, "minimum_tmp_free_bytes": 35 * GIB,
            "worker_memory_max_bytes": 44 * GIB, "spill_limit_bytes": 34 * GIB,
            "repeat_blocks": [list(ARMS if i % 2 == 0 else reversed(ARMS)) for i in range(repeats)],
            "baseline_manifest": str(BASELINE), "source_artifacts": baseline["source_artifacts"],
            "pins": {}}
    pinned = [Path(__file__).resolve(), BASELINE, *support.iterdir()]
    pinned += [Path(cfg[key]) for key in ("gpu_runner", "cpu_runner", "auditor", "source_archive")]
    plan["pins"] = {str(path): digest(path) for path in pinned}
    save(out / "plan.json", plan)
    print(json.dumps({"prepared": str(out), "measured_runs": repeats * 4,
                      "proofs_started": 0, "requires_new_boot": True}))


def read_plan(out):
    plan = json.loads((out / "plan.json").read_text())
    require(plan["schema"] == SCHEMA, "unexpected plan schema")
    for name, expected in plan["pins"].items():
        require(digest(name) == expected, "pinned file changed: " + name)
    helper = load_module(out / "controllers/block-v2-grouped-trial.py")
    require(helper.snapshot(Path(plan["config"]["reference"])) == plan["source_artifacts"],
            "prepared fixtures changed")
    return plan, helper


def command_output(arguments):
    return subprocess.check_output(arguments, text=True, timeout=15).strip()


def filesystem_type(path):
    observed = command_output(["findmnt", "--target", str(path), "--noheadings", "--output", "FSTYPE"])
    # A sandbox can expose the same filesystem through multiple overmounts.
    kinds = set(observed.split())
    require(len(kinds) == 1, "missing or ambiguous filesystem type: " + str(path))
    return kinds.pop()


def desktop_gpu_processes(output, gpu_uuid):
    """Allow only the current user's verified KDE compositor; never stop it."""
    observed = []
    desktop_group = None
    for row in csv.reader(io.StringIO(output)):
        require(len(row) == 4, "unexpected GPU process listing")
        uuid, pid, name, memory = [value.strip() for value in row]
        if uuid != gpu_uuid:
            continue
        require(pid.isdecimal(), "invalid GPU process PID")
        process = Path("/proc") / pid
        require(name == "/usr/bin/kwin_wayland" and process.stat().st_uid == os.getuid()
                and (process / "comm").read_text().strip() == "kwin_wayland",
                "GPU has a competing compute process: " + name)
        # KWin may be non-dumpable, making /proc/PID/exe unreadable even to its
        # owner. Bind the driver-reported executable to the active desktop
        # service instead. KWin can be a child of kwin_wayland_wrapper.
        if desktop_group is None:
            raw = command_output(["systemctl", "--user", "show", "plasma-kwin_wayland.service",
                                  "--property=ActiveState,ControlGroup", "--no-pager"])
            properties = dict(line.split("=", 1) for line in raw.splitlines())
            require(properties.get("ActiveState") == "active", "KDE compositor service is not active")
            desktop_group = properties.get("ControlGroup", "")
            require(desktop_group.startswith(f"/user.slice/user-{os.getuid()}.slice/")
                    and desktop_group.endswith("/plasma-kwin_wayland.service"), "unexpected desktop cgroup")
        require("0::" + desktop_group in (process / "cgroup").read_text().splitlines(),
                "GPU process is outside the verified desktop service")
        require(memory.isdecimal() and int(memory) <= 256, "unexpected compositor GPU memory use")
        observed.append({"pid": int(pid), "executable": name, "cgroup": desktop_group,
                         "gpu_memory_mib": int(memory)})
    return observed


def preflight(out, plan, helper, controller=None):
    require(boot_id() != plan["prepared_boot_id"], "reboot has not happened; preparation never starts proving")
    available = memory_available()
    require(available >= plan["minimum_available_ram_bytes"], "need at least 46 GiB MemAvailable")
    require(filesystem_type("/tmp") == "tmpfs", "/tmp must be tmpfs")
    fs = os.statvfs("/tmp")
    require(fs.f_bavail * fs.f_frsize >= plan["minimum_tmp_free_bytes"],
            "need at least 35 GiB free in /tmp; after reboot: sudo mount -o remount,size=36G /tmp")
    require(filesystem_type(out) not in ("tmpfs", "ramfs"), "disk arm/evidence must be persistent")
    require(shutil.disk_usage(out).free >= 36 * GIB, "disk arm needs 36 GiB free")
    units = command_output(["systemctl", "--user", "list-units", "--all", "--type=service",
                            "--state=active,activating,deactivating,reloading", "--plain",
                            "--no-legend", "--no-pager", "lattica-v2-*.service"])
    if controller:
        helper.validate_active_units(controller, units)
    else:
        require(not units, "another Lattica experiment is active; wait for it")
    gpu_rows = list(csv.reader(io.StringIO(command_output([
        "nvidia-smi", "--query-gpu=index,uuid,name,memory.total", "--format=csv,noheader,nounits"]))))
    matches = [[x.strip() for x in row] for row in gpu_rows
               if row and row[0].strip() == str(plan["config"]["gpu_index"])]
    require(len(matches) == 1 and matches[0][1] == plan["config"]["gpu_uuid"], "GPU identity changed")
    compute = command_output(["nvidia-smi", "--query-compute-apps=gpu_uuid,pid,process_name,used_gpu_memory",
                              "--format=csv,noheader,nounits"])
    desktop = desktop_gpu_processes(compute, plan["config"]["gpu_uuid"])
    return {"boot_id": boot_id(), "mem_available_bytes": available,
            "tmp_available_bytes": fs.f_bavail * fs.f_frsize, "gpu": matches[0],
            "desktop_gpu_processes": desktop,
            "lscpu": command_output(["lscpu", "--json"]),
            "note": "same unpinned hybrid-CPU placement policy; no core-type speedup inference"}


def invocation(out, plan, arm, label, register):
    cfg = plan["config"]
    argv = ["/usr/bin/python3", "-B", plan["arms"][arm]["controller"],
            "register" if register else "prove", str(out / "jobs" / label), str(out / "evidence" / label)]
    for key in ("reference", "gpu_runner", "cpu_runner", "auditor", "accounting", "source_archive",
                "backend", "gpu_index", "gpu_uuid", "quotient_fusion", "gpu_openings", "gpu_compact"):
        argv += ["--" + key.replace("_", "-"), str(cfg[key])]
    for key, value in zip(("profile", "chain", "root"), cfg["external"]):
        argv += ["--" + key, value]
    if not register:
        argv += ["--registration", str(out / "evidence" / f"register-{arm}" / "manifest.json")]
    return argv


def steps(plan):
    result = [(arm, f"register-{arm}", True) for arm in ARMS]
    for number, arms in enumerate(plan["repeat_blocks"], 1):
        result += [(arm, f"round-{number}-{arm}", False) for arm in arms]
    return result


def validate_progress(state, plan):
    attempts = state["attempts"]
    require(len(attempts) <= len(steps(plan)), "too many attempts")
    for item, (arm, label, register) in zip(attempts, steps(plan)):
        require(item["label"] == label and item["arm"] == arm and item["status"] == "complete",
                "incomplete/interrupted attempt; inspect evidence, never automatically retry")
    return len(attempts)


def run(out):
    plan, helper = read_plan(out)
    controller = helper.require_controller()
    require(controller == plan["unit"], "wrong controller service")
    state_path = out / "run-state.json"
    with helper.exclusive(out / "suite.lock"):
        state = json.loads(state_path.read_text()) if state_path.exists() else {
            "status": "RUNNING", "plan_sha256": digest(out / "plan.json"), "attempts": []}
        require(state["plan_sha256"] == digest(out / "plan.json"), "plan changed since first launch")
        first = validate_progress(state, plan)
        for item in state["attempts"]:
            manifest = out / "evidence" / item["label"] / "manifest.json"
            require(digest(manifest) == item["manifest_sha256"], "completed evidence changed")
        for arm, label, register in steps(plan)[first:]:
            # Abort if any input/tool changed, memory filled, or another job started.
            read_plan(out)
            observed = preflight(out, plan, helper, controller)
            scratch = Path(plan["arms"][arm]["scratch"])
            scratch.parent.mkdir(mode=0o700, exist_ok=True)
            helper.private_directory(scratch.parent)
            scratch.mkdir(mode=0o700, exist_ok=True)
            helper.private_directory(scratch)
            require(not any(scratch.iterdir()), "scratch is not empty")
            log = out / "logs" / f"{label}.log"
            argv = invocation(out, plan, arm, label, register)
            record = {"label": label, "arm": arm, "register": register, "status": "attempted",
                      "started_utc": time.time(), "preflight": observed, "command": argv, "log": str(log)}
            state["status"] = "RUNNING"
            state["attempts"].append(record)
            save(state_path, state)
            print(json.dumps({"starting": label}), flush=True)
            started = time.monotonic()
            try:
                with log.open("xb") as stream:
                    subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, check=True,
                                   env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                    stream.flush()
                    os.fsync(stream.fileno())
                manifest = out / "evidence" / label / "manifest.json"
                evidence = json.loads(manifest.read_text())
                expected = "GPU_KEYS_MATCH_CPU_RESEARCH_ONLY" if register else "GPU_PROOF_VERIFIED_RESEARCH_ONLY"
                require(evidence["status"] == expected, "controller did not qualify result")
                helper.require_no_other_work(controller)
                record.update(status="complete", elapsed_seconds=time.monotonic() - started,
                              manifest_sha256=digest(manifest), log_sha256=digest(log))
                save(state_path, state)
            except BaseException as error:
                record.update(status="failed_or_interrupted", error=str(error))
                state["status"] = "FAILED_OR_INTERRUPTED"
                save(state_path, state)
                raise
        state["status"] = "COMPLETE_RESEARCH_ONLY"
        save(state_path, state)
        summarize(out)


def summarize(out):
    plan, _ = read_plan(out)
    state = json.loads((out / "run-state.json").read_text())
    result = {"status": state["status"], "production_ready": False, "arms": {}}
    for arm in ARMS:
        rows = []
        for item in state["attempts"]:
            if item["arm"] != arm or item["register"] or item["status"] != "complete":
                continue
            path = out / "evidence" / item["label"] / "manifest.json"
            require(digest(path) == item["manifest_sha256"], "measured manifest changed")
            d = json.loads(path.read_text())
            stages = [a for a in d["attempts"] if a["name"] in ("pairs", "merges")]
            wall = sum(a["wall_seconds"] for a in stages)
            cpu = sum(a["telemetry"]["accounting"]["cpu_usage_usec"] for a in stages) / 1e6
            rows.append({"label": item["label"], "recursive_seconds": d["recursive_command_ms"] / 1000,
                         "worker_stage_seconds": wall, "cpu_seconds": cpu, "average_logical_cpus": cpu / wall,
                         "peak_worker_ram_bytes": max(a["telemetry"]["accounting"]["memory_peak"] for a in stages),
                         "peak_mapped_scratch_bytes": max(a["telemetry"]["duration"]["spill_peak_bytes"] for a in stages)})
        result["arms"][arm] = {"runs": rows, "median_recursive_seconds":
                               statistics.median(r["recursive_seconds"] for r in rows) if rows else None}
    save(out / "summary.json", result)
    print(json.dumps(result, indent=2))


def start(out):
    plan, helper = read_plan(out)
    preflight(out, plan, helper)
    if (out / "run-state.json").exists():
        state = json.loads((out / "run-state.json").read_text())
        require(state["status"] != "COMPLETE_RESEARCH_ONLY", "suite already complete")
        validate_progress(state, plan)
    # Runtime-only slice limits, restored after reboot rather than a persistent edit.
    subprocess.run(["systemctl", "--user", "start", SLICE], check=True, timeout=15)
    subprocess.run(["systemctl", "--user", "set-property", "--runtime", SLICE,
                    "MemoryMax=48G", "MemorySwapMax=0"], check=True, timeout=15)
    subprocess.run(["systemd-run", "--user", "--collect", "--expand-environment=no",
                    f"--unit={plan['unit']}", f"--slice={SLICE}", "--property=MemoryAccounting=yes",
                    "--property=MemoryMax=3G", "--property=MemorySwapMax=0", "--property=RuntimeMaxSec=21600",
                    "--property=KillMode=control-group", "--property=UMask=0077", "--property=LimitCORE=0",
                    "--", "/usr/bin/python3", "-B", str(Path(__file__).resolve()),
                    "_run", "--plan", str(out)], check=True, timeout=15)
    print("Started " + plan["unit"])
    print("Observe: journalctl --user -fu " + plan["unit"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check", "start", "_run", "summary"))
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--live", action="store_true", help="check post-reboot host resources too")
    args = parser.parse_args()
    os.umask(0o077)
    out = args.plan.resolve()
    require(re.fullmatch(r"/[A-Za-z0-9_./-]+", str(out)), "simple absolute plan path required")
    if args.action == "prepare":
        prepare(out, args.repeats)
    elif args.action == "check":
        plan, helper = read_plan(out)
        result = {"static_pins_and_fixtures": "PASS", "proofs_started": 0,
                  "new_boot": boot_id() != plan["prepared_boot_id"]}
        if args.live:
            result["preflight"] = preflight(out, plan, helper)
        print(json.dumps(result, indent=2))
    elif args.action == "start":
        start(out)
    elif args.action == "_run":
        run(out)
    else:
        summarize(out)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        sys.exit(1)
