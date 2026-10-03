#!/usr/bin/env python3
"""Bounded compact-opening qualification; never production activation.

Derived from the frozen GPU grouped controller without modifying or executing it.
COMPACT is explicit for every child; PINNED is always off. Observed work, not just
environment intent, is required. Old evidence cannot be resumed under this schema.

The frozen CPU controller is used only for its reviewed pure/file/resource
helpers. Its runner, stage policy, and CPU-only telemetry are never monkeypatched.
Attempted/incomplete stages are not automatically rerun on resume.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import time
import types

HELPER_SHA256 = "8bd17f9e084bb95119829b2c356e6f2968539e14011955d8ed623cb29c5e489e"
ACCOUNTING_SHA256 = "f9b665c3210ec602799acf5ada2338084063677d42d48065324f23f31bdd1ad0"
HELPER_PATH = Path(__file__).resolve().with_name("block-v2-grouped-trial.py")
PREDECESSOR_PATH = Path(__file__).resolve().with_name("block-v2-gpu-grouped-trial.py")
PREDECESSOR_SHA256 = "5c80b001f864289925452f6223520e7dc700f795147373987f68d402c6c56614"


def load_helpers():
    data = HELPER_PATH.read_bytes()
    if hashlib.sha256(data).hexdigest() != HELPER_SHA256:
        raise ValueError("frozen grouped helper pin mismatch")
    module = types.ModuleType("lattica_frozen_grouped_helpers")
    module.__file__ = str(HELPER_PATH)
    # Execute the bytes that were actually hashed, not a second unpinned read.
    exec(compile(data, str(HELPER_PATH), "exec"), module.__dict__)
    return module


H = load_helpers()
require = H.require
GIB = H.GIB
MAX_VRAM_MIB = 12 * 1024
MAX_VRAM_LOG = 8 * 2**20
VRAM_SCOPE = "worker cgroup across compute processes; sampled, not an instantaneous driver quota"
INPUT_NAMES = set(H.WALLETS + H.ROOT_FILES[1:])
KEYLESS_NAMES = set(H.WALLETS + ("height",))
SCHEMA = "gpu-compact-eight-v1"


def stages(config):
    if config["mode"] == "register":
        return [("seed", []), ("reference-check", ["check-registered"]),
                ("key-1", ["register", "1"]), ("key-2", ["register", "2"]),
                ("key-3", ["register", "3"]), ("check", ["check-registered"])]
    return [("seed", []), ("check", ["check-registered"]), ("pairs", ["wrap-all"]),
            ("merges", ["merge-all"]), ("prune", ["remove-inners"]),
            ("root", ["verify-root"]), ("export", []), ("audit", ["root-eight"])]


def gpu_stage(name):
    return name in ("key-1", "key-2", "key-3", "pairs", "merges")


def validate_transition(config, name, before, after, source):
    require(after is not None, "job missing after stage")
    if name == "seed":
        names = KEYLESS_NAMES if config["mode"] == "register" else INPUT_NAMES
        require(before is None and set(after) == names, "seed requires a new exact job")
        require(after == {key: source[key] for key in names}, "seed differs from pinned public fixtures")
        return
    H.validate_transition(name, before, after)
    if name.startswith("key-"):
        key = "key." + name[-1]
        require(after[key] == source[key], "GPU preprocessing cap differs from independently registered CPU cap")


def invocation(config, name, action):
    if name == "audit":
        return [config["auditor"], *action, str(Path(config["evidence"]) / "root-only"), *config["external"]]
    runner = config["gpu_runner"] if gpu_stage(name) else config["cpu_runner"]
    directory = config["reference"] if name == "reference-check" else config["job"]
    args = [runner, action[0], directory]
    if not name.startswith("key-"):
        args += config["external"]
    return args + action[1:]


def stage_command(config, controller, unit, name, action):
    validate_opening_mode(config)
    gpu = gpu_stage(name)
    resident = gpu and config["backend"] == "resident"
    return ["systemd-run", "--user", "--wait", "--pipe", "--collect", "--expand-environment=no",
            f"--unit={unit}", f"--slice={H.RESOURCE_SLICE}",
            "--property=MemoryAccounting=yes", "--property=MemoryHigh=40G",
            "--property=MemoryMax=44G", "--property=MemorySwapMax=0",
            "--property=RuntimeMaxSec=7200", "--property=LimitCORE=0", "--property=UMask=0077",
            "--property=KillMode=control-group", f"--property=BindsTo={controller}",
            f"--property=After={controller}",
            f"--property=ExecStopPost=/usr/bin/python3 -B {config['accounting']}",
            f"--setenv=LATTICA_V2_ACCOUNTING_UNIT={unit}",
            "--setenv=RAYON_NUM_THREADS=8", "--setenv=LATTICA_FFT_TRACE=1",
            "--setenv=LATTICA_PROFILE=1", "--setenv=LATTICA_PROFILE_TIMELINE=0",
            f"--setenv=LATTICA_SPILL_DIR={config['job']}/scratch",
            "--setenv=LATTICA_SPILL_MAX_BYTES=128849018880",
            f"--setenv=LATTICA_V2_GPU_HASH={int(gpu or name == 'audit')}",
            f"--setenv=LATTICA_V2_GPU_DEVICE={config['gpu_index'] if gpu else 4294967295}",
            "--setenv=LATTICA_V2_GPU_PIPELINE=0",
            f"--setenv=LATTICA_V2_GPU_RETAIN_TREES={int(gpu)}",
        f"--setenv=LATTICA_V2_GPU_RESIDENT_LDE={int(resident)}",
        f"--setenv=LATTICA_V2_GPU_OPENINGS={config['gpu_openings'] if gpu else 0}",
            f"--setenv=LATTICA_V2_GPU_OPENING_COMPACT={config['gpu_compact'] if gpu else 0}",
            "--setenv=LATTICA_V2_GPU_OPENING_PINNED=0",
            f"--setenv=LATTICA_V2_QUOTIENT_FUSION={config['quotient_fusion'] if gpu else 0}",
            "--", *invocation(config, name, action)]


def fields(line):
    tokens = shlex.split(line)
    result = {}
    for token in tokens[1:]:
        require("=" in token, "malformed GPU telemetry")
        key, value = token.split("=", 1)
        require(key and key not in result, "duplicate GPU telemetry field")
        result[key] = value
    return result


def validate_gpu_log(path, unit, name, resident, openings=False, compact=False):
    require(type(resident) is bool and type(openings) is bool and type(compact) is bool
            and (not openings or resident) and (not compact or openings), "opening backend classification")
    opening_checkpoints, compact_checkpoints, upload_checkpoints, policies = [], [], [], []
    accounting, durations, nodes, selected, initialized, checkpoints, ldes, keys = [], [], [], [], [], [], [], []
    shutdown = 0
    for line in H.regular_bytes(path, H.MAX_STAGE_LOG).decode().splitlines():
        require(not line.startswith("FAILED:"), "GPU stage reported failure")
        if line.startswith("stage_cgroup_accounting "):
            record = H.fields(line)
            require(set(record) == {"unit", "scope", "memory_peak", "memory_swap_peak", "memory_max", "memory_swap_max", "cpu_usage_usec"}, "accounting fields")
            require(record.pop("unit") == unit and record.pop("scope") == "exec_stop_post_snapshot", "accounting binding")
            record = {key: H.natural(value) for key, value in record.items()}
            require(record["memory_max"] == 44 * GIB and record["memory_swap_max"] == 0
                    and record["memory_swap_peak"] == 0 and record["memory_peak"] <= 44 * GIB, "worker resource gate")
            accounting.append(record)
        elif line.startswith("grouped_stage_elapsed_ms="):
            record = fields("stage " + line)
            require(set(record) == {"grouped_stage_elapsed_ms", "spill_peak_bytes", "cpu_only", "resident_lde", "gpu_openings", "production_ready"}, "duration fields")
            require(record["cpu_only"] == "false" and record["production_ready"] == "false"
                    and record["resident_lde"] == str(resident).lower()
                    and record["gpu_openings"] == str(openings).lower(), "GPU stage classification")
            require(H.natural(record["spill_peak_bytes"]) <= 120 * GIB, "spill gate")
            durations.append({"elapsed_ms": H.natural(record["grouped_stage_elapsed_ms"]), "spill_peak_bytes": H.natural(record["spill_peak_bytes"])})
        elif line.startswith("grouped_node_complete "):
            record = H.fields(line)
            require(record["resumed"] == "false" and record["production_ready"] == "false", "timed proof cannot be resumed")
            nodes.append({"artifact": record["artifact"], "elapsed_ms": H.natural(record["elapsed_ms"]),
                          "setups": H.natural(record["setups"]), "cache_hits": H.natural(record["cache_hits"])})
        elif line.startswith("gpu_grouped_research "):
            record = H.fields(line)
            require(record == {"resident_lde": str(resident).lower(), "gpu_openings": str(openings).lower(), "retained_trees": "true", "transfer_overlap": "false", "cpu_only": "false", "production_ready": "false"}, "backend marker")
            selected.append(record)
        elif line.startswith("gpu_grouped_opening_policy "):
            record = H.fields(line)
            require(record == {"compact": str(compact).lower(), "pinned": "false",
                               "cpu_only": "false", "production_ready": "false"}, "opening policy marker")
            policies.append(record)
        elif line.startswith("grouped_key_generated "):
            keys.append(H.fields(line))
        elif line.startswith("bounded_gpu_initialized "):
            record = fields(line)
            require(record["contexts"] == "1" and record["job_lease"] == "exclusive", "GPU context/lease")
            require(H.natural(record["managed_limit_bytes"]) == 8 * GIB
                    and H.natural(record["driver_reserve_bytes"]) == 4 * GIB, "GPU admission budget")
            initialized.append(record)
        elif line.startswith("bounded_gpu_checkpoint "):
            record = fields(line)
            require(H.natural(record["managed_peak_bytes"]) <= 8 * GIB, "managed GPU allocation limit")
            if record["label"] == "GPU grouped process remainder": checkpoints.append(record)
        elif line.startswith("bounded_gpu_lde_checkpoint "):
            record = fields(line)
            if record["label"] == "GPU grouped process remainder": ldes.append(record)
        elif line.startswith("bounded_gpu_opening_checkpoint "):
            record = fields(line)
            numeric = {"calls", "tiles", "uploaded_bytes", "downloaded_bytes", "kernel_ns", "wall_ns"}
            require(set(record) == numeric | {"label", "counters"}
                    and record["counters"] == "cumulative", "opening checkpoint fields/scope")
            values = {key: H.natural(record[key]) for key in numeric}
            require(values["kernel_ns"] <= values["wall_ns"], "opening kernel/wall accounting")
            if record["label"] == "GPU grouped process remainder": opening_checkpoints.append(values)
        elif line.startswith("bounded_gpu_opening_compact_checkpoint "):
            record = fields(line)
            numeric = {"calls", "saved_input_bytes", "compress_ns", "ntt_ns"}
            require(set(record) == numeric | {"label", "counters", "timings"}
                    and record["counters"] == "cumulative" and record["timings"] == "nonadditive",
                    "compact checkpoint fields/scope")
            values = {key: H.natural(record[key]) for key in numeric}
            if record["label"] == "GPU grouped process remainder": compact_checkpoints.append(values)
        elif line.startswith("bounded_gpu_opening_upload_checkpoint "):
            record = fields(line)
            numeric = {"pinned_uploaded_bytes", "pinned_chunks"}
            require(set(record) == numeric | {"label", "counters"}
                    and record["counters"] == "cumulative", "upload checkpoint fields/scope")
            values = {key: H.natural(record[key]) for key in numeric}
            require(all(value == 0 for value in values.values()), "unexpected pinned opening upload")
            if record["label"] == "GPU grouped process remainder": upload_checkpoints.append(values)
        elif line.startswith("bounded_gpu_shutdown "):
            require(H.fields(line) == {"managed_live_bytes": "0", "lease_released": "true"}, "GPU teardown")
            shutdown += 1
    require(all(len(records) == 1 for records in (accounting, durations, selected, initialized, checkpoints, ldes, opening_checkpoints, compact_checkpoints, upload_checkpoints, policies))
            and shutdown == 1, "missing/duplicate GPU stage evidence")
    expected = H.PAIRS if name == "pairs" else H.MERGES if name == "merges" else ()
    require(tuple(node["artifact"] for node in nodes) == expected, "GPU proof sequence")
    expected_keys = [{"mode": name[-1], "cpu_only": "false", "approval": "false"}] if name.startswith("key-") else []
    require(keys == expected_keys, "GPU key-generation marker")
    require(H.natural(checkpoints[0]["commits"]) > 0, "GPU work absent")
    count = H.natural(ldes[0]["commits"])
    require((count > 0) if resident else (count == 0), "resident backend work mismatch")
    opening = opening_checkpoints[0]
    expected_calls = len(expected) if openings else 0
    require(opening["calls"] == expected_calls, "opening work count mismatch")
    if expected_calls:
        require(opening["tiles"] >= expected_calls and all(opening[key] > 0 for key in
                ("uploaded_bytes", "downloaded_bytes", "kernel_ns", "wall_ns")), "opening work absent")
        require(opening["wall_ns"] < (durations[0]["elapsed_ms"] + 1) * 1_000_000,
                "opening wall time exceeds complete stage")
    else:
        require(all(value == 0 for value in opening.values()), "unexpected opening work")
    compact_work = compact_checkpoints[0]
    compact_calls = expected_calls if compact else 0
    require(compact_work["calls"] == compact_calls, "compact work count mismatch")
    if compact_calls:
        require(all(compact_work[key] > 0 for key in ("saved_input_bytes", "compress_ns", "ntt_ns")),
                "compact compression/extension work absent")
        require(all(compact_work[key] <= opening["wall_ns"] for key in ("compress_ns", "ntt_ns")),
                "compact timing exceeds complete opening span")
    else:
        require(all(value == 0 for value in compact_work.values()), "unexpected compact work")
    core_upload = H.natural(checkpoints[0]["uploaded_bytes"])
    core_download = H.natural(checkpoints[0]["downloaded_bytes"])
    transfers = {"core_uploaded_bytes": core_upload, "core_downloaded_bytes": core_download,
                 "opening_uploaded_bytes": opening["uploaded_bytes"], "opening_downloaded_bytes": opening["downloaded_bytes"],
                 "uploaded_bytes": core_upload + opening["uploaded_bytes"],
                 "downloaded_bytes": core_download + opening["downloaded_bytes"]}
    return {"accounting": accounting[0], "duration": durations[0], "nodes": nodes,
            "gpu": initialized[0], "checkpoint": checkpoints[0], "lde": ldes[0],
            "opening": opening, "opening_compact": compact_work,
            "opening_upload": upload_checkpoints[0], "opening_policy": policies[0],
            "recorded_host_device_transfers": transfers,
            "opening_timing_scope": "nonadditive subset of complete recursive stage wall time"}


def proof_transfer_totals(attempts):
    proof_stages = [record for record in attempts if record["name"] in ("pairs", "merges")]
    require([record["name"] for record in proof_stages] == ["pairs", "merges"], "complete proof transfer stages required")
    fields = ("core_uploaded_bytes", "core_downloaded_bytes", "opening_uploaded_bytes",
              "opening_downloaded_bytes", "uploaded_bytes", "downloaded_bytes")
    totals = {key: sum(record["telemetry"]["recorded_host_device_transfers"][key] for record in proof_stages)
              for key in fields}
    totals["opening_calls"] = sum(record["telemetry"]["opening"]["calls"] for record in proof_stages)
    totals["compact_calls"] = sum(record["telemetry"]["opening_compact"]["calls"] for record in proof_stages)
    totals["compact_saved_input_bytes"] = sum(record["telemetry"]["opening_compact"]["saved_input_bytes"] for record in proof_stages)
    return totals


def parse_vram_rows(output, belongs, expected_uuid):
    total, pids, seen = 0, [], set()
    for line in output.splitlines():
        if not line.strip(): continue
        fields = [part.strip() for part in line.split(",")]
        require(len(fields) == 3 and fields[1].isdecimal(), "invalid NVIDIA process inventory")
        uuid, pid, used = fields
        pid = int(pid)
        require((uuid, pid) not in seen, "duplicate NVIDIA process row")
        seen.add((uuid, pid))
        if not belongs(pid): continue
        require(uuid == expected_uuid and used.isdecimal(), "unavailable/wrong-device worker VRAM")
        total += int(used)
        pids.append(pid)
    require(total <= MAX_VRAM_MIB, "aggregate worker VRAM exceeds 12 GiB")
    return total, pids


class VramMonitor:
    """Sample only this worker's cgroup, never signal unrelated GPU processes."""
    def __init__(self, unit, uuid, path):
        own = [line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")]
        require(len(own) == 1, "monitor requires cgroup v2")
        self.group = str(Path(own[0]).parent / unit)
        self.uuid, self.path = uuid, path
        self.samples = self.positive_samples = self.peak_mib = self.bytes = self.errors = 0
        self.next_sample = 0
        self.output = path.open("xb")

    def belongs(self, pid):
        try:
            rows = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        except FileNotFoundError:
            return False
        return any(line == "0::" + self.group or line.startswith("0::" + self.group + "/") for line in rows)

    def sample(self):
        if time.monotonic() < self.next_sample: return
        self.next_sample = time.monotonic() + 0.5
        try:
            result = subprocess.run(["nvidia-smi", "--query-compute-apps=gpu_uuid,pid,used_gpu_memory",
                                     "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=5, check=True)
        except (subprocess.SubprocessError, OSError) as error:
            self.errors += 1
            require(self.errors < 3, f"NVIDIA monitor failed repeatedly: {error}")
            return
        self.errors = 0
        total, pids = parse_vram_rows(result.stdout, self.belongs, self.uuid)
        row = (json.dumps({"utc_ns": time.time_ns(), "total_mib": total, "pids": pids}, sort_keys=True) + "\n").encode()
        self.bytes += len(row)
        require(self.bytes <= MAX_VRAM_LOG, "VRAM evidence exceeds bounded log size")
        self.output.write(row)
        self.samples += 1
        self.positive_samples += int(total > 0)
        self.peak_mib = max(self.peak_mib, total)

    def close(self):
        if self.output.closed:
            return
        try:
            self.output.flush()
            os.fsync(self.output.fileno())
        finally:
            self.output.close()

    def result(self):
        require(self.samples > 0 and self.positive_samples > 0 and self.errors == 0, "worker GPU memory was not successfully observed")
        return {"samples": self.samples, "positive_samples": self.positive_samples,
                "peak_mib": self.peak_mib, "limit_mib": MAX_VRAM_MIB,
                "scope": VRAM_SCOPE}


def capture_gpu_stage(command, log, monitor, timeout=7230):
    with log.open("xb") as output, selectors.DefaultSelector() as selector:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline, count = time.monotonic() + timeout, 0
            while True:
                require(time.monotonic() < deadline, "GPU stage capture deadline exceeded")
                monitor.sample()
                if not selector.select(0.25): continue
                data = os.read(process.stdout.fileno(), 65536)
                if not data: break
                count += len(data)
                require(count <= H.MAX_STAGE_LOG, "GPU stage log exceeds limit")
                output.write(data)
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            output.flush()
            os.fsync(output.fileno())
            return code
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()


def seed_job(config, source):
    job, reference = Path(config["job"]), Path(config["reference"])
    names = KEYLESS_NAMES if config["mode"] == "register" else INPUT_NAMES
    job.mkdir(mode=0o700)
    (job / "scratch").mkdir(mode=0o700)
    for name in sorted(names):
        data = H.regular_bytes(reference / name)
        require({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} == source[name], "reference changed while seeding")
        fd = os.open(job / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    H.sync_directory(job)
    H.sync_directory(job.parent)


def pin_paths(config):
    paths = {key: Path(config[key]) for key in ("gpu_runner", "cpu_runner", "auditor", "accounting", "source_archive")}
    paths.update(controller=Path(__file__).resolve(), helpers=HELPER_PATH, predecessor=PREDECESSOR_PATH)
    if config["mode"] == "prove": paths["registration"] = Path(config["registration"])
    return paths


def implementation_pins(config):
    pins = {key: H.digest(path) for key, path in pin_paths(config).items()}
    require(pins["helpers"] == HELPER_SHA256 and pins["accounting"] == ACCOUNTING_SHA256
            and pins["predecessor"] == PREDECESSOR_SHA256, "frozen support pin mismatch")
    return pins


def verify_evidence(state, evidence):
    validate_opening_mode(state["config"])
    for number, record in enumerate(state["attempts"], 1):
        name = record["name"]
        require(record["status"] == "complete", "incomplete stage evidence")
        require(record["log"] == f"{number:02d}-{name}.log", "stage log name is not canonical")
        if name not in ("seed", "export"):
            require("log_sha256" in record and "telemetry" in record, "completed stage lacks evidence")
            log = evidence / record["log"]
            H.regular_bytes(log, H.MAX_STAGE_LOG)
            parsed = (validate_gpu_log(log, record["unit"], name, state["config"]["backend"] == "resident", bool(state["config"]["gpu_openings"]), bool(state["config"]["gpu_compact"]))
                      if gpu_stage(name) else H.validate_log(log, record["unit"], name))
            if gpu_stage(name):
                require(H.natural(parsed["gpu"]["device_index"]) == state["config"]["gpu_index"],
                        "saved GPU selection differs from configuration")
            require(parsed == record["telemetry"], "saved telemetry differs from the actual log")
        if gpu_stage(name):
            require(record.get("vram_log") == f"{number:02d}-{name}-vram.jsonl"
                    and "vram_log_sha256" in record and "vram" in record, "GPU stage lacks VRAM evidence")
    H.verify_saved_evidence(state, evidence)
    for record in state["attempts"]:
        if "vram_log_sha256" in record:
            path = evidence / record["vram_log"]
            require(len(H.regular_bytes(path, MAX_VRAM_LOG)) <= MAX_VRAM_LOG
                    and H.digest(path) == record["vram_log_sha256"], "VRAM evidence changed")
            require(summarize_vram(path) == record["vram"], "saved VRAM summary differs from samples")


def summarize_vram(path):
    samples = positive = peak = 0
    for line in H.regular_bytes(path, MAX_VRAM_LOG).splitlines():
        row = json.loads(line)
        require(set(row) == {"utc_ns", "total_mib", "pids"}
                and type(row["utc_ns"]) is int and row["utc_ns"] > 0
                and type(row["total_mib"]) is int and 0 <= row["total_mib"] <= MAX_VRAM_MIB
                and isinstance(row["pids"], list)
                and all(type(pid) is int and pid > 0 for pid in row["pids"])
                and len(set(row["pids"])) == len(row["pids"]), "invalid VRAM sample")
        require(row["total_mib"] == 0 or row["pids"], "positive VRAM sample lacks a worker")
        samples += 1
        positive += int(row["total_mib"] > 0)
        peak = max(peak, row["total_mib"])
    require(samples > 0 and positive > 0, "no positive worker VRAM samples")
    return {"samples": samples, "positive_samples": positive, "peak_mib": peak,
            "limit_mib": MAX_VRAM_MIB, "scope": VRAM_SCOPE}


def registration_gate(config, pins, source):
    path = Path(config["registration"])
    state = json.loads(H.regular_bytes(path))
    require(state["schema"] == SCHEMA and state["status"] == "GPU_KEYS_MATCH_CPU_RESEARCH_ONLY"
            and state["production_ready"] is False, "GPU key qualification is missing")
    registered = state["config"]
    validate_opening_mode(registered)
    require(registered["mode"] == "register", "not a registration record")
    for key in ("external", "backend", "gpu_index", "gpu_uuid", "quotient_fusion", "gpu_openings", "gpu_compact"):
        require(type(registered[key]) is type(config[key]) and registered[key] == config[key], "registration mode/profile/device differs")
    require(state["source_artifacts"] == source and state["artifacts"] == source, "registration fixture/key binding differs")
    for key in ("gpu_runner", "cpu_runner", "auditor", "accounting", "source_archive", "helpers", "controller", "predecessor"):
        require(state["pins"][key] == pins[key], "registration implementation pin differs")
    plan = stages(registered)
    require(H.validate_prefix(state, plan) == len(plan), "registration sequence incomplete")
    verify_evidence(state, path.parent)
    for record in state["attempts"]:
        if record["name"].startswith("key-"):
            expected = source["key." + record["name"][-1]]
            require(record["cpu_key_equivalence"] == expected, "registered CPU-cap equivalence missing")
            require(record["vram"]["positive_samples"] > 0 and record["vram"]["peak_mib"] <= MAX_VRAM_MIB,
                    "registration GPU resource evidence missing")


def run_stage(config, controller, name, action, evidence, state, state_path):
    number = len(state["attempts"]) + 1
    unit = f"lattica-v2-gpu-grouped-{os.getpid()}-{number}.service"
    log = evidence / f"{number:02d}-{name}.log"
    record = {"name": name, "status": "attempted", "unit": unit, "log": log.name,
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    state["attempts"].append(record)
    H.save(state_path, state)  # Durable before process launch or artifact writes.
    started = time.monotonic()
    monitor = None
    try:
        if name == "seed":
            seed_job(config, state["source_artifacts"])
        elif name == "export":
            record["bundle"] = H.export_bundle(Path(config["job"]), evidence / "root-only")
        else:
            command = stage_command(config, controller, unit, name, action)
            if gpu_stage(name):
                record["vram_log"] = f"{number:02d}-{name}-vram.jsonl"
                H.save(state_path, state)
                monitor = VramMonitor(unit, config["gpu_uuid"], evidence / record["vram_log"])
                code = capture_gpu_stage(command, log, monitor)
                monitor.close()
                require(code == 0, f"GPU stage {name} failed; inspect {log}")
                record["vram"] = monitor.result()
                record["vram_log_sha256"] = H.digest(evidence / record["vram_log"])
                monitor = None
                record["telemetry"] = validate_gpu_log(log, unit, name, config["backend"] == "resident", bool(config["gpu_openings"]), bool(config["gpu_compact"]))
                require(H.natural(record["telemetry"]["gpu"]["device_index"]) == config["gpu_index"], "GPU selection changed")
            else:
                code = H.capture_stage(command, log)
                require(code == 0, f"CPU stage {name} failed; inspect {log}")
                record["telemetry"] = H.validate_log(log, unit, name)
                if name == "audit":
                    require(record["telemetry"]["audit_proof_bytes"] == len(H.regular_bytes(evidence / "root-only" / "node.3.0")), "auditor proof length differs")
            # systemd-run observation ending alone is not permission to advance.
            # Require the authoritative service inventory to contain no worker.
            H.require_no_other_work(controller)
            record["log_sha256"] = H.digest(log)
        record["wall_seconds"] = time.monotonic() - started
        after = H.snapshot(Path(config["job"]))
        validate_transition(config, name, state["artifacts"], after, state["source_artifacts"])
        if name.startswith("key-"):
            record["cpu_key_equivalence"] = after["key." + name[-1]]
        state["artifacts"] = after
        record["status"] = "complete"
        H.save(state_path, state)
    except BaseException as error:
        record["status"] = "failed_or_interrupted"
        record["error"] = str(error)
        state["status"] = "FAILED_OR_INTERRUPTED"
        # Keep the original failure durable even if stop/observation fails.
        # A failed observation is not permission to retry or start another job.
        H.save(state_path, state)
        if name not in ("seed", "export"):
            try:
                stopped = subprocess.run(["systemctl", "--user", "stop", unit], timeout=30, check=False)
                record["cleanup_stop_returncode"] = stopped.returncode
                H.require_no_other_work(controller)
                record["cleanup_no_active_worker"] = True
            except (subprocess.SubprocessError, OSError, ValueError) as cleanup_error:
                record["cleanup_error"] = str(cleanup_error)
                record["cleanup_no_active_worker"] = False
            H.save(state_path, state)
        raise
    finally:
        if monitor is not None and not monitor.output.closed:
            monitor.close()


def validate_opening_mode(config):
    require(type(config["gpu_openings"]) is int and config["gpu_openings"] in (0, 1), "explicit GPU opening mode required")
    require(not config["gpu_openings"] or config["backend"] == "resident", "GPU openings require resident backend")
    require(type(config["gpu_compact"]) is int and config["gpu_compact"] in (0, 1), "explicit compact opening mode required")
    require(not config["gpu_compact"] or config["gpu_openings"] == 1, "compact openings require GPU openings")


def validate_configuration(config):
    require(config["mode"] in ("register", "prove") and config["backend"] in ("retained", "resident"), "unsupported workflow/backend")
    require(type(config["gpu_index"]) is int and 0 <= config["gpu_index"] < 2**32,
            "GPU index must be a bounded nonnegative integer")
    require(re.fullmatch(r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", config["gpu_uuid"]) is not None, "explicit NVIDIA GPU UUID required")
    require(type(config["quotient_fusion"]) is int and config["quotient_fusion"] in (0, 1), "explicit quotient fusion mode required")
    validate_opening_mode(config)
    require(len(config["external"]) == 3, "external profile/chain/root are mandatory")
    for i, value in enumerate(config["external"]):
        require(H.external_hex(value, root=i == 2) == value, "external input must be canonical lowercase hex")
    path_keys = ("job", "evidence", "reference", "gpu_runner", "cpu_runner", "auditor", "accounting", "source_archive")
    if config["mode"] == "prove": path_keys += ("registration",)
    else: require("registration" not in config, "registration workflow cannot consume its own evidence")
    for key in path_keys:
        value = config[key]
        require(re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is not None
                and not Path(value).is_symlink() and str(Path(value).resolve()) == value,
                "paths must be canonical simple absolute paths without symlinks/specifiers")
    paths = [Path(config[key]) for key in ("job", "evidence", "reference")]
    for i, first in enumerate(paths):
        for second in paths[i + 1:]:
            require(first != second and first not in second.parents and second not in first.parents,
                    "job, evidence and reference must be separate nonnested directories")
    binaries = [config[key] for key in ("gpu_runner", "cpu_runner", "auditor")]
    require(len(set(binaries)) == 3 and all(os.access(path, os.X_OK) for path in binaries),
            "separate executable GPU worker, CPU runner, and CPU auditor are required")


def validate_resume_binding(state, config, pins, source):
    validate_opening_mode(state["config"])
    require(state["schema"] == SCHEMA and state["config"] == config and state["pins"] == pins
            and state["source_artifacts"] == source, "resume binding changed")


def run(config, resume):
    validate_configuration(config)
    controller = H.require_controller()
    evidence, job, reference = (Path(config[key]) for key in ("evidence", "job", "reference"))
    source = H.snapshot(reference)
    require(source is not None and set(source) == INPUT_NAMES,
            "reference requires exactly eight public wallet proofs, height and CPU keys")
    lease = H.shared_lease_path()
    lease.mkdir(mode=0o700, exist_ok=True)
    H.private_directory(lease)
    if not resume: evidence.mkdir(mode=0o700)
    H.private_directory(evidence)
    with H.exclusive(lease / "exclusive.lock"), H.exclusive(evidence / "controller.lock"):
        H.require_no_other_work(controller)
        pins = implementation_pins(config)
        if config["mode"] == "prove": registration_gate(config, pins, source)
        plan, state_path = stages(config), evidence / "manifest.json"
        if resume:
            state = json.loads(H.regular_bytes(state_path))
            validate_resume_binding(state, config, pins, source)
            first = H.validate_prefix(state, plan)
            require(H.snapshot(job) == state["artifacts"], "job changed since checkpoint")
            verify_evidence(state, evidence)
        else:
            require(H.snapshot(job) is None, "qualification requires a new job")
            state = {"schema": SCHEMA, "config": config, "pins": pins, "source_artifacts": source,
                     "artifacts": None, "attempts": [], "status": "RUNNING", "production_ready": False,
                     "full_tree_security": "UNREVIEWED", "level6_qualified": False,
                     "configured_limits_not_peak_observations": {
                         "aggregate_ram_bytes": 48 * GIB, "controller_ram_bytes_at_most": 3 * GIB,
                         "worker_ram_bytes": 44 * GIB, "swap_bytes": 0, "spill_bytes": 120 * GIB,
                         "aggregate_scratch_bytes": 128 * GIB, "worker_vram_limit_mib": MAX_VRAM_MIB,
                         "log_bytes_per_stage": H.MAX_STAGE_LOG, "vram_log_bytes_per_stage": MAX_VRAM_LOG,
                         "worker_runtime_seconds": 7200, "controller_runtime_seconds_at_most": 21600}}
            H.save(state_path, state)
            first = 0
        for name, action in plan[first:]:
            H.require_no_other_work(controller)
            require(H.snapshot(job) == state["artifacts"] and H.snapshot(reference) == source,
                    "proof or reference artifacts changed between stages")
            require(implementation_pins(config) == pins, "pinned implementation changed")
            verify_evidence(state, evidence)
            if config["mode"] == "prove": registration_gate(config, pins, source)
            run_stage(config, controller, name, action, evidence, state, state_path)
        H.require_no_other_work(controller)
        require(implementation_pins(config) == pins and H.snapshot(reference) == source,
                "pins/reference changed before completion")
        verify_evidence(state, evidence)
        if config["mode"] == "register":
            require(state["artifacts"] == source, "final GPU keys differ from CPU reference")
            state["status"] = "GPU_KEYS_MATCH_CPU_RESEARCH_ONLY"
        else:
            require(set(state["artifacts"]) == set(H.ROOT_FILES), "local inner artifacts not pruned")
            state["recorded_proof_gpu_transfers"] = proof_transfer_totals(state["attempts"])
            state["status"] = "GPU_PROOF_VERIFIED_RESEARCH_ONLY"
            state["recursive_command_ms"] = sum(record["telemetry"]["duration"]["elapsed_ms"]
                                                 for record in state["attempts"] if record["name"] in ("pairs", "merges"))
            state["root"] = state["artifacts"]["node.3.0"]
            state["shared_reference_pruned"] = False
        H.save(state_path, state)
        print(json.dumps({"status": state["status"], "production_ready": False, "evidence": str(evidence)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("register", "prove"))
    parser.add_argument("job", type=Path)
    parser.add_argument("evidence", type=Path)
    for name in ("reference", "gpu-runner", "cpu-runner", "auditor", "accounting", "source-archive"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--registration", type=Path)
    parser.add_argument("--backend", choices=("retained", "resident"), required=True)
    parser.add_argument("--gpu-index", type=int, required=True)
    parser.add_argument("--gpu-uuid", required=True)
    parser.add_argument("--quotient-fusion", type=int, choices=(0, 1), required=True)
    parser.add_argument("--gpu-openings", type=int, choices=(0, 1), required=True)
    parser.add_argument("--gpu-compact", type=int, choices=(0, 1), required=True)
    for name in ("profile", "chain", "root"): parser.add_argument("--" + name, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    config = {key: getattr(args, key) for key in ("mode", "backend", "gpu_index", "gpu_uuid", "quotient_fusion", "gpu_openings", "gpu_compact")}
    config["external"] = [H.external_hex(args.profile), H.external_hex(args.chain), H.external_hex(args.root, root=True)]
    for key in ("job", "evidence", "reference", "gpu_runner", "cpu_runner", "auditor", "accounting", "source_archive", "registration"):
        path = getattr(args, key)
        if path is not None:
            require(not path.is_symlink(), "paths must not be symlinks")
            config[key] = str(path.resolve())
    def interrupted(*_): raise InterruptedError("GPU grouped controller interrupted")
    os.umask(0o077)
    for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, interrupted)
    run(config, args.resume)


if __name__ == "__main__":
    main()
