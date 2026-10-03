#!/usr/bin/env python3
"""CPU-only single-wrapper/eight-wallet research comparison controller.

Build, lifecycle, and proof qualification are separate evidence gates.
Preparation never approves its keys. Proving requires three external trust inputs.
An attempted but incomplete stage is never automatically rerun, including on resume.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

GIB = 2**30
MAX_ARTIFACT = 2**21
MAX_STAGE_LOG = 64 * 2**20
MAX_CONTROLLER_RUNTIME_US = 6 * 60 * 60 * 1_000_000
RESOURCE_SLICE = "lattica-v2-grouped.slice"
MODULUS = 0xFFFFFFFF00000001
ROOT_FILES = ("node.3.0", "height", "key.1", "key.2", "key.3")
WALLETS = tuple(f"wallet.{i}" for i in range(8))
LEAVES = tuple(f"node.0.{i}" for i in range(8))
MERGES = tuple(f"node.1.{i}" for i in range(4)) + ("node.2.0", "node.2.1", "node.3.0")
ARTIFACTS = set(ROOT_FILES + WALLETS + LEAVES + MERGES)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def external_hex(value, root=False):
    require(re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None,
            "external inputs must be exactly 64 ASCII hex characters")
    raw = bytes.fromhex(value)
    if root:
        require(all(int.from_bytes(raw[i:i + 8], "little") < MODULUS
                    for i in range(0, 32, 8)), "noncanonical external root")
    return value.lower()


def fields(line):
    result = {}
    for token in line.split()[1:]:
        require("=" in token, "invalid telemetry field")
        key, value = token.split("=", 1)
        require(key and key not in result, "duplicate telemetry field")
        result[key] = value
    return result


def natural(value):
    require(re.fullmatch(r"[0-9]+", value) is not None, "non-integer telemetry")
    return int(value)


def regular_bytes(path, maximum=MAX_ARTIFACT):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
            f"invalid artifact type/size: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        after = os.fstat(stream.fileno())
        require(stat.S_ISREG(after.st_mode), "opened artifact is not regular")
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                "artifact changed during open")
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, "artifact exceeded size bound")
    return data


def digest(path):
    require(stat.S_ISREG(path.lstat().st_mode), f"not a regular pinned file: {path}")
    value = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "not a regular file")
        for data in iter(lambda: stream.read(2**20), b""):
            value.update(data)
    return value.hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    temporary = path.with_name(path.name + ".new")
    # A leftover temporary file requires explicit inspection, never silent reuse.
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def private_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            f"expected private owned directory: {path}")


def snapshot(job):
    if not job.exists() and not job.is_symlink():
        return None
    private_directory(job)
    private_directory(job / "scratch")
    require(not any((job / "scratch").iterdir()), "scratch not empty between stages")
    result = {}
    for path in job.iterdir():
        if path.name == "scratch":
            continue
        require(path.name in ARTIFACTS, f"unexpected job artifact: {path.name}")
        data = regular_bytes(path)
        result[path.name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return result


@contextmanager
def exclusive(path):
    require(not path.is_symlink(), "lock must not be a symlink")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600, "unsafe lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def validate_memory_limits(controller_max, controller_swap, slice_name, slice_max, slice_swap):
    require(controller_max.isdecimal() and 0 < int(controller_max) <= 3 * GIB,
            "controller requires 0<MemoryMax<=3G")
    require(controller_swap == "0", "controller requires zero swap")
    require(slice_name == RESOURCE_SLICE and slice_max == str(48 * GIB) and slice_swap == "0",
            "controller requires the dedicated grouped slice with MemoryMax=48G and no swap")


def validate_active_units(controller, output):
    units = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        words = line.split(maxsplit=4)
        require(len(words) >= 4 and re.fullmatch(r"lattica-v2-[A-Za-z0-9_-]+\.service", words[0]) is not None,
                "unexpected active-service listing")
        require(words[0] not in units and words[1] == "loaded"
                and words[2] in {"active", "activating", "deactivating", "reloading"},
                "duplicate or invalid active-service state")
        units[words[0]] = words[2]
    require(controller in units and units[controller] != "deactivating",
            "current controller missing/stopping in live service inventory")
    others = sorted(set(units) - {controller})
    require(not others, "other experiment services remain live; refuse overlap: " + ",".join(others))


def require_no_other_work(controller):
    output = subprocess.check_output(
        ["systemctl", "--user", "list-units", "--all", "--type=service",
         "--state=active,activating,deactivating,reloading", "--plain", "--no-legend", "--no-pager",
         "lattica-v2-*.service"], text=True, timeout=10,
        env={**os.environ, "SYSTEMD_COLORS": "0"})
    validate_active_units(controller, output)


def validate_controller_properties(output, expected_group):
    properties = {}
    for line in output.splitlines():
        require("=" in line, "malformed controller property")
        key, value = line.split("=", 1)
        require(key not in properties, "duplicate controller property")
        properties[key] = value
    require(set(properties) == {"ControlGroup", "RuntimeMaxUSec"},
            "missing/unexpected controller properties")
    require(properties["ControlGroup"] == expected_group,
            "controller service/cgroup mismatch")
    # systemctl formats usec-valued properties as spans (for example `6h`).
    # Accept only its ordered, integral sub-day units. Unknown/infinite values
    # fail closed; no conversion to a floating-point or unbounded deadline.
    scales = {"h": 3_600_000_000, "min": 60_000_000, "s": 1_000_000,
              "ms": 1_000, "us": 1}
    total, prior_scale = 0, MAX_CONTROLLER_RUNTIME_US
    for token in properties["RuntimeMaxUSec"].split():
        match = re.fullmatch(r"([0-9]+)(h|min|s|ms|us)", token)
        require(match is not None, "controller runtime must be a finite systemd span")
        scale = scales[match[2]]
        require(scale < prior_scale, "duplicate/unordered controller runtime unit")
        total += int(match[1]) * scale
        prior_scale = scale
    require(0 < total <= MAX_CONTROLLER_RUNTIME_US,
            "controller requires 0<RuntimeMaxSec<=21600")
    return total


def require_controller():
    rows = [s[3:] for s in Path("/proc/self/cgroup").read_text().splitlines()
            if s.startswith("0::")]
    require(len(rows) == 1, "cgroup v2 controller required")
    group = Path("/sys/fs/cgroup") / rows[0].lstrip("/")
    validate_memory_limits((group / "memory.max").read_text().strip(),
                           (group / "memory.swap.max").read_text().strip(), group.parent.name,
                           (group.parent / "memory.max").read_text().strip(),
                           (group.parent / "memory.swap.max").read_text().strip())
    controller = group.name
    require(re.fullmatch(r"lattica-v2-[\w-]+\.service", controller) is not None,
            "controller must be a named lattica-v2 user service")
    observed = subprocess.check_output(
        ["systemctl", "--user", "show", controller,
         "--property=ControlGroup,RuntimeMaxUSec", "--no-pager"],
        text=True, timeout=10)
    validate_controller_properties(observed, rows[0])
    require_no_other_work(controller)
    return controller


def stages(config):
    if config["mode"] == "prepare":
        return [("prepare", ["prepare"]), ("height", ["common-height"]),
                ("key-1", ["register", "1"]), ("key-2", ["register", "2"]),
                ("key-3", ["register", "3"]), ("describe", ["describe-registry"])]
    return [("check", ["check-registered"]), ("leaves", ["wrap-all"]),
            ("merges", ["merge-all"]), ("prune", ["remove-inners"]),
            ("root", ["verify-root"]), ("export", []), ("audit", ["root-eight"])]


def validate_transition(name, before, after):
    require(after is not None, "stage did not leave a job directory")
    if name == "prepare":
        require(before is None and set(after) == set(WALLETS), "incomplete wallet preparation")
        return
    require(before is not None, "stage lacks prior job artifacts")
    added = {"height": ("height",), "key-1": ("key.1",), "key-2": ("key.2",),
             "key-3": ("key.3",), "leaves": LEAVES, "merges": MERGES}.get(name, ())
    removed = set(WALLETS + LEAVES + MERGES[:-1]) if name == "prune" else set()
    require(not set(added).intersection(before), "stage would reuse a prior output")
    require(set(after) == (set(before) - removed).union(added), "unexpected artifact transition")
    require(all(after[key] == value for key, value in before.items() if key not in removed),
            "stage changed an immutable input or completed proof")


def shared_lease_path():
    return Path(f"/tmp/lattica-v2-gpu-trial-{os.getuid()}")


def invocation(config, name, action):
    if name == "audit":
        return [config["auditor"], *action, str(Path(config["evidence"]) / "root-only"),
                *config["external"]]
    command = [config["runner"], action[0], config["job"]]
    if config["mode"] == "prove":
        command += config["external"]
    return command + action[1:]


def stage_command(config, controller, unit, name, action):
    # No shell evaluation. The accounting command is a systemd command-line
    # property: restrict its path separately to avoid systemd quoting/specifiers.
    accounting = config["accounting"]
    require(re.fullmatch(r"/[A-Za-z0-9_./-]+", accounting) is not None,
            "accounting path must be a simple absolute path")
    return ["systemd-run", "--user", "--wait", "--pipe", "--collect", "--expand-environment=no", f"--unit={unit}",
            f"--slice={RESOURCE_SLICE}",
            "--property=MemoryAccounting=yes", "--property=MemoryHigh=40G",
            "--property=MemoryMax=44G", "--property=MemorySwapMax=0",
            "--property=RuntimeMaxSec=7200", "--property=LimitCORE=0",
            f"--property=BindsTo={controller}", f"--property=After={controller}",
            f"--property=ExecStopPost=/usr/bin/python3 -B {accounting}",
            f"--setenv=LATTICA_V2_ACCOUNTING_UNIT={unit}",
            "--setenv=RAYON_NUM_THREADS=8", "--setenv=LATTICA_FFT_TRACE=1",
            "--setenv=LATTICA_PROFILE=1", "--setenv=LATTICA_PROFILE_TIMELINE=0",
            f"--setenv=LATTICA_SPILL_DIR={config['job']}/scratch",
            "--setenv=LATTICA_SPILL_MAX_BYTES=128849018880",
            f"--setenv=LATTICA_V2_GPU_HASH={1 if name == 'audit' else 0}",
            "--setenv=LATTICA_V2_GPU_DEVICE=4294967295",
            "--setenv=LATTICA_V2_GPU_PIPELINE=0", "--setenv=LATTICA_V2_GPU_RETAIN_TREES=0",
            "--", *invocation(config, name, action)]


def validate_log(path, unit, name):
    accounting, elapsed, nodes, markers = [], [], [], set()
    audit_bytes = None
    with path.open() as stream:
        for line in stream:
            require(not line.startswith(("FAILED:", "grouped_artifact_audit=FAIL")),
                    "stage reported failure")
            if line.startswith("stage_cgroup_accounting "):
                record = fields(line)
                require(set(record) == {"unit", "scope", "memory_peak", "memory_swap_peak",
                                       "memory_max", "memory_swap_max", "cpu_usage_usec"},
                        "unexpected accounting fields")
                require(record.pop("unit") == unit and record.pop("scope") == "exec_stop_post_snapshot",
                        "misbound accounting")
                record = {key: natural(value) for key, value in record.items()}
                require(record["memory_max"] == 44 * GIB and record["memory_swap_max"] == 0
                        and record["memory_swap_peak"] == 0
                        and record["memory_peak"] <= record["memory_max"], "resource gate")
                accounting.append(record)
            elif line.startswith("single_eight_stage_elapsed_ms="):
                record = fields("stage " + line)
                require(record["cpu_only"] == "true" and record["production_ready"] == "false",
                        "stage classification")
                require(natural(record["spill_peak_bytes"]) <= 120 * GIB, "spill gate")
                elapsed.append({"elapsed_ms": natural(record["single_eight_stage_elapsed_ms"]),
                                "spill_peak_bytes": natural(record["spill_peak_bytes"])})
            elif line.startswith("single_eight_node_complete "):
                record = fields(line)
                require(record["resumed"] == "false" and record["production_ready"] == "false",
                        "timed proof was resumed or misclassified")
                nodes.append({"artifact": record["artifact"], "elapsed_ms": natural(record["elapsed_ms"]),
                              "setups": natural(record["setups"]), "cache_hits": natural(record["cache_hits"])})
            elif line.startswith("single_eight_root_verification=PASS "):
                record = fields(line)
                require(record == {"level": "3", "count": "8", "inner_proofs_loaded": "0",
                                   "full_tree_security": "UNREVIEWED", "production_ready": "false"},
                        "root marker scope")
                require("root" not in markers, "duplicate root marker")
                markers.add("root")
            elif line.startswith("grouped_artifact_audit=PASS "):
                record = fields(line)
                audit_bytes = natural(record.pop("proof_bytes"))
                require(0 < audit_bytes <= MAX_ARTIFACT, "root size gate")
                require(record == {"kind": "level3-count8-subtree", "native_mutation_rejections": "38",
                                   "registry_policy_rejections": "4", "expected_statement_policy_rejections": "2",
                                   "bundle_files": "5", "inner_proofs_loaded": "0", "level6_qualified": "false",
                                   "full_tree_security": "UNREVIEWED", "production_ready": "false"},
                        "auditor marker scope")
                require("audit" not in markers, "duplicate audit marker")
                markers.add("audit")
    require(len(accounting) == 1, "missing/duplicate cgroup accounting")
    require(len(elapsed) == (0 if name == "audit" else 1), "missing/duplicate stage duration")
    expected = LEAVES if name == "leaves" else MERGES if name == "merges" else ()
    require(tuple(node["artifact"] for node in nodes) == expected, "incomplete/duplicate proof sequence")
    if name in ("root", "prune"):
        require("root" in markers, "missing root verification")
    if name == "audit":
        require("audit" in markers, "missing CPU audit")
    return {"accounting": accounting[0], "duration": elapsed[0] if elapsed else None,
            "nodes": nodes, "audit_proof_bytes": audit_bytes}


def export_bundle(job, destination):
    destination.mkdir(mode=0o700)
    hashes = {}
    for name in ROOT_FILES:
        data = regular_bytes(job / name)
        fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        hashes[name] = hashlib.sha256(data).hexdigest()
    sync_directory(destination)
    sync_directory(destination.parent)
    return hashes


def validate_prefix(state, plan):
    completed = state["attempts"]
    require(len(completed) <= len(plan), "too many stage attempts")
    for record, (name, _) in zip(completed, plan):
        require(record["name"] == name and record["status"] == "complete",
                "attempted stage is incomplete/failed; inspect it, never automatically rerun")
    return len(completed)


def verify_saved_evidence(state, evidence):
    for record in state["attempts"]:
        if "log_sha256" in record:
            require(digest(evidence / record["log"]) == record["log_sha256"], "completed log changed")
        if "bundle" in record:
            directory = evidence / "root-only"
            private_directory(directory)
            require(set(p.name for p in directory.iterdir()) == set(ROOT_FILES), "bundle membership changed")
            require({name: hashlib.sha256(regular_bytes(directory / name)).hexdigest()
                     for name in ROOT_FILES} == record["bundle"], "bundle changed")


def capture_stage(command, log, maximum=MAX_STAGE_LOG, timeout=7230):
    """Bound stdout on the controller side; RLIMIT_FSIZE would also break spill."""
    with log.open("xb") as output, selectors.DefaultSelector() as selector:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline, count = time.monotonic() + timeout, 0
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "stage capture deadline exceeded")
                if not selector.select(min(1, remaining)):
                    continue
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    break
                require(count + len(data) <= maximum, "stage log limit exceeded")
                output.write(data)
                count += len(data)
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            output.flush()
            os.fsync(output.fileno())
            return code
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()


def run_stage(config, controller, name, action, evidence, state, state_path):
    number = len(state["attempts"]) + 1
    unit = f"lattica-v2-single-eight-{os.getpid()}-{number}.service"
    log = evidence / f"{number:02d}-{name}.log"
    record = {"name": name, "status": "attempted", "unit": unit, "log": log.name,
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    state["attempts"].append(record)
    save(state_path, state)  # Durable BEFORE launching or mutating proof artifacts.
    started = time.monotonic()
    try:
        if name == "export":
            record["bundle"] = export_bundle(Path(config["job"]), evidence / "root-only")
        else:
            code = capture_stage(stage_command(config, controller, unit, name, action), log)
            require(code == 0, f"stage {name} failed; inspect {log}")
            record["telemetry"] = validate_log(log, unit, name)
            if name == "audit":
                require(record["telemetry"]["audit_proof_bytes"] == len(regular_bytes(evidence / "root-only" / "node.3.0")),
                        "auditor size differs from root-only artifact")
            record["log_sha256"] = digest(log)
        record["wall_seconds"] = time.monotonic() - started
        after = snapshot(Path(config["job"]))
        validate_transition(name, state["artifacts"], after)
        state["artifacts"] = after
        record["status"] = "complete"
        save(state_path, state)
    except BaseException as error:
        # BindsTo also stops a stage if this controller is SIGKILLed or expires.
        if name != "export":
            subprocess.run(["systemctl", "--user", "stop", unit], timeout=30, check=False)
        record["status"] = "failed_or_interrupted"
        record["error"] = str(error)
        state["status"] = "FAILED_OR_INTERRUPTED"
        save(state_path, state)
        raise


def run(config, resume):
    controller = require_controller()
    evidence, job = Path(config["evidence"]), Path(config["job"])
    require(evidence != job and evidence not in job.parents and job not in evidence.parents,
            "evidence and job must be separate, nonnested directories")
    lease = shared_lease_path()
    lease.mkdir(mode=0o700, exist_ok=True)
    private_directory(lease)
    if not resume:
        evidence.mkdir(mode=0o700)
    private_directory(evidence)
    with exclusive(lease / "exclusive.lock"), exclusive(evidence / "controller.lock"):
        require_no_other_work(controller)
        pins = {key: digest(Path(config[key])) for key in
                ("runner", "accounting", "source_archive") + (("auditor",) if config["mode"] == "prove" else ())}
        pins["controller"] = digest(Path(__file__).resolve())
        plan = stages(config)
        state_path = evidence / "manifest.json"
        if resume:
            state = json.loads(regular_bytes(state_path))
            require(state["schema"] == 1 and state["config"] == config and state["pins"] == pins,
                    "resume configuration/source/binary pins differ")
            first = validate_prefix(state, plan)
            require(snapshot(job) == state["artifacts"], "job artifacts changed since checkpoint")
            verify_saved_evidence(state, evidence)
        else:
            initial = snapshot(job)
            if config["mode"] == "prepare":
                require(initial is None, "preparation requires a new job")
            else:
                require(initial is not None and set(initial) == set(WALLETS + ROOT_FILES[1:]),
                        "proving requires exactly eight wallets and registered keys/height, no prior nodes")
            state = {"schema": 1, "config": config, "pins": pins, "attempts": [], "artifacts": initial,
                     "status": "RUNNING", "production_ready": False, "full_tree_security": "UNREVIEWED",
                     "configured_limits_not_peak_observations": {"slice": RESOURCE_SLICE,
                         "aggregate_ram_bytes": 48 * GIB, "controller_ram_bytes_at_most": 3 * GIB,
                         "controller_runtime_seconds_at_most": MAX_CONTROLLER_RUNTIME_US // 1_000_000,
                         "worker_ram_bytes": 44 * GIB, "swap_bytes": 0,
                         "spill_bytes": 120 * GIB, "log_bytes_per_stage": MAX_STAGE_LOG}}
            save(state_path, state)
            first = 0
        for name, action in plan[first:]:
            require_no_other_work(controller)
            require(snapshot(job) == state["artifacts"], "job changed between stages")
            verify_saved_evidence(state, evidence)
            for key, expected in pins.items():
                path = Path(__file__).resolve() if key == "controller" else Path(config[key])
                require(digest(path) == expected, "pinned implementation changed")
            run_stage(config, controller, name, action, evidence, state, state_path)
        verify_saved_evidence(state, evidence)
        for key, expected in pins.items():
            path = Path(__file__).resolve() if key == "controller" else Path(config[key])
            require(digest(path) == expected, "pinned implementation changed before completion")
        state["status"] = "PREPARED_UNAPPROVED" if config["mode"] == "prepare" else "PROOF_VERIFIED_RESEARCH_ONLY"
        if config["mode"] == "prepare":
            require(set(state["artifacts"]) == set(WALLETS + ROOT_FILES[1:]), "incomplete prepared fixture")
        if config["mode"] == "prove":
            require(set(state["artifacts"]) == set(ROOT_FILES), "inner artifacts remain after proof audit")
            state["recursive_command_ms"] = sum(r["telemetry"]["duration"]["elapsed_ms"]
                                                 for r in state["attempts"] if r["name"] in ("leaves", "merges"))
            state["root"] = state["artifacts"]["node.3.0"]
            state["level6_qualified"] = False
        save(state_path, state)
        print(json.dumps({"status": state["status"], "production_ready": False, "evidence": str(evidence)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "prove"))
    parser.add_argument("job", type=Path)
    parser.add_argument("evidence", type=Path)
    for name in ("runner", "accounting", "source-archive"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--auditor", type=Path)
    for name in ("profile", "chain", "root"):
        parser.add_argument("--" + name)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.mode == "prepare":
        require(args.auditor is None and all(getattr(args, n) is None for n in ("profile", "chain", "root")),
                "preparation does not accept or approve trust inputs")
        external = []
    else:
        require(args.auditor is not None and all(getattr(args, n) is not None for n in ("profile", "chain", "root")),
                "proving requires auditor plus externally approved profile, chain and root")
        external = [external_hex(args.profile), external_hex(args.chain), external_hex(args.root, root=True)]
    config = {"mode": args.mode, "external": external}
    for name in ("job", "evidence", "runner", "accounting", "source_archive", "auditor"):
        value = getattr(args, name)
        if value is not None:
            require(not value.is_symlink(), "paths must not be symlinks")
            config[name] = str(value.resolve())
            require(re.fullmatch(r"/[A-Za-z0-9_./-]+", config[name]) is not None,
                    "research paths must be simple absolute paths without whitespace or specifiers")
    require(os.access(config["runner"], os.X_OK), "runner not executable")
    if args.mode == "prove":
        require(config["runner"] != config["auditor"] and os.access(config["auditor"], os.X_OK),
                "separate executable CPU auditor required")
    def interrupted(*_):
        raise InterruptedError("controller interrupted")
    os.umask(0o077)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    run(config, args.resume)


if __name__ == "__main__":
    main()
