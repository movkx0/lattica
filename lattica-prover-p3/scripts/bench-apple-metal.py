#!/usr/bin/env python3
"""Freeze and run the CPU / Metal shared / Metal copy grouped-eight comparison.

Two audited pilots precede the selected measured matrix (54 trials by default).
An extension can reuse completed pilots only with identical binaries, proof
sources, fixtures and measurement policy. Every measured proof is fresh.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import time

CRATE = Path(__file__).resolve().parents[1]
GIB = 1 << 30
FIXTURE_NAMES = ["height", "key.1", "key.2", "key.3", *[f"wallet.{i}" for i in range(8)]]
GPU_KEYS = ["HASH", "RETAIN_TREES", "PIPELINE", "RESIDENT_LDE", "OPENINGS", "OPENING_COMPACT", "OPENING_PINNED", "PARALLEL_READBACK", "QUOTIENT_LDE", "COMPACT_PROVER_DATA"]

def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def arm(backend, threads, level="baseline", repeat=1, phase="measured"):
    return {"backend": backend, "threads": threads, "level": level,
            "readback": int(level != "baseline"), "fusion": int(level == "fusion" or level.startswith("quotient")),
            "quotient": int(level.startswith("quotient")),
            "compact": int("compact" in level), "defer_timing": int("deferred" in level), "repeat": repeat, "phase": phase}

def schedule(threads=(8, 16, 18, 24), *, baseline_only=False, pipeline_threads=(24,), pilots=True, pilot_level="baseline", optimizations=False):
    if not threads or len(set(threads)) != len(threads) or any(t not in (8, 16, 18, 24) for t in threads):
        raise ValueError("thread settings must be distinct selections from 8, 16, 18, 24")
    if len(set(pipeline_threads)) != len(pipeline_threads) or any(t not in (8, 16, 18, 24) for t in pipeline_threads):
        raise ValueError("invalid pipeline thread settings")
    if pilot_level not in ("baseline", "quotient", "quotient-compact-deferred"):
        raise ValueError("pilot level must be baseline or quotient")
    largest_thread_count = max((*threads, *(() if baseline_only else pipeline_threads)))
    pilot_trials = [arm(mode, largest_thread_count, level=pilot_level, phase="pilot") for mode in ("shared", "copy")] if pilots else []
    if optimizations:
        if baseline_only:
            raise ValueError("optimization matrix requires pipeline trials")
        pilot_trials = [arm(mode, count, level="quotient-compact-deferred", phase="pilot")
                        for count in sorted(set(threads) | set(pipeline_threads)) for mode in ("shared", "copy")] if pilots else []
    base = [(mode, count) for count in threads for mode in ("cpu", "shared", "copy")]
    measured = []
    for repeat in (1, 2, 3):
        order = base[::-1] if repeat == 2 else base
        measured += [arm(mode, threads, repeat=repeat) for mode, threads in order]
    extra = [] if baseline_only else [(mode, count, level) for count in pipeline_threads for level in ("readback", "fusion", "quotient") for mode in ("shared", "copy")]
    if optimizations:
        extra += [(mode, count, level) for count in pipeline_threads
                  for level in ("quotient-deferred", "quotient-compact", "quotient-compact-deferred")
                  for mode in ("shared", "copy")]
    for repeat in (1, 2, 3):
        order = extra[::-1] if repeat == 2 else extra
        measured += [arm(mode, count, level, repeat) for mode, count, level in order]
    assert len(measured) == 9 * len(threads) + 3 * len(extra)
    return pilot_trials + measured

def validate_extension(prior, current):
    if prior["status"] != "COMPLETE_VERIFIED_COMPARISON" or not all(t["verified"] for t in prior["trials"]):
        raise RuntimeError("extension requires a completed and verified reference series")
    pilots = [t for t in prior["trials"] if t["phase"] == "pilot"]
    if len(pilots) != 2 or {t["backend"] for t in pilots} != {"shared", "copy"}:
        raise RuntimeError("reference must contain two verified Metal pilots")
    for key in ("binary_sha256", "fixture_sha256", "external", "memory_policy", "timing_boundary", "hardware", "platform"):
        if prior[key] != current[key]:
            raise RuntimeError("extension differs from reference: " + key)
    proof_sources = lambda data: {name: sha for name, sha in data["source_hashes"].items() if not name.startswith("scripts/")}
    if proof_sources(prior) != proof_sources(current):
        raise RuntimeError("extension proof sources differ from reference")

def environment(config, scratch, gpu):
    env = os.environ.copy()
    env.update({"RAYON_NUM_THREADS": str(config["threads"]), "LATTICA_FFT_TRACE": "1",
                "LATTICA_PROFILE": "1", "LATTICA_PROFILE_TIMELINE": "0",
                "LATTICA_BENCHMARK_REPORT_DEFER": "1", "LATTICA_V2_METAL_DEFER_TIMING": "0",
                "LATTICA_SPILL_DIR": str(scratch), "LATTICA_SPILL_BACKING": "memory",
                "LATTICA_SPILL_MAX_BYTES": str(34 * GIB), "LATTICA_V2_QUOTIENT_FUSION": "0",
                "LATTICA_V2_GPU_DEVICE": "0" if gpu else "4294967295",
                "LATTICA_V2_METAL_RSS_LIMIT_BYTES": str(44 * GIB),
                "LATTICA_V2_METAL_TIMEOUT_SECONDS": "7200"})
    for key in GPU_KEYS:
        env["LATTICA_V2_GPU_" + key] = "0"
    if gpu:
        env["LATTICA_V2_METAL_MEMORY"] = config["backend"]
        for key in ("HASH", "RETAIN_TREES", "RESIDENT_LDE", "OPENINGS", "OPENING_COMPACT"):
            env["LATTICA_V2_GPU_" + key] = "1"
        env["LATTICA_V2_GPU_PARALLEL_READBACK"] = str(config["readback"])
        env["LATTICA_V2_GPU_QUOTIENT_LDE"] = str(config["quotient"])
        env["LATTICA_V2_QUOTIENT_FUSION"] = str(config["fusion"])
        env["LATTICA_V2_GPU_COMPACT_PROVER_DATA"] = str(config.get("compact", 0))
        env["LATTICA_V2_METAL_DEFER_TIMING"] = str(config.get("defer_timing", 0))
    return env

def observations():
    result = {"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    for name, command in {
        "swap": ["sysctl", "vm.swapusage"], "vm_stat": ["vm_stat"],
        "power": ["pmset", "-g", "batt"], "thermal": ["pmset", "-g", "therm"],
    }.items():
        p = subprocess.run(command, capture_output=True, text=True)
        result[name] = {"exit_code": p.returncode, "output": p.stdout, "stderr": p.stderr}
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--pilots-only", action="store_true")
    parser.add_argument("--pilot-level", choices=("baseline", "quotient", "quotient-compact-deferred"), default="baseline", help="qualify the largest enabled pipeline before measured trials")
    parser.add_argument("--threads", nargs="+", type=int, choices=(8, 16, 18, 24), default=(8, 16, 18, 24))
    parser.add_argument("--baseline-only", action="store_true")
    parser.add_argument("--pipeline-threads", nargs="+", type=int, choices=(8, 16, 18, 24), default=(24,))
    parser.add_argument("--reuse-pilots-from", type=Path, help="completed reference result.json; reuse its frozen binaries and validated pilots")
    parser.add_argument("--optimizations", action="store_true", help="include compact/deferred factorial arms and pilots at every thread count")
    parser.add_argument("--build-metadata", type=Path, default=CRATE / "target/metal-build-metadata.json")
    args = parser.parse_args()
    if args.optimizations and args.reuse_pilots_from:
        parser.error("optimization campaign requires fresh pilots at every selected thread count")
    if args.pilots_only and args.reuse_pilots_from:
        parser.error("--pilots-only cannot reuse pilots")
    selected_schedule = schedule(args.threads, baseline_only=args.baseline_only, pipeline_threads=args.pipeline_threads, pilots=not args.reuse_pilots_from, pilot_level=args.pilot_level, optimizations=args.optimizations)
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("requires Apple Silicon macOS")
    os.umask(0o077)
    lease_dir = Path("/tmp") / f"lattica-v2-metal-benchmark-{os.getuid()}"
    lease_dir.mkdir(mode=0o700, exist_ok=True)
    st = lease_dir.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError("invalid benchmark lease directory")
    lease = os.open(lease_dir / "exclusive.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out
    qualification = json.loads(args.qualification.read_text())
    if qualification["status"] != "PASS" or len(qualification["tests"]) < 54 or not all(t["passed"] for t in qualification["tests"]):
        raise RuntimeError("hardware qualification must pass first")
    if args.optimizations:
        from collections import Counter
        coverage = Counter((t.get("timing"),t["memory"]) for t in qualification["tests"])
        if any(coverage[t,m] < 32 for t in ("immediate","deferred") for m in ("shared","copy")):
            raise RuntimeError("optimization matrix requires full Metal qualification in both memory and timing modes")
        if not qualification.get("proof_source_sha256") or any(digest(CRATE/name) != sha for name,sha in qualification["proof_source_sha256"].items()):
            raise RuntimeError("hardware qualification proof sources do not match the campaign")
    prior = json.loads(args.reuse_pilots_from.read_text()) if args.reuse_pilots_from else None
    build = prior["build"] if prior is not None else json.loads(args.build_metadata.read_text())
    if prior is None:
        if not build.get("source_hashes"):
            raise RuntimeError("rebuild with source provenance using build-apple-metal.py")
        if any(digest(CRATE / name) != sha for name, sha in build["source_hashes"].items()):
            raise RuntimeError("proof sources differ from the compiled binaries")
    linux = json.loads(args.linux.read_text())
    external = linux["benchmark_plan"]["config"]["external"]
    originals = {"cpu": CRATE / "target/cpu/release/block-v2-grouped-probe",
                 "audit": CRATE / "target/cpu/release/block-v2-grouped-artifact-audit",
                 "publics": CRATE / "target/cpu/release/block-v2-grouped-publics",
                 "metal": CRATE / "target/release/block-v2-metal-grouped-probe"}
    if prior is None:
        originals = {role: Path(build["binaries"][source.name]["path"]) for role, source in originals.items()}
    if prior is not None:
        originals = {role: args.reuse_pilots_from.parent / "bin" / source.name for role, source in originals.items()}
    (out / "bin").mkdir()
    binaries = {}
    for role, source in originals.items():
        if digest(source) != build["binaries"][source.name]["sha256"]:
            raise RuntimeError("binary differs from recorded build: " + source.name)
        destination = out / "bin" / source.name
        shutil.copy2(source, destination)
        binaries[role] = destination
    shutil.copy2(__file__, out / "controller.py")
    shutil.copy2(args.linux, out / "linux-reference.json")
    shutil.copy2(args.qualification, out / "hardware-qualification.json")
    fixture = out / "fixture"
    fixture.mkdir()
    for name in FIXTURE_NAMES:
        source = args.fixture / name
        if not source.is_file() or source.is_symlink():
            raise RuntimeError("invalid fixture file " + name)
        shutil.copy2(source, fixture / name)
    for name in FIXTURE_NAMES[:4]:
        if digest(fixture / name) != linux["benchmark_plan"]["source_artifacts"][name]["sha256"]:
            raise RuntimeError("Linux registry pin mismatch: " + name)
    sources = [CRATE / "Cargo.toml", CRATE / "Cargo.lock", CRATE / "build.rs", *sorted((CRATE / "src").rglob("*")), Path(__file__), CRATE / "scripts/generate-metal-kernels.py", CRATE / "scripts/test-metal-backend.py", CRATE / "scripts/build-apple-metal.py", CRATE / "scripts/apple_benchmark_export.py", CRATE / "scripts/export-apple-benchmarks.py", *sorted((CRATE / "scripts/benchmark_report").glob("*.py"))]
    sources = [p for p in sources if p.is_file() and p.name != ".DS_Store"]
    source_hashes = {str(p.relative_to(CRATE)): digest(p) for p in sources}
    with tarfile.open(out / "source.tar.gz", "w:gz") as archive:
        for path in sources:
            archive.add(path, arcname=str(path.relative_to(CRATE)))
    report = {"schema": "apple-metal-grouped-eight-v1", "status": "RUNNING", "production_ready": False,
              "git_base": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=CRATE, text=True).strip(),
              "git_diff": subprocess.check_output(["git", "diff", "--stat"], cwd=CRATE, text=True),
              "hardware": subprocess.check_output(["sysctl", "machdep.cpu.brand_string", "hw.memsize", "hw.ncpu"], text=True),
              "platform": platform.platform(), "source_hashes": source_hashes, "build": build,
              "source_archive_sha256": digest(out / "source.tar.gz"),
              "controller_sha256": digest(out / "controller.py"),
              "binary_sha256": {role: digest(path) for role, path in binaries.items()},
              "fixture_sha256": {name: digest(fixture / name) for name in FIXTURE_NAMES},
              "external": external, "schedule": [c for c in selected_schedule if c["phase"] == "pilot"] if args.pilots_only else selected_schedule,
              "timing_boundary": "sum of wrapper and merge worker timers; shader initialization included; preparation/auditing excluded",
              "memory_policy": "34 GiB mapped scratch, 8 GiB Metal managed buffers, sampled 44 GiB worker RSS, 7200 seconds per stage; macOS swap is observed, not prohibited",
              "observations": [observations()], "stages": [], "trials": []}
    if prior is not None:
        validate_extension(prior, report)
        for trial in prior["trials"]:
            root = args.reuse_pilots_from.parent / (trial["label"] + "-root-only") / "node.3.0"
            if digest(root) != trial["root_sha256"]:
                raise RuntimeError("reference root digest mismatch: " + trial["label"])
        shutil.copy2(args.reuse_pilots_from, out / "prior-series.json")
        report["reused_pilots"] = {"reference": str(args.reuse_pilots_from.resolve()), "reference_sha256": digest(out / "prior-series.json"),
            "trials": [t["label"] for t in prior["trials"] if t["phase"] == "pilot"],
            "reason": "User-requested additional thread setting after the reference schedule was frozen"}
    active_child = [None]
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"controller signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    def save():
        temp = out / "result.json.new"
        temp.write_text(json.dumps(report, indent=2) + "\n")
        temp.replace(out / "result.json")
    def verify_pins():
        if any(digest(path) != report["binary_sha256"][role] for role, path in binaries.items()):
            raise RuntimeError("preserved binary changed")
        if any(digest(fixture / name) != value for name, value in report["fixture_sha256"].items()):
            raise RuntimeError("preserved fixture changed")
    def stage(label, role, arguments, config):
        verify_pins()
        path = out / (label + ".log")
        gpu = role == "metal"
        command = [str(binaries[role]), *map(str, arguments)]
        env = environment(config, out / "scratch", gpu)
        entry = {"label": label, "command": command, "log": str(path), "status": "RUNNING",
                 "configuration": config, "gpu": gpu}
        report["stages"].append(entry); save()
        print("START", label, flush=True)
        entry["started_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        start = heartbeat = time.monotonic(); peak = 0; stopped = None; reason = None
        resource_path = out / (label + "-resources.jsonl")
        entry["resource_log"] = str(resource_path)
        with path.open("w") as log, resource_path.open("w") as resources:
            child = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            active_child[0] = child
            while True:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    child.returncode = os.waitstatus_to_exitcode(status); active_child[0] = None; break
                sample = subprocess.run(["/bin/ps", "-o", "rss=", "-p", str(child.pid)], capture_output=True, text=True)
                if sample.returncode == 0 and sample.stdout.strip():
                    rss = int(sample.stdout) * 1024
                    peak = max(peak, rss)
                    resources.write(json.dumps({"utc_ns":str(time.time_ns()), "rss_bytes":rss, "pid":child.pid}) + "\n")
                    if peak > 44 * GIB: reason = "44 GiB RSS limit exceeded"
                elif sample.stderr.strip(): reason = "RSS monitoring unavailable: " + sample.stderr.strip()
                if time.monotonic() - start > 7200: reason = "two-hour stage timeout"
                if reason and stopped is None:
                    os.killpg(child.pid, signal.SIGTERM); stopped = time.monotonic()
                elif stopped is not None and time.monotonic() - stopped > 5:
                    os.killpg(child.pid, signal.SIGKILL)
                if time.monotonic() - heartbeat > 20:
                    print(f"PROGRESS {label}: {time.monotonic()-start:.0f}s peak RSS {peak/GIB:.2f} GiB", flush=True)
                    heartbeat = time.monotonic()
                time.sleep(0.5)
        text = path.read_text()
        timers = re.findall(r"grouped_stage_elapsed_ms=(\d+)", text)
        nodes = re.findall(r"grouped_node_complete artifact=(\S+) resumed=(\S+) elapsed_ms=(\d+)", text)
        entry.update({"status": "PASS" if child.returncode == 0 and reason is None else "FAIL",
                      "exit_code": child.returncode, "stop_reason": reason, "wall_seconds": time.monotonic()-start,
                      "reported_seconds": int(timers[0])/1000 if len(timers)==1 else None,
                      "cpu_seconds": usage.ru_utime+usage.ru_stime, "maximum_resident_bytes": usage.ru_maxrss,
                      "sampled_peak_rss_bytes": peak, "pageins": usage.ru_majflt, "log_sha256": digest(path), "resource_sha256": digest(resource_path),
                      "spill_peak_bytes": max(map(int,re.findall(r"spill_peak_bytes=(\d+)",text)),default=0),
                      "nodes": [{"name": n,"resumed": r,"seconds":int(ms)/1000} for n,r,ms in nodes]})
        if gpu:
            import shlex
            records = [dict(word.split("=",1) for word in shlex.split(line)[1:]) for line in text.splitlines() if line.startswith("metal_checkpoint ")]
            entry["metal"] = records[-1] if records else None
            if entry["status"] == "PASS":
                if not records or int(records[-1]["kernel_calls"]) <= 0 or int(records[-1]["kernel_ns"]) <= 0:
                    entry["status"] = "FAIL"; entry["stop_reason"] = "Metal work missing"
                elif records[-1]["memory"].lower() != config["backend"]:
                    entry["status"] = "FAIL"; entry["stop_reason"] = "Metal memory mode mismatch"
                elif (int(records[-1]["transfer_blit_bytes"]) > 0) != (config["backend"] == "copy"):
                    entry["status"] = "FAIL"; entry["stop_reason"] = "explicit transfer work mismatch"
        save()
        entry["completed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save()
        print(entry["status"], label, round(entry["wall_seconds"],3), flush=True)
        if entry["status"] != "PASS": raise RuntimeError(label + ": " + str(entry["stop_reason"] or text[-1800:]))
        return entry
    (out / "scratch").mkdir(); save()
    try:
        config = arm("cpu",24)
        stage("fixture-check","cpu",["check-registered",fixture,*external],config)
        stage("fixture-publics","publics",["dump-eight",fixture,external[1]],config)
        for index, config in enumerate(report["schedule"],1):
            label = f"{index:02d}-{config['phase']}-{config['backend']}-{config['threads']}t-{config['level']}-r{config['repeat']}"
            job = out / label; job.mkdir()
            for name in FIXTURE_NAMES: shutil.copy2(fixture/name,job/name)
            trial_start = time.monotonic()
            report["observations"].append({"trial":label,"before":observations()}); save()
            stage(label+"-check","cpu",["check-registered",job,*external],config)
            role = "cpu" if config["backend"] == "cpu" else "metal"
            pairs = stage(label+"-pairs",role,["wrap-all",job,*external],config)
            merges = stage(label+"-merges",role,["merge-all",job,*external],config)
            if len(pairs["nodes"]) != 4 or len(merges["nodes"]) != 3 or any(n["resumed"] != "false" for n in pairs["nodes"]+merges["nodes"]):
                raise RuntimeError("expected seven fresh proofs")
            if pairs["reported_seconds"] is None or merges["reported_seconds"] is None:
                raise RuntimeError("worker timing missing/ambiguous")
            stage(label+"-prune","cpu",["remove-inners",job,*external],config)
            bundle = out / (label+"-root-only"); bundle.mkdir()
            for name in [*FIXTURE_NAMES[:4],"node.3.0"]: shutil.copy2(job/name,bundle/name)
            if (bundle/"node.3.0").stat().st_size > 2 << 20: raise RuntimeError("root exceeds 2 MiB bound")
            audit = stage(label+"-audit","audit",["root-eight",bundle,*external],config)
            if "grouped_artifact_audit=PASS" not in Path(audit["log"]).read_text(): raise RuntimeError("CPU root audit missing")
            report["trials"].append({"label":label, **config, "verified":True,
                "recursive_seconds":pairs["reported_seconds"]+merges["reported_seconds"],
                "wrappers_seconds":pairs["reported_seconds"],"merges_seconds":merges["reported_seconds"],
                "controller_seconds":time.monotonic()-trial_start,
                "peak_rss_bytes":max(pairs["maximum_resident_bytes"],merges["maximum_resident_bytes"]),
                "peak_mapped_bytes":max(pairs["spill_peak_bytes"],merges["spill_peak_bytes"]),
                "root_bytes":(bundle/"node.3.0").stat().st_size,"root_sha256":digest(bundle/"node.3.0"),
                "pairs_metal":pairs.get("metal"),"merges_metal":merges.get("metal")})
            report["observations"].append({"trial":label,"after":observations()}); save()
            print("TRIAL",json.dumps(report["trials"][-1]),flush=True)
        report["status"] = "COMPLETE_VERIFIED_PILOTS" if args.pilots_only else ("COMPLETE_VERIFIED_EXTENSION" if prior is not None else "COMPLETE_VERIFIED_COMPARISON")
    except BaseException as error:
        child = active_child[0]
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL); child.wait()
            except ProcessLookupError:
                pass
            if report["stages"] and report["stages"][-1]["status"] == "RUNNING":
                report["stages"][-1].update(status="INTERRUPTED", stop_reason=str(error))
        report["status"] = "FAILED"; report["failure"] = str(error); save(); raise
    finally:
        report["observations"].append(observations()); save()
    print("COMPLETE",out/"result.json",flush=True)
    # Export after measurement and cleanup; a report failure must not invalidate proofs.
    try:
        from apple_benchmark_export import export_campaign
        exported = export_campaign(out / "result.json", out / "portable")
        print("PORTABLE", len(exported), out / "portable", flush=True)
    except Exception as error:
        print("REPORT_EXPORT_FAILED", str(error), "retry with export-apple-benchmarks.py", flush=True)

if __name__ == "__main__":
    main()
