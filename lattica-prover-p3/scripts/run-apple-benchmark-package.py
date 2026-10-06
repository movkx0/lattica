#!/usr/bin/env python3
"""Run the pinned Apple benchmark package in its own checkout."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import time

GIB = 1 << 30
LEVELS = ("quotient", "quotient-deferred", "quotient-compact-deferred")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, data):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(path)


def verify_package(package):
    manifest = json.loads((package / "manifest.json").read_text())
    if manifest["schema"] != "lattica-apple-benchmark-package-v1":
        raise ValueError("unsupported package manifest")
    for name, expected in manifest["payload_sha256"].items():
        path = package / name
        if (Path(name).is_absolute() or ".." in Path(name).parts or
                path.is_symlink() or not path.resolve().is_relative_to(package.resolve()) or
                not path.is_file() or digest(path) != expected):
            raise ValueError("package payload missing or changed: " + name)
    return manifest


def select_threads(logical_cpus, requested=None):
    supported = (8, 16, 18, 24)
    if requested is not None:
        if requested not in supported or requested > logical_cpus:
            raise ValueError("thread count must fit the detected CPUs and be 8, 16, 18, or 24")
        return requested
    available = [n for n in supported if n <= min(18, logical_cpus)]
    if not available:
        raise ValueError("this screening recipe requires at least eight logical CPUs")
    return max(available)


def schedule(threads):
    return [{"backend": "shared", "threads": threads, "level": level, "repeat": repeat}
            for repeat in (1, 2, 3)
            for level in (LEVELS if repeat % 2 else LEVELS[::-1])]


def clean_environment():
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("LATTICA_", "RAYON_"))}
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
                "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER"):
        env.pop(key, None)
    env.update(RUSTUP_TOOLCHAIN="1.96.0", RUSTFLAGS="-C target-cpu=native")
    return env


def test_executable(log):
    candidates = set()
    for line in log.read_text().splitlines():
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        if (record.get("reason") == "compiler-artifact" and
                record.get("target", {}).get("name") == "lattica_prover_p3" and
                record.get("profile", {}).get("test") and record.get("executable")):
            candidates.add(record["executable"])
    if len(candidates) != 1:
        raise ValueError("expected one compiled library test executable")
    return Path(candidates.pop())


def combine_qualification(paths, build, binary):
    reports = [json.loads(path.read_text()) for path in paths]
    combined = {"status": "PASS", "binary_sha256": digest(binary),
                "proof_source_sha256": build["source_hashes"], "tests": [],
                "source_reports": [{"path": str(p), "sha256": digest(p)} for p in paths]}
    for report in reports:
        if (report["status"] != "PASS" or
                report["binary_sha256"] != combined["binary_sha256"] or
                report["proof_source_sha256"] != combined["proof_source_sha256"]):
            raise ValueError("qualification binary or proof sources differ from the build")
        combined["tests"].extend(dict(test, timing=report["timing"]) for test in report["tests"])
    keys = [(t["timing"], t["memory"], t["test"]) for t in combined["tests"]]
    coverage = Counter((t, m) for t, m, _ in keys)
    expected = {(t, m) for t in ("immediate", "deferred") for m in ("shared", "copy")}
    if (len(keys) != len(set(keys)) or set(coverage) != expected or
            any(coverage[key] < 32 for key in expected) or
            not all(t["passed"] for t in combined["tests"])):
        raise ValueError("incomplete, duplicated, or failed Metal qualification")
    return combined


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True, help="existing Lattica Git repository")
    parser.add_argument("--out", type=Path, required=True, help="new directory for checkout and evidence")
    parser.add_argument("--threads", type=int, choices=(8, 16, 18, 24))
    parser.add_argument("--offline", action="store_true", help="require dependencies already in Cargo cache")
    parser.add_argument("--plan", action="store_true", help="verify package and print recipe without running it")
    args = parser.parse_args()
    if sys.version_info < (3, 11):
        parser.error("Python 3.11 or newer is required")
    package = Path(__file__).resolve().parent
    manifest = verify_package(package)
    repo, out = args.repo.resolve(), args.out.resolve()
    commit = manifest["source_commit"]
    if subprocess.run(["git", "-C", str(repo), "cat-file", "-e", commit + "^{commit}"],
                      capture_output=True).returncode:
        parser.error("pinned commit is missing; run git fetch origin in the Mac repository")
    threads = select_threads(os.cpu_count() or 1, args.threads)
    plan = {"schema": "lattica-apple-repetition-plan-v1", "source_commit": commit,
            "package_manifest_sha256": digest(package / "manifest.json"),
            "rust_toolchain": "1.96.0", "logical_cpus": os.cpu_count(),
            "schedule": schedule(threads), "fixture_files": manifest["fixture_files"],
            "memory_policy": manifest["memory_policy"], "production_ready": False,
            "scope": "Seven fresh recursive proofs per trial from eight existing public wallet proofs; independent CPU root audit. Proving milestone only; delivered transactions are not measured."}
    if args.plan:
        print(json.dumps(plan, indent=2))
        return
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("execution requires native Apple Silicon macOS")
    memory = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True))
    if memory < 64 * GIB:
        parser.error("this fixed memory recipe requires at least 64 GiB unified memory")
    if out.exists():
        parser.error("--out must be a new directory; existing evidence is never overwritten")
    env = clean_environment()
    for command in (["rustc", "--version"], ["cargo", "--version"]):
        version = subprocess.check_output(command, env=env, text=True).strip()
        if version.split()[1] != "1.96.0":
            parser.error("install Rust 1.96.0 before running this pinned package")
    os.umask(0o077)
    out.mkdir(parents=True)
    if shutil.disk_usage(out).free < 20 * GIB:
        parser.error("at least 20 GiB free disk space is required for the build and evidence")
    plan.update(unified_memory_bytes=memory, platform=platform.platform())
    save(out / "run-plan.json", plan)
    shutil.copy2(package / "manifest.json", out / "package-manifest.json")
    state = {"schema": "lattica-apple-package-result-v1", "status": "RUNNING",
             "source_commit": commit, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "steps": [], "production_ready": False, "portable_runs": []}
    checkout = out / "checkout"
    crate = checkout / "lattica-prover-p3"

    def run(label, command, cwd=repo):
        log = out / (label + ".log")
        entry = {"label": label, "command": list(map(str, command)), "log": str(log), "status": "RUNNING"}
        state["steps"].append(entry)
        save(out / "package-result.json", state)
        print("START", label, "— log:", log, flush=True)
        started = time.monotonic()
        try:
            with log.open("w") as stream:
                result = subprocess.run(entry["command"], cwd=cwd, env=env,
                                        stdout=stream, stderr=subprocess.STDOUT)
            entry.update(exit_code=result.returncode, status="PASS" if result.returncode == 0 else "FAIL")
            result.check_returncode()
        except (Exception, KeyboardInterrupt):
            entry["status"] = "FAIL"
            raise
        finally:
            entry.update(wall_seconds=time.monotonic() - started, log_sha256=digest(log))
            save(out / "package-result.json", state)
        print("PASS", label, flush=True)
        return log

    failure = None
    try:
        run("checkout", ["git", "worktree", "add", "--detach", checkout, commit])
        for name in manifest["overlays"]:
            shutil.copy2(package / name, crate / "scripts" / Path(name).name)
        if not args.offline:
            run("fetch-dependencies", ["cargo", "fetch", "--locked"], crate)
        run("build", [sys.executable, crate / "scripts/build-apple-metal.py"], crate)
        log = run("build-tests", ["cargo", "test", "--locked", "--offline", "--release",
                  "--no-default-features", "--features", "block-v2-wide-lanes,stream,gpu-metal",
                  "--lib", "--no-run", "--message-format=json"], crate)
        binary = test_executable(log)
        reports = []
        for timing in ("immediate", "deferred"):
            directory = out / ("qualification-" + timing)
            run("qualify-" + timing, [sys.executable, crate / "scripts/test-metal-backend.py",
                "--binary", binary, "--out", directory, "--timing", timing], crate)
            reports.append(directory / "result.json")
        build_file = crate / "target/metal-build-metadata.json"
        build = json.loads(build_file.read_text())
        qualified = combine_qualification(reports, build, binary)
        save(out / "qualification.json", qualified)
        run("benchmark", [sys.executable, crate / "scripts/bench-apple-metal.py",
            "--out", out / "campaign", "--fixture", package / "fixture",
            "--linux", package / "fixture-reference.json", "--qualification", out / "qualification.json",
            "--build-metadata", build_file, "--screening-threads", str(threads), "--screening-repeats", "3"], crate)
        state["status"] = "COMPLETE_VERIFIED_COMPARISON"
    except (Exception, KeyboardInterrupt) as error:
        failure = error
        state.update(status="FAILED", failure=f"{type(error).__name__}: {error}")
    finally:
        result = out / "campaign/result.json"
        if result.is_file():
            state["campaign_result_sha256"] = digest(result)
            command = [sys.executable, crate / "scripts/export-apple-benchmarks.py",
                       "--result", result, "--portable", out / "portable"]
            if failure is not None:
                command.append("--allow-verified-partial")
            try:
                run("export", command, crate)
                state["portable_runs"] = [{"path": str(p.relative_to(out)), "sha256": digest(p)}
                                          for p in sorted((out / "portable").glob("*.json"))]
            except (Exception, KeyboardInterrupt) as error:
                state["export_failure"] = f"{type(error).__name__}: {error}"
                state["status"] = "EXPORT_FAILED" if failure is None else "FAILED"
                failure = failure or error
        state["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save(out / "package-result.json", state)
        with tarfile.open(out / "portable-results.tar.gz", "w:gz") as archive:
            names = ["run-plan.json", "package-manifest.json", "package-result.json"]
            names += [item["path"] for item in state["portable_runs"]]
            for name in names:
                archive.add(out / name, arcname=name)
        print("Result:", state["status"], "—", out / "package-result.json", flush=True)
        print("Portable results:", out / "portable-results.tar.gz", flush=True)
    if failure is not None:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
