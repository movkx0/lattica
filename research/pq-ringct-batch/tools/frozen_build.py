#!/usr/bin/env python3
"""Prepared direct-rustc build/check; default mode never writes or launches."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import time
import uuid

PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parent.parent
RUSTC = Path("/home/access/code/lattica/.tools/rust-1.96.0/bin/rustc")
BUILD = ROOT / ".tools/pq-logs/graph-prefix-first4-v2-build.json"
BUILD_SHA = "ac116360e68247fc0b3ba32b3aa8cda6ea9b67c5aeef4063a848318c4b08d2bb"
# The original and first recovery lost their sessions without terminal measurements.
# Their evidence stays untouched; require the separately recorded second recovery.
BASELINE = ROOT / "research/pq-ringct/data/complete-spend-acceptance-recovery-v2-1db18b9e1bece2fd.json"
SOURCE_ROOTS = [
    "research/pq-ringct/src", "lattica-prover-p3/src",
    "lattica-prover-p3/vendor/p3-field/src", "lattica-prover-p3/vendor/p3-lookup/src",
    "lattica-prover-p3/vendor/p3-symmetric/src",
]
ARTIFACT_SHA = {
    "lattica_pq_ringct_research": "9240ed08406ea34148bca688d7e70a8aa122d1063064f779495316775431908a",
    "lattica_prover_p3": "a86de53c3670ebf8030ea60b9c07769660262d558728b120bffe7abc6cd5ed67",
    "p3_field": "03f1fd11ca3c2c59766438c595d11a70029dda1255641f3ec278b2dbeb14750d",
    "p3_batch_stark": "f88dafca3aa5b64f8001393352b9bfb1d5b1b374e26f3188df1b0563c59457b7",
    "sha3": "c60398c5331371c17a2e791587482be2083af2a25732bc17d56d4b787870f9dd",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            result.update(block)
    return result.hexdigest()


def read_json(path):
    def fields(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=fields)


def local(name):
    raw = ROOT / name
    resolved = raw.resolve()
    require(resolved.is_relative_to(ROOT), f"path escapes worktree: {name}")
    while raw != ROOT and raw.is_relative_to(ROOT):
        require(not raw.is_symlink(), f"symlink in managed path: {raw}")
        raw = raw.parent
    return resolved


def available():
    return int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                    if line.startswith("MemAvailable:"))) * 1024


class StageInterrupted(RuntimeError):
    """Cancellation must not be mistaken for a retryable wait4 interruption."""


def interrupted(signum, _frame):
    # SIGINT already raises KeyboardInterrupt. Route process termination through
    # guarded's kill/reap path as well, so cancellation cannot orphan rustc/tests.
    raise StageInterrupted(f"received signal {signum}")


def own_inputs():
    files = [PACKAGE / "Cargo.toml", PACKAGE / "README.md", Path(__file__).resolve()]
    files.extend(sorted((PACKAGE / "src").rglob("*.rs")))
    require(PACKAGE / "src/lib.rs" in files, "batch src/lib.rs is not prepared")
    require(all(not (PACKAGE.is_relative_to(ROOT / base)) for base in SOURCE_ROOTS),
            "batch package overlaps frozen sources")
    return {str(p.relative_to(ROOT)): sha(local(str(p.relative_to(ROOT)))) for p in files}


def frozen_inputs():
    require(sha(BUILD) == BUILD_SHA, "frozen v2 build record changed")
    build = read_json(BUILD)
    require(build["status"] == "passed" and build["all_subprocesses_terminal_and_reaped"]
            and not build["error"] and not build["post_audit_errors"], "v2 build/check did not pass")
    pinned = dict(build["pinned_inputs"])
    pinned.update(build["native_build_inputs"])
    pinned[str(BUILD.relative_to(ROOT))] = BUILD_SHA
    frozen = read_json(local(".tools/pq-logs/producer-branch-acceptance-v1-frozen-source.json"))
    source_build = read_json(local(frozen["complete_build_manifest"]))
    sources = source_build["source_sha256"]
    require(len(sources) == 960, "unexpected frozen source count")
    actual = {str(p.relative_to(ROOT)) for base in SOURCE_ROOTS
              for p in local(base).rglob("*.rs")}
    expected = {name for name in sources if name.endswith(".rs")
                and any(name.startswith(base + "/") for base in SOURCE_ROOTS)}
    require(actual == expected, "added or removed frozen Rust source")
    pinned.update(sources)
    require(all(sha(local(name)) == digest for name, digest in pinned.items()),
            "frozen source/support/native input changed")
    cargo = local(build["runs"][0]["log"])
    require(sha(cargo) == build["runs"][0]["log_sha256"], "frozen Cargo log changed")
    pinned[str(cargo.relative_to(ROOT))] = sha(cargo)
    artifacts, link_paths = {}, set()
    for line in cargo.read_text().splitlines():
        if not line.startswith("{"):
            continue
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact":
            name = item["target"]["name"]
            if name not in ARTIFACT_SHA or not {"lib", "rlib"}.intersection(item["target"]["kind"]):
                continue
            paths = [local(p) for p in item["filenames"] if p.endswith(".rlib")]
            require(name not in artifacts and len(paths) == 1, "ambiguous emitted library")
            require(sha(paths[0]) == ARTIFACT_SHA[name], f"frozen artifact changed: {name}")
            require(item["profile"]["opt_level"] == "3" and not item["profile"]["debuginfo"],
                    "frozen library profile differs")
            artifacts[name] = paths[0]
            pinned[str(paths[0].relative_to(ROOT))] = ARTIFACT_SHA[name]
        elif item.get("reason") == "build-script-executed":
            link_paths.update(item.get("linked_paths", []))
    require(set(artifacts) == set(ARTIFACT_SHA), "missing exact emitted library")
    return pinned, artifacts, sorted(link_paths)


def guarded(command, log):
    memory = available()
    require(memory >= 10 << 30, "fresh 10 GiB memory admission failed")
    require(shutil.disk_usage(ROOT).free >= 16 << 30, "16 GiB disk reserve failed")
    require(not log.exists(), "refuse raw-log overwrite")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("LATTICA_", "CARGO_PROFILE_", "CARGO_BUILD_"))
           and k not in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                         "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTDOC"}}
    env.update(RAYON_NUM_THREADS="2", CARGO_MANIFEST_DIR=str(PACKAGE),
               CARGO_PKG_NAME="lattica-pq-ringct-batch", CARGO_PKG_VERSION="0.1.0")
    process, usage, error = None, None, None
    started = time.perf_counter()

    def limit():
        resource.setrlimit(resource.RLIMIT_AS, (8 << 30, 8 << 30))

    def reap():
        while True:
            try:
                _, status, used = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                return used
            except InterruptedError:
                continue
    try:
        with log.open("x") as stream:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT,
                                       start_new_session=True, preexec_fn=limit)
            try:
                usage = reap()
            except BaseException:
                # Complete cleanup even if another cancellation arrives.
                handlers = {sig: signal.signal(sig, signal.SIG_IGN)
                            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
                try:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    usage = reap()
                finally:
                    for sig, handler in handlers.items():
                        signal.signal(sig, handler)
                raise
    except BaseException as caught:
        error = repr(caught)
    return {
        "command": command, "log": str(log.relative_to(ROOT)),
        "log_sha256": sha(log) if log.exists() else None, "error": error,
        "exit_code": process.returncode if process is not None else None,
        "terminal_and_reaped": process is None or process.returncode is not None,
        "wall_seconds": time.perf_counter() - started,
        "cpu_user_seconds": usage.ru_utime if usage else None,
        "cpu_system_seconds": usage.ru_stime if usage else None,
        "max_rss_kib": usage.ru_maxrss if usage else None,
        "address_space_limit_bytes": 8 << 30, "rayon_threads": 2,
        "admission_available_bytes": memory,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=["build", "check"], required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--exclusive-window-note")
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9_-]+", args.label) is not None, "invalid label")
    pinned, artifacts, links = frozen_inputs()
    own = own_inputs()
    stem = "pq-ringct-batch-" + args.label
    library = ROOT / f".tools/pq-binaries/lib{stem.replace('-', '_')}.rlib"
    tests = ROOT / f".tools/pq-binaries/{stem}-tests"
    records = {stage: ROOT / f".tools/pq-logs/{stem}-{stage}.json" for stage in ["build", "check"]}
    require(not records[args.stage].exists(), "refuse existing stage record")
    common = [str(RUSTC), "--edition=2021", "--crate-name", "lattica_pq_ringct_batch",
              str(PACKAGE / "src/lib.rs"), "-C", "opt-level=3", "-C", "debuginfo=0",
              "-L", "dependency=" + str(ROOT / ".tools/target-pq/release/deps")]
    for name, path in sorted(artifacts.items()):
        common.extend(["--extern", name + "=" + str(path)])
    for path in links:
        common.extend(["-L", path])
    if args.stage == "build":
        require(not library.exists() and not tests.exists(), "refuse output overwrite")
        commands = [common + ["--crate-type=rlib", "-o", str(library)],
                    common + ["--test", "-o", str(tests)]]
    else:
        prior = read_json(records["build"])
        require(prior["status"] == "passed" and prior["own_inputs"] == own
                and prior["pinned_inputs"] == pinned, "matching successful build required")
        require(sha(library) == prior["library_sha256"] and sha(tests) == prior["tests_sha256"],
                "batch build artifacts changed")
        commands = [[str(tests), "--test-threads=1", "--nocapture"]]
    if not args.execute:
        print(json.dumps({"prepared_only": True, "writes": False, "launch": False,
                          "stage": args.stage, "commands": commands,
                          "own_inputs": own, "frozen_build_sha256": BUILD_SHA}, indent=2))
        return
    require(args.exclusive_window_note and args.exclusive_window_note.strip(),
            "explicit coordinator window note required")
    terminal = read_json(BASELINE)
    require(terminal.get("all_subprocesses_terminal_and_reaped")
            and terminal.get("status") in {"passed", "failed_or_incomplete"},
            "full baseline must be terminal and reaped before any build/check")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    record = {"schema": "pq-ringct-batch-frozen-build-v1", "stage": args.stage,
              "status": "prepared", "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "own_inputs": own, "pinned_inputs": pinned, "runs": [],
              "baseline_terminal_sha256": sha(BASELINE),
              "exclusive_window_note": args.exclusive_window_note,
              "proof_execution": False, "complete_batch_proof": False}
    with records[args.stage].open("x") as stream:
        json.dump(record, stream, indent=2)
    error = None
    try:
        for index, command in enumerate(commands):
            result = guarded(command, ROOT / f".tools/pq-logs/{stem}-{args.stage}-{index}.log")
            record["runs"].append(result)
            require(result["exit_code"] == 0 and result["error"] is None, "subprocess failed")
        if args.stage == "check":
            content = local(record["runs"][0]["log"]).read_text()
            match = re.search(r"test result: ok\. ([0-9]+) passed;", content)
            require(match and int(match.group(1)) > 0, "no passing ordinary tests recorded")
            require(sha(library) == prior["library_sha256"] and sha(tests) == prior["tests_sha256"],
                    "batch build artifacts changed during check")
        record["library_sha256"], record["tests_sha256"] = sha(library), sha(tests)
    except BaseException as caught:
        error = repr(caught)
    post_error = None
    try:
        require(own_inputs() == own, "batch inputs changed during stage")
        require(frozen_inputs()[0] == pinned, "frozen inputs changed during stage")
    except BaseException as caught:
        post_error = repr(caught)
    record["error"], record["post_audit_error"] = error, post_error
    record["all_subprocesses_terminal_and_reaped"] = all(r["terminal_and_reaped"] for r in record["runs"])
    record["status"] = "passed" if error is None and post_error is None and record["all_subprocesses_terminal_and_reaped"] else "failed"
    temporary = records[args.stage].with_name(records[args.stage].name + ".tmp-" + uuid.uuid4().hex)
    with temporary.open("x") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, records[args.stage])
    print(json.dumps({"status": record["status"], "record": str(records[args.stage].relative_to(ROOT)),
                      "error": error, "post_audit_error": post_error}))
    require(record["status"] == "passed", "batch stage failed; evidence preserved")


if __name__ == "__main__":
    main()
