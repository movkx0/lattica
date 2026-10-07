#!/usr/bin/env python3
"""Check a real mixed root and retain rejected mutations in a fresh directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, data):
    with path.open("x") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")


def audit(binary, directory, log):
    command = [str(binary), "audit-root", str(directory), str(directory / "expected.json"),
               str(directory / "body.json"), str(directory / "node.6.0")]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("LATTICA_", "RAYON_"))}
    env["RAYON_NUM_THREADS"] = "1"
    started = time.monotonic()
    with log.open("x") as stream:
        result = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                timeout=120, check=False)
    events = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
    passed = [event for event in events if event.get("event") == "independent_cpu_root_audit"
              and event.get("passed") is True]
    return {"command": command, "returncode": result.returncode,
            "seconds": time.monotonic() - started, "passed_audit_events": len(passed),
            "log": {"path": str(log), "sha256": digest(log)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu-binary", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--keys", type=int, choices=(5, 6, 12), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    binary, bundle = args.cpu_binary.resolve(strict=True), args.bundle.resolve(strict=True)
    names = {"height.json", "body.json", "expected.json", "node.6.0"}
    names.update(f"key.{i}" for i in range(1, args.keys + 1))
    if {path.name for path in bundle.iterdir()} != names:
        raise ValueError("audit bundle must contain only root, policy, public body and trusted keys")
    if any(not (bundle / name).is_file() or (bundle / name).is_symlink() for name in names):
        raise ValueError("audit bundle contains a nonregular or linked artifact")
    pins = {name: digest(bundle / name) for name in sorted(names)}
    expected = json.loads((bundle / "expected.json").read_text())
    if expected["count"] < 4 or not expected["authorized_issuance"]:
        raise ValueError("these mixed-root mutations require at least four inputs and issuance")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    summary = {"schema_version": 1, "status": "running", "cases": [],
               "cpu_binary_sha256": digest(binary), "original_artifacts": pins,
               "registry_keys": args.keys, "rayon_threads": 1,
               "scope": "Rejection tests on an existing real root; no fresh proving or delivered-throughput measurement."}
    try:
        control = audit(binary, bundle, out / "positive-control.log")
        summary["positive_control"] = control
        if control["returncode"] != 0 or control["passed_audit_events"] != 1:
            raise ValueError("original root failed its positive control")
        cases = ["expected-root", "height", "issuance", "body-order", "proof-byte", "registry-key"]
        if args.keys in (6, 12):
            cases.append("finalizer-key")
        for case in cases:
            directory = out / case
            directory.mkdir()
            for name in names:
                shutil.copyfile(bundle / name, directory / name)
            if case in ("expected-root", "height", "issuance"):
                path = directory / "expected.json"
                data = json.loads(path.read_text())
                if case == "expected-root":
                    data["root"][0] = (data["root"][0] + 1) % (2**64 - 2**32 + 1)
                elif case == "height":
                    data["block_height"] += 1
                else:
                    index = next(iter(data["authorized_issuance"]))
                    data["authorized_issuance"][index] += 1
                path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
            elif case == "body-order":
                path = directory / "body.json"
                data = json.loads(path.read_text())
                data["transactions"][0], data["transactions"][1] = data["transactions"][1], data["transactions"][0]
                path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
            elif case == "proof-byte":
                path = directory / "node.6.0"
                data = bytearray(path.read_bytes())
                data[len(data) // 2] ^= 1
                path.write_bytes(data)
            else:
                name = f"key.{args.keys}" if case == "finalizer-key" else "key.1"
                if pins[name] == pins["key.2"]:
                    raise ValueError("key substitution must change the registered key")
                shutil.copyfile(bundle / "key.2", directory / name)
            outcome = audit(binary, directory, directory / "audit.log")
            outcome.update(case=case, expected="reject",
                           artifacts={name: digest(directory / name) for name in sorted(names)})
            summary["cases"].append(outcome)
            if outcome["returncode"] != 1 or outcome["passed_audit_events"]:
                raise ValueError(f"mutation did not produce an ordinary audit rejection: {case}")
        if digest(binary) != summary["cpu_binary_sha256"] or any(digest(bundle / name) != sha for name, sha in pins.items()):
            raise ValueError("trusted binary or original bundle changed")
        summary.update(status="passed", original_bundle_unchanged=True)
    except BaseException as error:
        summary.update(status="failed", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        write_json(out / "summary.json", summary)
    print(json.dumps({"status": summary["status"], "rejected_cases": len(summary["cases"])}))


if __name__ == "__main__":
    main()
