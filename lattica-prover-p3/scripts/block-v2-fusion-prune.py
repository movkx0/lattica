#!/usr/bin/env python3
"""Prune only the sixteen copied fusion-registration wallet proofs.

`plan` is read-only. `apply` requires an idle bounded experiment controller and
the shared experiment lease. The pinned reporter must validate both completed
consumers before any deletion. Original manifests, caps, roots, audit bundles,
and the shared eight-wallet fixture are preserved. No interrupted deletion is
automatically resumed. This is not a fresh cryptographic replay or qualification.
"""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import time

REPORTER_SHA = "07a8a626880ddf41e64e1936070ca8d5cd4be059c566a20200ac041bf65ade7e"
WALLETS = tuple(f"wallet.{i}" for i in range(8))
CAPS = ("height", "key.1", "key.2", "key.3")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(path, *, new=False):
    path = Path(path).absolute()
    require(path == path.resolve(strict=not new), "symlink or noncanonical path refused")
    if new:
        require(path.parent.is_dir(), "output parent must already exist")
        require(not path.exists() and not path.is_symlink(), "existing output cannot be resumed")
    return path


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def load_runtime():
    path = canonical(Path(__file__).with_name("report-block-v2-fusion.py"))
    require(path.is_file() and path.stat().st_size <= 1 << 20, "invalid reporter")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == REPORTER_SHA, "pinned reporter changed")
    spec = importlib.util.spec_from_file_location("prune_fusion_report", path)
    reporter = importlib.util.module_from_spec(spec)
    exec(compile(data, str(path), "exec"), reporter.__dict__)
    fusion, _ = reporter.load_trial_module()
    base = fusion.load_base()
    handoff = reporter.pinned_json(base, fusion.HANDOFF, fusion.HANDOFF_SHA)
    return reporter, base, canonical(Path(handoff["shared_wallet_directory"]))


def directory_id(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "expected private owned directory")
    return {"device": info.st_dev, "inode": info.st_ino}


def wallet_file(base, path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            "wallet must be private, owned, regular, and not hard-linked")
    return identity(base.regular_bytes(path, maximum=2 << 20))


def shared_snapshot(base, path):
    directory_id(path)
    require(set(p.name for p in path.iterdir()) == set(WALLETS), "shared fixture membership differs")
    return {name: wallet_file(base, path / name) for name in WALLETS}


def disjoint(paths):
    require(len(set(paths)) == len(paths), "aliased experiment directories")
    for i, left in enumerate(paths):
        for right in paths[i + 1:]:
            require(left not in right.parents and right not in left.parents,
                    "nested experiment directories")


def make_plan(reporter, base, references, shared):
    require(len(references) == 2, "exactly one off/on pair required")
    reports, entries, pinned, directories = [], [], [], [canonical(shared)]
    for mode, reference in enumerate(references):
        require(set(reference) == {"trial", "trial_sha256", "registration", "registration_sha256"},
                "unexpected consumer reference")
        trial, registration = (canonical(reference[k]) for k in ("trial", "registration"))
        require(trial.name == registration.name == "manifest.json", "canonical manifest name required")
        for key in ("trial_sha256", "registration_sha256"):
            require(isinstance(reference[key], str) and re.fullmatch(r"[0-9a-f]{64}", reference[key]),
                    "invalid manifest SHA256")
        # Full log/profile/artifact/registration/CPU-audit checks, not status-only acceptance.
        report = reporter.inspect(trial, reference["trial_sha256"], registration, reference["registration_sha256"])
        require(report["fusion"] == mode, "consumer mode differs from off/on position")
        reports.append(report)
        reg = reporter.pinned_json(base, registration, reference["registration_sha256"])
        proof = reporter.pinned_json(base, trial, reference["trial_sha256"])
        job = canonical(Path(reg["config"]["job"]))
        proof_job = canonical(Path(proof["config"]["job"]))
        require(job == registration.parent / "job" and proof_job == trial.parent / "job",
                "manifest job directories misbound")
        require(reg["config"]["quotient_fusion"] == proof["config"]["quotient_fusion"] == mode,
                "manifest modes differ")
        require(set(report["wallets"]) == set(WALLETS) and set(report["height_and_caps"]) == set(CAPS),
                "wrong registration artifact names")
        before = {**report["wallets"], **report["height_and_caps"]}
        require(base.snapshot(job) == reg["artifacts"] == before, "registration artifacts differ")
        for name in WALLETS:
            require(wallet_file(base, job / name) == report["wallets"][name], "wallet identity differs")
        root = {"node.3.0": report["root"], **report["height_and_caps"]}
        require(base.snapshot(proof_job) == proof["artifacts"] == root, "consumer root artifacts differ")
        entries.append({"mode": mode, "job": str(job), "directory_id": directory_id(job),
                        "before": before, "after": report["height_and_caps"],
                        "proof_job": str(proof_job), "proof_artifacts": root})
        pinned.extend({"path": str(path), "sha256": reference[key]} for path, key in
                      ((trial, "trial_sha256"), (registration, "registration_sha256")))
        directories.extend((trial.parent, registration.parent))
    disjoint(directories)
    comparison = reporter.compare(*reports)
    require(shared_snapshot(base, shared) == reports[0]["wallets"], "shared fixture identity differs")
    return {"schema": 1, "status": "READ_ONLY_REGISTRATION_PRUNE_PLAN",
            "registrations": entries, "manifest_pins": pinned,
            "protected_directories": [str(p) for p in directories],
            "shared_directory": str(shared), "shared_wallets": reports[0]["wallets"],
            "checked_comparison": comparison, "wallet_files_to_remove": 16,
            "reporter_sha256": REPORTER_SHA, "production_ready": False,
            "repeat_qualified": False, "depth_six_qualified": False,
            "fresh_cpu_replay_performed": False}


def check_preserved(base, plan, *, pruned):
    for pin in plan["manifest_pins"]:
        require(base.digest(canonical(pin["path"])) == pin["sha256"], "manifest changed")
    require(shared_snapshot(base, canonical(plan["shared_directory"])) == plan["shared_wallets"],
            "shared fixture changed")
    for entry in plan["registrations"]:
        job = canonical(entry["job"])
        require(directory_id(job) == entry["directory_id"], "registration directory replaced")
        require(base.snapshot(job) == entry["after" if pruned else "before"], "registration membership/content changed")
        require(base.snapshot(canonical(entry["proof_job"])) == entry["proof_artifacts"], "root artifacts changed")


def opened_wallet_identity(fd, name):
    opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(opened, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 2 << 20,
                "unsafe opened wallet")
        data = stream.read((2 << 20) + 1)
        require(len(data) <= 2 << 20, "wallet exceeds bound")
        after = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "wallet changed during open")
    return identity(data)


def apply_plan(base, plan, output, guard):
    require(plan["status"] == "READ_ONLY_REGISTRATION_PRUNE_PLAN" and plan["wallet_files_to_remove"] == 16,
            "invalid prune plan")
    output = canonical(output, new=True)
    disjoint([output, *(Path(p) for p in plan["protected_directories"])])
    guard()
    check_preserved(base, plan, pruned=False)
    with ExitStack() as stack:
        jobs = []
        for entry in plan["registrations"]:
            fd = os.open(entry["job"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            require({"device": info.st_dev, "inode": info.st_ino} == entry["directory_id"], "job changed while opening")
            for name in WALLETS:
                require(opened_wallet_identity(fd, name) == entry["before"][name], "wallet changed before pruning")
            jobs.append((entry, fd))
        output.mkdir(mode=0o700)  # Never reuse an interrupted/completed receipt directory.
        base.sync_directory(output.parent)
        receipt = output / "manifest.json"
        state = {"schema": 1, "status": "PRUNE_ATTEMPTED", "plan": plan, "removed": [],
                 "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "pruner_sha256": base.digest(Path(__file__).resolve()),
                 "registration_wallets_pruned": False, "shared_fixture_pruned": False,
                 "fresh_cpu_replay_performed": False, "production_ready": False,
                 "repeat_qualified": False, "depth_six_qualified": False}
        base.save(receipt, state)  # Durable attempted record precedes the first unlink.
        try:
            for entry, fd in jobs:
                guard()
                require(directory_id(canonical(entry["job"])) == entry["directory_id"], "job replaced before pruning")
                for name in WALLETS:
                    require(opened_wallet_identity(fd, name) == entry["before"][name], "wallet changed before unlink")
                    os.unlink(name, dir_fd=fd)
                    os.fsync(fd)
                    state["removed"].append({"job": entry["job"], "name": name, "identity": entry["before"][name]})
                    base.save(receipt, state)
            check_preserved(base, plan, pruned=True)
            guard()
            require(base.digest(Path(__file__).resolve()) == state["pruner_sha256"], "pruner changed during operation")
            state["status"] = "REGISTRATION_COPIES_PRUNED_FINAL_SHARED_PRUNING_AND_REPLAY_REQUIRED"
            state["registration_wallets_pruned"] = True
            state["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            base.save(receipt, state)
        except BaseException as error:
            state["status"] = "FAILED_OR_INTERRUPTED_MANUAL_INSPECTION_REQUIRED"
            state["error"] = str(error)
            base.save(receipt, state)
            raise
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply"))
    for label in ("off", "on"):
        parser.add_argument("--" + label, type=Path, required=True)
        parser.add_argument("--" + label + "-sha256", required=True)
        parser.add_argument("--" + label + "-registration", type=Path, required=True)
        parser.add_argument("--" + label + "-registration-sha256", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    require((args.output is not None) == (args.action == "apply"), "only apply requires a new output directory")
    os.umask(0o077)
    reporter, base, shared = load_runtime()
    references = [{"trial": getattr(args, label), "trial_sha256": getattr(args, label + "_sha256"),
                   "registration": getattr(args, label + "_registration"),
                   "registration_sha256": getattr(args, label + "_registration_sha256")}
                  for label in ("off", "on")]
    if args.action == "plan":
        print(json.dumps(make_plan(reporter, base, references, shared), indent=2, sort_keys=True))
        return
    controller = base.require_controller()
    lease = base.shared_lease_path()
    lease.mkdir(mode=0o700, exist_ok=True)
    base.private_directory(lease)
    with base.exclusive(lease / "exclusive.lock"):
        base.require_no_other_work(controller)
        plan = make_plan(reporter, base, references, shared)
        state = apply_plan(base, plan, args.output, lambda: base.require_no_other_work(controller))
        print(json.dumps({"status": state["status"], "removed": len(state["removed"]),
                          "manifest": str(args.output / "manifest.json"), "production_ready": False}))


if __name__ == "__main__":
    def interrupted(*_):
        raise InterruptedError("registration pruning interrupted")
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    main()
