#!/usr/bin/env python3
"""Durable repeated matched CPU comparison, one pair per invocation.

Reuses the pinned pilot's controllers, inputs, binaries and report checker.
Never resumes/retries an uncertain trial. A controller may finish a clean
completed prefix, but is bounded to the current pair (not a >6-hour series).
Final shared-fixture pruning and fresh replay are separate explicit actions.
Run only after the pinned pilot is terminal. Research comparison qualification
is not production tail-latency or security qualification.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import statistics
import subprocess
import time


def require(condition, message):
    if not condition:
        raise ValueError(message)


def order(pairs):
    require(type(pairs) is int and 5 <= pairs <= 20, "require 5..20 matched pairs")
    return [
        (pair, variant)
        for pair in range(1, pairs + 1)
        for variant in (("single", "grouped") if pair % 2 else ("grouped", "single"))
    ]


def prefix(state, pairs):
    plan = order(pairs)
    attempts = state["attempts"]
    require(len(attempts) <= len(plan), "extra trial attempts")
    for attempt, expected in zip(attempts, plan):
        require(type(attempt["pair"]) is int and (attempt["pair"], attempt["variant"]) == expected,
                "trial order differs from fixed alternating order")
        require(attempt["status"] == "complete", "uncertain attempt: inspect; never rerun")
    return len(attempts)


def summary(state, pairs):
    require(prefix(state, pairs) == 2 * pairs, "series is not fully measured")
    by_pair = {}
    for attempt in state["attempts"]:
        result = attempt["result"]
        require(result["production_ready"] is False, "misclassified trial")
        require(result["recursive_proofs"] == (15 if attempt["variant"] == "single" else 7),
                "incorrect proof count")
        for key in ("recursive_command_ms", "final_merge_ms"):
            require(type(result[key]) is int and result[key] > 0, "invalid measured time")
        require(result["final_merge_ms"] <= result["recursive_command_ms"],
                "final merge exceeds complete proving-command time")
        by_pair.setdefault(attempt["pair"], {})[attempt["variant"]] = result
    metrics = {}
    for variant in ("single", "grouped"):
        totals = [by_pair[p][variant]["recursive_command_ms"] for p in sorted(by_pair)]
        finals = [by_pair[p][variant]["final_merge_ms"] for p in sorted(by_pair)]
        metrics[variant] = {
            "median_recursive_ms": statistics.median(totals),
            "worst_recursive_ms": max(totals),
            "median_final_merge_ms": statistics.median(finals),
            "worst_final_merge_ms": max(finals),
            "final_merges_over_180_seconds": sum(x > 180_000 for x in finals),
        }
    metrics["pair_total_reduction_percent"] = [
        100 * (by_pair[p]["single"]["recursive_command_ms"]
               - by_pair[p]["grouped"]["recursive_command_ms"])
        / by_pair[p]["single"]["recursive_command_ms"]
        for p in sorted(by_pair)
    ]
    metrics["median_total_reduction_percent"] = (
        100 * (metrics["single"]["median_recursive_ms"]
               - metrics["grouped"]["median_recursive_ms"])
        / metrics["single"]["median_recursive_ms"]
    )
    metrics["production_ready"] = False
    metrics["tail_latency_qualified"] = False
    return metrics


def load_helper(path, digest):
    require(path.is_file() and not path.is_symlink(), "invalid pinned helper")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 1 << 20, "invalid helper type/size")
        data = stream.read((1 << 20) + 1)
    require(len(data) <= 1 << 20 and hashlib.sha256(data).hexdigest() == digest, "pilot helper changed")
    spec = importlib.util.spec_from_file_location("eight_pilot_helper", path)
    helper = importlib.util.module_from_spec(spec)
    # Execute exactly the bytes whose hash was checked, not a second loader read.
    exec(compile(data, str(path), "exec"), helper.__dict__)
    return helper


def copy_new(module, source, destination, expected):
    data = module.regular_bytes(source)
    require({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} == expected,
            "input changed before copy: " + str(source))
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class Series:
    def __init__(self, helper, config):
        self.helper = helper
        self.module = helper.GROUPED
        self.config = config
        self.output = Path(config["output"])
        self.path = self.output / "manifest.json"
        data = self.module.regular_bytes(helper.HANDOFF)
        require(hashlib.sha256(data).hexdigest() == helper.HANDOFF_SHA == config["handoff_sha256"],
                "handoff bytes differ from external pin")
        self.handoff = json.loads(data)

    def trial_config(self, pair, variant):
        supplied = self.handoff["variants"][variant]
        expected = supplied["expected"]
        stem = f"pair-{pair:02d}-{variant}"
        return {
            "mode": "prove", "job": str(self.output / (stem + "-job")),
            "evidence": str(self.output / (stem + "-evidence")),
            "runner": supplied["runner"],
            "auditor": str(Path(self.handoff["binary_directory"]) / "block-v2-grouped-artifact-audit"),
            "accounting": str(self.helper.ACCOUNTING),
            "source_archive": self.handoff["source_archive"],
            "external": [expected[k] for k in ("profile", "chain", "root")],
        }

    def source_files(self):
        return {
            "series.py": (Path(__file__).resolve(), self.config["series_sha256"]),
            "pilot-helper.py": (Path(self.config["helper"]), self.config["helper_sha256"]),
            "accounting.py": (self.helper.ACCOUNTING, self.helper.ACCOUNTING_SHA),
            "single-trial.py": self.helper.CONTROLLERS["single"],
            "grouped-trial.py": self.helper.CONTROLLERS["grouped"],
        }

    def archive_sources(self):
        directory = self.output / "controller-sources"
        directory.mkdir(mode=0o700)
        for name, (path, pin) in self.source_files().items():
            data = self.module.regular_bytes(path)
            require(hashlib.sha256(data).hexdigest() == pin, "source changed before archival")
            copy_new(self.module, path, directory / name, {"bytes": len(data), "sha256": pin})
        self.module.sync_directory(directory)
        self.module.sync_directory(self.output)
        self.validate_source_archive()

    def validate_source_archive(self):
        directory = self.output / "controller-sources"
        self.module.private_directory(directory)
        sources = self.source_files()
        require(set(p.name for p in directory.iterdir()) == set(sources), "archived source membership changed")
        for name, (_, pin) in sources.items():
            require(self.module.digest(directory / name) == pin, "archived controller source changed")

    def validate_pins(self, shared_required=True):
        h, m = self.helper, self.module
        require(m.digest(Path(__file__).resolve()) == self.config["series_sha256"], "series source changed")
        require(m.digest(Path(self.config["helper"])) == self.config["helper_sha256"], "helper changed")
        require(m.digest(h.HANDOFF) == h.HANDOFF_SHA == self.config["handoff_sha256"], "handoff changed")
        require(m.digest(h.ACCOUNTING) == h.ACCOUNTING_SHA, "accounting changed")
        require(m.digest(Path(self.handoff["source_archive"])) == self.handoff["source_archive_sha256"],
                "frozen archive changed")
        for path, pin in h.CONTROLLERS.values():
            require(m.digest(path) == pin, "controller changed")
        for name, pin in self.handoff["binary_sha256"].items():
            require(m.digest(Path(self.handoff["binary_directory"]) / name) == pin, "binary changed")
        require(self.handoff["status"] == "EXACT_SHARED_INPUTS_AND_BOTH_EXTERNAL_STATEMENTS_VALIDATED"
                and self.handoff["production_ready"] is False, "wrong fixture scope")
        shared = Path(self.handoff["shared_wallet_directory"])
        m.private_directory(shared)
        require(set(p.name for p in shared.iterdir()) == (set(m.WALLETS) if shared_required else set()),
                "shared fixture membership differs from lifecycle state")
        if shared_required:
            for name in m.WALLETS:
                data = m.regular_bytes(shared / name)
                require({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                        == self.handoff["wallets"][name], "shared wallet changed")

    def create_job(self, config, variant):
        m = self.module
        supplied = self.handoff["variants"][variant]
        require({name: supplied["inputs"][name] for name in m.WALLETS} == self.handoff["wallets"],
                "construction input mismatch")
        job = Path(config["job"])
        job.mkdir(mode=0o700)
        (job / "scratch").mkdir(mode=0o700)
        for name in m.WALLETS:
            copy_new(m, Path(self.handoff["shared_wallet_directory"]) / name,
                     job / name, self.handoff["wallets"][name])
        for name in m.ROOT_FILES[1:]:
            copy_new(m, Path(supplied["job"]) / name, job / name, supplied["inputs"][name])
        m.sync_directory(job)
        m.sync_directory(job.parent)
        require(m.snapshot(job) == supplied["inputs"], "copied job does not match exact fixture")

    def validate_pilot(self):
        path = self.helper.OUTPUT / "manifest.json"
        data = self.module.regular_bytes(path)
        require(hashlib.sha256(data).hexdigest() == self.config["pilot_manifest_sha256"], "pilot record changed")
        pilot = json.loads(data)
        require(pilot["status"] == "MATCHED_CPU_PILOT_COMPLETE_SHARED_FIXTURE_RETAINED",
                "pilot has not completed; do not start the repeated series")
        require(set(pilot["results"]) == {"single", "grouped"}, "pilot lacks both results")
        require([a["construction"] for a in pilot["attempts"]] == ["single", "grouped"],
                "unexpected pilot attempt order")
        for attempt in pilot["attempts"]:
            require(attempt["status"] == "complete", "pilot attempt incomplete")
            variant = attempt["construction"]
            module = self.helper.SINGLE if variant == "single" else self.helper.GROUPED
            actual = self.helper.verify_completed_trial(module, attempt["config"], variant)
            require(actual == pilot["results"][variant], "pilot report no longer matches artifacts")
            supplied = self.handoff["variants"][variant]
            require(attempt["config"]["external"] ==
                    [supplied["expected"][key] for key in ("profile", "chain", "root")],
                    "pilot external trust inputs differ")
        return pilot

    def validate_completed(self, state):
        require(state["schema"] == 1 and state["config"] == self.config
                and state["production_ready"] is False, "series configuration changed")
        self.validate_source_archive()
        completed = prefix(state, self.config["pairs"])
        for attempt in state["attempts"]:
            variant = attempt["variant"]
            require(attempt["config"] == self.trial_config(attempt["pair"], variant),
                    "saved trial configuration differs")
            module = self.helper.SINGLE if variant == "single" else self.helper.GROUPED
            actual = self.helper.verify_completed_trial(module, attempt["config"], variant)
            require(actual == attempt["result"], "completed trial evidence changed")
        return completed

    def advance(self, state, controller):
        require(state["prune"] is None and not state["replays"], "proving after finalization refused")
        first = self.validate_completed(state)
        self.validate_pilot()
        self.validate_pins()
        plan = order(self.config["pairs"])
        if first == len(plan):
            return
        # One bounded pair per service; clean continuation can start with its
        # second trial, but an attempted/failed first trial never reaches here.
        end = min(len(plan), 2 * (first // 2 + 1))
        for pair, variant in plan[first:end]:
            self.module.require_no_other_work(controller)
            self.validate_pins()
            config = self.trial_config(pair, variant)
            attempt = {"pair": pair, "variant": variant, "status": "attempted",
                       "config": config, "controller": controller,
                       "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            state["attempts"].append(attempt)
            state["status"] = "RUNNING"
            self.module.save(self.path, state)  # Before creating any job artifact.
            started = time.monotonic()
            try:
                self.create_job(config, variant)
                module = self.helper.SINGLE if variant == "single" else self.helper.GROUPED
                module.run(config, False)
                attempt["result"] = self.helper.verify_completed_trial(module, config, variant)
                self.validate_pins()
                attempt["controller_wall_seconds"] = time.monotonic() - started
                attempt["status"] = "complete"
                state["status"] = "READY_FOR_NEXT_TRIAL"
                self.module.save(self.path, state)
            except BaseException as error:
                attempt["status"] = "failed_or_interrupted"
                attempt["error"] = str(error)
                state["status"] = "FAILED_OR_INTERRUPTED"
                self.module.save(self.path, state)
                raise
        if len(state["attempts"]) == len(plan):
            state["metrics"] = summary(state, self.config["pairs"])
            state["status"] = "MEASURED_SHARED_FIXTURE_RETAINED"
            self.module.save(self.path, state)

    def replay_targets(self, state, pilot):
        targets = [{"label": f"pair-{a['pair']:02d}-{a['variant']}", "variant": a["variant"],
                    "config": a["config"], "root": a["result"]["root"]}
                   for a in state["attempts"]]
        targets.extend({"label": "pilot-" + a["construction"], "variant": a["construction"],
                        "config": a["config"], "root": pilot["results"][a["construction"]]["root"]}
                       for a in pilot["attempts"])
        return targets

    def validate_replays(self, state, targets):
        require(len(state["replays"]) <= len(targets), "extra replay attempts")
        for replay, target in zip(state["replays"], targets):
            require(replay["status"] == "complete" and replay["target"] == target,
                    "uncertain or misbound replay; never automatically rerun")
            log = self.output / replay["log"]
            require(self.module.digest(log) == replay["log_sha256"], "replay log changed")
            telemetry = self.module.validate_log(log, replay["unit"], "audit")
            require(telemetry == replay["telemetry"]
                    and telemetry["audit_proof_bytes"] == target["root"]["bytes"],
                    "replay accounting/artifact mismatch")
        return len(state["replays"])

    def finalize(self, state, controller):
        require(self.validate_completed(state) == 2 * self.config["pairs"], "all pairs required")
        pilot = self.validate_pilot()
        self.module.require_no_other_work(controller)
        if state["prune"] is None:
            require(not state["replays"], "replay cannot predate shared-fixture pruning")
            self.validate_pins()
            state["prune"] = {"status": "attempted", "wallets": self.handoff["wallets"],
                              "directory": self.handoff["shared_wallet_directory"]}
            state["status"] = "PRUNING_SHARED_FIXTURE"
            self.module.save(self.path, state)
            shared = Path(self.handoff["shared_wallet_directory"])
            for name in self.module.WALLETS:
                # Exact fixture membership/hash was checked before journaling.
                # A partial deletion is intentionally not automatically resumed.
                (shared / name).unlink()
            self.module.sync_directory(shared)
            require(not any(shared.iterdir()), "shared fixture remains")
            state["prune"]["status"] = "complete"
            state["shared_fixture_pruned"] = True
            state["status"] = "POST_PRUNING_REPLAY_PENDING"
            self.module.save(self.path, state)
        require(state["prune"]["status"] == "complete" and state["shared_fixture_pruned"] is True,
                "uncertain prune; manual inspection required")
        require(state["prune"]["directory"] == self.handoff["shared_wallet_directory"]
                and state["prune"]["wallets"] == self.handoff["wallets"], "prune record misbound")
        self.validate_pins(shared_required=False)
        targets = self.replay_targets(state, pilot)
        first = self.validate_replays(state, targets)
        for index in range(first, len(targets)):
            self.module.require_no_other_work(controller)
            target = targets[index]
            unit = f"lattica-v2-eight-series-replay-{os.getpid()}-{index + 1}.service"
            log = self.output / f"replay-{index + 1:02d}.log"
            record = {"target": target, "unit": unit, "log": log.name, "status": "attempted"}
            state["replays"].append(record)
            self.module.save(self.path, state)
            started = time.monotonic()
            try:
                command = self.module.stage_command(target["config"], controller, unit, "audit", ["root-eight"])
                require(self.module.capture_stage(command, log) == 0, "fresh CPU replay failed")
                record["telemetry"] = self.module.validate_log(log, unit, "audit")
                require(record["telemetry"]["audit_proof_bytes"] == target["root"]["bytes"],
                        "replayed root size mismatch")
                record["log_sha256"] = self.module.digest(log)
                record["wall_seconds"] = time.monotonic() - started
                record["status"] = "complete"
                self.validate_pins(shared_required=False)
                self.module.save(self.path, state)
            except BaseException as error:
                subprocess.run(["systemctl", "--user", "stop", unit], check=False, timeout=30)
                record["status"] = "failed_or_interrupted"
                record["error"] = str(error)
                state["status"] = "FAILED_OR_INTERRUPTED"
                self.module.save(self.path, state)
                raise
        self.validate_completed(state)
        self.validate_pilot()
        require(self.validate_replays(state, targets) == 2 * self.config["pairs"] + 2,
                "missing fresh root replay")
        self.validate_pins(shared_required=False)
        state["metrics"] = summary(state, self.config["pairs"])
        state["repeat_qualified"] = True  # Matched research sample, not production tails/security.
        state["status"] = "REPEATED_CPU_COMPARISON_POST_PRUNING_REPLAY_PASSED"
        self.module.save(self.path, state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("advance", "finalize"))
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--helper-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    order(args.pairs)
    os.umask(0o077)
    helper = load_helper(args.helper.resolve(), args.helper_sha256)
    module = helper.GROUPED
    controller = module.require_controller()  # Refuses the live pilot or any old worker.
    output = args.output.resolve()
    require(output != helper.OUTPUT and output not in helper.OUTPUT.parents
            and helper.OUTPUT not in output.parents, "series must be separate from pilot")
    config = {"pairs": args.pairs, "output": str(output), "helper": str(args.helper.resolve()),
              "helper_sha256": args.helper_sha256, "handoff_sha256": helper.HANDOFF_SHA,
              "series_sha256": module.digest(Path(__file__).resolve()),
              "pilot_manifest_sha256": module.digest(helper.OUTPUT / "manifest.json")}
    series = Series(helper, config)
    series.validate_pilot()
    if not args.resume:
        require(args.action == "advance", "new series must begin with advance")
        series.validate_pins()
        output.mkdir(mode=0o700)
        series.archive_sources()
        state = {"schema": 1, "config": config, "status": "READY_FOR_NEXT_TRIAL", "attempts": [],
                 "replays": [], "prune": None, "shared_fixture_pruned": False,
                 "repeat_qualified": False, "production_ready": False,
                 "kind": "REPEATED_SAME_EIGHT_CPU_COMPARISON_NOT_DEPTH_SIX"}
        module.save(series.path, state)
    module.private_directory(output)
    with module.exclusive(output / "series.lock"):
        state = json.loads(module.regular_bytes(series.path, maximum=4 << 20))
        require(state["config"] == config, "resume configuration/source pins changed")
        if args.action == "advance":
            series.advance(state, controller)
        else:
            series.finalize(state, controller)
        print(json.dumps({"status": state["status"], "completed_trials": len(state["attempts"]),
                          "repeat_qualified": state["repeat_qualified"], "production_ready": False}))


if __name__ == "__main__":
    def interrupted(*_):
        raise InterruptedError("series controller interrupted")
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    main()
