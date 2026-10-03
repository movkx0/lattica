#!/usr/bin/env python3
"""One fail-closed CPU quotient-fusion research trial; never production approval.

Reuses the pinned grouped controller's admission, stage lifecycle, accounting,
artifact transitions and root-only auditor. Does not modify that controller or
the original single/grouped comparison fixtures. Each invocation requires a new
output directory; attempted work is never automatically retried or resumed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import time

BASE_SHA = "8bd17f9e084bb95119829b2c356e6f2968539e14011955d8ed623cb29c5e489e"
ACCOUNTING_SHA = "f9b665c3210ec602799acf5ada2338084063677d42d48065324f23f31bdd1ad0"
HANDOFF_SHA = "d9a936a822f5ab2555a782712299c0ec837a08c1e39ceb6f99376f393d7c799b"
BASE = Path(__file__).resolve().parent.parent
HANDOFF = BASE / "target/block-v2-eight-comparison-inputs-20261001-a/expected-statements.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_base():
    path = BASE / "scripts/block-v2-grouped-trial.py"
    require(path.is_file() and not path.is_symlink(), "invalid base controller")
    with path.open("rb") as stream:
        data = stream.read(1 << 20)
    require(hashlib.sha256(data).hexdigest() == BASE_SHA, "pinned base controller changed")
    spec = importlib.util.spec_from_file_location("fusion_grouped_base", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def fusion_mode(value):
    require(type(value) is int and value in (0, 1), "fusion mode must be integer 0 or 1")
    return value


def inject_mode(command, mode, audit=False):
    mode = 0 if audit else fusion_mode(mode)
    require(command.count("--") == 1, "expected one systemd command separator")
    split = command.index("--")
    require(not any("LATTICA_V2_QUOTIENT_FUSION" in x for x in command[:split]),
            "duplicate fusion environment control")
    return command[:split] + [f"--setenv=LATTICA_V2_QUOTIENT_FUSION={mode}"] + command[split:]


def validate_mode(text, mode, audit=False):
    fusion_mode(mode)
    lines = [line for line in text.splitlines() if line.startswith("quotient_fusion_research")]
    expected = [] if audit else [f"quotient_fusion_research enabled={str(bool(mode)).lower()} production_ready=false"]
    require(lines == expected, "missing, duplicate, or incorrect quotient-fusion mode marker")


def validate_fusion_spans(text, mode, name):
    prefix = 'performance_span target="lattica_block_v2_perf" name="fused quotient ldes"'
    lines = [line for line in text.splitlines() if line.startswith(prefix)]
    expected = ({"pairs": 4, "merges": 3}.get(name, 0) if mode == 1 else 0)
    require(len(lines) == expected, "incorrect number of measured fused quotient operations")
    for line in lines:
        match = re.fullmatch(re.escape(prefix) + r" calls=1 total_ns=([0-9]+) max_ns=([0-9]+)", line)
        require(match is not None and int(match[1]) > 0 and match[1] == match[2],
                "malformed fused quotient operation telemetry")


def configure(module, mode):
    fusion_mode(mode)
    original_command, original_log = module.stage_command, module.validate_log

    def stage_command(config, controller, unit, name, action):
        return inject_mode(original_command(config, controller, unit, name, action), mode, name == "audit")

    def validate_log(path, unit, name):
        # Original accounting/sequence/resource validation remains mandatory.
        result = original_log(path, unit, name)
        text = module.regular_bytes(path, maximum=module.MAX_STAGE_LOG).decode("utf-8", errors="strict")
        validate_mode(text, mode, name == "audit")
        validate_fusion_spans(text, mode, name)
        result["quotient_fusion_requested"] = bool(mode) if name != "audit" else False
        result["preserved_auditor"] = name == "audit"
        return result

    module.stage_command, module.validate_log = stage_command, validate_log


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def copy_new(module, source, destination, expected):
    data = module.regular_bytes(source)
    require(identity(data) == expected, "source artifact differs from external pin: " + str(source))
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def validate_inputs(module, handoff):
    require(handoff["status"] == "EXACT_SHARED_INPUTS_AND_BOTH_EXTERNAL_STATEMENTS_VALIDATED"
            and handoff["production_ready"] is False, "wrong shared-fixture scope")
    supplied = handoff["variants"]["grouped"]
    require({name: supplied["inputs"][name] for name in module.WALLETS} == handoff["wallets"],
            "grouped wallet identities differ from shared fixture")
    expected = supplied["expected"]
    require((expected["level"], expected["count"], expected["mode"]) == (3, 8, 3), "wrong statement scope")
    external = [module.external_hex(expected[k], root=k == "root") for k in ("profile", "chain", "root")]
    shared = Path(handoff["shared_wallet_directory"])
    module.private_directory(shared)
    require(set(p.name for p in shared.iterdir()) == set(module.WALLETS), "shared wallet membership changed")
    for name in module.WALLETS:
        require(identity(module.regular_bytes(shared / name)) == handoff["wallets"][name], "wallet changed")
    for name in module.ROOT_FILES[1:]:
        require(identity(module.regular_bytes(Path(supplied["job"]) / name)) == supplied["inputs"][name],
                "baseline key/height changed")
    return external


def validate_registration(module, path, pin, config, files, supplied):
    data = module.regular_bytes(path)
    require(hashlib.sha256(data).hexdigest() == pin, "registration evidence pin differs")
    state = json.loads(data)
    require(state["status"] == "FULL_SIZE_PREPROCESSING_REPRODUCED_RESEARCH_ONLY"
            and state["production_ready"] is False and state["level6_qualified"] is False,
            "full-size registration gate incomplete or wrong scope")
    prior = state["config"]
    require(prior["action"] == "reproduce" and prior["mode"] == "prepare", "wrong registration action")
    for key in ("runner", "auditor", "accounting", "source_archive", "external", "quotient_fusion"):
        require(prior[key] == config[key], "registration belongs to different configuration: " + key)
    require(state["pins"] == {k: v[1] for k, v in files.items()}, "registration implementation pins differ")
    require(state["artifacts"] == supplied["inputs"] == module.snapshot(Path(prior["job"])),
            "registered caps or fixture changed")
    evidence = Path(prior["evidence"])
    module.verify_saved_evidence(state, evidence)
    plan = [(f"key-{i}", []) for i in (1, 2, 3)] + [("check", [])]
    require(module.validate_prefix(state, plan) == 4, "registration stages incomplete")
    for attempt in state["attempts"]:
        require(module.validate_log(evidence / attempt["log"], attempt["unit"], attempt["name"]) ==
                attempt["telemetry"], "registration telemetry changed")


def run(module, args):
    controller = module.require_controller()
    handoff_data = module.regular_bytes(HANDOFF)
    require(hashlib.sha256(handoff_data).hexdigest() == HANDOFF_SHA, "external handoff changed")
    handoff = json.loads(handoff_data)
    external = validate_inputs(module, handoff)
    supplied = handoff["variants"]["grouped"]
    auditor = Path(handoff["binary_directory"]) / "block-v2-grouped-artifact-audit"
    files = {
        "fusion-controller.py": (Path(__file__).resolve(), module.digest(Path(__file__).resolve())),
        "grouped-controller.py": (BASE / "scripts/block-v2-grouped-trial.py", BASE_SHA),
        "accounting.py": (BASE / "scripts/block-v2-accounting.py", ACCOUNTING_SHA),
        "handoff.json": (HANDOFF, HANDOFF_SHA),
        "runner": (args.runner, args.runner_sha256),
        "source-archive": (args.source_archive, args.source_archive_sha256),
        "auditor": (auditor, handoff["binary_sha256"][auditor.name]),
    }
    output = args.output
    job, evidence = output / "job", output / "evidence"
    config = {"mode": "prepare" if args.action == "reproduce" else "prove", "action": args.action,
              "job": str(job), "evidence": str(evidence), "external": external,
              "runner": str(args.runner), "auditor": str(auditor),
              "accounting": str(files["accounting.py"][0]), "source_archive": str(args.source_archive),
              "quotient_fusion": args.fusion}
    if args.action == "prove":
        require(args.registration is not None and args.registration_sha256 is not None,
                "proof requires pinned successful full-size registration evidence")
        validate_registration(module, args.registration, args.registration_sha256, config, files, supplied)
        files["registration"] = (args.registration, args.registration_sha256)
    for path in [p for p, _ in files.values()] + [Path(supplied["job"]), Path(handoff["shared_wallet_directory"])]:
        require(output != path and output not in path.parents and path not in output.parents,
                "output overlaps a pinned input")

    def check_pins():
        for label, (path, pin) in files.items():
            require(module.digest(path) == pin, "pinned file changed: " + label)
        validate_inputs(module, handoff)

    check_pins()
    lease = module.shared_lease_path()
    lease.mkdir(mode=0o700, exist_ok=True)
    module.private_directory(lease)
    with module.exclusive(lease / "exclusive.lock"):
        module.require_no_other_work(controller)
        output.mkdir(mode=0o700)  # Existing/uncertain attempt is never reused.
        module.sync_directory(output.parent)
        path = output / "manifest.json"
        state = {"schema": 1, "config": config, "pins": {k: v[1] for k, v in files.items()},
                 "status": "INITIALIZING", "attempts": [], "artifacts": None,
                 "production_ready": False, "repeat_qualified": False, "level6_qualified": False,
                 "full_tree_security": "UNREVIEWED", "shared_wallets_pruned": False,
                 "configured_limits_not_peak_observations": {
                     "aggregate_ram_bytes": 48 * module.GIB, "controller_ram_bytes_at_most": 3 * module.GIB,
                     "worker_ram_high_bytes": 40 * module.GIB, "worker_ram_max_bytes": 44 * module.GIB,
                     "worker_runtime_seconds": 7200, "controller_runtime_seconds_at_most": 21600,
                     "swap_bytes": 0, "managed_spill_bytes": 120 * module.GIB}}
        module.save(path, state)
        try:
            sources = output / "controller-sources"
            sources.mkdir(mode=0o700)
            for label in ("fusion-controller.py", "grouped-controller.py", "accounting.py", "handoff.json"):
                source, pin = files[label]
                copy_new(module, source, sources / label, {"bytes": source.stat().st_size, "sha256": pin})
            module.sync_directory(sources)
            job.mkdir(mode=0o700)
            (job / "scratch").mkdir(mode=0o700)
            evidence.mkdir(mode=0o700)
            names = module.WALLETS + (("height",) if args.action == "reproduce" else module.ROOT_FILES[1:])
            for name in names:
                directory = handoff["shared_wallet_directory"] if name in module.WALLETS else supplied["job"]
                copy_new(module, Path(directory) / name, job / name, supplied["inputs"][name])
            module.sync_directory(job)
            module.sync_directory(output)
            state["artifacts"] = module.snapshot(job)
            require(state["artifacts"] == {n: supplied["inputs"][n] for n in names}, "initial fixture mismatch")
            state["status"] = "RUNNING"
            module.save(path, state)
            plan = ([(f"key-{i}", ["register", str(i)]) for i in (1, 2, 3)] +
                    [("check", ["check-registered", *external])] if args.action == "reproduce" else module.stages(config))
            for name, action in plan:
                module.require_no_other_work(controller)
                check_pins()
                require(module.snapshot(job) == state["artifacts"], "job changed between stages")
                module.verify_saved_evidence(state, evidence)
                module.run_stage(config, controller, name, action, evidence, state, path)
                if name.startswith("key-"):
                    key = "key." + name[-1]
                    require(state["artifacts"][key] == supplied["inputs"][key], "full-size preprocessing cap differs")
            check_pins()
            module.verify_saved_evidence(state, evidence)
            require(module.validate_prefix(state, plan) == len(plan), "incomplete attempt sequence")
            for attempt in state["attempts"]:
                if attempt["name"] != "export":
                    require(module.validate_log(evidence / attempt["log"], attempt["unit"], attempt["name"]) ==
                            attempt["telemetry"], "completed telemetry changed")
            if args.action == "reproduce":
                require(state["artifacts"] == supplied["inputs"], "full-size registration mismatch")
                state["status"] = "FULL_SIZE_PREPROCESSING_REPRODUCED_RESEARCH_ONLY"
            else:
                require(set(state["artifacts"]) == set(module.ROOT_FILES), "local inner proofs remain")
                state["recursive_command_ms"] = sum(a["telemetry"]["duration"]["elapsed_ms"]
                                                     for a in state["attempts"] if a["name"] in ("pairs", "merges"))
                state["root"] = state["artifacts"]["node.3.0"]
                state["status"] = "FUSION_TRIAL_CPU_AUDITED_RESEARCH_ONLY"
            state["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            module.save(path, state)
            print(json.dumps({"status": state["status"], "production_ready": False, "manifest": str(path)}))
        except BaseException as error:
            state["status"] = "FAILED_OR_INTERRUPTED"
            state["error"] = str(error)
            module.save(path, state)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("reproduce", "prove"))
    parser.add_argument("--fusion", type=int, choices=(0, 1), required=True)
    for name in ("output", "runner", "source-archive"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("runner-sha256", "source-archive-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--registration", type=Path)
    parser.add_argument("--registration-sha256")
    args = parser.parse_args()
    require((args.registration is None and args.registration_sha256 is None) if args.action == "reproduce"
            else (args.registration is not None and args.registration_sha256 is not None),
            "only proving requires registration path and SHA256")
    for name in ("output", "runner", "source_archive", "registration"):
        value = getattr(args, name)
        if value is None:
            continue
        require(not value.is_symlink(), "symlink path refused")
        value = value.resolve()
        require(re.fullmatch(r"/[A-Za-z0-9_./-]+", str(value)) is not None, "unsafe research path")
        setattr(args, name, value)
    for value in (args.runner_sha256, args.source_archive_sha256, args.registration_sha256):
        if value is None:
            continue
        require(re.fullmatch(r"[0-9a-f]{64}", value) is not None, "invalid SHA256 pin")
    require(os.access(args.runner, os.X_OK), "runner not executable")
    os.umask(0o077)
    def interrupted(*_):
        raise InterruptedError("fusion controller interrupted")
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    module = load_base()
    configure(module, args.fusion)
    run(module, args)


if __name__ == "__main__":
    main()
