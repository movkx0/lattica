#!/usr/bin/env python3
"""Read-only validation/reporting for completed, pinned CPU fusion experiments.

Does not launch services, create proofs, prune data, or grant production approval.
Registration fixtures must still exist. Final post-shared-pruning root replay is
a separate gate. Profiler lifetimes are inclusive and are never added together
to manufacture a CPU/IO breakdown or compared as end-to-end command times.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex

TRIAL_SHA = "cb36fd551f3442a4eaa534536691cca8a0bda01c1b7dbe7bf7cfccfb87ec8e2c"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9]+", value) is not None,
            "invalid unsigned telemetry integer")
    return int(value)


def fields(line):
    result = {}
    for token in shlex.split(line)[1:]:
        require("=" in token, "unkeyed profiler field")
        key, value = token.split("=", 1)
        require(key and key not in result, "duplicate profiler field")
        result[key] = value
    return result


def profile_nodes(text, names, fusion):
    require(type(fusion) is int and fusion in (0, 1), "invalid fusion mode")
    blocks = {}
    current = None
    for line in text.splitlines():
        if line.startswith("performance_checkpoint "):
            record = fields(line)
            require(set(record) == {"label", "elapsed_ms", "spans_dropped", "spans_open", "timings"},
                    "unexpected checkpoint fields")
            label = record["label"]
            require(label not in blocks, "duplicate profiler checkpoint")
            require(record["spans_dropped"] == record["spans_open"] == "0"
                    and record["timings"] == "inclusive_nonadditive", "incomplete or incompatible profiling")
            current = {"elapsed_ms": natural(record["elapsed_ms"]), "spans": {}}
            blocks[label] = current
        elif line.startswith("performance_span "):
            require(current is not None, "span precedes checkpoint")
            record = fields(line)
            require(set(record) == {"target", "name", "calls", "total_ns", "max_ns"}, "unexpected span fields")
            key = (record["target"], record["name"])
            require(key not in current["spans"], "duplicate span identity")
            values = {k: natural(record[k]) for k in ("calls", "total_ns", "max_ns")}
            require(values["calls"] > 0 and values["max_ns"] <= values["total_ns"], "invalid span accounting")
            require(values["calls"] != 1 or values["max_ns"] == values["total_ns"], "single-call span differs")
            current["spans"][key] = values
    require(list(blocks) == [*names, "grouped process remainder"], "missing/misordered profiler checkpoints")
    quotient = ("p3_batch_stark::prover", "compute quotient")
    native = ("lattica_block_v2_perf", "native batch prove")
    fused = ("lattica_block_v2_perf", "fused quotient ldes")
    chunks = ("lattica_block_v2_perf", "fused quotient chunk")
    result = []
    for name in names:
        block = blocks[name]
        spans = block["spans"]
        require(native in spans and spans[native]["calls"] == 1
                and quotient in spans and spans[quotient]["calls"] == 1, "missing per-node prover/quotient span")
        require((fused in spans) == (chunks in spans) == bool(fusion), "per-node fusion mode mismatch")
        if fusion:
            count = spans[chunks]["calls"]
            require(spans[fused]["calls"] == 1 and 2 <= count <= 16 and count & (count - 1) == 0,
                    "invalid per-node fused chunk geometry")
        result.append({"artifact": name, "checkpoint_elapsed_ms": block["elapsed_ms"],
                       "timings": "inclusive_nonadditive",
                       "spans": [{"target": key[0], "name": key[1], **value}
                                 for key, value in sorted(spans.items())]})
    remainder = blocks["grouped process remainder"]["spans"]
    require(not any(key in remainder for key in (native, quotient, fused, chunks)),
            "unassigned proving work in remainder")
    return result


def load_trial_module():
    path = Path(__file__).with_name("block-v2-fusion-trial.py").resolve()
    require(path.is_file() and not path.is_symlink(), "invalid trial controller path")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == TRIAL_SHA, "unsupported trial controller revision")
    spec = importlib.util.spec_from_file_location("reported_fusion_trial", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module, path


def pinned_json(module, path, expected):
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "invalid manifest SHA256")
    data = module.regular_bytes(path)
    require(hashlib.sha256(data).hexdigest() == expected, "manifest SHA256 differs")
    return json.loads(data)


def bind_export(artifacts, root, bundle):
    require(artifacts["node.3.0"] == root, "root identity differs")
    require(bundle == {name: info["sha256"] for name, info in artifacts.items()},
            "exported audit bundle differs from the measured job/root")


def inspect(trial_path, trial_sha, registration_path, registration_sha):
    fusion, controller_path = load_trial_module()
    module = fusion.load_base()
    state = pinned_json(module, trial_path, trial_sha)
    require(state["schema"] == 1 and state["status"] == "FUSION_TRIAL_CPU_AUDITED_RESEARCH_ONLY"
            and state["production_ready"] is False and state["repeat_qualified"] is False
            and state["level6_qualified"] is False and state["full_tree_security"] == "UNREVIEWED",
            "trial incomplete, interrupted, or outside research scope")
    config = state["config"]
    require(config["action"] == config["mode"] == "prove", "not a proving trial")
    fusion.fusion_mode(config["quotient_fusion"])
    fusion.configure(module, config["quotient_fusion"])
    require(Path(config["job"]) == trial_path.parent / "job"
            and Path(config["evidence"]) == trial_path.parent / "evidence", "trial directories misbound")
    handoff = pinned_json(module, fusion.HANDOFF, fusion.HANDOFF_SHA)
    supplied = handoff["variants"]["grouped"]
    require(config["external"] == [supplied["expected"][k] for k in ("profile", "chain", "root")],
            "trial external statement differs from the pinned public handoff")
    files = {
        "fusion-controller.py": (controller_path, TRIAL_SHA),
        "grouped-controller.py": (fusion.BASE / "scripts/block-v2-grouped-trial.py", fusion.BASE_SHA),
        "accounting.py": (Path(config["accounting"]), fusion.ACCOUNTING_SHA),
        "handoff.json": (fusion.HANDOFF, fusion.HANDOFF_SHA),
        "runner": (Path(config["runner"]), state["pins"]["runner"]),
        "source-archive": (Path(config["source_archive"]), state["pins"]["source-archive"]),
        "auditor": (Path(config["auditor"]), handoff["binary_sha256"]["block-v2-grouped-artifact-audit"]),
    }
    require(state["pins"] == {**{k: v[1] for k, v in files.items()}, "registration": registration_sha},
            "trial implementation/registration pins differ")
    for name, (path, pin) in files.items():
        require(module.digest(path) == pin, "pinned implementation changed: " + name)
    fusion.validate_registration(module, registration_path, registration_sha, config, files, supplied)
    sources = trial_path.parent / "controller-sources"
    module.private_directory(sources)
    source_names = {"fusion-controller.py", "grouped-controller.py", "accounting.py", "handoff.json"}
    require(set(p.name for p in sources.iterdir()) == source_names, "source archive membership changed")
    for name in source_names:
        require(module.digest(sources / name) == files[name][1], "archived controller source changed")
    plan = module.stages(config)
    require(module.validate_prefix(state, plan) == len(plan), "incomplete stage sequence")
    evidence = Path(config["evidence"])
    module.private_directory(evidence)
    module.verify_saved_evidence(state, evidence)
    require(module.snapshot(Path(config["job"])) == state["artifacts"]
            and set(state["artifacts"]) == set(module.ROOT_FILES), "pruned job/root artifacts differ")
    exported = next(attempt["bundle"] for attempt in state["attempts"] if attempt["name"] == "export")
    bind_export(state["artifacts"], state["root"], exported)
    for name in module.ROOT_FILES[1:]:
        require(state["artifacts"][name] == supplied["inputs"][name], "root registry differs")
    nodes, profiles, recursive_ms, peak_ram, peak_spill = [], [], 0, 0, 0
    for index, attempt in enumerate(state["attempts"], 1):
        if attempt["name"] == "export":
            continue
        name = attempt["name"]
        require(attempt["log"] == f"{index:02d}-{name}.log", "stage log name differs")
        log = evidence / attempt["log"]
        telemetry = module.validate_log(log, attempt["unit"], name)
        require(telemetry == attempt["telemetry"], "recorded telemetry differs from pinned log")
        if name == "audit":
            require(telemetry["audit_proof_bytes"] == state["root"]["bytes"], "audited root size differs")
        if name not in ("pairs", "merges"):
            continue
        recursive_ms += telemetry["duration"]["elapsed_ms"]
        peak_ram = max(peak_ram, telemetry["accounting"]["memory_peak"])
        peak_spill = max(peak_spill, telemetry["duration"]["spill_peak_bytes"])
        nodes.extend(telemetry["nodes"])
        text = module.regular_bytes(log, maximum=module.MAX_STAGE_LOG).decode("utf-8", errors="strict")
        names = module.PAIRS if name == "pairs" else module.MERGES
        profiles.extend(profile_nodes(text, names, config["quotient_fusion"]))
    require([n["artifact"] for n in nodes] == list(module.PAIRS + module.MERGES), "wrong recursive chain")
    require(recursive_ms == state["recursive_command_ms"] and recursive_ms > 0
            and all(n["elapsed_ms"] > 0 for n in nodes)
            and sum(n["elapsed_ms"] for n in nodes) <= recursive_ms, "inconsistent command/node duration")
    return {"manifest": str(trial_path), "manifest_sha256": trial_sha,
            "registration_manifest": str(registration_path), "registration_sha256": registration_sha,
            "fusion": config["quotient_fusion"], "pins": state["pins"],
            "external": config["external"], "wallets": handoff["wallets"],
            "height_and_caps": {n: supplied["inputs"][n] for n in module.ROOT_FILES[1:]},
            "started_utc": state["attempts"][0]["started_utc"], "finished_utc": state["finished_utc"],
            "recursive_command_ms": recursive_ms, "final_merge_ms": nodes[-1]["elapsed_ms"],
            "nodes": nodes, "root": state["root"], "peak_worker_cgroup_bytes": peak_ram,
            "peak_live_mapped_spill_bytes": peak_spill, "swap_peak_bytes": 0,
            "per_node_inclusive_profiles": profiles, "recorded_preserved_cpu_audit": "PASS",
            "fresh_cpu_audit_by_reporter": False, "shared_fixture_pruned": False,
            "repeat_qualified": False, "depth_six_qualified": False, "production_ready": False}


def utc(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value)
            is not None, "invalid UTC timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def compare(off, on):
    require(off["fusion"] == 0 and on["fusion"] == 1, "comparison must be fusion-off vs fusion-on")
    require(off["manifest_sha256"] != on["manifest_sha256"], "comparison reuses one trial")
    for key in ("external", "wallets", "height_and_caps"):
        require(off[key] == on[key], "comparison uses different public inputs/registry: " + key)
    for key in ("fusion-controller.py", "grouped-controller.py", "accounting.py", "handoff.json",
                "runner", "source-archive", "auditor"):
        require(off["pins"][key] == on["pins"][key], "comparison uses different implementation: " + key)
    for result in (off, on):
        require(result["production_ready"] is False and result["repeat_qualified"] is False
                and result["recorded_preserved_cpu_audit"] == "PASS", "unaccepted trial")
        require(utc(result["started_utc"]) <= utc(result["finished_utc"]), "negative trial interval")
    require(utc(off["finished_utc"]) <= utc(on["started_utc"]) or
            utc(on["finished_utc"]) <= utc(off["started_utc"]), "trials overlapped")
    changes = {}
    for key in ("recursive_command_ms", "final_merge_ms", "peak_worker_cgroup_bytes", "peak_live_mapped_spill_bytes"):
        require(type(off[key]) is int and type(on[key]) is int and off[key] > 0 and on[key] > 0,
                "invalid matched metric")
        changes[key] = {"off": off[key], "on": on[key], "reduction_percent": 100 * (off[key] - on[key]) / off[key]}
    return {"status": "ONE_MATCHED_FUSION_PAIR_NOT_REPEAT_QUALIFIED", "pairs": 1,
            "order": ["off", "on"] if utc(off["started_utc"]) < utc(on["started_utc"]) else ["on", "off"],
            "changes": changes, "off": off, "on": on,
            "repeat_qualified": False, "depth_six_qualified": False, "production_ready": False,
            "limitations": ["One matched research pair, not tail-latency qualification or an arrival simulation.",
                            "Final-merge time is not complete post-seal finalization time.",
                            "Inclusive profiler spans overlap; never add them into a total-time breakdown.",
                            "Mapped spill is not additional RSS; cgroup values are worker, not sampled aggregate peaks.",
                            "No independent governor/load/thermal normalization or GPU comparison.",
                            "Recorded CPU audits were rechecked; reporter did not run a fresh cryptographic audit.",
                            "Shared fixtures/registration wallet copies still require final pruning and replay."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="action", required=True)
    for action, labels in (("inspect", ("trial",)), ("compare", ("off", "on"))):
        sub = modes.add_parser(action)
        for label in labels:
            sub.add_argument("--" + label, type=Path, required=True)
            sub.add_argument("--" + label + "-sha256", required=True)
            sub.add_argument("--" + label + "-registration", type=Path, required=True)
            sub.add_argument("--" + label + "-registration-sha256", required=True)
    args = parser.parse_args()
    results = []
    for label in (("trial",) if args.action == "inspect" else ("off", "on")):
        paths = [getattr(args, name) for name in (label, label + "_registration")]
        require(all(not p.is_symlink() for p in paths), "symlink manifest refused")
        results.append(inspect(paths[0].resolve(), getattr(args, label + "_sha256"),
                               paths[1].resolve(), getattr(args, label + "_registration_sha256")))
    print(json.dumps(results[0] if args.action == "inspect" else compare(*results), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
