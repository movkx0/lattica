#!/usr/bin/env python3
"""One-shot bounded public-proof padding trial. No resume/retry or activation."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HELPER_SHA = "8bd17f9e084bb95119829b2c356e6f2968539e14011955d8ed623cb29c5e489e"
ROOT_FILES = ("height", "key.1", "key.2", "key.3", "node.6.0")
SOURCE_FILES = ("height", "key.1", "key.2", "key.3", "node.3.0")
EMPTIES = ("empty.3", "empty.4", "empty.5")
MERGES = ("node.4.0", "node.5.0", "node.6.0")
INNERS = ("node.3.0", *EMPTIES, *MERGES[:2])
ARTIFACTS = set(SOURCE_FILES) | set(EMPTIES) | set(MERGES)
GIB = 1 << 30

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def transition(name, before, after):
    added = set(EMPTIES if name == "empties" else MERGES if name == "merges" else ())
    removed = set(INNERS if name == "prune" else ())
    require(set(after) == (set(before) | added) - removed, "unexpected artifact membership transition")
    for key in set(before) - removed:
        require(after[key] == before[key], "existing artifact changed: " + key)

def telemetry(text, unit, name, support):
    accounting, durations, nodes, roots, audits, checks, prunes = [], [], [], [], [], [], []
    for line in text.splitlines():
        require(not line.startswith(("FAILED:", "padding_probe=FAIL", "grouped_artifact_audit=FAIL")),
                "stage reported failure")
        prefixes = ("stage_cgroup_accounting ", "padding_stage_elapsed_ms=", "padding_node_complete ",
                    "padding_input_check=PASS ", "padding_root_verification=PASS ",
                    "padding_inner_artifacts_removed=", "grouped_artifact_audit=PASS ")
        if not line.startswith(prefixes):
            continue
        fields = support.fields("record " + line if "=" in line.split()[0] else line)
        if line.startswith("stage_cgroup_accounting "):
            require(set(fields) == {"unit", "scope", "memory_peak", "memory_swap_peak", "memory_max",
                                    "memory_swap_max", "cpu_usage_usec"}, "accounting fields")
            require(fields.pop("unit") == unit and fields.pop("scope") == "exec_stop_post_snapshot",
                    "accounting unit/scope")
            record = {key: support.natural(value) for key, value in fields.items()}
            require(record["memory_max"] == 44 * GIB and record["memory_peak"] <= 44 * GIB
                    and record["memory_swap_max"] == record["memory_swap_peak"] == 0, "memory/swap gate")
            accounting.append(record)
        elif line.startswith("padding_stage_elapsed_ms="):
            require(set(fields) == {"padding_stage_elapsed_ms", "spill_peak_bytes"}, "duration fields")
            record = {key: support.natural(value) for key, value in fields.items()}
            require(record["spill_peak_bytes"] <= 120 * GIB, "spill gate")
            durations.append({"elapsed_ms": record["padding_stage_elapsed_ms"],
                              "spill_peak_bytes": record["spill_peak_bytes"]})
        elif line.startswith("padding_node_complete "):
            require(set(fields) == {"artifact", "elapsed_ms", "setups", "cache_hits", "production_ready"}
                    and fields.pop("production_ready") == "false", "node fields")
            record = {"artifact": fields.pop("artifact")}
            record.update({key: support.natural(value) for key, value in fields.items()})
            nodes.append(record)
        elif line.startswith("padding_input_check=PASS "):
            require(fields == {"padding_input_check": "PASS", "source_level": "3", "target_level": "6",
                               "count": "8", "production_ready": "false"}, "input marker")
            checks.append(True)
        elif line.startswith("padding_root_verification=PASS "):
            require(fields == {"padding_root_verification": "PASS", "level": "6", "count": "8",
                               "inner_proofs_loaded": "0", "full_count_qualified": "false",
                               "full_tree_security": "UNREVIEWED", "production_ready": "false"}, "root marker")
            roots.append(True)
        elif line.startswith("padding_inner_artifacts_removed="):
            require(fields == {"padding_inner_artifacts_removed": "6",
                               "pruning_does_not_approve_profile": "true"}, "pruning marker")
            prunes.append(True)
        elif line.startswith("grouped_artifact_audit=PASS "):
            size = support.natural(fields.pop("proof_bytes", ""))
            require(0 < size <= 2 << 20, "root envelope bound")
            require(fields == {"grouped_artifact_audit": "PASS", "kind": "level6-count8-padded",
                               "native_mutation_rejections": "38", "registry_policy_rejections": "4",
                               "expected_statement_policy_rejections": "2", "bundle_files": "5",
                               "inner_proofs_loaded": "0", "level6_qualified": "false",
                               "full_tree_security": "UNREVIEWED", "production_ready": "false"}, "audit marker")
            audits.append(size)
    require(len(accounting) == 1, "missing/duplicate accounting")
    require(len(durations) == (0 if name == "audit" else 1), "missing/duplicate duration")
    expected = EMPTIES if name == "empties" else MERGES if name == "merges" else ()
    require(tuple(n["artifact"] for n in nodes) == expected, "proof sequence")
    for i, node in enumerate(nodes):
        require(node["setups"] == 1 and node["cache_hits"] == i, "preprocessing reuse sequence")
    require(len(checks) == (1 if name == "check" else 0), "check marker count")
    require(len(roots) == (1 if name in ("root", "prune") else 0), "root marker count")
    require(len(prunes) == (1 if name == "prune" else 0), "prune marker count")
    require(len(audits) == (1 if name == "audit" else 0), "audit marker count")
    return {"accounting": accounting[0], "duration": durations[0] if durations else None,
            "nodes": nodes, "audit_proof_bytes": audits[0] if audits else None}

def load_support(path):
    require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == HELPER_SHA, "bounded helper pin mismatch")
    spec = importlib.util.spec_from_file_location("padding_bounded_support", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    # Process-local policy specialization. The frozen helper file is never edited.
    module.ARTIFACTS = ARTIFACTS
    module.ROOT_FILES = ROOT_FILES
    def invocation(config, name, action):
        if name == "audit":
            profile, chain, source, padded = config["external"]
            return [config["auditor"], "root-padded-eight", str(Path(config["evidence"]) / "root-only"),
                    profile, chain, padded]
        return [config["runner"], action, config["job"], *config["external"]]
    module.invocation = invocation
    return module

def verify_pins(config, support):
    required = {config[k] for k in ("helper", "accounting", "runner", "auditor", "calculator", "source_archive", "handoff")}
    require(required <= set(config["pins"]), "missing implementation/input pin")
    for path, expected in config["pins"].items():
        require(support.digest(Path(path)) == expected, "pin changed: " + path)

def source_snapshot(config, support):
    source = Path(config["source"])
    support.private_directory(source)
    require({p.name for p in source.iterdir()} == set(SOURCE_FILES), "source is not exact root-only bundle")
    actual = {}
    for name in SOURCE_FILES:
        data = support.regular_bytes(source / name)
        actual[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    require(actual == config["inputs"], "source input hash/size changed")
    return actual

def expected_statements(config):
    profile, chain, source_root, padded_root = config["external"]
    require(len(config["publics"]) == 8, "eight public statements required")
    for command, root, level in (("root-eight", source_root, 3), ("root-padded-eight", padded_root, 6)):
        result = subprocess.run([config["calculator"], command, profile, chain, *config["publics"]],
                                capture_output=True, text=True, timeout=30, check=True)
        require(len(result.stdout) < 2048 and not result.stderr, "unexpected calculator output")
        fields = dict(part.split("=", 1) for part in result.stdout.strip().split()[1:])
        require(result.stdout.startswith("grouped_expected_statement "), "calculator marker")
        require(fields == {"mode": "3", "level": str(level), "count": "8", "profile": profile,
                           "chain": chain, "root": root, "native_zig": "true", "proof_verified": "false",
                           "registry_approved": "false", "level6_qualified": "false",
                           "production_ready": "false"}, "native expected statement mismatch")

def run_stage(config, controller, name, action, state, support):
    evidence = Path(config["evidence"])
    state_path = evidence / "manifest.json"
    number = len(state["attempts"]) + 1
    unit = f"lattica-v2-grouped-{os.getpid()}-{number}.service"
    log = evidence / f"{number:02d}-{name}.log"
    record = {"name": name, "status": "attempted", "unit": unit, "log": log.name,
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    state["attempts"].append(record)
    support.save(state_path, state)  # Durable before any stage launch.
    started = time.monotonic()
    try:
        if name == "export":
            record["bundle"] = support.export_bundle(Path(config["job"]), evidence / "root-only")
        else:
            code = support.capture_stage(support.stage_command(config, controller, unit, name, action), log)
            require(code == 0, f"stage {name} failed; no retry permitted; inspect {log}")
            record["telemetry"] = telemetry(log.read_text(), unit, name, support)
            if name == "audit":
                require(record["telemetry"]["audit_proof_bytes"] ==
                        len(support.regular_bytes(evidence / "root-only" / "node.6.0")), "audit size mismatch")
            record["log_sha256"] = support.digest(log)
        record["wall_seconds"] = time.monotonic() - started
        after = support.snapshot(Path(config["job"]))
        transition(name, state["artifacts"], after)
        state["artifacts"] = after
        record["status"] = "complete"
        support.save(state_path, state)
    except BaseException as error:
        if name != "export":
            subprocess.run(["systemctl", "--user", "stop", unit], timeout=30, check=False)
        record["status"] = "failed_or_interrupted"
        record["error"] = str(error)
        state["status"] = "FAILED_OR_INTERRUPTED"
        support.save(state_path, state)
        raise

def interrupted(*_):
    raise InterruptedError("padding controller interrupted")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    config_path = Path(args.config)
    require(config_path.is_file() and not config_path.is_symlink()
            and config_path.stat().st_size <= 131072, "configuration type/size")
    config = json.loads(config_path.read_text())
    require(config["schema"] == 1 and len(config["external"]) == 4, "configuration schema")
    support = load_support(config["helper"])
    controller = support.require_controller()
    lease = support.shared_lease_path()
    support.private_directory(lease)
    with support.exclusive(lease / "exclusive.lock"):
        support.require_no_other_work(controller)
        verify_pins(config, support)
        source_snapshot(config, support)
        expected_statements(config)
        # All destinations must be absent. No resume, fallback or implicit retry.
        job, evidence = Path(config["job"]), Path(config["evidence"])
        job.mkdir(mode=0o700)
        (job / "scratch").mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
        for name in SOURCE_FILES:
            data = support.regular_bytes(Path(config["source"]) / name)
            with (job / name).open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
        support.sync_directory(job)
        state = {"schema": 1, "status": "RUNNING", "config": config, "controller": controller,
                 "controller_sha256": support.digest(Path(__file__)),
                 "configuration_sha256": support.digest(config_path),
                 "artifacts": support.snapshot(job), "attempts": [], "production_ready": False,
                 "full_count_qualified": False, "full_tree_security": "UNREVIEWED",
                 "limits": {"aggregate_ram_bytes": 48*GIB, "worker_ram_bytes": 44*GIB,
                            "controller_ram_bytes_at_most": 3*GIB, "swap_bytes": 0, "spill_bytes": 120*GIB}}
        require(state["artifacts"] == config["inputs"], "copied source mismatch")
        support.save(evidence / "manifest.json", state)
        try:
            for name, action in (("check", "check"), ("empties", "empty-all"), ("merges", "merge-all"),
                                 ("prune", "remove-inners"), ("root", "verify-root"),
                                 ("export", ""), ("audit", "")):
                verify_pins(config, support)
                source_snapshot(config, support)
                require(support.digest(config_path) == state["configuration_sha256"], "configuration changed")
                require(support.digest(Path(__file__)) == state["controller_sha256"], "controller changed")
                support.require_no_other_work(controller)
                require(support.snapshot(job) == state["artifacts"], "job changed between stages")
                support.verify_saved_evidence(state, evidence)
                run_stage(config, controller, name, action, state, support)
            require(set(state["artifacts"]) == set(ROOT_FILES), "final root-only membership")
            support.verify_saved_evidence(state, evidence)
            verify_pins(config, support)
            source_snapshot(config, support)
            state["status"] = "PADDED_COUNT8_ROOT_VERIFIED_RESEARCH_ONLY"
            state["root"] = state["artifacts"]["node.6.0"]
            state["recursive_command_ms"] = sum(a["telemetry"]["duration"]["elapsed_ms"]
                                                for a in state["attempts"] if a["name"] in ("empties", "merges"))
            support.save(evidence / "manifest.json", state)
            print(json.dumps({"status": state["status"], "production_ready": False}), flush=True)
        except BaseException as error:
            state["status"] = "FAILED_OR_INTERRUPTED"
            state["error"] = str(error)
            support.save(evidence / "manifest.json", state)
            raise

if __name__ == "__main__":
    main()
