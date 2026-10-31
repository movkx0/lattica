#!/usr/bin/env python3
"""Prepare isolated N3/N4 recursive-batch acceptance; default never writes or launches.

Execution requires a successful, terminal frozen two-graph baseline and a
separately coordinated resource window. Complete byte-identical cache admission
supports deterministic replay through the frozen load-or-prove API; that API is
not replay-only. Any observed proof generation or changed replay file rejects
acceptance. The new batch merges are the only intended fresh proofs.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
import uuid

# Importing the shared prepared builder must not create __pycache__ in dry mode.
sys.dont_write_bytecode = True
import frozen_build as frozen

ROOT = frozen.ROOT
PACKAGE = frozen.PACKAGE
CLIENT = PACKAGE / "tools/accept_recursive_batch.rs"
SELF = Path(__file__).resolve()
BASELINE = frozen.BASELINE
SOURCE_ID = "dcb76008a97d7f98c483134482ec65769d5d1fcc0ca858c8b6f7fd43939150a2"
GRAPH_PROFILE = "4bc6d06ac109a269904637b564628cb5c9542a9c70e685f06276747295ba24aa"
FIXTURE0_SHA = "b78c234c604cdbc2e44925715f6c900a739e24408223df60ab6a9b1846d5898a"
SETTINGS = {
    "LATTICA_SPEND_ALGEBRA_BATCH": "64",
    "LATTICA_SPEND_NTT_BATCH": "32",
    "LATTICA_SPEND_MUL_BATCH": "32",
    "LATTICA_SPEND_NATIVE_GIB": "32",
    "LATTICA_SPEND_OUTER_GIB": "48",
    "LATTICA_SPEND_AES_SERIAL_BATCH": "64",
    "LATTICA_SPEND_SHAKE_SERIAL_BATCH": "32",
    "LATTICA_SPEND_COMPOSITE_LAYOUT": "branches",
}
EXTRA_ARTIFACTS = {
    "serde_json": (
        ".tools/target-pq/release/deps/libserde_json-2fdf57a3e2cbb58a.rlib",
        "24b024cb7bfa7f27b383097cbb47abdbe4cc38701e3fd45b33a73d8cfaed0259",
    ),
    "postcard": (
        ".tools/target-pq/release/deps/libpostcard-2617d6fce2e6bbac.rlib",
        "26c32c8fa4bb6309458a290e1d3db44b9d8889254e1f059946e98ae072496ac6",
    ),
}
RESERVE = 16 << 30
CACHE_NAMESPACES = {"sources", "algebra", "crypto", "auxiliary", "outer"}
require = frozen.require
read_json = frozen.read_json
local = frozen.local
sha = frozen.sha


def metadata(path):
    path = local(str(path))
    require(path.is_file(), f"missing regular file: {path}")
    digests = (hashlib.sha256(), hashlib.sha3_256())
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            size += len(block)
            for digest in digests:
                digest.update(block)
    require(path.stat().st_size == size, f"file size changed during read: {path}")
    return {"bytes": size, "sha256": digests[0].hexdigest(),
            "sha3_256": digests[1].hexdigest()}


def tree_metadata(directory):
    directory = local(str(directory))
    require(directory.is_dir(), f"missing directory: {directory}")
    result = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), f"symlink in preserved tree: {path}")
        if path.is_dir():
            continue
        require(path.is_file(), f"non-regular preserved artifact: {path}")
        result[str(path.relative_to(directory))] = metadata(path)
    return result


def basic(entries):
    return {name: {key: row[key] for key in ("bytes", "sha256")}
            for name, row in entries.items()}


def bytes_hex(value):
    require(isinstance(value, list) and len(value) == 32
            and all(type(v) is int and 0 <= v <= 255 for v in value),
            "expected canonical 32-byte array")
    return bytes(value).hex()


def fixture_metadata(path):
    result = metadata(path)
    require(0 < result["bytes"] <= 16 << 20, "fixture exceeds bounded archive size")
    value = read_json(path)
    require(set(value) == {"schema", "context", "setup_seed", "statement", "proof"}
            and type(value["schema"]) is int and value["schema"] == 1,
            "unexpected native fixture schema")
    require(value["context"] == [71] * 32 and value["setup_seed"] == [29] * 32,
            "fixture context/setup differs from chosen baseline")
    for field in ("statement", "proof"):
        require(isinstance(value[field], list) and value[field]
                and all(type(byte) is int and 0 <= byte <= 255 for byte in value[field]),
                f"invalid fixture byte array: {field}")
    return result, value


def cache_inventory(directory, expected):
    entries = tree_metadata(directory)
    require(basic(entries) == expected, "complete baseline cache inventory differs")
    present = set()
    for name, row in entries.items():
        parts = Path(name).parts
        require(len(parts) == 2 and parts[0] in CACHE_NAMESPACES
                and re.fullmatch(r"[0-9a-f]{64}\.json", parts[1]),
                f"unsupported complete cache entry: {name}")
        present.add(parts[0])
        require(0 < row["bytes"] <= 64 << 20, f"cache entry exceeds bound: {name}")
        value = read_json(local(str(directory / name)))
        require(isinstance(value, list) and type(value[0]) is int and value[0] == 1,
                f"unsupported cache schema: {name}")
        key = parts[1][:-5]
        if parts[0] == "outer":
            require(len(value) == 5 and bytes_hex(value[1]) == SOURCE_ID
                    and bytes_hex(value[2]) == key, f"outer source/key mismatch: {name}")
        elif parts[0] == "sources":
            require(len(value) == 4 and bytes_hex(value[1]) == key,
                    f"source cache key mismatch: {name}")
        else:
            require(len(value) == 4 and value[1] == key,
                    f"native cache key mismatch: {name}")
    require(present == CACHE_NAMESPACES, "complete cache omits a required namespace")
    return entries


def baseline_admission():
    value = read_json(local(str(BASELINE)))
    require(value.get("schema") == "pq-ringct-two-complete-graphs-acceptance-v1"
            and value.get("status") == "passed"
            and value.get("all_subprocesses_terminal_and_reaped")
            and value.get("two_complete_graphs_and_actual_ordered_pair_accepted"),
            "successful terminal and reaped complete baseline required")
    require(value["measurement"]["exit_code"] == 0 and value["measurement"]["error"] is None
            and not value["post_run_errors"], "baseline execution was incomplete")
    for flag in (
        "pinned_inputs_unchanged", "original_qualification_cache_unchanged",
        "prior_and_seeded_job_entries_unchanged", "fixture0_unchanged",
        "existing_fixture1_unchanged", "fixture1_has_distinct_statement",
        "pair_artifact_bytes_hash_and_reverification_record_match",
    ):
        require(value.get(flag) is True, f"baseline preservation/acceptance failed: {flag}")
    require(value["source_audit_before_launch"]["passed"]
            and value["source_audit_after_completion"]["passed"],
            "baseline frozen audits failed")
    require(value["compiled_source_identity"] == SOURCE_ID
            and value["records"]["COMPILED_SOURCE_IDENTITY"] == [SOURCE_ID],
            "baseline compiled source identity differs")
    require(all(value["environment"].get(key) == setting for key, setting in SETTINGS.items())
            and value["environment"].get("RAYON_NUM_THREADS") == "8",
            "baseline chosen91 configuration differs")
    require(set(value["environment"]) == set(SETTINGS) | {
        "LATTICA_SPEND_JOB_DIRECTORY", "RAYON_NUM_THREADS"},
        "baseline includes unqualified configuration overrides")
    complete = value["records"].get("COMPLETE_GRAPH_PROOF", [])
    require(len(complete) == 2 and [row["index"] for row in complete] == [0, 1]
            and all(row["verified"] and row["registered_leaves"] == 91
                    and not row["ledger_binding"] for row in complete),
            "both exact complete graph proofs must be accepted")
    pair = value["records"].get("COMPLETE_GRAPH_PAIR_VERIFIED", [])
    require(len(pair) == 1 and pair[0]["actual_complete_graph_proofs"] == 2
            and pair[0]["actual_aggregate_stark"]
            and pair[0]["order_context_root_mutations_rejected"]
            and not pair[0]["ledger_binding"], "baseline pair acceptance is incomplete")
    pinned = dict(value["pinned_inputs_sha256"])
    pinned[str(BASELINE.relative_to(ROOT))] = sha(BASELINE)
    log = local(value["raw_log"])
    require(sha(log) == value["raw_log_sha256"], "baseline raw log changed")
    pinned[str(log.relative_to(ROOT))] = value["raw_log_sha256"]
    binary = local(value["binary"])
    require(sha(binary) == value["binary_sha256"], "baseline binary changed")
    pinned[str(binary.relative_to(ROOT))] = value["binary_sha256"]
    require(all(sha(local(name)) == digest for name, digest in pinned.items()),
            "baseline prerequisite/support artifact changed")
    job = local(value["job_directory"])
    require(value["environment"]["LATTICA_SPEND_JOB_DIRECTORY"] == str(job),
            "baseline job directory differs from its execution")
    require(job.is_relative_to(ROOT / ".tools/pq-child-cache"),
            "baseline job is outside managed cache directory")
    fixtures = []
    statements = []
    expected_hashes = [FIXTURE0_SHA, value["fixture1_sha256_after"]]
    for index in range(2):
        path = local(str(job / f"fixture-{index}.json"))
        entry, fixture = fixture_metadata(path)
        require(entry["sha256"] == expected_hashes[index], f"baseline fixture{index} changed")
        fixtures.append({"index": index, "path": str(path), **entry})
        statements.append(fixture["statement"])
    require(statements[0] != statements[1], "baseline fixtures are not distinct statements")
    entries = cache_inventory(job / "cache", value["job_cache_after_completion"])
    artifacts = value["records"].get("COMPLETE_GRAPH_PAIR_ARTIFACT", [])
    require(len(artifacts) == 1, "baseline pair artifact missing")
    artifact = artifacts[0]
    artifact_path = local(artifact["path"])
    require(artifact_path.is_relative_to(job / "artifacts")
            and artifact["codec"] == "diagnostic-postcard-public-and-proof-tuple"
            and artifact["compiled_source_identity"] == SOURCE_ID
            and artifact["decoded_complete_payload_reverified"]
            and not artifact["includes_trusted_registered_key"]
            and not artifact["includes_ledger_body"], "invalid baseline proof artifact contract")
    artifact_meta = metadata(artifact_path)
    require(artifact_meta["bytes"] == artifact["bytes"] > 0
            and artifact_meta["sha3_256"] == artifact["sha3_256"],
            "baseline proof artifact bytes/hash differ")
    pinned[str(artifact_path.relative_to(ROOT))] = artifact_meta["sha256"]
    return {
        "baseline": {"path": str(BASELINE), **metadata(BASELINE)},
        "job": job, "fixtures": fixtures, "cache_entries": entries,
        "original_job_inventory": tree_metadata(job), "pinned_inputs": pinned,
    }


def own_inputs():
    own = frozen.own_inputs()
    for path in (SELF, CLIENT):
        own[str(path.relative_to(ROOT))] = sha(local(str(path)))
    return own


def build_inputs(batch_label):
    pinned, artifacts, links = frozen.frozen_inputs()
    own = own_inputs()
    for name, (path, digest) in EXTRA_ARTIFACTS.items():
        file = local(path)
        require(sha(file) == digest, f"frozen acceptance dependency changed: {name}")
        # Its exact filename must have been emitted by the pinned Cargo run.
        cargo = local(frozen.read_json(frozen.BUILD)["runs"][0]["log"])
        matches = []
        for line in cargo.read_text().splitlines():
            if line.startswith("{"):
                item = json.loads(line)
                if item.get("reason") == "compiler-artifact" and item["target"]["name"] == name:
                    if str(file) in item["filenames"]:
                        matches.append(item)
        require(len(matches) == 1 and matches[0]["profile"]["opt_level"] == "3"
                and not matches[0]["profile"]["debuginfo"], "unqualified acceptance dependency")
        artifacts[name] = file
        pinned[path] = digest
    core_own = frozen.own_inputs()
    for stage in ("build", "check"):
        path = local(f".tools/pq-logs/pq-ringct-batch-{batch_label}-{stage}.json")
        record = read_json(path)
        require(record["schema"] == "pq-ringct-batch-frozen-build-v1"
                and record["stage"] == stage and record["status"] == "passed"
                and record["all_subprocesses_terminal_and_reaped"]
                and record["error"] is None and record["post_audit_error"] is None
                and record["own_inputs"] == core_own
                and record["pinned_inputs"] == frozen.frozen_inputs()[0],
                f"matching qualified batch library {stage} required")
        pinned[str(path.relative_to(ROOT))] = sha(path)
        for run in record["runs"]:
            require(run["terminal_and_reaped"] and run["exit_code"] == 0 and run["error"] is None,
                    "batch library subprocess was incomplete")
            log = local(run["log"])
            require(sha(log) == run["log_sha256"], "batch library log changed")
            pinned[str(log.relative_to(ROOT))] = run["log_sha256"]
    lib = local(f".tools/pq-binaries/libpq_ringct_batch_{batch_label.replace('-', '_')}.rlib")
    tests = local(f".tools/pq-binaries/pq-ringct-batch-{batch_label}-tests")
    require(sha(lib) == record["library_sha256"] and sha(tests) == record["tests_sha256"],
            "qualified batch library/test binary changed")
    pinned[str(lib.relative_to(ROOT))] = sha(lib)
    pinned[str(tests.relative_to(ROOT))] = sha(tests)
    artifacts["lattica_pq_ringct_batch"] = lib
    # Binds this external package/client and the precise frozen direct-link state.
    identity = hashlib.sha3_256(json.dumps(
        {"schema": "pq-ringct-batch-acceptance-build-identity-v1",
         "own_inputs": own, "pinned_inputs": pinned},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return own, pinned, artifacts, links, identity


def copy_exact(source, destination, expected):
    source = local(str(source))
    destination = local(str(destination))
    require(not destination.exists(), f"refuse copied artifact overwrite: {destination}")
    require(metadata(source) == expected, f"copy source changed: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(".copy-" + uuid.uuid4().hex)
    try:
        with source.open("rb") as inp, temporary.open("xb") as out:
            shutil.copyfileobj(inp, out, 1 << 20)
            out.flush()
            os.fsync(out.fileno())
        require(metadata(temporary) == expected and metadata(source) == expected,
                f"copy/source changed during copy: {source}")
        os.link(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_json_new(path, value):
    with local(str(path)).open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


class StageInterrupted(RuntimeError):
    pass


def interrupted(signum, _frame):
    raise StageInterrupted(f"received signal {signum}")


def guarded(command, log, stage, source_identity):
    guard, minimum, threads = ((8 << 30, 10 << 30, "2") if stage == "build"
                               else (48 << 30, 50 << 30, "8"))
    available = frozen.available()
    require(available >= minimum, f"fresh memory admission failed for {stage}")
    require(shutil.disk_usage(ROOT).free >= RESERVE, "16 GiB disk reserve failed")
    require(not log.exists(), "refuse raw-log overwrite")
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("LATTICA_", "CARGO_PROFILE_", "CARGO_BUILD_"))
           and key not in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                           "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTDOC"}}
    env.update(RAYON_NUM_THREADS=threads, CARGO_MANIFEST_DIR=str(PACKAGE),
               CARGO_PKG_NAME="lattica-pq-ringct-batch", CARGO_PKG_VERSION="0.1.0",
               LATTICA_BATCH_SOURCE_IDENTITY=source_identity)
    if stage == "prove":
        env.update(SETTINGS, LATTICA_PROVING_REPORT="1", LATTICA_PROVING_POLICY="compatible")
    process, usage, error = None, None, None
    started = time.perf_counter()

    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (guard, guard))

    def reap():
        while True:
            try:
                _, status, used = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                return used
            except InterruptedError:
                continue
    try:
        with log.open("x") as output:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True, preexec_fn=limits)
            try:
                usage = reap()
            except BaseException:
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
        "command": command, "stage": stage, "log": str(log.relative_to(ROOT)),
        "log_sha256": sha(log) if log.exists() else None,
        "exit_code": process.returncode if process is not None else None,
        "terminal_and_reaped": process is None or process.returncode is not None,
        "error": error, "wall_seconds": time.perf_counter() - started,
        "cpu_user_seconds": usage.ru_utime if usage else None,
        "cpu_system_seconds": usage.ru_stime if usage else None,
        "max_rss_kib": usage.ru_maxrss if usage else None,
        "address_space_limit_bytes": guard, "fresh_memavailable_required_bytes": minimum,
        "admission_available_bytes": available, "rayon_threads": int(threads),
    }


def replay_observations(content):
    """Reject fresh proof observations between each client's replay markers."""
    events, errors, active, completed = [], [], None, []
    source_hits = {}
    reports = []
    for line in content.splitlines():
        if line.startswith("BATCH_ACCEPTANCE "):
            event = json.loads(line[len("BATCH_ACCEPTANCE "):])
            require(isinstance(event, dict) and isinstance(event.get("event"), str),
                    "malformed acceptance event")
            events.append(event)
            if event["event"] == "replay_begin":
                require(active is None and event["fixture_index"] == len(completed),
                        "noncanonical replay marker order")
                active = event["fixture_index"]
                source_hits[active] = []
            elif event["event"] == "replay_end":
                require(active == event["fixture_index"] and event["cache_unchanged"],
                        "replay completion is missing or cache changed")
                require(sorted(source_hits[active]) == ["private", "statement"],
                        "replay did not report both existing source proof hits")
                completed.append(active)
                active = None
        elif line.startswith("proving_stage_report "):
            report = json.loads(line[len("proving_stage_report "):])
            require(report["schema"] == "lattica-proving-stages-v1", "unexpected proving report")
            reports.append(report)
            if active is not None and report["entry_point"] != "block_v2_preprocessing":
                errors.append(f"fresh proving during fixture {active}: {report['entry_point']}")
            if not report["succeeded"] or report["completion_rejected"]:
                errors.append("unsuccessful/rejected proving stage")
        if active is not None:
            if "SOURCE_CACHE " in line:
                match = re.fullmatch(r"SOURCE_CACHE (statement|private) (hit|generated)", line)
                require(match is not None, "unknown source cache observation")
                if match.group(2) == "generated":
                    errors.append(f"native source proof generated during fixture {active}")
                else:
                    source_hits[active].append(match.group(1))
            if "cache_hit=false" in line:
                errors.append(f"cache miss during fixture {active}")
    require(active is None and completed == [0, 1], "both complete replay spans required")
    require(not errors, "; ".join(errors))
    return events, reports


def validate_recursive_witness_checks(events, case, result):
    """Require actual private-opening assertion checks plus valid parent proofs."""
    selected = [event for event in events if event.get("case") == case]
    phase = f"complete-n{case}"
    audits = [row for row in selected if row["event"] == "recursive_child_witness_checks"]
    require(len(audits) == 1 and audits[0]["phase"] == phase
            and audits[0]["scope"] == "emitted aggregate-child verifier assertion rejection",
            "missing or incorrectly scoped recursive witness diagnostics")
    checks = audits[0]["checks"]
    require(type(checks) is list and len(checks) == case - 2
            and result["recursive_witness_check_count"] == len(checks)
            and result["recursive_witness_checks"] == checks
            and result["recursive_witness_check_scope"] == audits[0]["scope"]
            and result["case_proving_seconds_includes_recursive_witness_checks"] is True
            and result["negative_stark_proofs_generated"] == 0,
            "recursive witness coverage or timing scope differs from the case result")
    for index, check in enumerate(checks):
        require(type(check["child_index"]) is int and check["child_index"] == index
                and check["child_span"] == [2 * index, 2]
                and all(type(word) is int for word in check["child_span"])
                and check["mutated_field"] == "trace_local[0].basis[0]"
                and check["execution_error"] == "Unsatisfied"
                and check["same_compiled_program"] is True
                and check["public_values_unchanged"] is True
                and check["original_witness_restored"] is True
                and check["valid_parent_positive_control"] is True
                and check["negative_stark_proof_generated"] is False,
                "actual recursive child opening was not rejected by unchanged assertions")
        require(type(check["principal_buffer_bound_bytes"]) is int
                and type(check["evaluation_budget_bytes"]) is int
                and 0 < check["principal_buffer_bound_bytes"]
                <= check["evaluation_budget_bytes"] == 1 << 30,
                "recursive witness evaluation lacks its bounded-buffer admission")
        seconds = check["evaluation_seconds"]
        require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0,
                "invalid recursive witness evaluation timing")
    seconds = result["recursive_witness_check_seconds"]
    require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0
            and math.isclose(seconds, sum(row["evaluation_seconds"] for row in checks),
                             rel_tol=1e-12, abs_tol=1e-9)
            and seconds <= result["case_proving_seconds"],
            "recursive witness evaluation time is missing from case measurement")
    ordered = []
    for event in ("batch_node_compiled", "artifact", "recursive_child_witness_checks",
                  "batch_node_proved"):
        rows = [row for row in selected if row["event"] == event and row.get("phase") == phase]
        require(len(rows) == 1, "recursive witness diagnostic lacks its valid parent control")
        ordered.append(events.index(rows[0]))
    require(ordered == sorted(set(ordered)),
            "recursive witness success was not reported after valid parent artifact verification")
    completed = [row for row in selected if row["event"] == "case_proving_complete"]
    require(len(completed) == 1 and events.index(completed[0]) > ordered[-1]
            and completed[0]["recursive_witness_check_count"] == len(checks)
            and completed[0]["recursive_witness_check_seconds"] == seconds
            and completed[0]["case_proving_seconds_includes_recursive_witness_checks"] is True,
            "case completion omits recursive witness diagnostics")


def validate_run(log, job_directory, source_identity):
    # Final event/artifact fields are additionally checked by the runner; a
    # subprocess exit code alone can never establish recursive acceptance.
    events, reports = replay_observations(log.read_text())
    require(not any(event["event"] == "error" for event in events), "client emitted an error")
    fixtures = [event for event in events if event["event"] == "fixture_verified"]
    require(len(fixtures) == 2 and [row["fixture_index"] for row in fixtures] == [0, 1]
            and all(row["native_verified"] is True for row in fixtures),
            "both original fixtures must be native-verified")
    first_replay = next(i for i, row in enumerate(events) if row["event"] == "replay_begin")
    require(all(events.index(row) < first_replay for row in fixtures),
            "fixtures must be native-verified before either replay")
    final = [event for event in events if event["event"] == "result"]
    require(len(final) == 2 and [row["case"] for row in final] == [3, 4],
            "both complete batch results required")
    witness_audits = [row for row in events if row["event"] == "recursive_child_witness_checks"]
    require([row.get("case") for row in witness_audits] == [3, 4],
            "exactly one recursive witness diagnostic event per final merge is required")
    dropped = [event for event in events if event["event"] == "original_graph_children_dropped"]
    require(len(dropped) == 1 and dropped[0]["actual_complete_graph_children"] == 2
            and dropped[0]["pending_final_cases"] == [3, 4]
            and dropped[0]["prepared_proving_state_retained"] is False,
            "original complete graph children must be dropped before final acceptance")
    drop_index = events.index(dropped[0])
    require(all(events.index(row) > drop_index for row in final)
            and all(events.index(row) < drop_index for row in events
                    if row["event"] in ("batch_node_proved", "recursive_child_witness_checks")),
            "final verification did not follow all merges and original-child drop")
    cases = []
    artifact_paths = set()
    for case, result in zip((3, 4), final):
        selected = [event for event in events if event.get("case") == case]
        require(result["ordered_fixture_indices"] == [0, 1, 0, 1][:case]
                and result["source_fingerprint"] == SOURCE_ID
                and result["graph_plan_label"] == GRAPH_PROFILE
                and result["batch_source_identity"] == source_identity
                and result["complete_batch_verified"] is True
                and result["actual_merge_count"] == case - 1
                and result["aggregate_child_count"] == case - 2
                and result["original_children_dropped_before_final_verification"] is True
                and result["decoded_complete_payload_reverified"] is True
                and result["expected_statement_reference_count"] == case
                and result["artifact_size_is_not_transaction_or_block_size"] is True
                and result["full_public_statements_ring_data_and_ledger_availability_external"] is True
                and result["ledger_binding"] is False, "incomplete aggregate-child batch result")
        require(result["isolated_case_rss_measured"] is False
                and all(type(result[field]) in (int, float)
                        and math.isfinite(result[field]) and result[field] >= 0
                        for field in ("case_proving_seconds", "case_final_verification_seconds",
                                      "single_plan_verification_seconds")),
                "invalid case timing or isolated-memory claim")
        require(result["single_plan_verification_seconds"]
                <= result["case_final_verification_seconds"]
                and result["single_plan_verification_scope"] == {
                    "method": "Plan::verify_expected", "call_count": 1,
                    "cryptographic_verification_calls": 1,
                    "includes_expected_ordered_root_computation": True,
                    "prebuilt_trusted_key_and_plan": True,
                    "precomputed_original_statement_digests": True,
                    "proof_already_decoded": True,
                    "process_state": "previously exercised; caches not reset",
                    "measurement": "wall_clock_seconds", "cpu_seconds_measured": False,
                    "cold_start_measured": False, "production_latency_qualified": False,
                }, "invalid single-call verification timing scope")
        require(result["aggregate_plus_graph_verified"] is (case == 3)
                and result["aggregate_plus_aggregate_verified"] is (case == 4)
                and result["canonical_odd_tail_verified"] is (case == 3)
                and result["partial_coverage_rejection_verified"] is True,
                "required recursive child topology was not verified")
        negatives = [event for event in selected if event["event"] == "negative_results"]
        validate_recursive_witness_checks(events, case, result)
        require(len(negatives) == 1 and negatives[0]["all_public_fields_rejected"] == 25
                and negatives[0]["noncanonical_digest_words_rejected"] == 4,
                "public-field/digest negative coverage differs")
        for name in (
            "opening_mutation_rejected", "reordered_a_b_rejected", "omitted_original_rejected",
            "changed_duplicated_original_rejected", "extra_original_rejected",
            "wrong_context_rejected", "wrong_profile_rejected", "trailing_artifact_bytes_rejected",
        ):
            require(negatives[0][name] is True, f"negative case not rejected: {name}")
        premerge = [event for event in selected if event["event"] == "negative"]
        require(len(premerge) == 4 and {row["name"] for row in premerge} == {
            "reordered_positions", "omitted_position", "duplicated_position", "scope_and_graph_bindings"}
            and all(row["rejected"] is True for row in premerge), "premerge negative coverage differs")
        scoped = next(row for row in premerge if row["name"] == "scope_and_graph_bindings")
        require(all(scoped[name] is True for name in (
            "separate_scope", "swapped_graph_proof", "wrong_graph_statement", "wrong_graph_profile")),
            "graph/scope binding negatives incomplete")
        partial = [event for event in selected if event["event"] == "partial_coverage"]
        expected_partial = [[0, 2]] if case == 3 else [[0, 2], [2, 2]]
        require([row["span"] for row in partial] == expected_partial
                and all(row["registered_partial_verified"] is True
                        and row["complete_original_coverage_rejected"] is True for row in partial),
                "valid partial proof was not rejected as complete")
        nodes = [event for event in selected if event["event"] == "batch_node_proved"]
        expected_spans = [[0, 2], [0, 3]] if case == 3 else [[0, 2], [2, 2], [0, 4]]
        require([row["span"] for row in nodes] == expected_spans
                and sum(row["aggregate_children"] for row in nodes) == case - 2
                and all(row["actual_stark_proof"] is True and row["cache_hit"] is False
                        and row["prepared_proving_state_dropped"] is True
                        and row["total"] == case for row in nodes),
                "actual recursive merge nodes differ")
        artifacts = [event for event in selected if event["event"] == "artifact"]
        require(len(artifacts) == case - 1, "all actual merge proof artifacts required")
        preserved = []
        for artifact in artifacts:
            path = local(artifact["path"])
            require(path.is_relative_to(job_directory / "artifacts" / f"case-{case}")
                    and artifact["codec"] == "diagnostic-postcard-public-and-proof-tuple"
                    and artifact["decoded_payload_reverified"] is True
                    and artifact["includes_trusted_registered_key"] is False
                    and artifact["includes_original_statements"] is False
                    and artifact["includes_ledger_body"] is False
                    and artifact["batch_source_identity"] == source_identity,
                    "invalid batch artifact contract")
            entry = metadata(path)
            require(entry["bytes"] == artifact["bytes"] > 0
                    and entry["sha3_256"] == artifact["sha3_256"], "batch artifact bytes/hash mismatch")
            require(path not in artifact_paths, "duplicate artifact path")
            artifact_paths.add(path)
            preserved.append({"phase": artifact["phase"], "path": str(path.relative_to(ROOT)), **entry})
        complete_artifact = [row for row in preserved if row["phase"] == f"complete-n{case}"]
        require(len(complete_artifact) == 1
                and local(result["final_artifact_path"]) == local(complete_artifact[0]["path"])
                and result["final_artifact_bytes"] == complete_artifact[0]["bytes"]
                and result["final_artifact_sha3_256"] == complete_artifact[0]["sha3_256"],
                "final acceptance artifact differs from proved artifact")
        cases.append({"case": case, "passed": True, "result": result, "artifacts": preserved,
                      "isolated_case_cpu_or_peak_rss_measured": False})
    complete_run = [event for event in events if event["event"] == "run_result"]
    require(len(complete_run) == 1 and complete_run[0]["cases"] == [3, 4]
            and complete_run[0]["actual_complete_graph_replays"] == 2
            and complete_run[0]["actual_merge_count"] == 5
            and complete_run[0]["recursive_witness_check_count"] == 3
            and complete_run[0]["negative_stark_proofs_generated"] == 0
            and complete_run[0]["both_complete_batches_verified"] is True
            and complete_run[0]["copied_cache_and_fixtures_unchanged"] is True
            and complete_run[0]["original_children_dropped_before_final_verification"] is True
            and complete_run[0]["isolated_case_rss_measured"] is False
            and complete_run[0]["ledger_binding"] is False
            and complete_run[0]["source_fingerprint"] == SOURCE_ID
            and complete_run[0]["graph_plan_label"] == GRAPH_PROFILE
            and complete_run[0]["batch_source_identity"] == source_identity
            and complete_run[0]["case_results"] == [
                {key: value for key, value in row.items() if key != "event"} for row in final
            ],
            "single-recovery complete N3/N4 run result missing")
    fresh = [report for report in reports if report["entry_point"] == "block_v2_registered_program"]
    require(len(fresh) == 5, "fresh batch proving count differs from five merge nodes")
    actual_artifacts = {local(str(job_directory / "artifacts" / name))
                        for name in tree_metadata(job_directory / "artifacts")}
    require(actual_artifacts == artifact_paths, "unexpected or missing batch proof artifact files")
    return {"events": events, "proving_reports": reports, "cases": cases,
            "run_result": complete_run[0],
            "replay_audit": {
                "complete_replay_spans": 2,
                "observed_native_generation_or_cache_misses": 0,
                "outer_proving_reports_during_replay": 0,
                "source_proof_cache_hits": 4,
                "strict_replay_only_api": False,
            },
            "fresh_batch_proofs": len(fresh), "recursive_child_witness_checks": 3,
            "negative_stark_proofs_generated": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("build", "prove"), required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--batch-label", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--exclusive-window-note")
    args = parser.parse_args()
    for label in (args.label, args.batch_label):
        require(re.fullmatch(r"[A-Za-z0-9_-]+", label) is not None, "invalid label")
    admitted = baseline_admission()
    own, pinned, artifacts, links, identity = build_inputs(args.batch_label)
    pinned.update(admitted["pinned_inputs"])
    stem = "pq-ringct-batch-accept-" + args.label
    binary = local(f".tools/pq-binaries/{stem}")
    records = {stage: local(f".tools/pq-logs/{stem}-{stage}.json") for stage in ("build", "prove")}
    require(not records[args.stage].exists(), "refuse existing acceptance-stage record")
    job = local(f".tools/pq-child-cache/{stem}")
    require(not job.is_relative_to(admitted["job"]) and not admitted["job"].is_relative_to(job),
            "acceptance and original baseline jobs must be separate")
    if args.stage == "build":
        require(not binary.exists(), "refuse acceptance binary overwrite")
        command = [str(frozen.RUSTC), "--edition=2021", "--crate-name", "accept_recursive_batch",
                   str(CLIENT), "-C", "opt-level=3", "-C", "debuginfo=0",
                   "-L", "dependency=" + str(ROOT / ".tools/target-pq/release/deps")]
        for name, path in sorted(artifacts.items()):
            command.extend(("--extern", name + "=" + str(path)))
        for path in links:
            command.extend(("-L", path))
        commands = [command + ["-o", str(binary)]]
    else:
        prior = read_json(records["build"])
        require(prior["status"] == "passed" and prior["all_subprocesses_terminal_and_reaped"]
                and prior["own_inputs"] == own and prior["pinned_inputs"] == pinned
                and prior["batch_source_identity"] == identity,
                "matching successful acceptance build required")
        require(sha(binary) == prior["binary_sha256"], "acceptance binary changed")
        pinned[str(binary.relative_to(ROOT))] = sha(binary)
        pinned[str(records["build"].relative_to(ROOT))] = sha(records["build"])
        require(not job.exists(), "use a fresh acceptance job; prior evidence is preserved")
        commands = [[str(binary), str(job / "admission.json"), str(job / "artifacts"), "both"]]
    copy_bytes = (sum(row["bytes"] for row in admitted["cache_entries"].values())
                  + sum(row["bytes"] for row in admitted["fixtures"]))
    if not args.execute:
        print(json.dumps({
            "prepared_only": True, "writes": False, "launch": False, "stage": args.stage,
            "commands": commands, "batch_source_identity": identity,
            "complete_baseline_cache_entries": len(admitted["cache_entries"]),
            "planned_prove_copy_bytes": copy_bytes, "cases": [3, 4],
            "replay_only_api": False,
        }, indent=2))
        return
    require(args.exclusive_window_note and args.exclusive_window_note.strip(),
            "explicit coordinator window note required")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    record = {
        "schema": "pq-ringct-batch-recursive-acceptance-v1", "stage": args.stage,
        "status": "prepared", "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "own_inputs": own, "pinned_inputs": pinned, "batch_source_identity": identity,
        "baseline": admitted["baseline"], "original_job_directory": str(admitted["job"].relative_to(ROOT)),
        "original_job_inventory": admitted["original_job_inventory"],
        "exclusive_window_note": args.exclusive_window_note, "runs": [], "cases": [],
        "job_directory": str(job.relative_to(ROOT)), "replay_only_api": False,
        "admission_basis": "Successful complete frozen baseline and identical fixtures, source, settings and exact full copied cache inventory.",
        "scope": "N3/N4 ordered repeated standalone relations using two preserved original fixtures; no ledger acceptance or compute-savings claim.",
    }
    write_json_new(records[args.stage], record)
    error, post_errors = None, []
    copied = None
    try:
        if args.stage == "prove":
            require(shutil.disk_usage(ROOT).free >= RESERVE + copy_bytes,
                    "insufficient disk for isolated replay copy plus16GiB reserve")
            job.mkdir(parents=True)
            cache = job / "cache"
            fixtures = []
            for item in admitted["fixtures"]:
                destination = job / f"fixture-{item['index']}.json"
                entry = {key: item[key] for key in ("bytes", "sha256", "sha3_256")}
                copy_exact(Path(item["path"]), destination, entry)
                fixtures.append({"index": item["index"], "path": str(destination), **entry})
            for name, entry in admitted["cache_entries"].items():
                copy_exact(admitted["job"] / "cache" / name, cache / name, entry)
            require(tree_metadata(cache) == admitted["cache_entries"], "copied cache inventory differs")
            admission = {
                "schema": "pq-ringct-batch-replay-admission-v1", "cases": [3, 4],
                "ordered_fixture_indices": {"3": [0, 1, 0], "4": [0, 1, 0, 1]},
                "baseline": admitted["baseline"], "source_fingerprint": SOURCE_ID,
                "graph_plan_label": GRAPH_PROFILE, "batch_source_identity": identity,
                "fixtures": fixtures, "cache_directory": str(cache),
                "cache_entries": admitted["cache_entries"], "settings": SETTINGS,
                "output_directory": str(job / "artifacts"),
            }
            admission_path = job / "admission.json"
            write_json_new(admission_path, admission)
            copied = {"admission": metadata(admission_path), "fixtures": fixtures,
                      "cache_entries": tree_metadata(cache)}
            record["copied_admission"] = copied
            require(shutil.disk_usage(ROOT).free >= RESERVE, "post-copy disk reserve failed")
        require(all(sha(local(name)) == digest for name, digest in pinned.items()), "pinned input changed before launch")
        require(own_inputs() == own, "batch/client source changed before launch")
        require(tree_metadata(admitted["job"]) == admitted["original_job_inventory"],
                "original baseline job changed before launch")
        for index, command in enumerate(commands):
            if args.stage == "prove":
                require(tree_metadata(job / "cache") == admitted["cache_entries"],
                        "copied replay cache changed before launch")
            run = guarded(command, local(f".tools/pq-logs/{stem}-{args.stage}-{index}.log"),
                          args.stage, identity)
            run["cases"] = [3, 4] if args.stage == "prove" else []
            record["runs"].append(run)
            require(run["exit_code"] == 0 and run["error"] is None, "acceptance subprocess failed")
            if args.stage == "prove":
                require(tree_metadata(job / "cache") == admitted["cache_entries"],
                        "replay cache changed or gained entries")
                for item in copied["fixtures"]:
                    require(metadata(Path(item["path"])) == {key: item[key] for key in ("bytes", "sha256", "sha3_256")},
                            "copied fixture changed")
                require(metadata(job / "admission.json") == copied["admission"],
                        "copied admission changed")
                result = validate_run(local(run["log"]), job, identity)
                result["replay_audit"]["copied_cache_unchanged_after_run"] = True
                record.update(result)
                record["whole_run_measurement"] = run
                record["isolated_case_cpu_or_peak_rss_measured"] = False
        record["binary_sha256"] = sha(binary)
    except BaseException as caught:
        error = repr(caught)
    try:
        require(build_inputs(args.batch_label)[0] == own, "batch/client source changed")
        require(all(sha(local(name)) == digest for name, digest in pinned.items()), "pinned inputs changed")
        require(tree_metadata(admitted["job"]) == admitted["original_job_inventory"],
                "original baseline cache/fixture/artifact changed")
        if copied is not None:
            require(tree_metadata(job / "cache") == copied["cache_entries"],
                    "copied replay cache changed")
            require(metadata(job / "admission.json") == copied["admission"],
                    "copied admission changed")
            for item in copied["fixtures"]:
                require(metadata(Path(item["path"])) == {key: item[key] for key in ("bytes", "sha256", "sha3_256")},
                        "copied fixture changed")
        record["preservation_audits_passed"] = True
    except BaseException as caught:
        post_errors.append(repr(caught))
        record["preservation_audits_passed"] = False
    try:
        record["output_job_inventory_after_completion"] = tree_metadata(job) if job.exists() else {}
        record["binary_sha256_after_completion"] = sha(binary) if binary.exists() else None
    except BaseException as caught:
        post_errors.append("output inventory: " + repr(caught))
    record["error"], record["post_audit_errors"] = error, post_errors
    record["all_subprocesses_terminal_and_reaped"] = all(row["terminal_and_reaped"] for row in record["runs"])
    passed = error is None and not post_errors and record["all_subprocesses_terminal_and_reaped"]
    if args.stage == "prove":
        passed = passed and [row["case"] for row in record["cases"]] == [3, 4]
    record["status"] = "passed" if passed else "failed_or_incomplete"
    record["complete_n3_n4_batch_proofs_accepted"] = bool(passed and args.stage == "prove")
    temporary = records[args.stage].with_name(records[args.stage].name + ".tmp-" + uuid.uuid4().hex)
    write_json_new(temporary, record)
    os.replace(temporary, records[args.stage])
    print(json.dumps({"status": record["status"], "record": str(records[args.stage].relative_to(ROOT)),
                      "error": error, "post_audit_errors": post_errors}))
    require(passed, "acceptance stage failed; evidence preserved")


if __name__ == "__main__":
    main()
