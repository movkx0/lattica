#!/usr/bin/env python3
"""Read-only comparison of exact guarded seven-note CPU/GPU experiments.

Accepts two screening records or six alternating records. This never launches a
worker and never qualifies faithful RingCT, protocol redesign or adoption.
"""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

GIB = 1 << 30
RECIPE = "seven-distinct-public-fixtures-v1"
GPU = "fresh_gpu_required"
CPU = "fresh_cpu_required"
SCHEMA = "private-note-same-profile-cpu-gpu-comparison-v1"
SELECTORS = {
    GPU: "note_gpu::workflow::tests::gpu_seven_distinct_note_workflow_verifies_roundtrips_and_cleans_up",
    CPU: "note_gpu::workflow::tests::cpu_seven_distinct_note_workflow_verifies_roundtrips_and_cleans_up",
}
STAGES = set("public_values witness_trace preprocessing transform quotient randomness hiding commitment opening fri_fold fri_query final_polynomial scalar transcript grinding".split())
SWITCHES = "HASH RETAIN_TREES QUERY_GATHER RESIDENT_LDE OPENINGS QUOTIENT_LDE QUOTIENT_EVAL QUOTIENT_RESIDENT LOOKUP OPENING_EVAL FRI_RESIDENT PCS_DEVICE_ONLY WITNESS RANDOMNESS TRANSCRIPT FRI_FOLD".split()
# Independently reviewed C020/C021 proof/profile/report sources.
SOURCE_PINS = {
    "lattica-prover-p3/src/block_v2/legacy_wallet/note_admission/runtime.rs": "38979e2d34ff3db588982e003bc0b4b2336f72a93c1015d9055a9d578546d013",
    "lattica-prover-p3/src/config.rs": "d1fa5ce54a825032a1b67c06e2c5df8652c6e97429c182672678aab22a9fbcc9",
    "lattica-prover-p3/src/joinsplit_air.rs": "014016f51ed22a36d99ab4c733fadfd048d749a0863a761190cb50bf73242327",
    "research/pq-direct-spend/src/note_gpu/fixtures.rs": "dd93f90da5ca52f3697f297fe4ba055f4d36e93a8d2588fbb40a66d5af60a238",
    "research/pq-direct-spend/src/note_gpu/shape.rs": "31adc3feeaf9cf51d2002b93d0b4ab5a03b45c3533bd078c68984061d1e72fb6",
    "research/pq-direct-spend/src/note_gpu/verification.rs": "141e43b5d7c85e7f16005ed7e42f7f011f3a149c091faab288f0e33d77d3b0e6",
    "research/pq-direct-spend/src/note_gpu/verification/air.rs": "7450ca018be5deeae36cb841cf63b106273410eb5a59cbe0ac18412c4fce6cf3",
    "research/pq-direct-spend/src/note_gpu/workflow.rs": "26b79e511ec8ade81027800480ee898e331f1479ce0417c873450725098ca429",
    "research/pq-direct-spend/src/note_gpu/workflow/cpu.rs": "6e3c615d24963c81229b9a478af02187ad9b06d0e19cdd25bc5f517ac233d74e",
    "research/pq-direct-spend/src/note_gpu/workflow/cpu/plan.rs": "e727fd80f5ca4a7e2e0c9e12797d01f287a1410e1dd18b8dd8b6da0a8a42612d",
    "research/pq-direct-spend/src/note_gpu/workflow/tests.rs": "84ffcc763dc73afcc0252c948296f443a79947de5ba8c3cb40de9a0a89250426"
}
TIMES = "fixture_generation_ns public_preparation_ns native_dispatch_and_retirement_ns reported_native_proof_scope_ns canonical_handoff_decode_ns independent_cpu_verification_ns artifact_roundtrip_ns proof_payload_destruction_ns prepare_through_payload_cleanup_ns".split()
CPU_TIMES = "fresh_configuration_ns trace_generation_ns canonical_encoding_ns configuration_and_proof_cleanup_ns".split()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, name, low=0, high=(1 << 128) - 1):
    require(type(value) is int and low <= value <= high, "invalid " + name)
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid digest")
    return value


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def decode_json(raw):
    def bad_constant(_):
        raise ValueError("nonfinite JSON number")
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=bad_constant)


def read(path, limit):
    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    require(len(data) <= limit, "evidence exceeds reader limit")
    return data


def fields(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), "wrong fields: " + label)


def tokens(line):
    result = {}
    for item in line.split():
        require(item.count("=") == 1, "malformed report field")
        key, raw = item.split("=")
        require(key not in result and raw, "duplicate/empty report field")
        if raw in ("true", "false", "none"):
            value = {"true": True, "false": False, "none": None}[raw]
        elif re.fullmatch(r"0|[1-9][0-9]{0,38}", raw):
            value = int(raw)
        else:
            value = raw
        result[key] = value
    return result


def expected_environment(command, backend, environment):
    root = Path(command[0]).parents[4]
    require(root.is_absolute(), "worker executable must be absolute")
    base = {
        "PATH": "/home/access/code/lattica/.tools/rust-1.96.0/bin:/usr/bin:/bin",
        "HOME": "/home/access",
        "CARGO_HOME": str(root / ".tools/cargo-opencl"),
        "CARGO_TARGET_DIR": str(root / ".tools/target-opencl"),
        "CARGO_BUILD_JOBS": "2",
        "RAYON_NUM_THREADS": "8",
        "LATTICA_PROVING_REPORT": "1",
        "LATTICA_PROVING_POLICY": "cpu-required" if backend == CPU else "gpu-required",
    }
    if backend == GPU:
        base.update({"LATTICA_V2_GPU_" + name: "1" for name in SWITCHES})
        base.update({
            "LATTICA_V2_QUOTIENT_FUSION": "1",
            "LATTICA_V2_GPU_PUBLIC_HASH": "baseline",
            "LATTICA_V2_GPU_RETAINED_TREE_STORAGE": "device",
            "LATTICA_V2_GPU_PIPELINE": "0",
            "LATTICA_V2_GPU_MANAGED_BYTES": str(8 * GIB),
            "LATTICA_V2_GPU_CONTEXT_BYTES": str(4 * GIB),
            "LATTICA_V2_HOST_OUTPUT_BYTES": str(24 * GIB),
            "LATTICA_V2_GPU_DEVICE": "0",
            "LATTICA_GPU_DEVICE_UUID": environment.get("LATTICA_GPU_DEVICE_UUID"),
        })
        require(re.fullmatch(r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", base["LATTICA_GPU_DEVICE_UUID"] or ""), "invalid GPU identity")
    require(environment == base, "changed fixed worker environment")
    return base


def terminal(record):
    require(record.get("schema") == "pq-opencl-optimization-correctness-job-v2"
            and record.get("status") == "passed" and record.get("error") is None,
            "unsuccessful guard record")
    for key in ("launch", "source_inputs_unchanged", "executable_unchanged",
                "all_subprocesses_terminal_and_reaped", "service_stop_completed"):
        require(record.get(key) is True, "missing guard completion: " + key)
    state = record.get("terminal_state", {})
    for key, expected in {"Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
                          "MainPID": "0", "ControlPID": "0", "NRestarts": "0",
                          "MemorySwapMax": "0"}.items():
        require(state.get(key) == expected, "guard terminal mismatch: " + key)
    maximum = number(record.get("memory_max_bytes"), "process limit", 1, 47 * GIB)
    high = number(record.get("memory_high_bytes"), "process high limit", 1, maximum)
    require(state.get("MemoryMax") == str(maximum) and state.get("MemoryHigh") == str(high),
            "terminal memory limits changed")
    expected_quota = "200%" if record.get("profile") == "build" else "800%"
    require(record.get("cpu_quota") == expected_quota, "thread quota changed")
    peak = state.get("MemoryPeak", "")
    require(type(peak) is str and re.fullmatch(r"[1-9][0-9]*", peak), "missing cgroup memory peak")
    number(int(peak), "cgroup peak", 1, maximum)
    post = record.get("post_stop_state", {})
    require(post.get("MainPID") == post.get("ControlPID") == "0"
            and post.get("ControlGroup") == "" and post.get("ActiveState") == "inactive"
            and post.get("SubState") == "dead", "worker not fully stopped")
    require(record.get("process_admission", {}).get("conflicts") == [], "conflicting worker")
    source = record.get("input_sha256")
    require(type(source) is dict and 1 <= len(source) <= 8192, "missing source snapshot")
    for path, value in source.items():
        require(type(path) is str and path and not Path(path).is_absolute() and ".." not in Path(path).parts,
                "invalid source path")
        digest(value)
    return int(peak)


def guarded_record(path, backend):
    raw = read(path, 4 << 20)
    record = decode_json(raw)
    peak = terminal(record)
    require(record.get("profile") in ("full", "direct-full") and record.get("expect_tests") is True,
            "wrong workflow guard profile")
    for key in ("benchmark", "expect_result", "expect_direct_result", "comparison_baseline", "performance_qualified"):
        require(record.get(key) is False, "mixed guard acceptance mode: " + key)
    command = record.get("command", [])
    require(type(command) is list and len(command) == 6 and type(command[0]) is str,
            "wrong worker command")
    require(Path(command[0]).name.startswith("lattica_pq_direct_spend_research-")
            and command[1:] == [SELECTORS[backend], "--exact", "--ignored", "--test-threads=1", "--nocapture"],
            "wrong exact test selector")
    environment = record.get("environment", {})
    expected_environment(command, backend, environment)
    serialized = b"".join((key + "=" + environment[key] + "\0").encode() for key in sorted(environment))
    mode_fields = {"note_startup_environment", "note_cpu_environment", "owned_runtime_environment"}
    require(mode_fields <= set(record), "missing backend environment mode fields")
    receipt_field = "note_cpu_environment" if backend == CPU else "note_startup_environment"
    require(all(record[key] is None for key in mode_fields - {receipt_field}),
            "mixed note/owned-runtime environment modes")
    startup = record[receipt_field]
    fields(startup, ["schema", "entry_count", "serialized_bytes", "sha256_sorted_name_equals_value_nul",
                     "requires_env_clear_before_exec", "requires_immutable_environment_after_exec",
                     "physical_identity_verified", "complete_external_admission", "dispatch_authority"],
           "backend startup receipt")
    expected_startup_schema = "private-note-cpu-workflow-environment-v1" if backend == CPU else "private-note-startup-environment-v1"
    require(startup.get("schema") == expected_startup_schema
            and startup.get("sha256_sorted_name_equals_value_nul") == sha(serialized)
            and startup.get("entry_count") == len(environment)
            and startup.get("serialized_bytes") == len(serialized)
            and startup.get("requires_env_clear_before_exec") is True
            and startup.get("requires_immutable_environment_after_exec") is True
            and startup.get("physical_identity_verified") is False
            and startup.get("complete_external_admission") is False
            and startup.get("dispatch_authority") is False,
            "startup environment receipt differs")
    service = record.get("service_command", [])
    require(service.count("/usr/bin/env") == 1, "missing unique env-clear launch")
    env_index = service.index("/usr/bin/env")
    require(service[:4] == ["/usr/bin/systemd-run", "--user", "--quiet", "--unit=" + record["unit"]],
            "wrong service launcher")
    properties = {}
    for argument in service[4:env_index]:
        require(argument.startswith("--property=") and argument.count("=") >= 2, "unknown service option")
        key, value = argument.removeprefix("--property=").split("=", 1)
        require(key not in properties, "duplicate service property")
        properties[key] = value
    expected_properties = {
        "Type": "exec", "RemainAfterExit": "yes", "Restart": "no",
        "MemoryMax": str(record["memory_max_bytes"]), "MemoryHigh": str(record["memory_high_bytes"]),
        "MemorySwapMax": "0", "CPUQuota": "800%", "TasksMax": "256",
        "RuntimeMaxSec": str(number(record.get("runtime_seconds"), "guard runtime", 1)),
        "TimeoutStopSec": "10", "KillMode": "control-group",
        "WorkingDirectory": str(Path(command[0]).parents[4]),
        "StandardOutput": "append:" + record["raw_log"], "StandardError": "inherit",
    }
    require(properties == expected_properties, "actual service properties differ")
    tail = service[env_index + 1:]
    expected_pairs = [key + "=" + value for key, value in environment.items()]
    require(tail == ["-i", *expected_pairs, *command], "actual launch environment/command differs")
    require(SOURCE_PINS and all(record["input_sha256"].get(key) == value for key, value in SOURCE_PINS.items()),
            "unreviewed note proof/profile/report sources")
    provenance = record.get("executable_provenance", {})
    require(provenance.get("path") == command[0], "executable provenance path differs")
    digest(provenance.get("sha256"))
    build_raw = read(provenance["build_record"], 4 << 20)
    require(sha(build_raw) == provenance.get("build_record_sha256"), "changed build record")
    build = decode_json(build_raw)
    terminal(build)
    require(build.get("profile") == "build" and build.get("input_sha256") == record["input_sha256"]
            and build.get("built_artifact_sha256", {}).get(command[0]) == provenance["sha256"],
            "build/source/executable provenance differs")
    build_log = read(build["raw_log"], 64 << 20)
    require(sha(build_log) == build.get("raw_log_sha256"), "changed build log")
    log = read(record["raw_log"], 64 << 20)
    require(sha(log) == record.get("raw_log_sha256"), "changed workflow log")
    started, finished = (datetime.fromisoformat(record[key]) for key in ("started_utc", "finished_utc"))
    require(started.utcoffset() is not None and finished > started, "invalid run interval")
    evidence = {
        "record_path": str(path), "record_sha256": sha(raw),
        "raw_log_path": record["raw_log"], "raw_log_sha256": sha(log),
        "build_record_path": provenance["build_record"], "build_record_sha256": sha(build_raw),
        "build_log_path": build["raw_log"], "build_log_sha256": sha(build_log),
        "executable_path": command[0], "executable_sha256": provenance["sha256"],
        "source_snapshot_sha256": sha(json.dumps(record["input_sha256"], sort_keys=True, separators=(",", ":")).encode()),
        "environment": environment, "environment_sha256": sha(serialized),
        "started_utc": record["started_utc"], "finished_utc": record["finished_utc"],
        "guard_wall_seconds": record["wall_seconds"], "guarded_cgroup_host_peak_bytes": peak,
        "memory_max_bytes": record["memory_max_bytes"], "memory_high_bytes": record["memory_high_bytes"],
        "guard_profile": record["profile"],
    }
    return log.decode("utf-8", errors="strict"), evidence


def audit_log(content, backend):
    case_tag = "private_note_cpu_seven_case" if backend == CPU else "private_note_seven_case"
    workflow_tag = "private_note_cpu_seven_workflow" if backend == CPU else "private_note_seven_workflow"
    allowed = {case_tag, workflow_tag, workflow_tag + "_terminal", "private_note_seven_case_identity",
               "private_note_case_managed_memory", "private_note_workflow_managed_memory"}
    collected = {key: [] for key in allowed}
    stage_reports, devices, test_results = [], [], []
    for line in content.splitlines():
        prefix = "test " + SELECTORS[backend] + " ... "
        if line.startswith(prefix):
            line = line[len(prefix):]
        if line.startswith("private_note_"):
            tag, rest = line.split(" ", 1)
            require(tag in allowed, "wrong/unknown workflow marker")
            collected[tag].append(tokens(rest))
        elif line.startswith("proving_stage_report "):
            stage_reports.append(decode_json(line.removeprefix("proving_stage_report ")))
        elif line.startswith("bounded_gpu_identity "):
            devices.append(decode_json(line.removeprefix("bounded_gpu_identity ")))
        elif line.startswith("test result:"):
            test_results.append(line)
    require(len(test_results) == 1 and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s", test_results[0]), "wrong test terminal result")
    for tag in (case_tag, "private_note_seven_case_identity", "private_note_case_managed_memory"):
        require(len(collected[tag]) == 7, "missing/duplicate seven-case records")
        for item in collected[tag]:
            number(item.get("ordinal"), "case ordinal", 0, 6)
        require([item.get("ordinal") for item in collected[tag]] == list(range(7)), "reordered/missing cases")
    for tag in (workflow_tag, workflow_tag + "_terminal", "private_note_workflow_managed_memory"):
        require(len(collected[tag]) == 1, "missing/duplicate workflow record")
    cases = collected[case_tag]
    for case, identity, memory in zip(cases, collected["private_note_seven_case_identity"], collected["private_note_case_managed_memory"]):
        common = {"native_proofs": 1, "recursive_proofs": 0, "active_rows": 2560, "padded_rows": 4096,
                  "fresh_public_preparation": True, "proof_payloads_destroyed": True}
        common.update({"runtime_retired": True} if backend == GPU else {"cpu_required": True, "gpu_work_performed": False})
        fields(case, ["ordinal", "native_proof_bytes", *TIMES, *common, *(CPU_TIMES if backend == CPU else [])], "case")
        require(all(type(case[key]) is type(value) and case[key] == value for key, value in common.items()), "case count/profile/cleanup mismatch")
        number(case["ordinal"], "case ordinal", 0, 6)
        number(case["native_proof_bytes"], "proof bytes", 1, 64 << 20)
        for key in TIMES + (CPU_TIMES if backend == CPU else []):
            number(case[key], key, 1)
        require(case["reported_native_proof_scope_ns"] <= case["native_dispatch_and_retirement_ns"], "nested proof interval exceeds dispatch")
        disjoint = ["public_preparation_ns", "native_dispatch_and_retirement_ns", "canonical_handoff_decode_ns",
                    "independent_cpu_verification_ns", "artifact_roundtrip_ns", "proof_payload_destruction_ns"]
        require(sum(case[key] for key in disjoint) <= case["prepare_through_payload_cleanup_ns"], "case subintervals exceed complete case")
        if backend == CPU:
            require(sum(case[key] for key in CPU_TIMES) + case["reported_native_proof_scope_ns"] <= case["native_dispatch_and_retirement_ns"], "CPU subintervals exceed dispatch")
        fields(identity, ["backend", "ordinal", "fixture_recipe", "public_statement_digest", "canonical_packet_hash"], "identity")
        require(identity["backend"] == backend and identity["fixture_recipe"] == RECIPE, "case identity profile differs")
        fields(memory, ["backend", "ordinal", "managed_device_peak_bytes", "actual_process_device_peak_bytes"], "case memory")
        require(memory["backend"] == backend and memory["actual_process_device_peak_bytes"] == "external_guard_only", "memory scope differs")
        if backend == CPU:
            require(memory["managed_device_peak_bytes"] is None, "CPU claims GPU peak")
        else:
            number(memory["managed_device_peak_bytes"], "managed device peak", 1, 8 * GIB)
        case.update(public_statement_digest=digest(identity["public_statement_digest"]),
                    canonical_packet_hash=digest(identity["canonical_packet_hash"]),
                    managed_device_peak_bytes=memory["managed_device_peak_bytes"])
    require(len({case["public_statement_digest"] for case in cases}) == 7, "duplicate public statements")
    require(len({case["canonical_packet_hash"] for case in cases}) == 7, "duplicate proof packets")
    workflow = collected[workflow_tag][0]
    expected = {"cases": 7, "distinct_statements": 7, "distinct_nullifiers": 14, "native_proofs": 7,
                "recursive_proofs": 0, "independent_cpu_verifications": 14, "canonical_roundtrips": 7,
                "actual_memory_source": "external_guard", "cpu_baseline_qualified": backend == CPU,
                "complete_ringct_workflow": False, "production_acceptance": False}
    if backend == CPU:
        expected.update(native_gpu_runtimes=0, fresh_cpu_proof_configurations=7)
    timing = ["fixture_generation_and_distinctness_ns", "complete_note_research_workflow_ns",
              "host_payload_reservation_peak_bytes", "report_retained_bytes"]
    fields(workflow, [*expected, *timing], "workflow")
    require(all(type(workflow[key]) is type(value) and workflow[key] == value for key, value in expected.items()), "workflow profile/count mismatch")
    for key in timing:
        number(workflow[key], key, 1)
    require(sum(case["fixture_generation_ns"] for case in cases) <= workflow["fixture_generation_and_distinctness_ns"], "generation timing mismatch")
    require(workflow["fixture_generation_and_distinctness_ns"] + sum(case["prepare_through_payload_cleanup_ns"] for case in cases) <= workflow["complete_note_research_workflow_ns"], "summed case interval exceeds workflow")
    require(workflow["report_retained_bytes"] <= workflow["host_payload_reservation_peak_bytes"] <= 32 * GIB, "source host allowance exceeded")
    ending = {"original_quota_released": True, "all_proof_payloads_destroyed": True, "complete_ringct_workflow": False}
    ending.update({"all_native_runtimes_retired": True} if backend == GPU else {"all_cpu_configurations_destroyed": True, "gpu_work_performed": False})
    observed_ending = collected[workflow_tag + "_terminal"][0]
    fields(observed_ending, ending, "terminal cleanup")
    require(all(observed_ending[key] is value for key, value in ending.items()), "incomplete original owner cleanup")
    memory = collected["private_note_workflow_managed_memory"][0]
    fields(memory, ["backend", "managed_device_peak_bytes", "source", "actual_process_device_peak_bytes"], "workflow memory")
    peak = max(case["managed_device_peak_bytes"] for case in cases) if backend == GPU else None
    if backend == GPU:
        number(memory["managed_device_peak_bytes"], "workflow managed peak", 1, 8 * GIB)
    require(memory == {"backend": backend, "managed_device_peak_bytes": peak,
                       "source": "exact_retired_engine_max" if backend == GPU else "no_gpu_runtime",
                       "actual_process_device_peak_bytes": "external_guard_only"}, "managed peak provenance differs")
    if backend == GPU:
        require(len(stage_reports) == len(devices) == 7, "missing native GPU reports/identities")
        require(all(device == devices[0] for device in devices) and devices[0].get("name") == "NVIDIA GeForce RTX 5080", "changed physical GPU")
        for report, case in zip(stage_reports, cases):
            require(report.get("schema") == "lattica-proving-stages-v1"
                    and report.get("entry_point") == "private_note_gpu" and report.get("policy") == "gpu_required"
                    and report.get("succeeded") is True and report.get("stage_coverage_complete") is True
                    and report.get("completion_rejected") is False and report.get("observation_errors") == 0
                    and report.get("elapsed_ns") == case["reported_native_proof_scope_ns"]
                    and report.get("components") == [], "native GPU report mismatch")
            number(report.get("observation_errors"), "stage observation errors", 0, 0)
            capabilities = report.get("capabilities", {})
            require(capabilities.get("scope") == "proof_request" and capabilities.get("profile") == "legacy_quadratic"
                    and capabilities.get("max_log_fri_arity") == 4, "native proof profile changed")
            number(capabilities.get("max_log_fri_arity"), "FRI arity", 4, 4)
            declared = capabilities.get("stages", [])
            require(len(declared) == len(STAGES) and {item.get("stage") for item in declared} == STAGES
                    and all(item.get("backend") == "open_cl" for item in declared), "native stage capability differs")
            observations = report.get("observations", [])
            require(type(observations) is list and len(observations) == len(STAGES) + 1
                    and {item.get("stage") for item in observations} == STAGES | {"serialization"}, "native stage observation set differs")
            for item in observations:
                calls = number(item.get("calls"), "stage calls", 1)
                number(item.get("completed_calls"), "completed calls", calls, calls)
                if item["stage"] == "serialization":
                    require(item.get("backend") == "cpu" and item.get("device_calls") == 0, "serialization scope differs")
                else:
                    require(item.get("backend") == "open_cl", "native CPU fallback")
                    number(item.get("device_calls"), "device calls", calls, calls)
                    number(item.get("device_ns"), "device observation", 1)
    else:
        require(not stage_reports and not devices, "CPU workflow entered GPU/report wrapper")
    return {"backend": backend, "fixture_recipe": RECIPE, "workflow": workflow, "cases": cases,
            "managed_device_peak_bytes": peak, "actual_process_device_peak_bytes": None,
            "device_identity": devices[0] if devices else None}


def compare(runs):
    require(len(runs) in (2, 6), "need one screen pair or three alternating pairs")
    first = runs[0]
    reference_ids = [case["public_statement_digest"] for case in first["cases"]]
    seen_packets, seen_records, environments = set(), set(), {}
    for index, run in enumerate(runs):
        require(run["backend"] in (CPU, GPU) and (index == 0 or run["backend"] != runs[index - 1]["backend"]), "runs do not alternate")
        require([case["public_statement_digest"] for case in run["cases"]] == reference_ids, "exact seven-case mismatch")
        evidence = run["evidence"]
        wall = evidence["guard_wall_seconds"]
        require(type(wall) in (float, int) and math.isfinite(wall) and wall > 0
                and run["workflow"]["complete_note_research_workflow_ns"] <= wall * 1_000_000_000,
                "complete workflow exceeds guard wall interval")
        for key in ("source_snapshot_sha256", "executable_path", "executable_sha256", "build_record_sha256",
                    "memory_max_bytes", "memory_high_bytes", "guard_profile"):
            require(evidence[key] == first["evidence"][key], "matched provenance/resource mismatch: " + key)
        require(evidence["record_sha256"] not in seen_records, "reused guard record")
        seen_records.add(evidence["record_sha256"])
        if index:
            require(datetime.fromisoformat(runs[index - 1]["evidence"]["finished_utc"]) <= datetime.fromisoformat(evidence["started_utc"]), "reordered or overlapping workers")
        if run["backend"] in environments:
            require(evidence["environment"] == environments[run["backend"]], "changed repetition environment")
        environments[run["backend"]] = evidence["environment"]
        for case in run["cases"]:
            require(case["canonical_packet_hash"] not in seen_packets, "reused proof packet")
            seen_packets.add(case["canonical_packet_hash"])
    cpu_runs = [run for run in runs if run["backend"] == CPU]
    gpu_runs = [run for run in runs if run["backend"] == GPU]
    require(len(cpu_runs) == len(gpu_runs), "unmatched repetition counts")
    for run in gpu_runs:
        require(run["device_identity"] == gpu_runs[0]["device_identity"]
                and run["device_identity"]["uuid"] == run["evidence"]["environment"]["LATTICA_GPU_DEVICE_UUID"], "physical GPU differs from guard or other run")
    def med(group, selector):
        return statistics.median(selector(run) for run in group)
    cpu_complete = med(cpu_runs, lambda run: run["workflow"]["complete_note_research_workflow_ns"])
    gpu_complete = med(gpu_runs, lambda run: run["workflow"]["complete_note_research_workflow_ns"])
    cases = []
    for ordinal, identity in enumerate(reference_ids):
        cpu_ns = med(cpu_runs, lambda run: run["cases"][ordinal]["prepare_through_payload_cleanup_ns"])
        gpu_ns = med(gpu_runs, lambda run: run["cases"][ordinal]["prepare_through_payload_cleanup_ns"])
        cases.append({"ordinal": ordinal, "public_statement_digest": identity,
                      "cpu_median_prepare_through_payload_cleanup_ns": cpu_ns,
                      "gpu_median_prepare_through_payload_cleanup_ns": gpu_ns,
                      "cpu_median_stage_ns": {key: med(cpu_runs, lambda run: run["cases"][ordinal][key]) for key in TIMES + CPU_TIMES},
                      "gpu_median_stage_ns": {key: med(gpu_runs, lambda run: run["cases"][ordinal][key]) for key in TIMES},
                      "cpu_over_gpu_case_ratio": cpu_ns / gpu_ns})
    return {"schema": SCHEMA, "comparison": "same_private_note_construction_cpu_versus_gpu",
            "stage": "single_screen_pair" if len(runs) == 2 else "three_alternating_pairs",
            "repetitions_per_backend": len(cpu_runs), "fixture_recipe": RECIPE,
            "complete_workflow_boundary": "fixture_admission_generation_through_proof_fixture_session_cleanup",
            "cpu_median_complete_note_research_workflow_ns": cpu_complete,
            "gpu_median_complete_note_research_workflow_ns": gpu_complete,
            "cpu_over_gpu_complete_workflow_ratio": cpu_complete / gpu_complete,
            "case_medians": cases, "runs": runs,
            "actual_process_device_peak_bytes": None,
            "complete_ringct_workflow": False, "qualified_faithful_ringct_workflow": False,
            "protocol_redesign_speedup_qualified": False, "research_adoption_qualified": False,
            "production_acceptance": False, "performance_promoted": False,
            "limitations": [
                "Both backends prove the same standalone private-note relation; this compares execution backends only.",
                "No faithful RingCT complete workflow or recursive aggregation is measured.",
                "No ratio here satisfies protocol-redesign adoption criteria or replaces cryptographic review.",
                "Source reservation, exact Engine managed peak and external cgroup host peak are distinct observations.",
                "Total process device peak is unavailable. Guard/process wall time is separate from the complete research interval.",
                "Mutation qualification remains separate from these workflow timings.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path, nargs="+")
    args = parser.parse_args()
    require(len(args.records) in (2, 6), "supply two or six chronological guard records")
    runs = []
    for path in args.records:
        preview = decode_json(read(path, 4 << 20))
        command = preview.get("command")
        require(type(command) is list and len(command) == 6, "malformed guard command")
        selector = command[1]
        backend = next((key for key, value in SELECTORS.items() if value == selector), None)
        require(backend is not None, "unknown workflow selector")
        content, evidence = guarded_record(path, backend)
        run = audit_log(content, backend)
        run["evidence"] = evidence
        runs.append(run)
    print(json.dumps(compare(runs), indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
