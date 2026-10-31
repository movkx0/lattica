#!/usr/bin/env python3
"""Read-only audit of one exact guarded seven-case direct-ring research screen.

This replays bounded evidence, not cryptographic verification or a new benchmark.
It never launches a process, changes acceptance, or qualifies a RingCT speedup.
"""
import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import uuid

from note_workflow_report import decode_json, digest, fields, number, read, require, sha, terminal

ROOT = Path(__file__).resolve().parents[3]


def helper(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


direct = helper("direct_ring_screen_native_audit", "research/pq-ringct/tools/opencl_direct_spend_audit.py")
public_hash = helper("direct_ring_screen_public_hash", "research/pq-ringct/tools/public_hash_evidence.py")
GIB = 1 << 30
SELECTOR = "ring_screen::tests::gpu_seven_distinct_ring_workflows_verify_roundtrips_and_retire"
PROFILE = "lattica/research/ring-direct-v1/n10/in2/out2/bits52"
SCHEMA = "lattica-research-direct-ring-seven-case-screen-v1"
CASE_SCHEMA = "lattica-research-direct-ring-seven-case-workflow-v1"
TIMING = "preflight through seven retired proof/codec/verifier owners and per-case reports; excludes final summary serialization and process launch"
SWITCHES = "HASH RETAIN_TREES QUERY_GATHER RESIDENT_LDE OPENINGS QUOTIENT_LDE QUOTIENT_EVAL QUOTIENT_RESIDENT LOOKUP OPENING_EVAL FRI_RESIDENT PCS_DEVICE_ONLY WITNESS RANDOMNESS TRANSCRIPT FRI_FOLD".split()
# Reviewed direct relation/compiler/artifact and C023-r2 screen sources.
SOURCE_PINS = {
    "lattica-prover-p3/src/block_v2/profile.rs": "3c303e53f2ca79c7049f799ea710fedfec0656318af5c09150c243d2dd5be6cf",
    "research/pq-direct-spend/src/lib.rs": "c709dbef2d11552bb2815b3fbbc186fc9fad6192c70fbfdc3cd2883ea4523246",
    "research/pq-direct-spend/src/ring.rs": "d1d6be97a815cc57bafa7eb3269e29d95d68b77f08c1119a7dad4bf89e6dca5d",
    "research/pq-direct-spend/src/ring_circuit.rs": "17c5761641db93194e37901391975db992e9686201c753f1ac64aea3a8181118",
    "research/pq-direct-spend/src/ring_circuit/artifact.rs": "0fbddea98c4663c4028a6c6968bca25a5df3ab15d3ef8fd902e39848d90d897a",
    "research/pq-direct-spend/src/ring_circuit/artifact/header.rs": "94ed308eeae41b41bcda8702c0b9bb8ffca87f8df8f53241990b48c85e1ca643",
    "research/pq-direct-spend/src/ring_circuit/artifact/tests.rs": "7d39db70f76b468d61af34dbd28f9ecd8e0bac1665d98086977dac68da92ca95",
    "research/pq-direct-spend/src/ring_circuit/proving.rs": "e05c00bec2f02d8256cd7ab979346e575c935976f8895cfae116515f6bd9b968",
    "research/pq-direct-spend/src/ring_circuit/proving/lifecycle.rs": "f5a0c31845bf85b08add62d31ec468ae9b5c5626160414eceaf7347c6d5a3a2f",
    "research/pq-direct-spend/src/ring_circuit/proving/metadata.rs": "7669d9e198fc62756edf1dc7d0a20f80b4465320d392176ae9315893931d8797",
    "research/pq-direct-spend/src/ring_circuit/proving/receipts.rs": "9c2908fb9892b0fb168c887673f4779635c9bebb1f19b594f087467bb5915415",
    "research/pq-direct-spend/src/ring_circuit/proving/tests.rs": "a8f330edbe3c722f437a980b1324fbd40b8a86999cc2ac345db490fb15b99c1c",
    "research/pq-direct-spend/src/ring_circuit/verification.rs": "389f36d9e04da31633ab3af16d3c4eac15c47a8360f53a91d0cf4ecf9f3c3f4e",
    "research/pq-direct-spend/src/ring_circuit/verification/lifecycle.rs": "96b28a470ae9cad90f2d936cd9e978b99a176532ee8535cba03aa1e8b98557d4",
    "research/pq-direct-spend/src/ring_circuit/verification/lifecycle/tests.rs": "64ae76b9b67891982b357e40079da863496d0da40831efaebe175555df8db7dc",
    "research/pq-direct-spend/src/ring_circuit/verification/reconstruction.rs": "cd0d36d4370f17da22a7ac3fd4ed28a8161ad2bed75f54011df3abc412fda120",
    "research/pq-direct-spend/src/ring_circuit/verification/tests.rs": "e5c40963575a0c78478a22700663100b4d1f164ecd9d2d15c7294453a4d1069e",
    "research/pq-direct-spend/src/ring_circuit_budget.rs": "9a05dd6251dabb288aaa9b12849c9606134899d6dac46de01c5eb3690f2ddd7e",
    "research/pq-direct-spend/src/ring_circuit_evaluation.rs": "2fb9188f6761d7e0fe5fc8e8901d51065e7a732fb3034354ee3d919aef0fb5ba",
    "research/pq-direct-spend/src/ring_circuit_limits.rs": "6bf1ded70fd0efe009835f5aee3802758dfe55f0f192de0a0e2be7c4eab39486",
    "research/pq-direct-spend/src/ring_circuit_linear.rs": "3215bdc5ce06f615bec27720c21b0c28ba5fb3032ffc616f773988109538b0fa",
    "research/pq-direct-spend/src/ring_circuit_linear_audit.rs": "5a60f63751377ed5c31c4457c61ed5cf7bf06f5e50a295dab9a602d50eeea4a9",
    "research/pq-direct-spend/src/ring_circuit_mont.rs": "16a7c14b92092edd27b4bea5b22cb090d2331fd3c1fa9f3456ea98f3fe4c19e5",
    "research/pq-direct-spend/src/ring_circuit_ntt.rs": "234eef332f9638ca2a4fab141d31663fefb31be3dacc98cbd4c4f82ce96565cd",
    "research/pq-direct-spend/src/ring_circuit_ntt_audit.rs": "8c34cb0f40b217b74dfb1e30044dab0b94ae6a873b740d39e395dff67cfd1b3e",
    "research/pq-direct-spend/src/ring_circuit_ranges.rs": "17ea3f0dd384ec31035565203d5bed19ecbc31f5dddbc74ca9510f641ba93acb",
    "research/pq-direct-spend/src/ring_circuit_ranges_audit.rs": "cdddce460d84afa0b4d28c1fabb2024ce293fea49bfb95d5960a0580f8f9a031",
    "research/pq-direct-spend/src/ring_circuit_ternary.rs": "20750099d264ba816354f8a2438fb3476bac1951e578f1551138243ecd164f04",
    "research/pq-direct-spend/src/ring_circuit_ternary_audit.rs": "ea3964664747c832b16bf2a0485d20c8ba8c5748f6e3108a584e5931f27f05eb",
    "research/pq-direct-spend/src/ring_native.rs": "df937fc05e68063c2ba8a9bb209101ad4c10e537089064eddc66b672958afea5",
    "research/pq-direct-spend/src/ring_screen.rs": "632491994fc9040c6e4b0607a8512eb8d95620c72d97d1204eafdfcdc8d891ff",
    "research/pq-direct-spend/src/ring_screen/bounds.rs": "1b891d17492720c024c050e6f9e3c0a80ca090e12e620f7abc86d75eb300f795",
    "research/pq-direct-spend/src/ring_screen/fixtures.rs": "fb8b8ba93a295b5f45f12b703dbeaa3347ca44d94ac876416b276887fda16732",
    "research/pq-direct-spend/src/ring_screen/io.rs": "32dd76d1da4d3d3660b998052ae238531c0dade7e3f7d11736cee4452b5ba397",
    "research/pq-direct-spend/src/ring_screen/tests.rs": "c5d037479e48b46cd72443a924d4e763636c2d87e1e893598f26fda4db0b4f73",
    "research/pq-direct-spend/src/ring_screen/workflow.rs": "7b998984b488cd9e8608a4991318f8d9da76b2cafeec9d1dc94cc629097aa445",
    "research/pq-direct-spend/tools/note_workflow_report.py": "5dcd6fc32c98018b5a138e768f58381a295f7009f1c02b0d674c8f5a005b6abd",
    "research/pq-ringct/tools/opencl_direct_spend_audit.py": "f6db7c02b8806522ad10d2a605e75aa10c113483959aba5ef506eb3649a24204",
    "research/pq-ringct/tools/public_hash_evidence.py": "e975dca606a450dc36c99b10d85c240436f192f71ada183e7b884e1e552b4093"
}
HELPERS = ("research/pq-direct-spend/tools/note_workflow_report.py",
           "research/pq-ringct/tools/opencl_direct_spend_audit.py",
           "research/pq-ringct/tools/public_hash_evidence.py")
FALSE_SCOPE = "production_acceptance_changed complete_faithful_ringct_workflow cryptographic_security_review_complete protocol_adoption_qualified protocol_redesign_twofold_qualified n3_n4_aggregate_qualification public_preprocessing_reused original_quota_receipt".split()
CASE_FIELDS = "schema identity research_only complete_faithful_ringct_workflow recursive_aggregate_proofs fresh_relation_proofs proof_generation proving_policy public_hash descriptor public_binding independent_cpu_verified reused_prover_state artifact_roundtrip cryptographic_mutation_checks artifact_bytes artifact_sha3_256 encode_required_host_bytes decode_required_host_bytes fixture_regeneration_ns compilation_ns prover_setup_ns proving_ns prover_lifecycle_ns codec_and_disk_ns verifier_reconstruction_ns verifier_setup_ns cpu_verification_ns mutation_checks_ns verifier_lifecycle_ns complete_research_workflow_ns prover_terminal verifier_terminal".split()
SUITE_FIELDS = "schema profile representation context research_only recursive_aggregate_proofs fresh_relation_proofs distinct_public_statements distinct_serials public_hash_kernel caller_reserved_bytes orchestration_payload_bytes fixture_staging process_host_peak_bytes managed_gpu_peak_bytes preflight_fixture_generation_ns complete_seven_case_screen_ns timing_boundary manifest cases".split() + FALSE_SCOPE


def report_file(path):
    require(path.is_file() and not path.is_symlink(), "missing or symlinked report")
    raw = read(path, 1 << 20)
    return decode_json(raw), sha(raw)


def inventory(directory, maximum):
    names = set()
    for path in directory.iterdir():
        require(len(names) < maximum, "evidence directory exceeds file bound")
        names.add(path.name)
    return names


def expected_environment(root, output, pin):
    require(type(pin) is str and re.fullmatch(r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", pin), "invalid GPU pin")
    result = {
        "PATH": "/home/access/code/lattica/.tools/rust-1.96.0/bin:/usr/bin:/bin", "HOME": "/home/access",
        "CARGO_HOME": str(root / ".tools/cargo-opencl"), "CARGO_TARGET_DIR": str(root / ".tools/target-opencl"),
        "CARGO_BUILD_JOBS": "2", "RAYON_NUM_THREADS": "8", "LATTICA_PROVING_REPORT": "1",
        "LATTICA_PROVING_POLICY": "gpu-required", "LATTICA_V2_QUOTIENT_FUSION": "1",
        "LATTICA_GPU_DEVICE_UUID": pin, "LATTICA_V2_GPU_PUBLIC_HASH": "baseline",
        "LATTICA_V2_GPU_DEVICE": "0", "LATTICA_V2_GPU_MANAGED_BYTES": str(8 * GIB),
        "LATTICA_V2_GPU_CONTEXT_BYTES": str(4 * GIB), "LATTICA_V2_HOST_OUTPUT_BYTES": str(32 * GIB),
        "LATTICA_V2_GPU_RETAINED_TREE_STORAGE": "host", "LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES": str(8 * GIB),
        "LATTICA_V2_GPU_LDE_WORKSPACE_BYTES": "0", "LATTICA_NATIVE_SPEND_QUALIFICATION": "1",
        "LATTICA_DIRECT_RING_SCREEN_QUALIFICATION": "1", "LATTICA_DIRECT_RING_SCREEN_OUTPUT_DIR": str(output),
    }
    result.update({"LATTICA_V2_GPU_" + key: "1" for key in SWITCHES})
    return result


def guard_record(path):
    raw = read(path, 4 << 20)
    record = decode_json(raw)
    host_peak = terminal(record)
    require(record.get("profile") == "direct-full" and record.get("expect_tests") is True, "wrong guard profile")
    for key in ("benchmark", "expect_result", "expect_direct_result", "comparison_baseline", "performance_qualified"):
        require(record.get(key) is False, "mixed screen mode: " + key)
    require(record.get("memory_max_bytes") == 45 * GIB and record.get("memory_high_bytes") == 43 * GIB
            and record.get("fresh_memavailable_required_bytes") == 47 * GIB, "changed direct-full envelope")
    command = record.get("command")
    require(type(command) is list and len(command) == 6 and type(command[0]) is str, "invalid exact worker command")
    binary = Path(command[0])
    require(binary.is_absolute() and binary.name.startswith("lattica_pq_direct_spend_research-")
            and command[1:] == [SELECTOR, "--exact", "--ignored", "--test-threads=1", "--nocapture"], "wrong exact selector")
    root = binary.parents[4]
    require(binary.parent == root / ".tools/target-opencl/release/deps", "unexpected worker location")
    label = record.get("label")
    require(type(label) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,55}", label), "invalid run label")
    output = (root / ".tools/pq-opencl-opt/artifacts" / label).resolve()
    require(len(str(output).encode()) <= 1024, "output path exceeds screen bound")
    environment = record.get("environment", {})
    pin = environment.get("LATTICA_GPU_DEVICE_UUID")
    require(environment == expected_environment(root, output, pin), "changed screen environment")
    require(record.get("public_hash_kernel") == "baseline", "candidate screen is not qualified")
    for key in ("note_startup_environment", "note_cpu_environment", "owned_runtime_environment"):
        require(key in record and record[key] is None, "mixed isolated environment")
    encoded = b"".join((key + "=" + environment[key] + "\0").encode() for key in sorted(environment))
    receipt = record.get("direct_ring_screen_environment")
    fields(receipt, "schema selector output_directory entry_count serialized_bytes sha256_sorted_name_equals_value_nul requires_env_clear_before_exec requires_immutable_environment_after_exec complete_faithful_ringct_workflow n3_n4_aggregate_qualification performance_qualified dispatch_authority".split(), "screen environment receipt")
    require(receipt["schema"] == "direct-ring-seven-case-screen-environment-v1" and receipt["selector"] == SELECTOR
            and receipt["output_directory"] == str(output) and receipt["entry_count"] == len(environment)
            and receipt["serialized_bytes"] == len(encoded) and receipt["sha256_sorted_name_equals_value_nul"] == sha(encoded), "screen environment receipt differs")
    for key in ("requires_env_clear_before_exec", "requires_immutable_environment_after_exec"):
        require(receipt[key] is True, "screen environment lifetime missing")
    for key in ("complete_faithful_ringct_workflow", "n3_n4_aggregate_qualification", "performance_qualified", "dispatch_authority"):
        require(receipt[key] is False, "environment receipt overclaims qualification")
    service = record.get("service_command", [])
    require(service.count("/usr/bin/env") == 1, "missing env-clear launch")
    env_index = service.index("/usr/bin/env")
    require(service[:4] == ["/usr/bin/systemd-run", "--user", "--quiet", "--unit=" + record["unit"]], "wrong service launcher")
    properties = {}
    for entry in service[4:env_index]:
        require(type(entry) is str and entry.startswith("--property="), "unknown service option")
        name, value = entry.removeprefix("--property=").split("=", 1)
        require(name not in properties, "duplicate service property")
        properties[name] = value
    require(properties == {
        "Type": "exec", "RemainAfterExit": "yes", "Restart": "no", "MemoryMax": str(45 * GIB),
        "MemoryHigh": str(43 * GIB), "MemorySwapMax": "0", "CPUQuota": "800%", "TasksMax": "256",
        "RuntimeMaxSec": str(number(record.get("runtime_seconds"), "runtime", 1, 86400)), "TimeoutStopSec": "10",
        "KillMode": "control-group", "WorkingDirectory": str(root), "StandardOutput": "append:" + record["raw_log"],
        "StandardError": "inherit",
    }, "service envelope differs")
    require(service[env_index + 1:] == ["-i", *[key + "=" + value for key, value in environment.items()], *command], "actual launch differs")
    require(SOURCE_PINS and all(record["input_sha256"].get(key) == value for key, value in SOURCE_PINS.items()), "unreviewed screen proof sources")
    provenance = record.get("executable_provenance", {})
    require(provenance.get("path") == command[0], "executable provenance path differs")
    digest(provenance.get("sha256"))
    build_raw = read(provenance["build_record"], 4 << 20)
    require(sha(build_raw) == provenance.get("build_record_sha256"), "changed build record")
    build = decode_json(build_raw)
    terminal(build)
    require(build.get("profile") == "build" and build["input_sha256"] == record["input_sha256"]
            and build.get("built_artifact_sha256", {}).get(command[0]) == provenance["sha256"], "build/source/executable provenance mismatch")
    build_log = read(build["raw_log"], 64 << 20)
    require(sha(build_log) == build.get("raw_log_sha256"), "changed build log")
    log = read(record["raw_log"], 64 << 20)
    require(sha(log) == record.get("raw_log_sha256"), "changed screen log")
    start, finish = (datetime.fromisoformat(record[key]) for key in ("started_utc", "finished_utc"))
    require(start.utcoffset() is not None and finish.utcoffset() is not None and finish > start, "invalid run interval")
    wall = record.get("wall_seconds")
    require(type(wall) in (int, float) and math.isfinite(wall) and wall > 0, "invalid guard wall time")
    evidence = {
        "guard_record": str(path), "guard_record_sha256": sha(raw), "raw_log": record["raw_log"], "raw_log_sha256": sha(log),
        "build_record": provenance["build_record"], "build_record_sha256": sha(build_raw), "build_log_sha256": sha(build_log),
        "executable": command[0], "executable_sha256": provenance["sha256"],
        "source_snapshot_sha256": sha(json.dumps(record["input_sha256"], sort_keys=True, separators=(",", ":")).encode()),
        "environment_sha256": sha(encoded), "physical_gpu_uuid": pin, "output_directory": str(output),
        "guarded_cgroup_host_peak_bytes": host_peak, "process_device_peak_bytes": None,
        "process_memory_max_bytes": 45 * GIB, "process_memory_high_bytes": 43 * GIB, "swap_limit_bytes": 0,
        "started_utc": record["started_utc"], "finished_utc": record["finished_utc"], "guard_wall_seconds": record["wall_seconds"],
    }
    return output, log.decode("utf-8", errors="strict"), evidence


def identity(value, index):
    fields(value, ["case", "statement_sha3_256", "serials"], "case identity")
    require(number(value["case"], "case ordinal") == index, "missing or reordered case")
    statement = direct.byte_array(value["statement_sha3_256"], 32, "statement digest")
    serials = value["serials"]
    require(type(serials) is list and len(serials) == 2, "wrong serial count")
    return statement, tuple(direct.byte_array(value, 32, "serial") for value in serials)


def audit_case(case, proving, verification, artifact, index, pin):
    fields(case, CASE_FIELDS, "case report")
    identity(case["identity"], index)
    require(case["schema"] == CASE_SCHEMA and case["research_only"] is True
            and case["complete_faithful_ringct_workflow"] is False and case["reused_prover_state"] is False
            and number(case["recursive_aggregate_proofs"], "aggregate count") == 0
            and number(case["fresh_relation_proofs"], "fresh count") == 1
            and case["proof_generation"] == "fresh-only" and case["proving_policy"] == "gpu_required"
            and case["independent_cpu_verified"] is True and case["artifact_roundtrip"] is True
            and number(case["cryptographic_mutation_checks"], "mutations") == 2, "case scope changed")
    public_hash.workflow_records(case, proving, verification, expected_kernel="baseline")
    descriptor = case["descriptor"]
    fields(descriptor, "active_rows padded_rows wires witness_values canonical_manifest_digest registered_program_id".split(), "proof descriptor")
    padded = number(descriptor["padded_rows"], "padded rows", 8, 1 << 20)
    require(padded & (padded - 1) == 0, "nonbinary rows")
    number(descriptor["active_rows"], "active rows", 1, padded)
    number(descriptor["wires"], "wires", 4, 1 << 24)
    number(descriptor["witness_values"], "witness values", 1, descriptor["wires"] - 4)
    require(proving.get("schema") == "lattica-research-direct-ring-gpu-proof-v1"
            and proving.get("proof_generation") == "fresh-only" and proving.get("policy") == "gpu_required"
            and proving.get("registration_lifetime") == "consumed-once"
            and proving.get("witness_instructions_retired_before_quotient") is True
            and proving.get("independent_verification_required") is True, "proving policy changed")
    require(verification.get("schema") == "lattica-research-direct-ring-independent-verification-v1"
            and verification.get("verified") is True and verification.get("public_reconstruction") == "complete-program-and-fresh-preprocessing-cap"
            and verification.get("verifier_preprocessing_policy") == "gpu_required" and verification.get("proof_verification_backend") == "cpu"
            and verification.get("reused_prover_state") is False and verification.get("synthetic_hints_evaluated") is False
            and number(verification.get("mutation_checks"), "independent mutations") == 2, "independent verifier contract changed")
    require(verification.get("descriptor") == descriptor and verification.get("expected_context") == [0x73] * 32
            and verification.get("expected_public_binding") == case["public_binding"], "independent statement binding differs")
    direct.field_array(case["public_binding"], "case public binding")
    for report in (proving, verification):
        direct.bounds(report, descriptor)
        require(report["compiler"]["memory_profile"] == "2g" and report["compiler"]["wire_profile"] == "16m"
                and report["compiler"]["witness_values"] == descriptor["witness_values"], "changed fixed compiler profile")
        require(report["footprint"]["tree_storage_mode"] == "host_backing" and report["footprint"]["host_tree_quota_bytes"] == 8 * GIB, "changed host tree profile")
        require(direct.byte_array(report["footprint"]["physical_device_uuid"], 16, "physical UUID") == uuid.UUID(pin[4:]).bytes, "physical device differs")
        direct.native(report.get("registration", {}), False)
    require(proving.get("device", {}).get("uuid") == pin, "prover device pin differs")
    direct.native(proving.get("proving", {}), True)
    direct.terminal(proving.get("terminal", {}), True)
    direct.terminal(verification.get("terminal", {}), False)
    require(case["prover_terminal"] == proving["terminal"] and case["verifier_terminal"] == verification["terminal"], "case terminal receipt differs")
    for report in (proving, verification):
        require(report["terminal"]["managed_peak_bytes"] <= report["footprint"]["device_phase_peak_bytes"], "observed peak exceeds admitted phase")
    retained = number(proving.get("retained_proof_bytes"), "retained proof", 1, 64 << 20)
    number(verification.get("retained_artifact_bytes"), "retained artifact", 1, (64 << 20) + (16 << 10))
    number(verification.get("cpu_verifier_reserved_bytes"), "CPU verifier", 64 << 20, 257 << 20)
    require(number(case["artifact_bytes"], "artifact length", 220, (2 << 20) + 212) == len(artifact)
            and hashlib.sha3_256(artifact).digest() == direct.byte_array(case["artifact_sha3_256"], 32, "artifact digest"), "artifact round trip differs")
    direct.header(artifact, verification)
    require(number(case["encode_required_host_bytes"], "encoder admission") == retained + (2 << 20) + 212 + (16 << 10)
            and number(case["decode_required_host_bytes"], "decoder admission") == len(artifact) + (64 << 20) + (16 << 10), "codec admission differs")
    for outer, inner in {"prover_setup_ns": "setup_ns", "proving_ns": "proving_ns", "prover_lifecycle_ns": "total_proving_lifecycle_ns"}.items():
        require(number(case[outer], outer, 1) == number(proving.get(inner), inner, 1), "proving time differs")
    for outer, inner in {"verifier_reconstruction_ns": "reconstruction_ns", "verifier_setup_ns": "gpu_preprocessing_ns", "cpu_verification_ns": "cpu_verification_ns", "mutation_checks_ns": "mutation_checks_ns", "verifier_lifecycle_ns": "total_verification_lifecycle_ns"}.items():
        require(number(case[outer], outer, 1) == number(verification.get(inner), inner, 1), "verifier time differs")
    total = number(case["complete_research_workflow_ns"], "case total", 1)
    require(sum(number(case[key], key, 1) for key in ("fixture_regeneration_ns", "compilation_ns", "prover_lifecycle_ns", "codec_and_disk_ns", "verifier_lifecycle_ns")) <= total, "case timer omits a phase")
    require(case["prover_setup_ns"] + case["proving_ns"] <= case["prover_lifecycle_ns"]
            and sum(case[key] for key in ("verifier_reconstruction_ns", "verifier_setup_ns", "cpu_verification_ns", "mutation_checks_ns")) <= case["verifier_lifecycle_ns"], "lifecycle timer omits a phase")
    for report, keys, total_key in (
        (proving, "admission_ns session_start_ns setup_ns proving_ns teardown_ns", "total_proving_lifecycle_ns"),
        (verification, "reconstruction_ns admission_ns session_start_ns gpu_preprocessing_ns teardown_ns cpu_verification_ns mutation_checks_ns", "total_verification_lifecycle_ns"),
    ):
        require(sum(number(report.get(key), key) for key in keys.split()) <= report[total_key],
                "detailed lifecycle timer omits a phase")


def audit_directory(directory, content, pin):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), "missing screen directory")
    require(inventory(directory, 9) == {"screen.json", "preflight.json", *[f"case-{i}" for i in range(7)]}, "screen contains incomplete or additional results")
    screen, screen_hash = report_file(directory / "screen.json")
    manifest, manifest_hash = report_file(directory / "preflight.json")
    fields(screen, SUITE_FIELDS, "screen report")
    require(screen["schema"] == SCHEMA and screen["profile"] == PROFILE and screen["representation"] == direct.REPRESENTATION
            and screen["context"] == [0x73] * 32 and screen["research_only"] is True, "screen profile changed")
    require(all(screen[key] is False for key in FALSE_SCOPE), "screen overclaims qualification/reuse")
    for key, expected in {"recursive_aggregate_proofs": 0, "fresh_relation_proofs": 7, "distinct_public_statements": 7, "distinct_serials": 14, "caller_reserved_bytes": 1 << 20}.items():
        require(number(screen[key], key) == expected, "screen inventory differs: " + key)
    require(screen["public_hash_kernel"] == "baseline" and screen["process_host_peak_bytes"] is None
            and screen["timing_boundary"] == TIMING, "screen memory/kernel/timer scope changed")
    number(screen["orchestration_payload_bytes"], "orchestration", 1, 32 << 10)
    staging = screen["fixture_staging"]
    parts = "ring_backing_bytes native_parameter_bytes aes_stream_bytes inline_payload_bytes".split()
    fields(staging, parts + ["required_host_bytes"], "fixture staging")
    require(number(staging["required_host_bytes"], "fixture staging", 1, 32 * GIB)
            == sum(number(staging[key], key, 1) for key in parts) + (32 << 10), "fixture staging inventory differs")
    require(type(manifest) is list and len(manifest) == 7 and manifest == screen["manifest"], "preflight manifest differs")
    require(type(screen["cases"]) is list and len(screen["cases"]) == 7, "incomplete screen cases")
    statements, serials, artifacts, maxima = set(), set(), set(), []
    hashes = {"screen.json": screen_hash, "preflight.json": manifest_hash}
    for index, case in enumerate(screen["cases"]):
        statement, pair = identity(manifest[index], index)
        require(statement not in statements and pair[0] != pair[1] and not any(item in serials for item in pair), "duplicate preflight statement or serial")
        statements.add(statement)
        serials.update(pair)
        folder = directory / f"case-{index}"
        require(folder.is_dir() and not folder.is_symlink() and inventory(folder, 4) == {"workflow.json", "proving.json", "verification.json", "proof.bin"}, "case has missing/failure/additional evidence")
        reports = {}
        for name in ("workflow.json", "proving.json", "verification.json"):
            reports[name], hashes[f"case-{index}/{name}"] = report_file(folder / name)
        require(reports["workflow.json"] == case and case.get("identity") == manifest[index], "case report differs from suite/preflight")
        proof = folder / "proof.bin"
        require(proof.is_file() and not proof.is_symlink(), "missing artifact")
        artifact = read(proof, (2 << 20) + 212)
        hashes[f"case-{index}/proof.bin"] = sha(artifact)
        audit_case(case, reports["proving.json"], reports["verification.json"], artifact, index, pin)
        packet_digest = bytes(case["artifact_sha3_256"])
        require(packet_digest not in artifacts, "duplicate fresh artifact")
        artifacts.add(packet_digest)
        maxima.extend(case[key]["managed_peak_bytes"] for key in ("prover_terminal", "verifier_terminal"))
    require(number(screen["managed_gpu_peak_bytes"], "managed peak", 1, 8 * GIB) == max(maxima), "suite managed peak omits a session")
    require(number(screen["complete_seven_case_screen_ns"], "suite time", 1) >= number(screen["preflight_fixture_generation_ns"], "preflight time", 1)
            + sum(case["complete_research_workflow_ns"] for case in screen["cases"]), "suite timer omits preflight or a case")
    summaries, test_results = [], []
    for line in content.splitlines():
        prefix = "test " + SELECTOR + " ... "
        if line.startswith(prefix):
            line = line[len(prefix):]
        if line.startswith("DIRECT_RING_SEVEN_CASE_SCREEN "):
            summaries.append(decode_json(line.removeprefix("DIRECT_RING_SEVEN_CASE_SCREEN ")))
        if line.startswith("test result:"):
            test_results.append(line)
    require(summaries == [screen], "stdout screen summary missing/duplicated/changed")
    require(len(test_results) == 1 and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s", test_results[0]), "wrong exact test completion")
    return {"screen": screen, "file_sha256": hashes, "retired_gpu_sessions": len(maxima),
            "fresh_relation_gpu_proofs": 7, "independent_cpu_acceptances": 7, "cryptographic_mutation_rejections": 14,
            "recursive_proofs": 0, "managed_gpu_peak_bytes": max(maxima)}


def audit(path):
    helper_hashes = {key: sha(read(ROOT / key, 1 << 20)) for key in HELPERS}
    require(all(helper_hashes[key] == SOURCE_PINS.get(key) for key in HELPERS), "unreviewed audit helper source")
    directory, content, evidence = guard_record(path)
    result = audit_directory(directory, content, evidence["physical_gpu_uuid"])
    require(result["screen"]["complete_seven_case_screen_ns"] / 1e9 <= evidence["guard_wall_seconds"],
            "screen timer exceeds complete guard interval")
    result.update({"schema": "direct-ring-seven-case-evidence-audit-v1", "evidence": evidence,
                   "auditor_sha256": sha(read(__file__, 1 << 20)), "audit_helper_sha256": helper_hashes, "research_only": True,
                   "complete_faithful_ringct_workflow": False, "n3_n4_aggregate_qualification": False,
                   "protocol_redesign_twofold_qualified": False, "production_adoption_qualified": False,
                   "cryptographic_security_review_complete": False,
                   "audit_scope": "source/executable-bound reported evidence and artifact headers/digests; does not independently execute proof verification"})
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.record), indent=2, sort_keys=True))
