#!/usr/bin/env python3
"""Audit exact single-case identity-receipt research evidence; never runs a prover."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import uuid
import ring_screen_report as baseline
from ring_screen_report import (read, decode_json, require, fields, number, digest, sha, terminal,
    report_file, inventory, identity, direct, public_hash, CASE_FIELDS, GIB)
from note_workflow_report import tokens

PROFILE = 'direct-ring-cross-session-identity-receipt-v1'
SELECTORS = {'baseline': 'ring_screen::identity_experiment::tests::gpu_direct_ring_identity_cold_baseline',
             'receipt-v1': 'ring_screen::identity_experiment::tests::gpu_direct_ring_identity_receipt_cross_session'}
SOURCE_PINS = dict(baseline.SOURCE_PINS)
SOURCE_PINS.update({'lattica-prover-p3/src/block_v2/gpu_hash/engine.rs': '3de8f7e5d5d6f327551816307b8ebf7b10a5f46d6699e7ea05fdfc2b6633ce60', 'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/public_hash.rs': '83eafdf5779d2fe723d271b4e03232ebcb427dd4da86840a2d3771645e4ad873', 'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/public_hash/report.rs': 'e59b318698787a29c4ec936e6204c855fb6208f94776c4d9e3829a1a2aa0459a', 'lattica-prover-p3/src/block_v2/machine/backend.rs': 'cc5c379dc8834dac35c51efac4d5b7413ce726cd509591fc72657661286e45d2', 'lattica-prover-p3/src/block_v2/machine/backend/cache_storage.rs': 'da0b916206d3a6972ce659f0f8080de8562d47e9f7d3c93f89616ca3aac2df43', 'lattica-prover-p3/src/block_v2/machine/backend/consuming.rs': '2360d4d863488255333199c66e4540ab56783d8d74a0758809c505422a9c7e04', 'lattica-prover-p3/src/block_v2/machine/backend/identity_receipt.rs': 'bb4f59f4f2040fc5fc9577816b397d5f04cf8fc4b9dfbb71d015bad5ea27b3f7', 'lattica-prover-p3/src/block_v2/machine/backend/identity_receipt_tests.rs': '8d0d86de946c93eaa2d627cc3aa13593fd415f80f8169517ce84be33515f60c0', 'lattica-prover-p3/src/block_v2/machine/fingerprint/bounded.rs': '2cb4765ac61c9e454e5d041311a21de7d46e48076f41663ba3250174fb7c73c8', 'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission.rs': 'fd3d7e7ccc97126b5ed3b03a5ff2b9f0a1f3dd3dd36f7792666d575c79ca2959', 'lattica-prover-p3/src/gpu_device.rs': 'e1a17177ab97ff5f6fc6b0cc24a0457156214c16d7839ea6d06e7e3744ab1a14', 'research/pq-direct-spend/src/lib.rs': 'c709dbef2d11552bb2815b3fbbc186fc9fad6192c70fbfdc3cd2883ea4523246', 'research/pq-direct-spend/src/ring.rs': 'd1d6be97a815cc57bafa7eb3269e29d95d68b77f08c1119a7dad4bf89e6dca5d', 'research/pq-direct-spend/src/ring_circuit/artifact.rs': '0fbddea98c4663c4028a6c6968bca25a5df3ab15d3ef8fd902e39848d90d897a', 'research/pq-direct-spend/src/ring_circuit/artifact/header.rs': '94ed308eeae41b41bcda8702c0b9bb8ffca87f8df8f53241990b48c85e1ca643', 'research/pq-direct-spend/src/ring_circuit/proving/lifecycle.rs': 'f5a0c31845bf85b08add62d31ec468ae9b5c5626160414eceaf7347c6d5a3a2f', 'research/pq-direct-spend/src/ring_circuit/proving/receipts.rs': '9c2908fb9892b0fb168c887673f4779635c9bebb1f19b594f087467bb5915415', 'research/pq-direct-spend/src/ring_circuit/verification/lifecycle.rs': '96b28a470ae9cad90f2d936cd9e978b99a176532ee8535cba03aa1e8b98557d4', 'research/pq-direct-spend/src/ring_screen/bounds.rs': '1b891d17492720c024c050e6f9e3c0a80ca090e12e620f7abc86d75eb300f795', 'research/pq-direct-spend/src/ring_screen/fixtures.rs': 'fb8b8ba93a295b5f45f12b703dbeaa3347ca44d94ac876416b276887fda16732', 'research/pq-direct-spend/tools/ring_screen_report.py': '0184d94acc385998d59b60284d9f19d2ce70431ce295a02bc0f07f5571c68ff9', 'research/pq-ringct/src/opencl/session.rs': '4f16b83abcd13da1e7ab1ad06fa6f01250b1725721e77eacc484f6878d7ed5dc', 'research/pq-direct-spend/src/gpu_workflow.rs': '5d389cb33854905114ded71262362b388a743646c21c0b757b75550bfab27efe', 'research/pq-direct-spend/src/ring_circuit/identity_reuse.rs': '706d96a2a680e80b8d19c0be4f4f76f12f92b14626eaca00d8b54180574abd61', 'research/pq-direct-spend/src/ring_circuit/identity_reuse/SOURCE_BOUNDS.md': '8e778b18f14ddaeda8848865ec8bbbbbc5e595edbbab1d52de13193c718aea8a', 'research/pq-direct-spend/src/ring_circuit/identity_reuse/tests.rs': '9faca039b13c4ad0ae15bafe95e86316f3b9f5c017ba860a3357ecf87b3b6d98', 'research/pq-direct-spend/src/ring_circuit/proving.rs': '506ee63cb951ceec86a5163f8f6adddfd1d6df208b2246ae5bb2016f58fdd987', 'research/pq-direct-spend/src/ring_circuit/proving/metadata.rs': '0f32f99238361c6e0107017d582510cf2520607d715ee4733a6fc4843fea15c6', 'research/pq-direct-spend/src/ring_circuit/verification.rs': 'b7a57454c291edea0183dbb7e4572fa2fbde1f5f3690d0cd38cfcc54205cf91b', 'research/pq-direct-spend/src/ring_circuit/verification/reconstruction.rs': 'e7168457157dde6bdac4ffb6d7e5ef0ff30f4ce323ec92c76da817f08f80f3e4', 'research/pq-direct-spend/src/ring_screen/identity_experiment.rs': 'f0398a3c579dc5eafcd49951d41ab7189835730b429b63e0725a7ad8ce4ff8d4', 'research/pq-direct-spend/src/ring_screen/identity_experiment/AUDIT_SPEC.md': 'f73389f1f4b9ef01b4e02a17717e654e204431b9eca08afbee603a28b8ba0d6d', 'research/pq-direct-spend/src/ring_screen/io.rs': 'd244e9dbd50a952f433539aab94c2cdeb4bff955099cffd2e1915b28fce04445', 'research/pq-direct-spend/src/ring_screen/workflow.rs': '35625ff7634ca56b13ed33441d3190b8bc9bf12eb3cece3906884e643a1a255d', 'research/pq-direct-spend/src/ring_circuit.rs': '9b785d18ac330b689725a86df1d6529e22c3b349a33eae75611280d5e7640f4a', 'research/pq-direct-spend/src/ring_screen.rs': '5dc5f5bb3741f6efbf224ab0f704858d46b77e06a7ac9614ae794335750c6821', 'research/pq-direct-spend/Cargo.toml': '0905e436fb1499a100e7d1b6d9d222cbeb2c1c2a8f9ffdd62d27db0e133421f8', 'research/pq-ringct/tools/opencl_private_spend_validate.py': 'e67dc40cfdbfb5970f71f608a1e1c9f255cf9565baedaa4d1675b56f801de7fb', 'research/pq-direct-spend/src/ring_circuit/verification/tests.rs': '3b05fb8bf3f803210958e689b9081faa1a3959b08e4b6616a2e5c010c893fae3', 'research/pq-direct-spend/src/ring_circuit/verification/SYNTHETIC_WITNESS_BOUNDS.md': '9625c18885f3df8d0086c5666bee5def84a6b3774f10ec0c8d1a6129512ff13b'})
KNOWN_IDENTITY = {'case': 0, 'serials': [[41, 151, 152, 15, 62, 144, 186, 88, 111, 22, 192, 127, 158, 124, 152, 93, 15, 121, 104, 9, 237, 221, 173, 186, 178, 190, 3, 105, 107, 21, 39, 238], [50, 74, 97, 140, 210, 223, 234, 69, 2, 146, 156, 186, 127, 188, 123, 138, 141, 14, 5, 185, 27, 190, 66, 0, 115, 158, 144, 206, 37, 140, 38, 170]], 'statement_sha3_256': [140, 172, 42, 130, 190, 176, 112, 222, 59, 30, 0, 95, 126, 21, 163, 164, 216, 27, 163, 137, 31, 239, 104, 247, 113, 138, 85, 78, 18, 211, 24, 72]}
KNOWN_PUBLIC = [2249874722195506242, 7882786099538675784, 12190503968149664712, 13133728887804208508]
KNOWN_DESCRIPTOR = {'active_rows': 321781, 'canonical_manifest_digest': [184, 226, 21, 114, 133, 46, 155, 94, 150, 97, 228, 88, 254, 109, 168, 139, 243, 190, 59, 61, 79, 172, 12, 234, 163, 251, 26, 110, 104, 56, 137, 241], 'padded_rows': 524288, 'registered_program_id': [5030004100719169221, 6911553581468856451, 14386911184622720820, 3382824573370034423], 'wires': 6113774, 'witness_values': 59822}

def expected_environment(root, output, pin, mode):
    environment = baseline.expected_environment(root, output, pin)
    del environment['LATTICA_DIRECT_RING_SCREEN_QUALIFICATION']
    del environment['LATTICA_DIRECT_RING_SCREEN_OUTPUT_DIR']
    environment.update(LATTICA_DIRECT_RING_IDENTITY_QUALIFICATION='1',
        LATTICA_DIRECT_RING_IDENTITY_OUTPUT_DIR=str(output), LATTICA_DIRECT_RING_IDENTITY_MODE=mode)
    return environment

def guard_record(path):
    mode = decode_json(read(path, 4 << 20)).get("direct_ring_identity_environment", {}).get("mode")
    require(mode in SELECTORS, "invalid identity mode")
    SELECTOR = SELECTORS[mode]
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
    require(environment == expected_environment(root, output, pin, mode), "changed screen environment")
    require(record.get("public_hash_kernel") == "baseline", "candidate screen is not qualified")
    for key in ("note_startup_environment", "note_cpu_environment", "owned_runtime_environment", "direct_ring_screen_environment", "owned_source_shape_environment"):
        require(key in record and record[key] is None, "mixed isolated environment")
    encoded = b"".join((key + "=" + environment[key] + "\0").encode() for key in sorted(environment))
    receipt = record.get("direct_ring_identity_environment")
    fields(receipt, "schema mode selector output_directory entry_count serialized_bytes sha256_sorted_name_equals_value_nul requires_env_clear_before_exec requires_immutable_environment_after_exec complete_faithful_ringct_workflow n3_n4_aggregate_qualification performance_qualified dispatch_authority".split(), "screen environment receipt")
    require(receipt["schema"] == "direct-ring-identity-experiment-environment-v1" and receipt["mode"] == mode and receipt["selector"] == SELECTOR
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
    require(build.get("command") == ["/home/access/code/lattica/.tools/rust-1.96.0/bin/cargo", "test", "--release", "--locked", "--offline", "--manifest-path", "research/pq-direct-spend/Cargo.toml", "--features", "gpu-identity-reuse-experiment", "--lib", "--no-run"], "identity experiment build feature/command differs")
    build_log = read(build["raw_log"], 64 << 20)
    require(sha(build_log) == build.get("raw_log_sha256"), "changed build log")
    log = read(record["raw_log"], 64 << 20)
    require(sha(log) == record.get("raw_log_sha256"), "changed screen log")
    start, finish = (datetime.fromisoformat(record[key]) for key in ("started_utc", "finished_utc"))
    require(start.utcoffset() is not None and finish.utcoffset() is not None and finish > start, "invalid run interval")
    wall = record.get("wall_seconds")
    require(type(wall) in (int, float) and math.isfinite(wall) and wall > 0, "invalid guard wall time")
    require(sha(read(Path(provenance["resolved_path"]), 256 << 20)) == provenance["sha256"], "changed executable bytes")
    for helper in (*baseline.HELPERS, "research/pq-direct-spend/tools/ring_screen_report.py"):
        require(sha(read(root / helper, 4 << 20)) == SOURCE_PINS[helper], "changed imported audit helper")
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
    return output, log.decode("utf-8", errors="strict"), evidence, mode


def audit_case(case, proving, verification, artifact, index, pin, mode):
    reused = mode == "receipt-v1"
    expected_schema = "lattica-research-direct-ring-identity-reuse-workflow-v1" if reused else baseline.CASE_SCHEMA
    fields(case, CASE_FIELDS + (["identity_reuse_profile"] if reused else []), "case report")
    identity(case["identity"], index)
    require(case["schema"] == expected_schema and case["research_only"] is True
            and case["complete_faithful_ringct_workflow"] is False and case["reused_prover_state"] is reused
            and number(case["recursive_aggregate_proofs"], "aggregate count") == 0
            and number(case["fresh_relation_proofs"], "fresh count") == 1
            and case["proof_generation"] == "fresh-only" and case["proving_policy"] == "gpu_required"
            and case["independent_cpu_verified"] is True and case["artifact_roundtrip"] is True
            and number(case["cryptographic_mutation_checks"], "mutations") == 2, "case scope changed")
    audit_identity_provenance(case, proving, verification, mode)
    require(case["identity"] == KNOWN_IDENTITY and case["public_binding"] == KNOWN_PUBLIC, "fixture-0 identity differs")
    descriptor = case["descriptor"]
    require(descriptor == KNOWN_DESCRIPTOR, "fixed fixture compiler/program descriptor differs")
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
    require(verification.get("schema") == ("lattica-research-direct-ring-identity-reuse-verification-v1" if reused else "lattica-research-direct-ring-independent-verification-v1")
            and verification.get("verified") is True and verification.get("public_reconstruction") == "complete-program-and-fresh-preprocessing-cap"
            and verification.get("verifier_preprocessing_policy") == "gpu_required" and verification.get("proof_verification_backend") == "cpu"
            and verification.get("reused_prover_state") is reused and verification.get("synthetic_hints_evaluated") is False
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


ROOT_FIELDS = ['schema', 'mode', 'research_only', 'case_count', 'public_preprocessing_reused', 'reused_preprocessing_part', 'fresh_preprocessing_cap', 'complete_faithful_ringct_workflow', 'protocol_redesign_twofold_qualified', 'production_acceptance_changed', 'original_shared_ledger_receipt', 'source_identity_host_bytes', 'receipt_sublimit_bytes', 'combined_metadata_limit_bytes', 'caller_reserved_bytes', 'validated_gpu_registration_receipts', 'validated_gpu_proof_receipts', 'identity_receipt_hits', 'full_gpu_identity_hashes_required', 'retired_gpu_sessions', 'independent_cpu_acceptances', 'mutation_rejections', 'evidence_files', 'orchestration_payload_bytes', 'complete_single_case_screen_ns', 'timing_boundary', 'workflow']
TIMING = 'preflight through one fresh proof, artifact roundtrip, independently reconstructed cap, CPU acceptance/mutations and retirement; excludes final summary serialization and process launch'

def audit_identity_provenance(case, proving, verification, mode):
    public_hash.validate_record(proving.get('public_hash'), expected_kernel='baseline')
    require(case.get('public_hash') == proving.get('public_hash'), 'workflow source hashing differs')
    if mode == 'baseline':
        require('identity_reuse_profile' not in case and 'identity_reuse' not in verification, 'baseline has reuse fields')
        public_hash.workflow_records(case, proving, verification, expected_kernel='baseline')
        return
    require(case.get('identity_reuse_profile') == PROFILE, 'wrong receipt profile')
    reuse=verification.get('identity_reuse')
    keys='profile identity_hint_hit full_identity_stream_checked public_preprocessing_reused reused_part fresh_preprocessing_cap prepared_program_reused proof_reused fresh_identity_gpu_hash prover_session_retired_before_verifier_start expected_statement_reconstructed lookup_digest receipt_payload_bytes source_admitted_host_bytes receipt_sublimit_bytes combined_metadata_limit_bytes idle_device_bytes receipt_retained_after_setup_bytes reuse_distance_registrations receipt_lifetime_ns registered_program_id source_public_hash verifier_fresh_public_hash'.split()
    fields(reuse,keys,'identity reuse receipt')
    for key in 'identity_hint_hit full_identity_stream_checked public_preprocessing_reused fresh_preprocessing_cap prover_session_retired_before_verifier_start expected_statement_reconstructed'.split():
        require(reuse[key] is True,'missing actual receipt condition: '+key)
    for key in ('prepared_program_reused','proof_reused','fresh_identity_gpu_hash'):
        require(reuse[key] is False,'receipt overclaims '+key)
    require(reuse['profile']==PROFILE and reuse['reused_part']=='protocol-program-identity-only'
            and reuse['lookup_digest']=='sha3-512-over-complete-canonical-identity-stream-v1','changed receipt contract')
    require(number(reuse['receipt_payload_bytes'],'receipt payload',1)==112,'receipt payload differs')
    require(reuse['receipt_sublimit_bytes']==1<<20 and reuse['combined_metadata_limit_bytes']==64<<20,'changed metadata limits')
    number(reuse['source_admitted_host_bytes'],'receipt source',112,(1<<20)-(32<<10))
    number(reuse['receipt_lifetime_ns'],'receipt lifetime',1)
    for key in ('idle_device_bytes','receipt_retained_after_setup_bytes','reuse_distance_registrations'):
        require(number(reuse[key],key)==0,'unexpected retained/reused state')
    require(reuse['registered_program_id']==case['descriptor']['registered_program_id'],'receipt identity differs')
    require(reuse['source_public_hash']==proving['public_hash'],'cached source provenance differs')
    require('public_hash' in verification,'missing fresh public-hash observation field')
    fresh=verification['public_hash']
    require(reuse['verifier_fresh_public_hash']==fresh,'fresh observation was relabeled')
    require(fresh is None,'receipt verifier observed fresh public hashing')


def caller_identity_charge(screen, proving, verification):
    charge=number(screen['source_identity_host_bytes'],'source identity bytes',112,(1<<20)-(32<<10))
    for report in (proving,verification):
        requested=number(report.get('caller_requested_bytes'),'caller requested bytes',1,1<<20)
        require(charge+(32<<10)<=requested,'identity and orchestration charge exceed actual caller reservation')


def identity_markers(content, mode):
    require(mode in SELECTORS, "unknown identity mode")
    sequence=[];full=[];miss=[];hit=[]
    for line in content.splitlines():
        if line.startswith('bounded_gpu_program_identity '):
            entry=tokens(line.split(" ",1)[1]);full.append(entry);sequence.append('hash')
            require(set(entry)=={"fields","batches","device_ns","uploaded_bytes","downloaded_bytes"},"unknown full hash fields")
            for key in ('fields','batches','device_ns','uploaded_bytes','downloaded_bytes'):
                number(entry.get(key), 'full identity '+key, 1)
        elif line.startswith('bounded_gpu_program_identity_reuse '):
            entry=tokens(line.split(" ",1)[1])
            require(entry.get('full_stream_checked') is True and entry.get('receipt_bytes')==112,'incomplete identity receipt marker')
            number(entry.get('fields'),'identity stream length',1)
            if entry.get('hit') is True:
                require(set(entry)=={'hit','fields','receipt_bytes','full_stream_checked'},'unknown hit fields')
                hit.append(entry);sequence.append('hit')
            else:
                require(set(entry)=={'hit','hint_present','fields','receipt_bytes','full_stream_checked'} and entry['hit'] is False and entry['hint_present'] is False,'unexpected miss/retry')
                miss.append(entry);sequence.append('miss')
        elif line.startswith('bounded_gpu_program_identity'):
            raise ValueError('unexpected additional identity marker')
    expected=['hash','miss','hit'] if mode=='receipt-v1' else ['hash','miss','hash','miss']
    require(sequence==expected,'missing, extra, reordered or retried identity execution')
    counts={int(item['fields']) for item in full+miss+hit}
    require(len(counts)==1,'identity stream coverage differs')
    return dict(full_gpu_identity_hashes=len(full),identity_receipt_hits=len(hit),identity_fields=next(iter(counts)),receipt_payload_bytes=112,raw_hash_device_ns=sum(int(item['device_ns']) for item in full))


def audit(path):
    output, content, evidence, mode=guard_record(Path(path))
    require(output.is_dir() and not output.is_symlink() and inventory(output,3)=={'identity-screen.json','preflight.json','case-0'},'unexpected output inventory')
    screen,screen_sha=report_file(output/'identity-screen.json')
    manifest,manifest_sha=report_file(output/'preflight.json')
    fields(screen,ROOT_FIELDS,'identity root report')
    require(screen['schema']=='lattica-research-direct-ring-identity-screen-v1' and screen['mode']==mode and screen['research_only'] is True,'wrong identity root')
    reused=mode=='receipt-v1'
    require(screen['public_preprocessing_reused'] is reused and screen['fresh_preprocessing_cap'] is True and screen['reused_preprocessing_part']==('protocol-program-identity-only' if reused else 'none'),'wrong preprocessing boundary')
    for key in ('complete_faithful_ringct_workflow','protocol_redesign_twofold_qualified','production_acceptance_changed','original_shared_ledger_receipt'):
        require(screen[key] is False,'unsupported scope: '+key)
    for key,value in dict(case_count=1,validated_gpu_registration_receipts=2,validated_gpu_proof_receipts=1,retired_gpu_sessions=2,independent_cpu_acceptances=1,mutation_rejections=2,identity_receipt_hits=int(reused),full_gpu_identity_hashes_required=1 if reused else 2,receipt_sublimit_bytes=1<<20,combined_metadata_limit_bytes=64<<20,caller_reserved_bytes=1<<20).items():
        require(number(screen[key],key)==value,'wrong counter/limit '+key)
    number(screen['source_identity_host_bytes'],'source identity bytes',112,(1<<20)-(32<<10))
    number(screen['orchestration_payload_bytes'],'orchestration',1,32<<10)
    require(screen['timing_boundary']==TIMING,'changed timing boundary')
    require(screen['evidence_files']==['case-0/proving.json','case-0/verification.json','case-0/workflow.json','case-0/proof.bin'],'changed evidence inventory')
    require(type(manifest) is list and len(manifest)==7 and manifest[0]==KNOWN_IDENTITY,'changed preflight fixture')
    folder=output/'case-0'
    require(folder.is_dir() and not folder.is_symlink() and inventory(folder,4)=={'workflow.json','proving.json','verification.json','proof.bin'},'missing/additional case evidence')
    reports={};hashes={'identity-screen.json':screen_sha,'preflight.json':manifest_sha}
    for name in ('workflow.json','proving.json','verification.json'):
        reports[name],hashes['case-0/'+name]=report_file(folder/name)
    case=reports['workflow.json'];proving=reports['proving.json'];verification=reports['verification.json']
    require(case==screen['workflow'],'workflow differs from summary')
    proof=folder/'proof.bin';require(proof.is_file() and not proof.is_symlink(),'missing proof')
    artifact=read(proof,(2<<20)+212);hashes['case-0/proof.bin']=sha(artifact)
    caller_identity_charge(screen,proving,verification)
    audit_case(case,proving,verification,artifact,0,evidence['physical_gpu_uuid'],mode)
    if reused:
        require(verification['identity_reuse']['source_admitted_host_bytes']==screen['source_identity_host_bytes'],'receipt source accounting differs')
        require(verification['identity_reuse']['receipt_lifetime_ns']<=case['complete_research_workflow_ns'],'receipt timer exceeds workflow')
    actual=identity_markers(content,mode)
    require(actual["identity_fields"]==50763347, "fixed fixture-0 identity stream coverage differs")
    summaries=[];tests=[];stages=[];devices=[]
    for line in content.splitlines():
        prefix='test '+SELECTORS[mode]+' ... '
        if line.startswith(prefix):line=line[len(prefix):]
        if line.startswith('DIRECT_RING_IDENTITY_SCREEN '):summaries.append(decode_json(line.removeprefix('DIRECT_RING_IDENTITY_SCREEN ')))
        if line.startswith('test result:'):tests.append(line)
        if line.startswith('proving_stage_report '):stages.append(decode_json(line.removeprefix('proving_stage_report ')))
        if line.startswith('bounded_gpu_identity '):devices.append(decode_json(line.removeprefix('bounded_gpu_identity ')))
    require(summaries==[screen],'saved/stdout report differs')
    require(len(tests)==1 and re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s',tests[0]),'wrong exact test result')
    require(stages==[proving['registration'],proving['proving'],verification['registration']],'raw GPU receipts differ or repeated')
    require(len(devices)==2 and all(d.get('uuid')==evidence['physical_gpu_uuid'] for d in devices),'wrong device sessions')
    total=number(screen['complete_single_case_screen_ns'],'screen time',1)
    require(total>=case['complete_research_workflow_ns'] and total<=evidence['guard_wall_seconds']*1e9,'screen time omits workflow or exceeds wall')
    return dict(schema='lattica-direct-ring-identity-evidence-audit-v1',research_only=True,complete_faithful_ringct_workflow=False,performance_qualified=False,source_executable_artifact_log_bound=True,mode=mode,evidence=evidence,file_sha256=hashes,actual_identity_execution=actual,screen=screen)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=audit(args.record)
    encoded=json.dumps(result,indent=2)+'\n'
    if args.output:
        with args.output.open('x') as stream:stream.write(encoded)
    else:print(encoded,end='')
