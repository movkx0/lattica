"""Synthetic consistency evidence only: no worker, GPU work, or valid proof."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

import ring_screen_report as report
from test_note_workflow_report import evidence_bundle

# Reuse the already audited direct-artifact fixture and complete phase census.
# Importing these definitions never runs a guard, a test, or a proof.
RING_TOOLS = Path(__file__).resolve().parents[2] / "pq-ringct/tools"
sys.path.insert(0, str(RING_TOOLS))
import test_opencl_private_spend_direct as direct_fixture

PIN = "GPU-11111111-1111-1111-1111-111111111111"


def case_bundle(index):
    old, proving, verification, artifact = direct_fixture.DirectResearchPolicyTests().evidence()
    packet = bytearray(artifact)
    packet[44:76] = bytes([0x73] * 32)
    packet[-1] = index  # Distinct synthetic bytes, not a cryptographic proof.
    artifact = bytes(packet)
    verification["expected_context"] = [0x73] * 32
    proving["device"] = {"uuid": PIN}
    proving.update(admission_ns=1, session_start_ns=1, teardown_ns=1,
                   setup_ns=1, proving_ns=1, total_proving_lifecycle_ns=6)
    verification.update(reconstruction_ns=1, gpu_preprocessing_ns=1,
                        admission_ns=1, session_start_ns=1, teardown_ns=1,
                        cpu_verification_ns=1, mutation_checks_ns=1,
                        total_verification_lifecycle_ns=8)
    identity = {"case": index, "statement_sha3_256": [index + 1] * 32,
                "serials": [[2 * index + 1] * 32, [2 * index + 2] * 32]}
    case = {"schema": report.CASE_SCHEMA, "identity": identity, "research_only": True,
            "complete_faithful_ringct_workflow": False, "recursive_aggregate_proofs": 0,
            "fresh_relation_proofs": 1, "proof_generation": "fresh-only", "proving_policy": "gpu_required",
            "public_hash": old["public_hash"], "descriptor": verification["descriptor"],
            "public_binding": verification["expected_public_binding"], "independent_cpu_verified": True,
            "reused_prover_state": False, "artifact_roundtrip": True, "cryptographic_mutation_checks": 2,
            "artifact_bytes": len(artifact), "artifact_sha3_256": list(hashlib.sha3_256(artifact).digest()),
            "encode_required_host_bytes": old["artifact_encode_required_host_bytes"],
            "decode_required_host_bytes": old["artifact_decode_required_host_bytes"],
            "fixture_regeneration_ns": 1, "compilation_ns": 1, "prover_setup_ns": 1,
            "proving_ns": 1, "prover_lifecycle_ns": 6, "codec_and_disk_ns": 1,
            "verifier_reconstruction_ns": 1, "verifier_setup_ns": 1, "cpu_verification_ns": 1,
            "mutation_checks_ns": 1, "verifier_lifecycle_ns": 8, "complete_research_workflow_ns": 20,
            "prover_terminal": copy.deepcopy(proving["terminal"]),
            "verifier_terminal": copy.deepcopy(verification["terminal"])}
    return case, proving, verification, artifact


def suite_bundle():
    cases = [case_bundle(i) for i in range(7)]
    manifest = [copy.deepcopy(case[0]["identity"]) for case in cases]
    suite = {"schema": report.SCHEMA, "profile": report.PROFILE,
             "representation": report.direct.REPRESENTATION, "context": [0x73] * 32,
             "research_only": True, **dict.fromkeys(report.FALSE_SCOPE, False),
             "recursive_aggregate_proofs": 0, "fresh_relation_proofs": 7,
             "distinct_public_statements": 7, "distinct_serials": 14,
             "public_hash_kernel": "baseline", "caller_reserved_bytes": 1 << 20,
             "orchestration_payload_bytes": 1024,
             "fixture_staging": {"ring_backing_bytes": 1, "native_parameter_bytes": 1,
                                 "aes_stream_bytes": 1, "inline_payload_bytes": 1,
                                 "required_host_bytes": (32 << 10) + 4},
             "process_host_peak_bytes": None, "managed_gpu_peak_bytes": 123,
             "preflight_fixture_generation_ns": 10, "complete_seven_case_screen_ns": 160,
             "timing_boundary": report.TIMING, "manifest": copy.deepcopy(manifest),
             "cases": [copy.deepcopy(case[0]) for case in cases]}
    return suite, manifest, cases


def write_bundle(path, bundle):
    suite, manifest, cases = bundle
    path.mkdir(parents=True)
    (path / "screen.json").write_text(json.dumps(suite))
    (path / "preflight.json").write_text(json.dumps(manifest))
    for index, (case, proving, verification, artifact) in enumerate(cases):
        directory = path / f"case-{index}"
        directory.mkdir()
        for name, value in (("workflow", case), ("proving", proving), ("verification", verification)):
            (directory / (name + ".json")).write_text(json.dumps(value))
        (directory / "proof.bin").write_bytes(artifact)
    return "DIRECT_RING_SEVEN_CASE_SCREEN " + json.dumps(suite) + "\n" + (
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 31 filtered out; finished in 0.01s\n")


def guard_bundle(root):
    path, record = evidence_bundle(root)
    output = root / ".tools/pq-opencl-opt/artifacts/synthetic-screen"
    content = write_bundle(output, suite_bundle())
    Path(record["raw_log"]).write_text(content)
    record.update(label="synthetic-screen", public_hash_kernel="baseline",
                  fresh_memavailable_required_bytes=47 * report.GIB,
                  input_sha256=dict(report.SOURCE_PINS), note_cpu_environment=None,
                  raw_log_sha256=report.sha(content.encode()))
    record["command"][1] = report.SELECTOR
    environment = report.expected_environment(root, output, PIN)
    record["environment"] = environment
    encoded = b"".join((key + "=" + environment[key] + "\0").encode() for key in sorted(environment))
    record["direct_ring_screen_environment"] = {
        "schema": "direct-ring-seven-case-screen-environment-v1", "selector": report.SELECTOR,
        "output_directory": str(output), "entry_count": len(environment), "serialized_bytes": len(encoded),
        "sha256_sorted_name_equals_value_nul": report.sha(encoded), "requires_env_clear_before_exec": True,
        "requires_immutable_environment_after_exec": True, "complete_faithful_ringct_workflow": False,
        "n3_n4_aggregate_qualification": False, "performance_qualified": False, "dispatch_authority": False}
    service = record["service_command"]
    record["service_command"] = service[:service.index("/usr/bin/env")] + [
        "/usr/bin/env", "-i", *[key + "=" + value for key, value in environment.items()], *record["command"]]
    provenance = record["executable_provenance"]
    build_path = Path(provenance["build_record"])
    build = json.loads(build_path.read_bytes())
    build["input_sha256"] = dict(report.SOURCE_PINS)
    build_path.write_text(json.dumps(build))
    provenance["build_record_sha256"] = report.sha(build_path.read_bytes())
    path.write_text(json.dumps(record))
    return path, record


class RingScreenReportTests(unittest.TestCase):
    def check_directory(self, bundle=None):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "screen"
            content = write_bundle(path, bundle or suite_bundle())
            return report.audit_directory(path, content, PIN)

    def test_seven_consistent_cases_keep_research_scope_and_all_owners(self):
        result = self.check_directory()
        self.assertEqual(result["retired_gpu_sessions"], 14)
        self.assertEqual(result["fresh_relation_gpu_proofs"], 7)
        self.assertEqual(result["independent_cpu_acceptances"], 7)
        self.assertEqual(result["cryptographic_mutation_rejections"], 14)
        self.assertEqual(result["recursive_proofs"], 0)
        self.assertEqual(len(result["file_sha256"]), 30)
        for key in report.FALSE_SCOPE:
            self.assertIs(result["screen"][key], False)

    def test_duplicate_reordered_missing_or_false_scope_suite_refuses(self):
        mutations = [
            lambda s, m, c: m.reverse(),
            lambda s, m, c: m[1].update(statement_sha3_256=m[0]["statement_sha3_256"]),
            lambda s, m, c: m[1]["serials"].__setitem__(0, m[0]["serials"][1]),
            lambda s, m, c: m[0]["serials"].__setitem__(1, m[0]["serials"][0]),
            lambda s, m, c: s["cases"].pop(),
            lambda s, m, c: s.update(fresh_relation_proofs=True),
            lambda s, m, c: s.update(protocol_redesign_twofold_qualified=True),
            lambda s, m, c: s.update(managed_gpu_peak_bytes=122),
            lambda s, m, c: s.update(complete_seven_case_screen_ns=84),
            lambda s, m, c: s.update(public_hash_kernel="sbox-pair-v1"),
        ]
        for index, mutate in enumerate(mutations):
            suite, manifest, cases = suite_bundle()
            mutate(suite, manifest, cases)
            suite["manifest"] = copy.deepcopy(manifest)
            for ordinal, identity in enumerate(manifest):
                cases[ordinal][0]["identity"] = copy.deepcopy(identity)
                if ordinal < len(suite["cases"]):
                    suite["cases"][ordinal]["identity"] = copy.deepcopy(identity)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.check_directory((suite, manifest, cases))

    def test_native_scope_terminal_device_bounds_and_timer_mutations_refuse(self):
        mutations = [
            lambda c, p, v: p["terminal"].update(completion_claimed=False),
            lambda c, p, v: v["terminal"].update(completion_claimed=True),
            lambda c, p, v: v["terminal"].update(queue_drained=False),
            lambda c, p, v: p["registration"]["observations"].pop(),
            lambda c, p, v: p["proving"]["observations"][0].update(backend="cpu"),
            lambda c, p, v: v["registration"]["observations"][0].update(device_calls=0),
            lambda c, p, v: p["device"].update(uuid="GPU-00000000-0000-0000-0000-000000000001"),
            lambda c, p, v: v["footprint"].update(physical_device_uuid=[0] * 16),
            lambda c, p, v: p["footprint"].update(host_phase_bound_complete=False),
            lambda c, p, v: p["footprint"].update(managed_limit_bytes=9 * report.GIB),
            lambda c, p, v: v["footprint"]["opening_phases"].update(query_device_peak_bytes=9 * report.GIB),
            lambda c, p, v: p["footprint"].update(native_host_budget_bytes=24 * report.GIB),
            lambda c, p, v: v.update(reused_prover_state=True),
            lambda c, p, v: v.update(mutation_checks=1),
            lambda c, p, v: c.update(complete_research_workflow_ns=10),
            lambda c, p, v: c.update(prover_setup_ns=2),
            lambda c, p, v: p.pop("admission_ns"),
            lambda c, p, v: v.update(teardown_ns=1000),
            lambda c, p, v: c.update(encode_required_host_bytes=c["encode_required_host_bytes"] - 1),
        ]
        for index, mutate in enumerate(mutations):
            case, proving, verification, artifact = case_bundle(0)
            mutate(case, proving, verification)
            case["prover_terminal"] = copy.deepcopy(proving["terminal"])
            case["verifier_terminal"] = copy.deepcopy(verification["terminal"])
            with self.subTest(index=index), self.assertRaises(ValueError):
                report.audit_case(case, proving, verification, artifact, 0, PIN)

    def test_rehashed_artifact_header_mutations_refuse(self):
        for offset in (0, 8, 40, 44, 76, 108, 116, 124, 132, 140, 172, 204, 219):
            case, proving, verification, artifact = case_bundle(0)
            changed = bytearray(artifact)
            changed[offset] ^= 1
            case["artifact_sha3_256"] = list(hashlib.sha3_256(changed).digest())
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                report.audit_case(case, proving, verification, bytes(changed), 0, PIN)

    def test_duplicate_fresh_packet_and_changed_packet_digest_refuse(self):
        suite, manifest, cases = suite_bundle()
        case, proving, verification, _ = cases[1]
        duplicate = cases[0][3]
        case["artifact_sha3_256"] = list(hashlib.sha3_256(duplicate).digest())
        cases[1] = case, proving, verification, duplicate
        suite["cases"][1] = copy.deepcopy(case)
        with self.assertRaises(ValueError):
            self.check_directory((suite, manifest, cases))
        case, proving, verification, artifact = case_bundle(0)
        with self.assertRaises(ValueError):
            report.audit_case(case, proving, verification, artifact[:-1] + b"x", 0, PIN)

    def test_extra_failure_symlink_and_duplicate_stdout_evidence_refuse(self):
        for kind in ("failure", "extra", "symlink", "stdout", "test", "json"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "screen"
                content = write_bundle(path, suite_bundle())
                if kind == "failure":
                    (path / "case-0/failure.json").write_text("{}")
                elif kind == "extra":
                    (path / "extra.json").write_text("{}")
                elif kind == "symlink":
                    proof = path / "case-0/proof.bin"
                    moved = Path(temporary) / "moved.bin"
                    proof.rename(moved)
                    proof.symlink_to(moved)
                elif kind == "stdout":
                    content += content.splitlines()[0] + "\n"
                elif kind == "test":
                    content += content.splitlines()[1] + "\n"
                else:
                    (path / "screen.json").write_text('{"schema":1,"schema":2}')
                with self.assertRaises(ValueError):
                    report.audit_directory(path, content, PIN)

    def test_guarded_evidence_binding_and_no_adoption_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = guard_bundle(Path(temporary))
            result = report.audit(path)
            self.assertEqual(result["retired_gpu_sessions"], 14)
            self.assertIs(result["protocol_redesign_twofold_qualified"], False)
            self.assertIs(result["production_adoption_qualified"], False)
            self.assertEqual(result["evidence"]["guarded_cgroup_host_peak_bytes"], 1024)
            self.assertIsNone(result["evidence"]["process_device_peak_bytes"])

    def test_changed_guard_sources_binary_log_environment_and_cleanup_refuse(self):
        mutations = [
            lambda r: r["input_sha256"].update({next(iter(report.SOURCE_PINS)): "0" * 64}),
            lambda r: r["executable_provenance"].update(sha256="0" * 64),
            lambda r: r.update(raw_log_sha256="0" * 64),
            lambda r: r.update(note_cpu_environment={}),
            lambda r: r["command"].__setitem__(1, "another::test"),
            lambda r: r["environment"].update(LATTICA_V2_GPU_MANAGED_BYTES=str(9 * report.GIB)),
            lambda r: r["service_command"].remove("-i"),
            lambda r: r["direct_ring_screen_environment"].update(dispatch_authority=True),
            lambda r: r["post_stop_state"].update(MainPID="1"),
            lambda r: r["terminal_state"].update(MemorySwapMax="1"),
            lambda r: r.update(source_inputs_unchanged=False),
            lambda r: r.update(finished_utc="2026-10-24T00:00:00+00:00"),
            lambda r: r.update(wall_seconds=True),
            lambda r: r.update(wall_seconds=-1),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                path, record = guard_bundle(Path(temporary))
                mutate(record)
                path.write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    report.guard_record(path)


if __name__ == "__main__":
    unittest.main()
