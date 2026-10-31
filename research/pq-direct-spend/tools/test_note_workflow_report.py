import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest

import note_workflow_report as report


def hash_of(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def line(tag, values):
    def scalar(value):
        if type(value) is bool:
            return "true" if value else "false"
        if value is None:
            return "none"
        return str(value)
    return tag + " " + " ".join(key + "=" + scalar(value) for key, value in values.items())


def fixture(backend, repetition=0):
    cpu = backend == report.CPU
    tag = "private_note_cpu_seven" if cpu else "private_note_seven"
    lines = []
    for ordinal in range(7):
        if not cpu:
            device = {"uuid": "GPU-00000000-0000-0000-0000-000000000001", "name": "NVIDIA GeForce RTX 5080"}
            lines.append("bounded_gpu_identity " + json.dumps(device))
            observed = [{"stage": stage, "backend": "open_cl", "calls": 1,
                         "completed_calls": 1, "device_calls": 1, "device_ns": 1}
                        for stage in sorted(report.STAGES)]
            observed.append({"stage": "serialization", "backend": "cpu", "calls": 1,
                             "completed_calls": 1, "device_calls": 0})
            stage = {"schema": "lattica-proving-stages-v1", "entry_point": "private_note_gpu", "policy": "gpu_required",
                     "succeeded": True, "stage_coverage_complete": True, "completion_rejected": False,
                     "observation_errors": 0, "elapsed_ns": 50, "components": [], "observations": observed,
                     "capabilities": {"scope": "proof_request", "profile": "legacy_quadratic", "max_log_fri_arity": 4,
                                      "stages": [{"stage": key, "backend": "open_cl"} for key in sorted(report.STAGES)]}}
            lines.append("proving_stage_report " + json.dumps(stage))
        lines.append(line("private_note_case_managed_memory", {
            "backend": backend, "ordinal": ordinal, "managed_device_peak_bytes": None if cpu else 100 + ordinal,
            "actual_process_device_peak_bytes": "external_guard_only"}))
        lines.append(line("private_note_seven_case_identity", {
            "backend": backend, "ordinal": ordinal, "fixture_recipe": report.RECIPE,
            "public_statement_digest": hash_of(("statement", ordinal)),
            "canonical_packet_hash": hash_of((backend, repetition, ordinal))}))
        case = {"ordinal": ordinal, **{key: 10 for key in report.TIMES},
                "native_dispatch_and_retirement_ns": 100, "reported_native_proof_scope_ns": 50,
                "prepare_through_payload_cleanup_ns": 200, "native_proof_bytes": 500,
                "native_proofs": 1, "recursive_proofs": 0, "active_rows": 2560, "padded_rows": 4096,
                "fresh_public_preparation": True, "proof_payloads_destroyed": True}
        if cpu:
            case.update({key: 5 for key in report.CPU_TIMES})
            case.update(cpu_required=True, gpu_work_performed=False)
        else:
            case["runtime_retired"] = True
        lines.append(line(tag + "_case", case))
    workflow = {"cases": 7, "distinct_statements": 7, "distinct_nullifiers": 14, "native_proofs": 7,
                "recursive_proofs": 0, "independent_cpu_verifications": 14, "canonical_roundtrips": 7,
                "fixture_generation_and_distinctness_ns": 100, "complete_note_research_workflow_ns": 2000,
                "host_payload_reservation_peak_bytes": 1 << 20, "report_retained_bytes": 1024,
                "actual_memory_source": "external_guard", "cpu_baseline_qualified": cpu,
                "complete_ringct_workflow": False, "production_acceptance": False}
    if cpu:
        workflow.update(native_gpu_runtimes=0, fresh_cpu_proof_configurations=7)
    lines.append(line(tag + "_workflow", workflow))
    lines.append(line("private_note_workflow_managed_memory", {
        "backend": backend, "managed_device_peak_bytes": None if cpu else 106,
        "source": "no_gpu_runtime" if cpu else "exact_retired_engine_max", "actual_process_device_peak_bytes": "external_guard_only"}))
    ending = {"original_quota_released": True, "all_proof_payloads_destroyed": True, "complete_ringct_workflow": False}
    ending.update({"all_cpu_configurations_destroyed": True, "gpu_work_performed": False} if cpu else {"all_native_runtimes_retired": True})
    lines.append(line(tag + "_workflow_terminal", ending))
    lines.append("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 0.01s")
    return "test " + report.SELECTORS[backend] + " ... " + "\n".join(lines)


def audited_runs():
    runs = []
    for index in range(6):
        backend = report.CPU if index % 2 == 0 else report.GPU
        run = report.audit_log(fixture(backend, index), backend)
        run["evidence"] = {
            "source_snapshot_sha256": hash_of("source"), "executable_path": "/fixed/binary",
            "executable_sha256": hash_of("binary"), "build_record_sha256": hash_of("build"),
            "memory_max_bytes": 45 * report.GIB, "memory_high_bytes": 43 * report.GIB, "guard_profile": "direct-full",
            "record_sha256": hash_of(index), "started_utc": f"2026-10-25T00:00:{2 * index:02}+00:00",
            "finished_utc": f"2026-10-25T00:00:{2 * index + 1:02}+00:00", "guard_wall_seconds": 1.0,
            "environment": {"policy": backend, **({"LATTICA_GPU_DEVICE_UUID": run["device_identity"]["uuid"]} if backend == report.GPU else {})}}
        runs.append(run)
    return runs


def evidence_bundle(root, backend=report.CPU, plan=None):
    """Synthetic immutable-style guard evidence; creates no executable/worker."""
    binary = plan["command"][0] if plan else str(root / ".tools/target-opencl/release/deps/lattica_pq_direct_spend_research-synthetic")
    log = root / "cpu.log"
    log.write_text(fixture(backend))
    build_log = root / "build.log"
    build_log.write_text("synthetic build record fixture\n")
    build_path = root / "build.json"
    environment = {"PATH": "/home/access/code/lattica/.tools/rust-1.96.0/bin:/usr/bin:/bin", "HOME": "/home/access",
                   "CARGO_HOME": str(root / ".tools/cargo-opencl"), "CARGO_TARGET_DIR": str(root / ".tools/target-opencl"),
                   "CARGO_BUILD_JOBS": "2", "RAYON_NUM_THREADS": "8", "LATTICA_PROVING_REPORT": "1", "LATTICA_PROVING_POLICY": "cpu-required"}
    if plan is not None:
        environment = dict(plan["environment"])
    base = {"schema": "pq-opencl-optimization-correctness-job-v2", "status": "passed", "error": None,
            "launch": True, "source_inputs_unchanged": True, "executable_unchanged": True,
            "all_subprocesses_terminal_and_reaped": True, "service_stop_completed": True,
            "memory_max_bytes": 45 * report.GIB, "memory_high_bytes": 43 * report.GIB,
            "cpu_quota": "800%", "input_sha256": dict(report.SOURCE_PINS), "process_admission": {"conflicts": []},
            "terminal_state": {"Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
                               "MainPID": "0", "ControlPID": "0", "NRestarts": "0", "MemorySwapMax": "0",
                               "MemoryMax": str(45 * report.GIB), "MemoryHigh": str(43 * report.GIB), "MemoryPeak": "1024"},
            "post_stop_state": {"MainPID": "0", "ControlPID": "0", "ControlGroup": "", "ActiveState": "inactive", "SubState": "dead"}}
    build = dict(base, profile="build", cpu_quota="200%", raw_log=str(build_log),
                 raw_log_sha256=report.sha(build_log.read_bytes()), built_artifact_sha256={binary: hash_of("binary")})
    build_path.write_text(json.dumps(build))
    command = [binary, report.SELECTORS[backend], "--exact", "--ignored", "--test-threads=1", "--nocapture"]
    encoded = b"".join((key + "=" + environment[key] + "\0").encode() for key in sorted(environment))
    properties = {"Type": "exec", "RemainAfterExit": "yes", "Restart": "no", "MemoryMax": str(45 * report.GIB),
                  "MemoryHigh": str(43 * report.GIB), "MemorySwapMax": "0", "CPUQuota": "800%", "TasksMax": "256",
                  "RuntimeMaxSec": "7200", "TimeoutStopSec": "10", "KillMode": "control-group", "WorkingDirectory": str(Path(binary).parents[4]),
                  "StandardOutput": "append:" + str(log), "StandardError": "inherit"}
    record = dict(base, profile="direct-full", command=command, environment=environment, expect_tests=True, benchmark=False,
                  expect_result=False, expect_direct_result=False, comparison_baseline=False, performance_qualified=False,
                  unit="synthetic.service", runtime_seconds=7200, raw_log=str(log), raw_log_sha256=report.sha(log.read_bytes()),
                  started_utc="2026-10-25T00:00:00+00:00", finished_utc="2026-10-25T00:00:01+00:00", wall_seconds=1.0,
                  executable_provenance={"path": binary, "sha256": hash_of("binary"), "build_record": str(build_path),
                                         "build_record_sha256": report.sha(build_path.read_bytes())},
                  note_startup_environment=None, owned_runtime_environment=None,
                  note_cpu_environment={"schema": "private-note-cpu-workflow-environment-v1", "sha256_sorted_name_equals_value_nul": report.sha(encoded),
                                            "entry_count": len(environment), "serialized_bytes": len(encoded),
                                            "requires_env_clear_before_exec": True, "requires_immutable_environment_after_exec": True,
                                            "physical_identity_verified": False, "complete_external_admission": False, "dispatch_authority": False})
    if plan is not None:
        for key in ("note_startup_environment", "note_cpu_environment", "owned_runtime_environment"):
            record[key] = plan[key]
    record["service_command"] = ["/usr/bin/systemd-run", "--user", "--quiet", "--unit=synthetic.service"]
    record["service_command"] += ["--property=" + key + "=" + value for key, value in properties.items()]
    record["service_command"] += ["/usr/bin/env", "-i", *[key + "=" + value for key, value in environment.items()], *command]
    path = root / "cpu.json"
    path.write_text(json.dumps(record))
    return path, record


class NoteWorkflowReportTests(unittest.TestCase):
    def test_real_guard_plans_use_exact_backend_receipts_without_running_workers(self):
        path = Path(__file__).resolve().parents[2] / "pq-ringct/tools/opencl_private_spend_validate.py"
        spec = importlib.util.spec_from_file_location("note_report_real_guard", path)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        # build_plan only constructs policy data. execute() is never called;
        # there is no command execution, device query, binary or proving.
        for backend in (report.CPU, report.GPU):
            binary = str(guard.ROOT / ".tools/target-opencl/release/deps/lattica_pq_direct_spend_research-synthetic")
            arguments = types.SimpleNamespace(
                profile="direct-full", label="note-report-plan-fixture", seconds=7200,
                command=[binary, report.SELECTORS[backend], "--exact", "--ignored", "--test-threads=1", "--nocapture"],
                expect_tests=True, expect_result=False, execute=True, exclusive_window=True,
                build_label="synthetic-build", record_artifact=[],
                note_workflow_cpu=backend == report.CPU, note_owned_proof=backend == report.GPU,
                owned_runtime_test=None,
                device_uuid="GPU-00000000-0000-0000-0000-000000000001" if backend == report.GPU else None)
            plan = guard.build_plan(arguments)
            field = "note_cpu_environment" if backend == report.CPU else "note_startup_environment"
            self.assertIsInstance(plan[field], dict)
            with tempfile.TemporaryDirectory() as directory:
                record_path, record = evidence_bundle(Path(directory), backend, plan)
                content, _ = report.guarded_record(record_path, backend)
                report.audit_log(content, backend)
                # Each other mode must be explicitly absent, including the
                # runtime-only guard which must not masquerade as a note run.
                for other in {"note_cpu_environment", "note_startup_environment", "owned_runtime_environment"} - {field}:
                    changed = dict(record, **{other: plan[field]})
                    record_path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        report.guarded_record(record_path, backend)

    def test_exact_seven_case_screen_and_repetitions_keep_adoption_false(self):
        runs = audited_runs()
        for subset in (runs[:2], runs):
            result = report.compare(subset)
            self.assertEqual(len(result["case_medians"]), 7)
            self.assertEqual(result["cpu_over_gpu_complete_workflow_ratio"], 1)
            for key in ("complete_ringct_workflow", "qualified_faithful_ringct_workflow", "protocol_redesign_speedup_qualified",
                        "research_adoption_qualified", "production_acceptance", "performance_promoted"):
                self.assertIs(result[key], False)

    def test_complete_and_each_case_median_use_all_three_observations(self):
        runs = audited_runs()
        for index, multiplier in enumerate((2, 1, 4, 1, 3, 1)):
            runs[index]["workflow"]["complete_note_research_workflow_ns"] *= multiplier
            for case in runs[index]["cases"]:
                case["prepare_through_payload_cleanup_ns"] *= multiplier
        result = report.compare(runs)
        self.assertEqual(result["cpu_median_complete_note_research_workflow_ns"], 6000)
        self.assertEqual(result["cpu_over_gpu_complete_workflow_ratio"], 3)
        self.assertTrue(all(case["cpu_over_gpu_case_ratio"] == 3 for case in result["case_medians"]))
        self.assertIs(result["research_adoption_qualified"], False)

    def test_every_case_identity_is_matched(self):
        for ordinal in range(7):
            runs = audited_runs()
            runs[1]["cases"][ordinal]["public_statement_digest"] = hash_of("changed")
            with self.assertRaises(ValueError):
                report.compare(runs)

    def test_source_binary_build_limits_and_environment_mismatches_fail(self):
        for key in ("source_snapshot_sha256", "executable_path", "executable_sha256", "build_record_sha256", "memory_max_bytes", "memory_high_bytes", "guard_profile"):
            runs = audited_runs()
            runs[1]["evidence"][key] = "changed"
            with self.assertRaises(ValueError):
                report.compare(runs)
        runs = audited_runs()
        runs[2]["evidence"]["environment"]["extra"] = "1"
        with self.assertRaises(ValueError):
            report.compare(runs)

    def test_wrong_order_overlaps_and_reused_packets_are_rejected(self):
        for mutation in ("order", "overlap", "packet", "record"):
            runs = audited_runs()
            if mutation == "order":
                runs[1], runs[2] = runs[2], runs[1]
            elif mutation == "overlap":
                runs[1]["evidence"]["started_utc"] = runs[0]["evidence"]["started_utc"]
            elif mutation == "packet":
                runs[1]["cases"][0]["canonical_packet_hash"] = runs[0]["cases"][0]["canonical_packet_hash"]
            else:
                runs[1]["evidence"]["record_sha256"] = runs[0]["evidence"]["record_sha256"]
            with self.assertRaises(ValueError):
                report.compare(runs)

    def test_missing_duplicate_reordered_and_wrong_backend_markers_fail(self):
        raw = fixture(report.CPU)
        matching = [line for line in raw.splitlines() if line.startswith("private_note_cpu_seven_case ")]
        for changed in (raw.replace(matching[0] + "\n", ""), raw + "\n" + matching[0],
                        raw.replace("ordinal=0", "ordinal=6"), raw.replace("backend=fresh_cpu_required", "backend=fresh_gpu_required")):
            with self.assertRaises(ValueError):
                report.audit_log(changed, report.CPU)

    def test_numeric_types_memory_scope_and_cleanup_fail_closed(self):
        raw = fixture(report.CPU)
        for old, new in (("ordinal=1", "ordinal=true"), ("native_proofs=1", "native_proofs=true"),
                         ("managed_device_peak_bytes=none", "managed_device_peak_bytes=0"),
                         ("original_quota_released=true", "original_quota_released=1"),
                         ("actual_process_device_peak_bytes=external_guard_only", "actual_process_device_peak_bytes=0"),
                         ("prepare_through_payload_cleanup_ns=200", "prepare_through_payload_cleanup_ns=1")):
            with self.assertRaises(ValueError):
                report.audit_log(raw.replace(old, new), report.CPU)

    def test_gpu_native_execution_and_managed_peak_are_checked(self):
        raw = fixture(report.GPU)
        for old, new in (("managed_device_peak_bytes=106", "managed_device_peak_bytes=107"),
                         ('"device_calls": 1', '"device_calls": 0'), ('"max_log_fri_arity": 4', '"max_log_fri_arity": 5'),
                         ('"succeeded": true', '"succeeded": false'), ('"NVIDIA GeForce RTX 5080"', '"other GPU"')):
            with self.assertRaises(ValueError):
                report.audit_log(raw.replace(old, new, 1), report.GPU)

    def test_json_duplicate_keys_and_nonfinite_values_are_rejected(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.assertRaises(ValueError):
                report.decode_json(raw)

    def test_changed_fixed_environment_is_rejected(self):
        command = ["/campaign/.tools/target-opencl/release/deps/lattica_pq_direct_spend_research-hash"]
        environment = {"PATH": "/home/access/code/lattica/.tools/rust-1.96.0/bin:/usr/bin:/bin", "HOME": "/home/access",
                       "CARGO_HOME": "/campaign/.tools/cargo-opencl", "CARGO_TARGET_DIR": "/campaign/.tools/target-opencl",
                       "CARGO_BUILD_JOBS": "2", "RAYON_NUM_THREADS": "8", "LATTICA_PROVING_REPORT": "1", "LATTICA_PROVING_POLICY": "cpu-required"}
        report.expected_environment(command, report.CPU, environment)
        for key, value in (("RAYON_NUM_THREADS", "2"), ("LATTICA_PROVING_POLICY", "gpu-required"), ("LATTICA_V2_GPU_HASH", "1")):
            changed = dict(environment, **{key: value})
            with self.assertRaises(ValueError):
                report.expected_environment(command, report.CPU, changed)

    def test_record_reader_binds_workflow_and_build_log_bytes(self):
        for which in ("workflow", "build"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, record = evidence_bundle(root)
                content, evidence = report.guarded_record(path, report.CPU)
                self.assertEqual(content, fixture(report.CPU))
                self.assertEqual(evidence["raw_log_sha256"], record["raw_log_sha256"])
                target = root / ("cpu.log" if which == "workflow" else "build.log")
                target.write_bytes(target.read_bytes() + b"changed")
                with self.assertRaises(ValueError):
                    report.guarded_record(path, report.CPU)

    def test_record_reader_rejects_source_limits_selector_and_cleanup_mutations(self):
        for mutation in ("source", "swap", "duplicate_property", "selector", "cleanup", "build_record"):
            with tempfile.TemporaryDirectory() as directory:
                path, record = evidence_bundle(Path(directory))
                if mutation == "source":
                    record["input_sha256"].pop(next(iter(report.SOURCE_PINS)))
                elif mutation == "swap":
                    record["terminal_state"]["MemorySwapMax"] = "1"
                elif mutation == "duplicate_property":
                    record["service_command"].insert(4, "--property=MemoryMax=1")
                elif mutation == "selector":
                    record["command"][1] = "note_gpu"
                elif mutation == "cleanup":
                    record["post_stop_state"]["ControlPID"] = "123"
                else:
                    record["executable_provenance"]["build_record_sha256"] = hash_of("changed")
                path.write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    report.guarded_record(path, report.CPU)


if __name__ == "__main__":
    unittest.main()
