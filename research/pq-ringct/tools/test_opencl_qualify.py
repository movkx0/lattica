"""Admission and evidence checks without invoking a compiler or GPU."""
import importlib.util
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("opencl_qualify", Path(__file__).with_name("opencl_qualify.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def arguments(**overrides):
    values = dict(stage="aggregate", target="aggregate", mode="diagnostic", execute=False,
                  relation="pq-byte",
                  device_index=0, device_mib=2048, host_mib=4096, max_rows=1048576,
                  seconds=1800, output=Path("/tmp/output.postcard"), fixture=Path("/tmp/fixture.json"),
                  cache_dir=Path("/tmp/cache"), count=3, native_mib=32768)
    values.update(overrides)
    return SimpleNamespace(**values)


def aggregate_evidence(directory):
    """Synthetic aggregate payload plus actual byte-probe GPU wire reports.

    This exercises the evidence parser, never cryptographic proof validity.
    """
    output = Path(directory) / "synthetic.postcard"
    payload = b"synthetic parser-test artifact, not a proof"
    output.write_bytes(payload)
    args = arguments(output=output)
    fixture = Path(__file__).with_name("fixtures") / "opencl-byte-v2-stage-reports.json"
    original = json.loads(fixture.read_text())["reports"]
    reports = [copy.deepcopy(report) for _ in range(3) for report in original]
    result = {
        "schema": "lattica-pq-opencl-recursive-aggregation-v1", "mode": "diagnostic",
        "passed": True, "cpu_verification": True, "changed_public_rejected": True,
        "changed_proof_rejected": True, "strict_stage_reports_required": True,
        "complete_ledger_transaction_qualified": False, "original_profile": True,
        "num_queries": 128, "blowup": 16, "extension": "Goldilocks cubic trinomial",
        "hiding": True, "proof_count": 3, "recursive_depth": 2,
        "complete_matrict_relation_qualified": False, "ordered_public_value_count": 3,
        "decoded_verification_after_gpu_shutdown": True,
        "layers": [{
            "depth": depth, "rows": 64 << depth,
            "changed_public_rejected_count": depth + 1,
            "strict_gpu_request": True, "actual_stark_proof": True,
            "cpu_verification": True, "changed_public_rejected": True,
            "changed_proof_rejected": True, "prepared_proving_state_dropped": True,
        } for depth in range(3)],
        "recursive_witness_checks": [{
            "child_index": 0, "mutated_field": "trace_local[0].basis[0]",
            "execution_error": "Unsatisfied", "original_witness_restored": True,
            "same_compiled_program": True, "public_values_unchanged": True,
            "valid_parent_positive_control": True, "negative_stark_proof_generated": False,
            "evaluation_budget_bytes": runner.GIB, "principal_buffer_bound_bytes": 1024,
        }],
        "session": {
            "host_allowance_bytes": args.host_mib << 20,
            "device_allowance_bytes": args.device_mib << 20,
            "gpu_context_allowance_bytes": 4 * runner.GIB, "max_rows": args.max_rows,
            "commits": 3, "allocations": 3, "managed_peak_bytes": 1 << 20,
            "device": {"opencl_index": 0, "name": "parser test device",
                       "driver": "parser test driver", "max_allocation_bytes": 1 << 30,
                       "global_bytes": 16 * runner.GIB},
        },
        "artifact": {"path": str(output), "decoded_payload_reverified": True,
                     "includes_trusted_registered_key": False, "bytes": len(payload),
                     "sha3_256": hashlib.sha3_256(payload).hexdigest()},
    }
    return args, reports, result


def aggregate_log(directory, reports, result):
    path = Path(directory) / "aggregate.log"
    path.write_text("".join("proving_stage_report " + json.dumps(report) + "\n"
                            for report in reports) + json.dumps(result) + "\n")
    return path


def synthetic_gpu_report(entry, scope, stages):
    """Synthetic wire receipt for parser tests, not cryptographic GPU evidence."""
    return {
        "schema": "lattica-proving-stages-v1", "entry_point": entry,
        "policy": "gpu_required", "succeeded": True, "stage_coverage_complete": True,
        "completion_rejected": False, "observation_errors": 0, "components": [],
        "capabilities": {"profile": "block_v2_cubic", "scope": scope,
                         "stages": [{"stage": stage, "backend": "open_cl"} for stage in sorted(stages)]},
        "observations": [{"stage": stage, "backend": "open_cl", "calls": 1,
                          "completed_calls": 1, "device_calls": 1}
                         for stage in sorted(stages)],
    }


def report_line(report):
    return "proving_stage_report " + json.dumps(report)


def phase_index(events, name):
    return next(index for index, line in enumerate(events)
                if line.startswith("OPENCL_AGGREGATION ")
                and json.loads(line.removeprefix("OPENCL_AGGREGATION "))["event"] == name)


def report_indices(events, entry=None):
    return [index for index, line in enumerate(events)
            if line.startswith("proving_stage_report ")
            and (entry is None or json.loads(line.removeprefix("proving_stage_report "))["entry_point"] == entry)]


def full_evidence(directory, count):
    args, reports, result = aggregate_evidence(directory)
    args.mode, args.count = "matrict", count
    args.host_mib, args.device_mib = 32768, 8192
    args.fixture = Path(directory) / "synthetic-fixture.json"
    args.fixture.write_text('{"scope":"synthetic parser fixture, not a native proof"}')
    args.cache_dir = Path(directory) / "cache"
    args.cache_dir.mkdir()
    source = "ab" * 32
    (args.cache_dir / ".opencl-compiled-source-identity").write_text(source)
    for key in ("layers", "proof_count", "recursive_depth", "recursive_witness_checks",
                "ordered_public_value_count"):
        result.pop(key)
    topology = [([[0, 1], [1, 1]], [0, 2], 1, 0)]
    topology += ([([[0, 2], [2, 1]], [0, 3], 2, 1)] if count == 3 else
                 [([[2, 1], [3, 1]], [2, 2], 1, 0), ([[0, 2], [2, 2]], [0, 4], 2, 2)])
    cache = {"policy": "fresh_only", "families": {
        family: {"reads": 0, "hits": 0, "proof_attempts": 1, "fresh_proofs": 1}
        for family in ("sources", "algebra", "crypto", "auxiliary", "outer")}}
    result.update(mode="matrict", count=count, merge_count=count - 1,
                  complete_matrict_relation_qualified=True, repeated_standalone_relation=True,
                  registered_graph_leaves=91, changed_public_rejected_count=25,
                  original_graph_dropped_before_final_verification=True,
                  gpu_child_preparation_seconds=12.5, child_preparation_backend="opencl",
                  source_identity=source, cache=cache, fresh_complete_graph_proofs=1,
                  unique_fixture_statements=1, repeated_child_proof=True,
                  fresh_distinct_transaction_qualified=False,
                  fixture_pattern="repeated_single_fixture",
                  fixture_sha3_256=hashlib.sha3_256(args.fixture.read_bytes()).hexdigest(),
                  merges=[{"child_spans": children, "span": span, "level": level,
                           "aggregate_children": aggregate_children, "padded_rows": 262144,
                           "active_rows": 220000, "strict_gpu_request": True,
                           "native_parent_verification": True,
                           "prepared_registration_retained_in_context": True,
                           "backend": "opencl", "request_policy": "GpuRequired",
                           "cache_policy": "fresh_only", "proof_cache_hit": False}
                          for children, span, level, aggregate_children in topology])
    result["session"].update(host_allowance_bytes=args.host_mib << 20,
                             device_allowance_bytes=args.device_mib << 20)
    result["artifact"].update(includes_original_statements=False, includes_ledger_body=False)
    result["context"] = {
        "schema": "pq-serial-proving-context-v1", "policy": "gpu_required",
        "session_closed": True, "prepared_entries": 0, "registrations": count,
        "session_finish": copy.deepcopy(result["session"]),
        "operations": {"prove_calls": count, "prove_succeeded": count,
                       "native_cpu_calls": 0, "native_cpu_succeeded": 0,
                       "native_gpu_calls": 4, "native_gpu_succeeded": 4,
                       "native_gpu_complete_reports": 4,
                       "witness_preparation_calls": count,
                       "witness_preparation_succeeded": count,
                       "witness_preparation_complete_reports": count, "failures": []},
    }
    preparation = synthetic_gpu_report("pq_graph_witness_preparation", "operation", {"witness_trace"})
    native = [synthetic_gpu_report(entry, "proof_request", runner.GPU_NATIVE_STAGES)
              for entry in ("pq_statement", "matrict_affine_gpu", "pq_aes_lane_native", "pq_uniform_gpu")]
    events = [
        "OPENCL_AGGREGATION " + json.dumps({"event": "gpu_child_preparation_begin", "details": {
            "policy": "gpu-required", "counts_as_gpu_work": True, "proof_cache_policy": "fresh_only",
            "source_specific_cache": str(args.cache_dir)}}),
        "bounded_gpu_identity " + json.dumps(result["session"]["device"]),
        "bounded_gpu_initialized synthetic_parser_fixture=true",
        report_line(preparation),
    ]
    events += [report_line(report) for report in native + reports[:2]]
    events += ["OPENCL_AGGREGATION " + json.dumps({"event": "gpu_child_preparation_end", "details": {
        "complete_graph_verified": True, "registered_leaves": 91, "source_identity": source,
        "policy": "gpu-required", "seconds": 12.5, "cache": cache, "fresh_complete_graph_proofs": 1}})]
    for index in range(count - 1):
        events.append(report_line(preparation))
        events += [report_line(report) for report in reports[2 * index:2 * index + 2]]
    events += ["bounded_gpu_shutdown managed_live_bytes=0 lease_released=true"]
    return args, events, result


def full_log(directory, events, result):
    path = Path(directory) / "full.log"
    path.write_text("\n".join(events + [json.dumps(result)]) + "\n")
    return path


class AdmissionTests(unittest.TestCase):
    def test_full_n3_and_n4_exact_evidence_accepts(self):
        for count in (3, 4):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                args, events, result = full_evidence(directory, count)
                accepted = runner.validate_aggregate(full_log(directory, events, result), args)
                self.assertTrue(accepted["full_mode_evidence"]["exact_ordered_topology_checked"])
                self.assertEqual(accepted["full_mode_evidence"]["gpu_targeted_report_count"], 2 * (count - 1))

    def test_full_topology_and_geometry_mutations_refuse(self):
        for field, value in (("child_spans", [[1, 1], [0, 1]]), ("span", [1, 2]),
                             ("level", 2), ("aggregate_children", 1),
                             ("padded_rows", 262143), ("active_rows", 262145)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, events, result = full_evidence(directory, 3)
                result["merges"][0][field] = value
                with self.assertRaises(ValueError):
                    runner.validate_aggregate(full_log(directory, events, result), args)

    def test_full_policy_phase_count_and_shutdown_mutations_refuse(self):
        for case in ("missing_begin", "missing_end", "cpu_proving", "old_cpu_event",
                     "gpu_before_begin", "extra_gpu", "misordered_gpu", "missing_shutdown", "shutdown_early"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                args, events, result = full_evidence(directory, 3)
                end = phase_index(events, "gpu_child_preparation_end")
                merge_reports = [i for i in report_indices(events) if i > end
                                 and json.loads(events[i].removeprefix("proving_stage_report "))["entry_point"]
                                 in runner.GPU_MACHINE_INVENTORIES]
                if case == "missing_begin":
                    events.pop(phase_index(events, "gpu_child_preparation_begin"))
                elif case == "missing_end":
                    events.pop(end)
                elif case == "cpu_proving":
                    index = report_indices(events)[0]
                    events[index] = events[index].replace('"gpu_required"', '"cpu_required"')
                elif case == "old_cpu_event":
                    events[0] = events[0].replace("gpu_child_preparation_begin", "cpu_child_preparation_begin")
                elif case == "gpu_before_begin":
                    events.insert(0, events[report_indices(events)[0]])
                elif case == "extra_gpu":
                    events.insert(-1, events[merge_reports[-1]])
                elif case == "misordered_gpu":
                    left, right = merge_reports[:2]
                    events[left], events[right] = events[right], events[left]
                elif case == "missing_shutdown":
                    events.pop()
                elif case == "shutdown_early":
                    events.insert(end + 1, events.pop())
                with self.assertRaises(ValueError):
                    runner.validate_aggregate(full_log(directory, events, result), args)

    def test_full_fixture_marker_and_scope_mutations_refuse(self):
        for case in ("fixture", "marker", "marker_symlink", "fixture_pattern",
                     "decoded_verification_after_gpu_shutdown", "includes_ledger_body", "includes_original_statements"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                args, events, result = full_evidence(directory, 4)
                marker = args.cache_dir / ".opencl-compiled-source-identity"
                if case == "fixture": args.fixture.write_text("changed")
                elif case == "marker": marker.write_text("cd" * 32)
                elif case == "marker_symlink":
                    target = Path(directory) / "marker-target"
                    marker.rename(target)
                    marker.symlink_to(target)
                elif case == "fixture_pattern": result[case] = "distinct_fixtures"
                elif case == "decoded_verification_after_gpu_shutdown": result[case] = False
                else: result["artifact"][case] = True
                with self.assertRaises(ValueError):
                    runner.validate_aggregate(full_log(directory, events, result), args)

    def test_full_gpu_backend_and_completion_mutations_refuse(self):
        for field, value in (("backend", "cpu"), ("completed_calls", 0), ("device_calls", 0)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, events, result = full_evidence(directory, 3)
                index = report_indices(events, "pq_statement")[0]
                report = json.loads(events[index].removeprefix("proving_stage_report "))
                report["observations"][0][field] = value
                events[index] = report_line(report)
                with self.assertRaises(ValueError):
                    runner.validate_aggregate(full_log(directory, events, result), args)

    def test_actual_serialized_gpu_reports_accept_complete_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            args, reports, result = aggregate_evidence(directory)
            self.assertEqual({r["policy"] for r in reports}, {"gpu_required"})
            accepted = runner.validate_aggregate(aggregate_log(directory, reports, result), args)
            self.assertTrue(accepted["result"]["passed"])
            self.assertEqual(len(accepted["strict_gpu_stage_reports"]), 6)

    def test_full_native_and_preparation_inventory_mutations_refuse(self):
        for entry in ("pq_statement", "pq_graph_witness_preparation"):
            for mutation in ("missing_stage", "duplicate_stage", "failed_component", "wrong_scope"):
                with self.subTest(entry=entry, mutation=mutation), tempfile.TemporaryDirectory() as directory:
                    args, events, result = full_evidence(directory, 3)
                    index = report_indices(events, entry)[0]
                    report = json.loads(events[index].removeprefix("proving_stage_report "))
                    if mutation == "missing_stage":
                        missing = report["capabilities"]["stages"].pop()["stage"]
                        report["observations"] = [o for o in report["observations"] if o["stage"] != missing]
                    elif mutation == "duplicate_stage":
                        report["observations"].append(copy.deepcopy(report["observations"][0]))
                    elif mutation == "failed_component":
                        report["components"] = [{"id": "unexpected", "succeeded": False}]
                    else:
                        report["capabilities"]["scope"] = "registered_proof"
                    events[index] = report_line(report)
                    with self.assertRaises(ValueError):
                        runner.validate_aggregate(full_log(directory, events, result), args)

    def test_full_context_accounting_and_release_mutations_refuse(self):
        for field, value in (("session_closed", False), ("prepared_entries", 1),
                             ("registrations", 99), ("native_cpu_calls", 1),
                             ("native_gpu_complete_reports", 3), ("prove_succeeded", 0),
                             ("witness_preparation_complete_reports", 0)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, events, result = full_evidence(directory, 3)
                target = result["context"] if field in {"session_closed", "prepared_entries", "registrations"} else result["context"]["operations"]
                target[field] = value
                with self.assertRaises(ValueError):
                    runner.validate_aggregate(full_log(directory, events, result), args)

    def test_full_fresh_cache_and_receipt_inventory_mutations_refuse(self):
        for mutation in ("reuse_policy", "cache_hit", "failed_proof", "missing_family", "invented_fresh_native"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                args, events, result = full_evidence(directory, 3)
                cache = result["cache"]
                if mutation == "reuse_policy":
                    cache["policy"] = "reuse"
                elif mutation == "cache_hit":
                    cache["families"]["crypto"].update(reads=1, hits=1)
                elif mutation == "failed_proof":
                    cache["families"]["crypto"]["proof_attempts"] += 1
                elif mutation == "missing_family":
                    del cache["families"]["sources"]
                else:
                    cache["families"]["sources"].update(fresh_proofs=2, proof_attempts=2)
                # Keep event/result agreement so the actual cache contract must reject.
                index = phase_index(events, "gpu_child_preparation_end")
                event = json.loads(events[index].removeprefix("OPENCL_AGGREGATION "))
                event["details"]["cache"] = cache
                events[index] = "OPENCL_AGGREGATION " + json.dumps(event)
                with self.assertRaises(ValueError):
                    runner.validate_aggregate(full_log(directory, events, result), args)

    def test_full_repeated_fixture_scope_cannot_claim_distinct_transactions(self):
        for field, value in (("unique_fixture_statements", 3), ("repeated_child_proof", False),
                             ("fresh_complete_graph_proofs", 3),
                             ("fresh_distinct_transaction_qualified", True),
                             ("child_preparation_backend", "cpu")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, events, result = full_evidence(directory, 3)
                result[field] = value
                with self.assertRaises(ValueError):
                    runner.validate_aggregate(full_log(directory, events, result), args)

    def test_deprecated_cpu_preparation_switch_refuses_before_planning(self):
        with self.assertRaisesRegex(ValueError, "remove it to use strict GPU child preparation"):
            runner.build_plan(arguments(mode="matrict", allow_cpu_child_preparation=True))

    def test_full_native_budget_cannot_exceed_shared_worker_host_allowance(self):
        with self.assertRaisesRegex(ValueError, "must not exceed --host-mib"):
            runner.build_plan(arguments(mode="matrict", host_mib=4096, native_mib=32768))

    def test_malformed_wire_policy_refuses(self):
        for policy in ("gpu-required", "GPU_REQUIRED", None):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as directory:
                args, reports, result = aggregate_evidence(directory)
                reports[0]["policy"] = policy
                with self.assertRaisesRegex(ValueError, "unknown serialized proving policy"):
                    runner.validate_aggregate(aggregate_log(directory, reports, result), args)

    def test_missing_or_reordered_layer_evidence_refuses(self):
        for field, bad in (("depth", 1), ("changed_public_rejected_count", 2),
                           ("strict_gpu_request", False), ("cpu_verification", False),
                           ("prepared_proving_state_dropped", False)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, reports, result = aggregate_evidence(directory)
                result["layers"][0][field] = bad
                with self.assertRaises(ValueError):
                    runner.validate_aggregate(aggregate_log(directory, reports, result), args)
        for field, bad in (("layers", []), ("ordered_public_value_count", 2),
                           ("decoded_verification_after_gpu_shutdown", False)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, reports, result = aggregate_evidence(directory)
                result[field] = bad
                with self.assertRaises(ValueError):
                    runner.validate_aggregate(aggregate_log(directory, reports, result), args)

    def test_witness_restoration_and_positive_control_are_required(self):
        for field, bad in (("execution_error", "other"), ("original_witness_restored", False),
                           ("same_compiled_program", False), ("public_values_unchanged", False),
                           ("valid_parent_positive_control", False),
                           ("negative_stark_proof_generated", True),
                           ("principal_buffer_bound_bytes", runner.GIB + 1)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, reports, result = aggregate_evidence(directory)
                result["recursive_witness_checks"][0][field] = bad
                with self.assertRaisesRegex(ValueError, "corrupted-child rejection"):
                    runner.validate_aggregate(aggregate_log(directory, reports, result), args)
        with tempfile.TemporaryDirectory() as directory:
            args, reports, result = aggregate_evidence(directory)
            result["recursive_witness_checks"] = []
            with self.assertRaisesRegex(ValueError, "one aggregate-child witness check"):
                runner.validate_aggregate(aggregate_log(directory, reports, result), args)

    def test_protected_known_desktop_name_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            process = Path(directory) / "1381"
            process.mkdir()
            (process / "comm").write_text("systemd\n")
            observation = runner.protected_nonworker(process, PermissionError("protected exe"))
            self.assertEqual(observation["pid"], 1381)
            self.assertEqual(observation["comm"], "systemd")
            self.assertIn("known protected", observation["reason"])

    def test_protected_unknown_worker_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            process = Path(directory) / "9000"
            process.mkdir()
            (process / "comm").write_text("rustc\n")
            with self.assertRaisesRegex(ValueError, "unknown same-user process"):
                runner.protected_nonworker(process, PermissionError("protected exe"))

    def test_historical_unit_may_be_gone_after_reboot(self):
        with patch.object(runner, "command", return_value=SimpleNamespace(stdout="not-found\n", stderr="")):
            evidence = runner.baseline_gate()
        self.assertEqual(evidence["status"], "passed")
        self.assertIsNone(evidence["state"])

    def test_live_historical_unit_refuses(self):
        with patch.object(runner, "command", return_value=SimpleNamespace(stdout="loaded\n", stderr="")), \
                patch.object(runner, "service", return_value={"MainPID": "123"}):
            with self.assertRaisesRegex(ValueError, "live or unverified"):
                runner.baseline_gate()

    def test_unavailable_service_manager_refuses(self):
        with patch.object(runner, "command", return_value=SimpleNamespace(stdout="", stderr="bus unavailable")):
            with self.assertRaisesRegex(ValueError, "cannot inspect"):
                runner.baseline_gate()

    def test_tampered_baseline_record_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "changed.json"
            changed.write_text('{"status":"passed"}')
            with patch.object(runner, "BASELINE", changed):
                with self.assertRaisesRegex(ValueError, "identity changed"):
                    runner.baseline_gate()

    def test_stage_caps_and_explicit_full_preparation(self):
        diagnostic = runner.build_plan(arguments())
        full = runner.build_plan(arguments(mode="matrict", host_mib=32768))
        build = runner.build_plan(arguments(stage="build"))
        self.assertEqual(diagnostic["memory_max_bytes"], 16 * runner.GIB)
        self.assertEqual(diagnostic["environment"]["RAYON_NUM_THREADS"], "4")
        self.assertEqual(full["memory_max_bytes"], 48 * runner.GIB)
        self.assertEqual(full["fresh_memavailable_required_bytes"], 50 * runner.GIB)
        self.assertNotIn("--allow-cpu-child-preparation", full["command"])
        self.assertNotIn("--allow-cpu-child-preparation", diagnostic["command"])
        self.assertEqual(build["memory_max_bytes"], 8 * runner.GIB)
        self.assertEqual(build["environment"]["CARGO_BUILD_JOBS"], "2")
        self.assertNotIn("LATTICA_PROVING_POLICY", build["environment"])
        self.assertEqual(diagnostic["environment"]["LATTICA_PROVING_POLICY"], "gpu-required")

    def test_aes_component_host_cap_does_not_expand_other_stages(self):
        aes = runner.build_plan(arguments(stage="probe", target="probe",
                                          relation="pq-aes-component", host_mib=32768,
                                          device_mib=8192))
        byte = runner.build_plan(arguments(stage="probe", target="probe", relation="pq-byte"))
        diagnostic = runner.build_plan(arguments())
        self.assertEqual(aes["memory_max_bytes"], 40 * runner.GIB)
        self.assertEqual(aes["memory_high_bytes"], 38 * runner.GIB)
        self.assertEqual(aes["fresh_memavailable_required_bytes"], 44 * runner.GIB)
        self.assertEqual(aes["environment"]["RAYON_NUM_THREADS"], "4")
        self.assertEqual(aes["managed_device_allowance_bytes"], 8 * runner.GIB)
        self.assertEqual(aes["device_context_reserve_bytes"], 4 * runner.GIB)
        self.assertEqual(byte["memory_max_bytes"], 16 * runner.GIB)
        self.assertEqual(diagnostic["memory_max_bytes"], 16 * runner.GIB)

    def test_bad_gpu_report_refuses_before_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "log"
            log.write_text("proving_stage_report " + json.dumps({
                "policy": "gpu_required", "schema": "lattica-proving-stages-v1",
                "succeeded": True, "stage_coverage_complete": False,
                "completion_rejected": False, "observation_errors": 0,
            }) + "\n")
            with self.assertRaisesRegex(ValueError, "strict GPU policy"):
                runner.validate_aggregate(log, arguments())


if __name__ == "__main__":
    unittest.main()
