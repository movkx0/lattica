"""Typed mutation evidence tests; synthetic wire records are not GPU proofs."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "opencl_qualify", Path(__file__).with_name("opencl_qualify.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def fixture(relation):
    args = SimpleNamespace(stage="probe", target="probe", mode="diagnostic", execute=False,
                           relation=relation, device_index=0, device_mib=2048,
                           host_mib=4096, max_rows=1048576, seconds=1800,
                           native_mib=4096)
    recursive = relation == "pq-aes-component"
    result = {
        "schema": "lattica-pq-opencl-qualification-v1", "stage": relation,
        "passed": True, "cpu_verification": True,
        "changed_public_rejected": True, "changed_proof_rejected": True,
        "complete_transaction_qualified": False, "original_profile": True,
        "num_queries": 128, "blowup": 16, "extension": "Goldilocks cubic trinomial",
        "hiding": True, "strict_stage_reports_required": True,
        "host_allowance_bytes": args.host_mib << 20,
        "device_allowance_bytes": args.device_mib << 20,
        "gpu_context_allowance_bytes": 4 * runner.GIB, "max_rows": args.max_rows,
        "mutation_outcome_classification": "typed-numerical-rejection-v1",
        "mutation_numerical_rejections": 2,
        "mutation_probe_host_reserved_bytes": 4096,
        "mutation_remaining_host_bytes": (args.host_mib << 20) - 4096,
        "details": {"recursive_component": recursive,
                    "complete_request_verified": recursive,
                    "native_child_backend": "cpu" if recursive else None,
                    "complete_matrict_graph_verified": False},
        "gpu": {"commits": 1, "allocations": 1, "managed_peak_bytes": 1 << 20},
        "device": {"opencl_index": 0, "name": "synthetic parser device",
                   "driver": "parser fixture", "max_allocation_bytes": runner.GIB,
                   "global_bytes": 16 * runner.GIB},
    }
    return args, result


def validate(directory, args, result):
    wire = Path(__file__).with_name("fixtures") / "opencl-byte-v2-stage-reports.json"
    reports = json.loads(wire.read_text())["reports"]
    log = Path(directory) / "synthetic-probe.log"
    log.write_text("".join("proving_stage_report " + json.dumps(report) + "\n"
                           for report in reports) + json.dumps(result) + "\n")
    return runner.validate_probe(log, args)


class TypedProbeEvidenceTests(unittest.TestCase):
    def test_both_scopes_accept_only_complete_typed_evidence(self):
        for relation in ("pq-byte", "pq-aes-component"):
            with self.subTest(relation=relation), tempfile.TemporaryDirectory() as directory:
                args, result = fixture(relation)
                accepted = validate(directory, args, result)
                self.assertFalse(accepted["full_transaction_qualified"])

    def test_missing_fields_and_wrong_outcome_types_refuse(self):
        for relation in ("pq-byte", "pq-aes-component"):
            args, original = fixture(relation)
            mutations = [(key, None) for key in original if key.startswith("mutation_")]
            mutations += [("mutation_outcome_classification", "any-error-v0")]
            mutations += [("mutation_numerical_rejections", v)
                          for v in (True, False, 0, 1, 3, "2", 2.0)]
            mutations += [("mutation_probe_host_reserved_bytes", v)
                          for v in (True, False, 0, -1, "4096", 4096.0)]
            mutations += [("mutation_remaining_host_bytes", v)
                          for v in (True, False, -1, runner.GIB - 1, "1000", 1000.0)]
            for key, value in mutations:
                with self.subTest(relation=relation, key=key, value=value), tempfile.TemporaryDirectory() as directory:
                    result = copy.deepcopy(original)
                    if value is None:
                        result.pop(key)
                    else:
                        result[key] = value
                    with self.assertRaises(ValueError):
                        validate(directory, args, result)

    def test_inconsistent_sum_and_insufficient_output_room_refuse(self):
        args, original = fixture("pq-byte")
        for remaining in (original["mutation_remaining_host_bytes"] + 1,
                          runner.GIB):
            with self.subTest(remaining=remaining), tempfile.TemporaryDirectory() as directory:
                result = copy.deepcopy(original)
                result["mutation_remaining_host_bytes"] = remaining
                if remaining == runner.GIB:
                    result["mutation_probe_host_reserved_bytes"] = (args.host_mib << 20) - remaining
                with self.assertRaises(ValueError):
                    validate(directory, args, result)

    def test_probe_output_cap_preserves_original_host_and_aggregate_environment(self):
        for relation in ("pq-byte", "pq-aes-component"):
            args, _ = fixture(relation)
            plan = runner.build_plan(args)
            self.assertEqual(int(plan["environment"]["LATTICA_V2_HOST_OUTPUT_BYTES"]),
                             2 * runner.GIB)
            host_flag = plan["command"].index("--host-bytes")
            self.assertEqual(int(plan["command"][host_flag + 1]), args.host_mib << 20)
        args.stage = "aggregate"
        args.target = "aggregate"
        args.output = Path("/tmp/synthetic-output.postcard")
        args.fixture = Path("/tmp/synthetic-fixture.json")
        args.cache_dir = Path("/tmp/synthetic-cache")
        args.count = 3
        self.assertEqual(int(runner.build_plan(args)["environment"]["LATTICA_V2_HOST_OUTPUT_BYTES"]),
                         args.host_mib << 20)
        self.assertEqual(runner.probe_output_bytes(runner.GIB + 4096), runner.GIB)


if __name__ == "__main__":
    unittest.main()
