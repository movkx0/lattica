#!/usr/bin/env python3
"""Synthetic orchestration checks; these records never qualify a real proof."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("fleet_comparison", Path(__file__).with_name("block-v2-typed-fleet-compare.py"))
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class FleetComparison(unittest.TestCase):
    def fixture(self, root):
        fixture = root / "fixture"
        fixture.mkdir()
        for name in (*D.T.public_names("finalizer"), *(f"wallet.{i}" for i in range(4))):
            (fixture / name).write_text("262144" if name == "height.json" else "synthetic test input")
        return fixture

    def test_pair_order_and_aggregate_use_pair_windows(self):
        pairs = []
        for number, concurrent in enumerate((60, 80, 110), 1):
            trials = [{"mode": mode, "execution_elapsed_seconds": 100 if mode == "sequential" else concurrent,
                       "source": {}, "first_worker_sample_ns": i * 3 + 1,
                       "last_worker_sample_ns": i * 3 + 2} for i, mode in enumerate(D.trial_order(number))]
            pairs.append(D.pair_measurement(number, trials))
        result = D.aggregate(pairs)
        self.assertEqual(result["matched_pairs"], 3)
        self.assertEqual(result["median_execution_elapsed_seconds"], {"sequential": 100, "concurrent": 80})
        self.assertAlmostEqual(result["median_within_pair_reduction_percent"], 20)
        self.assertEqual(result["concurrent_faster_pairs"], 2)
        with self.assertRaises(ValueError): D.pair_measurement(2, trials)
        invalid = copy.deepcopy(trials)
        invalid[1]["first_worker_sample_ns"] = invalid[0]["last_worker_sample_ns"]
        with self.assertRaisesRegex(ValueError, "timestamps"): D.pair_measurement(3, invalid)
        for bad in (0, -1, float("nan"), True):
            invalid = copy.deepcopy(trials)
            invalid[0]["execution_elapsed_seconds"] = bad
            with self.assertRaises(ValueError): D.pair_measurement(3, invalid)

    def fleet(self, root):
        directory = root / "fleet"
        directory.mkdir()
        fixture = self.fixture(root)
        cpu = root / "cpu"
        cpu.write_text("synthetic CPU identity")
        assignment = {"schema": "lattica-typed-fleet-assignment-v1",
                      "limits_by_gpu": {uuid: {"gpu": {"uuid": uuid}} for uuid in ("GPU-a", "GPU-b")}}
        assigned = directory / "resource-assignment.json"
        assigned.write_text(json.dumps(assignment))
        trials, verified = [], {}
        for uuid in assignment["limits_by_gpu"]:
            child = directory / uuid
            child.mkdir()
            work = child / "001-typed"
            work.mkdir()
            (child / "resource-assignment.json").write_text(json.dumps({"limits": assignment["limits_by_gpu"][uuid]}))
            (child / "summary.json").write_text("{}")
            (child / "config.json").write_text(json.dumps({"cpu_binary": str(cpu),
                "pins": {str(cpu): D.G.digest(cpu)}, "fixture": str(fixture)}))
            (work / "result.json").write_text(json.dumps({"profile_sha256": "profile", "artifacts": {}}))
            (work / "telemetry.jsonl").write_text('{"time_ns":1}\n{"time_ns":2}\n')
            (child / "plan.json").write_text("{}")
            for name in ("prove.log", "audit.log", "accounting.json"):
                (work / name).write_text("synthetic test data")
            trial = {"gpu_uuid": uuid, "worker_seconds": 1.0, "fresh_proofs": 8, "root_bytes": 1,
                     "root_sha256": "0" * 64, "cpu_audited": True,
                     "summary_source": D.C.pin(child / "summary.json"), "result_source": D.C.pin(work / "result.json")}
            trials.append(trial)
            verified[str(child)] = trial
        controller = Path(D.F.__file__).resolve()
        summary = {"schema": "lattica-typed-fleet-v1", "status": "succeeded", "mode": "concurrent",
            "construction": "finalizer", "count_per_root": 4, "ram_admission": "compact", "worker_slots": 2,
            "cpu_audited_roots": 2, "fresh_recursive_proofs": 16, "execution_elapsed_seconds": 2,
            "resource_assignment": D.C.pin(assigned), "input_pins": {str(controller): D.G.digest(controller)},
            "parent_memory_events_before": {"max": 0}, "parent_memory_events_after": {"max": 0},
            "parent_memory_event_deltas": {"max": 0},
            "attempts": [{"uuid": uuid, "status": "succeeded"} for uuid in assignment["limits_by_gpu"]], "trials": trials}
        args = (directory, "concurrent", "finalizer", 4, assignment, "gpu", D.G.digest(cpu), "profile",
                {p.name: D.G.digest(p) for p in D.T.fixture_files(fixture, 4, "finalizer")})
        return summary, args, verified

    def test_fleet_rechecks_identity_memory_provenance_and_expected_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary, args, verified = self.fleet(Path(tmp))
            summary_path = args[0] / "summary.json"
            def check(data):
                summary_path.write_text(json.dumps(data))
                with patch.object(D.C, "checked_trial", side_effect=lambda path, *rest: verified[str(path)]):
                    return D.checked_fleet(*args)
            self.assertEqual(check(summary)["fresh_recursive_proofs"], 16)
            for key, value in (("mode", "sequential"), ("status", "failed"), ("count_per_root", 8),
                               ("cpu_audited_roots", 1), ("fresh_recursive_proofs", 15),
                               ("cleanup_failures", ["context remains"]), ("execution_elapsed_seconds", 0)):
                changed = copy.deepcopy(summary)
                changed[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError): check(changed)
            changed = copy.deepcopy(summary)
            changed["parent_memory_events_after"]["max"] = 1
            with self.assertRaises(ValueError): check(changed)
            changed = copy.deepcopy(summary)
            changed["trials"][1]["gpu_uuid"] = "GPU-a"
            with self.assertRaises(ValueError): check(changed)
            (Path(tmp) / "fixture/wallet.0").write_text("changed input")
            with self.assertRaisesRegex(ValueError, "fixtures changed"): check(summary)

    def test_worker_validation_failure_is_never_promoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary, args, _ = self.fleet(Path(tmp))
            (args[0] / "summary.json").write_text(json.dumps(summary))
            with patch.object(D.C, "checked_trial", side_effect=ValueError("root audit failed")):
                with self.assertRaisesRegex(ValueError, "root audit failed"): D.checked_fleet(*args)

    def exercise(self, pairs, fail_at=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self.fixture(root)
            for name in ("cpu", "gpu"):
                (root / name).write_text("synthetic " + name)
            assignment = root / "assignment.json"
            assignment.write_text(json.dumps({"limits_by_gpu": {"GPU-a": {}, "GPU-b": {}}}))
            out = root / "comparison"
            commands = []
            def execute(command, log, timeout):
                commands.append(command)
                if len(commands) == fail_at:
                    log.write_text("synthetic failure retained")
                    raise RuntimeError("synthetic admission failure")
            def check(directory, mode, *args):
                return {"mode": mode, "execution_elapsed_seconds": 2 if mode == "sequential" else 1,
                        "first_worker_sample_ns": len(commands) * 3 + 1,
                        "last_worker_sample_ns": len(commands) * 3 + 2,
                        "trials": [], "cpu_audited_roots": 2, "fresh_recursive_proofs": 16,
                        "source": {"path": str(directory / "summary.json")}, "pins": {}}
            argv = ["fleet-compare", "--gpu-binary", str(root / "gpu"), "--cpu-binary", str(root / "cpu"),
                    "--fixture", str(fixture), "--gpu-uuid", "GPU-a", "--gpu-uuid", "GPU-b",
                    "--resource-assignment", str(assignment), "--calibration-trial", str(root),
                    "--pairs", str(pairs), "--evidence", str(out)]
            with patch.object(sys, "argv", argv), patch.object(D.F, "load_calibrations", return_value=({}, {})), \
                    patch.object(D.C, "execute_controller", side_effect=execute), \
                    patch.object(D, "checked_fleet", side_effect=check), patch("builtins.print"):
                if fail_at:
                    with self.assertRaisesRegex(RuntimeError, "synthetic admission failure"): D.main()
                else:
                    D.main()
            return json.loads((out / "summary.json").read_text()), commands

    def test_five_pairs_alternate_and_retain_each_successful_trial(self):
        result, commands = self.exercise(5)
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["repeat_qualified"])
        self.assertEqual((result["cpu_audited_roots"], result["fresh_recursive_proofs"]), (20, 160))
        self.assertEqual([c[c.index("--mode") + 1] for c in commands],
                         [mode for number in range(1, 6) for mode in D.trial_order(number)])
        self.assertIsNone(result["active_trial"])
        partial, _ = self.exercise(1)
        self.assertFalse(partial["repeat_qualified"])

    def test_failure_stops_without_retrying_or_claiming_a_completed_pair(self):
        result, commands = self.exercise(5, fail_at=2)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["repeat_qualified"])
        self.assertEqual(len(commands), 2)
        self.assertEqual(len(result["trials"]), 1)
        self.assertEqual(result["pairs"], [])
        self.assertEqual(result["active_trial"]["mode"], "concurrent")


if __name__ == "__main__":
    unittest.main()
