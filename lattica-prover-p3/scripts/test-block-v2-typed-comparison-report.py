#!/usr/bin/env python3
"""Single-worker matched comparison imports, using synthetic metadata only."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from benchmark_report.history import comparison_windows
from benchmark_report.model import blank_run, json_bytes, observed_throughput, reference
from benchmark_report.typed import GPU_SCHEMA


class TypedConstructionReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.series = self.root / "synthetic-comparison"
        self.series.mkdir()
        assignment = self.series / "resource-assignment.json"
        assignment.write_text('{"schema":"synthetic-assignment"}')
        self.data = {"schema": "lattica-typed-comparison-v1", "status": "succeeded",
                     "baseline_construction": "finalizer", "candidate_construction": "paired",
                     "requested_pairs": 5, "count": 4, "pairs": [], "trials": [],
                     "resource_assignment": reference(assignment, self.root),
                     "timing_boundary": "Synthetic worker window; durable application excluded."}
        self.runs = []
        for pair in range(1, 6):
            order = ["finalizer", "paired"] if pair % 2 else ["paired", "finalizer"]
            self.data["pairs"].append({"pair": pair, "order": order,
                "worker_seconds": {"finalizer": 40, "paired": 20}, "worker_reduction_percent": 50})
            for construction in order:
                directory = self.series / f"pair-{pair}-{construction}"
                directory.mkdir()
                elapsed, proofs = (40, 8) if construction == "finalizer" else (20, 4)
                result = {"schema": GPU_SCHEMA, "status": "succeeded", "construction": construction,
                          "count": 4, "cpu_audited": True, "fresh_proofs": proofs,
                          "elapsed_seconds": elapsed, "artifacts": {"node.6.0": "1" * 64},
                          "resource_assignment_sha256": self.data["resource_assignment"]["sha256"]}
                result_path = directory / "result.json"
                result_path.write_bytes(json_bytes(result))
                summary_path = directory / "summary.json"
                summary_path.write_bytes(json_bytes({"schema": GPU_SCHEMA, "status": "succeeded", "result": result}))
                self.data["trials"].append({"pair": pair, "construction": construction,
                    "cpu_audited": True, "fresh_proofs": proofs, "worker_seconds": elapsed,
                    "root_sha256": "1" * 64, "result_source": reference(result_path, self.root),
                    "summary_source": reference(summary_path, self.root)})
                run = blank_run(f"synthetic-{pair}-{construction}", "Synthetic construction test")
                run.update(status="succeeded", measurement_scope="typed_recursive_aggregation")
                run["verification"].update(cpu_audited=True, root_bytes=1)
                run["timing"]["elapsed_seconds"] = elapsed
                run["workload"].update(user_transactions=3, issuance_transactions=1,
                    fixture_reuse=True, count_evidence="Synthetic public-body test fixture")
                run["sources"] = [reference(result_path, self.root)]
                self.runs.append(run)

    def windows(self, data=None, runs=None):
        (self.series / "summary.json").write_bytes(json_bytes(self.data if data is None else data))
        return comparison_windows(self.root, [self.series], self.runs if runs is None else runs)

    def assert_withheld(self, groups):
        self.assertTrue(groups)
        for windows in groups.values():
            self.assertTrue(all(not w["complete_mapping"] for w in windows))
            self.assertTrue(all(not w["recorded"]["repeat_qualified"] for w in windows))

    def test_complete_rates_use_worker_windows_and_exclude_issuance(self):
        groups = self.windows()
        self.assertEqual(len(groups), 2)
        for group, windows in groups.items():
            self.assertEqual(len(windows), 5)
            self.assertTrue(all(w["complete_mapping"] and w["recorded"]["repeat_qualified"] for w in windows))
            result = observed_throughput(self.runs, windows)
            self.assertEqual(result["processed_user_transactions"], 15)
            self.assertEqual(result["measured_seconds"], 200 if group.endswith(":finalizer") else 100)
            self.assertEqual(result["transactions_per_minute"], 4.5 if group.endswith(":finalizer") else 9)
            self.assertEqual(windows[0]["recorded"]["worker_reduction_percent"], 50)
            self.assertIn("durable application excluded", windows[0]["recorded"]["timing_boundary"])

    def test_incomplete_campaign_withholds_both_arms(self):
        for mutation in ("running", "failed", "missing_pair", "missing_trial"):
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(self.data)
                if mutation == "missing_pair":
                    data["pairs"].pop()
                elif mutation == "missing_trial":
                    data["trials"].pop()
                else:
                    data["status"] = mutation
                self.assert_withheld(self.windows(data))

    def test_changed_pins_withhold_both_arms(self):
        for key in ("result_source", "summary_source", "resource_assignment"):
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                pointer = data[key] if key == "resource_assignment" else data["trials"][0][key]
                pointer["sha256"] = "0" * 64
                self.assert_withheld(self.windows(data))

    def test_trial_claims_must_match_pinned_results(self):
        for key, value in (("cpu_audited", False), ("fresh_proofs", 4),
                           ("worker_seconds", 2), ("root_sha256", "0" * 64)):
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data["trials"][0][key] = value
                self.assert_withheld(self.windows(data))

    def test_missing_and_duplicate_run_mappings_withhold_both_arms(self):
        self.assert_withheld(self.windows(runs=self.runs[1:]))
        runs = copy.deepcopy(self.runs)
        runs[1]["run_id"] = runs[0]["run_id"]
        self.assert_withheld(self.windows(runs=runs))

    def test_alternating_order_and_pair_identity_are_required(self):
        data = copy.deepcopy(self.data)
        data["trials"][0], data["trials"][1] = data["trials"][1], data["trials"][0]
        self.assert_withheld(self.windows(data))
        data = copy.deepcopy(self.data)
        data["pairs"][0]["pair"] = 2
        self.assert_withheld(self.windows(data))

    def test_same_or_unknown_construction_is_rejected(self):
        for construction in ("finalizer", "unknown"):
            data = copy.deepcopy(self.data)
            data["candidate_construction"] = construction
            self.assertEqual(self.windows(data), {})

    def test_pair_measurements_must_match_trials(self):
        for key, value in (("worker_seconds", {"finalizer": 41, "paired": 20}),
                           ("order", ["paired", "finalizer"]), ("worker_reduction_percent", 60)):
            data = copy.deepcopy(self.data)
            data["pairs"][0][key] = value
            self.assert_withheld(self.windows(data))


if __name__ == "__main__":
    unittest.main()
