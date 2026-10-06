#!/usr/bin/env python3
"""Synthetic importer coverage; no test record is real proving evidence."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from benchmark_report.history import comparison_windows, pinned_comparison_source
from benchmark_report.model import blank_run, json_bytes, observed_throughput, reference
from benchmark_report.report import import_history, initial_catalog, store_run


class TypedFleetReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.series = self.root / "lattica-prover-p3/target/synthetic-series"
        self.series.mkdir(parents=True)
        self.runs = []
        self.data = {"schema": "lattica-typed-fleet-comparison-v1", "status": "succeeded",
                     "requested_pairs": 5, "repeat_qualified": True, "construction": "finalizer",
                     "count_per_root": 4, "pairs": [{"pair": n} for n in range(1, 6)], "trials": []}
        for number in range(1, 6):
            for mode, elapsed in (("sequential", 100), ("concurrent", 60)):
                directory = self.series / f"pair-{number:02d}-{mode}"
                directory.mkdir()
                fleet = directory / "summary.json"
                fleet.write_text('{"status":"succeeded"}')
                workers = []
                for gpu in range(2):
                    result = directory / f"gpu-{gpu}" / "result.json"
                    result.parent.mkdir()
                    result.write_text("{}")
                    source = reference(result, self.root)
                    rid = f"synthetic-{number}-{mode}-{gpu}"
                    run = blank_run(rid, "Synthetic typed fixture")
                    run.update(status="succeeded", measurement_scope="typed_recursive_aggregation")
                    run["verification"].update(cpu_audited=True, root_bytes=1)
                    run["timing"]["elapsed_seconds"] = elapsed / 2
                    run["workload"].update(user_transactions=3, issuance_transactions=1,
                        fixture_reuse=True, count_evidence="Synthetic public-body test fixture")
                    run["sources"] = [source]
                    self.runs.append(run)
                    workers.append({"worker_seconds": elapsed / 2, "result_source": source})
                fleet.write_bytes(json_bytes({"schema": "lattica-typed-fleet-v1", "status": "succeeded",
                    "construction": "finalizer", "count_per_root": 4, "mode": mode,
                    "execution_elapsed_seconds": elapsed, "trials": workers,
                    "cpu_audited_roots": 2, "fresh_recursive_proofs": 16}))
                self.data["trials"].append({"pair": number, "mode": mode,
                    "execution_elapsed_seconds": elapsed, "trials": workers,
                    "cpu_audited_roots": 2, "fresh_recursive_proofs": 16,
                    "first_worker_sample_ns": 1790000000000000000 + number * 1000000000,
                    "last_worker_sample_ns": 1790000000100000000 + number * 1000000000,
                    "source": reference(fleet, self.root)})

    def windows(self, data=None):
        (self.series / "summary.json").write_bytes(json_bytes(self.data if data is None else data))
        return comparison_windows(self.root, [self.series], self.runs)

    def test_rates_count_each_fleet_window_once_and_exclude_issuance(self):
        groups = self.windows()
        self.assertEqual(len(groups), 2)
        for group, windows in groups.items():
            self.assertEqual(len(windows), 5)
            self.assertTrue(all(w["complete_mapping"] for w in windows))
            self.assertTrue(all(w["recorded"]["repeat_qualified"] for w in windows))
            self.assertIsInstance(windows[0]["recorded"]["first_worker_sample_ns"], str)
            result = observed_throughput(self.runs, windows)
            self.assertEqual(result["processed_user_transactions"], 30)
            self.assertEqual(result["measured_seconds"], 500 if group.endswith(":sequential") else 300)
            self.assertEqual(result["transactions_per_minute"], 3.6 if group.endswith(":sequential") else 6)

    def test_incomplete_campaign_never_promotes_completed_trials_to_an_aggregate(self):
        for status in ("running", "failed"):
            data = copy.deepcopy(self.data)
            data["status"] = status
            for windows in self.windows(data).values():
                self.assertTrue(all(not w["complete_mapping"] for w in windows))
                self.assertTrue(all(not w["recorded"]["repeat_qualified"] for w in windows))
        data = copy.deepcopy(self.data)
        data["pairs"].pop()
        self.assertTrue(all(not w["complete_mapping"] for windows in self.windows(data).values() for w in windows))

    def test_changed_missing_or_duplicate_worker_sources_block_the_window(self):
        source = self.data["trials"][0]["trials"][0]["result_source"]
        path = self.root / source["path"]
        path.write_text("changed source")
        windows = next(w for k, w in self.windows().items() if k.endswith(":sequential"))
        self.assertFalse(windows[0]["complete_mapping"])
        path.unlink()
        windows = next(w for k, w in self.windows().items() if k.endswith(":sequential"))
        self.assertFalse(windows[0]["complete_mapping"])
        path.write_text("{}")
        data = copy.deepcopy(self.data)
        data["trials"][0]["trials"][1] = data["trials"][0]["trials"][0]
        windows = next(w for k, w in self.windows(data).items() if k.endswith(":sequential"))
        self.assertFalse(windows[0]["complete_mapping"])

    def test_source_resolution_never_reads_outside_the_repository(self):
        with patch("benchmark_report.history.digest") as digest:
            self.assertIsNone(pinned_comparison_source(self.root, {"path": "../outside.json", "sha256": "0" * 64}))
            digest.assert_not_called()

    def test_duplicate_trial_or_pair_numbers_never_qualify_a_campaign(self):
        for field in ("trials", "pairs"):
            data = copy.deepcopy(self.data)
            data[field][-1] = copy.deepcopy(data[field][0])
            for windows in self.windows(data).values():
                self.assertTrue(all(not w["complete_mapping"] for w in windows))
                self.assertTrue(all(not w["recorded"]["repeat_qualified"] for w in windows))

    def test_trial_duration_must_match_the_pinned_fleet_source(self):
        data = copy.deepcopy(self.data)
        data["trials"][0]["execution_elapsed_seconds"] = 1
        windows = next(w for k, w in self.windows(data).items() if k.endswith(":sequential"))
        self.assertFalse(windows[0]["source_consistent"])
        self.assertFalse(windows[0]["complete_mapping"])

    def test_import_keeps_the_typed_scope_and_blocks_partial_rates(self):
        output = self.root / "report"
        catalog = initial_catalog()
        catalog["runs"] = [store_run(output, run) for run in self.runs]
        (output / "catalog.json").write_bytes(json_bytes(catalog))
        self.windows()
        catalog = import_history(output, self.root, [self.series])
        self.assertEqual(len(catalog["comparisons"]), 2)
        for comparison in catalog["comparisons"]:
            self.assertEqual(comparison["scope"], "typed_recursive_aggregation")
            self.assertEqual(comparison["aggregate"]["processed_user_transactions"], 30)
        self.data["status"] = "failed"
        self.windows()
        catalog = import_history(output, self.root, [self.series])
        self.assertTrue(all(c["aggregate"] is None for c in catalog["comparisons"]))


if __name__ == "__main__":
    unittest.main()
