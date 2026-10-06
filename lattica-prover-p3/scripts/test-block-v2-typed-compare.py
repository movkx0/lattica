#!/usr/bin/env python3
"""Comparison controller tests; synthetic inputs never establish proof qualification."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("typed_compare", Path(__file__).with_name("block-v2-typed-compare.py"))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class TypedComparison(unittest.TestCase):
    def test_alternating_pairs_and_within_pair_statistics(self):
        self.assertEqual([C.trial_order(n) for n in range(1, 4)],
                         [("reference", "finalizer"), ("finalizer", "reference"), ("reference", "finalizer")])
        pairs = [C.pair_measurement(1, [{"construction": "reference", "worker_seconds": 100},
                                       {"construction": "finalizer", "worker_seconds": 50}]),
                 C.pair_measurement(2, [{"construction": "finalizer", "worker_seconds": 60},
                                       {"construction": "reference", "worker_seconds": 50}])]
        result = C.aggregate(pairs)
        self.assertEqual(result["matched_pairs"], 2)
        self.assertEqual(result["finalizer_faster_pairs"], 1)
        self.assertAlmostEqual(result["median_within_pair_reduction_percent"], 15)
        self.assertEqual(result["median_worker_seconds"], {"reference": 75, "finalizer": 55})
        self.assertIsNone(C.aggregate([]))

    def test_partial_duplicate_and_nonfinite_pairs_are_rejected(self):
        valid = [{"construction": "reference", "worker_seconds": 100},
                 {"construction": "finalizer", "worker_seconds": 50}]
        for trials in (valid[:1], [valid[0], valid[0]]):
            with self.assertRaises(ValueError): C.pair_measurement(1, trials)
        for value in (0, -1, True, float("nan"), float("inf")):
            trials = copy.deepcopy(valid)
            trials[1]["worker_seconds"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                C.pair_measurement(1, trials)

    def test_finalizer_paired_comparison_uses_the_selected_baseline(self):
        self.assertEqual(C.trial_order(1, "finalizer", "paired"), ("finalizer", "paired"))
        self.assertEqual(C.trial_order(2, "finalizer", "paired"), ("paired", "finalizer"))
        trials = [{"construction": "finalizer", "worker_seconds": 100},
                  {"construction": "paired", "worker_seconds": 60}]
        pair = C.pair_measurement(1, trials, "finalizer", "paired")
        self.assertEqual(pair["worker_reduction_percent"], 40)
        result = C.aggregate([pair], "finalizer", "paired")
        self.assertEqual(result["median_worker_seconds"], {"finalizer": 100, "paired": 60})
        self.assertEqual(result["paired_faster_pairs"], 1)
        self.assertNotIn("finalizer_faster_pairs", result)
        with self.assertRaises(ValueError): C.pair_measurement(1, trials)
        with self.assertRaises(ValueError): C.validate_public_fixtures({"paired": Path("unused")}, 4)

    def test_both_registries_require_identical_public_inputs_and_height(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = {name: Path(tmp) / name for name in ("reference", "finalizer")}
            kinds = ["joinsplit", "htlc_redeem", "htlc_refund", "issuance"] * 16
            for name, directory in fixtures.items():
                directory.mkdir()
                for index in range(64): (directory / f"wallet.{index}").write_text(str(index))
                for key in range(1, C.T.construction_spec(name)["keys"] + 1):
                    (directory / f"key.{key}").write_text(name + str(key))
                (directory / "body.json").write_text(json.dumps({"transactions": [{"kind": k} for k in kinds]}))
                (directory / "height.json").write_text("262144")
            result = C.validate_public_fixtures(fixtures, 4)
            self.assertEqual(len(result["identical_files"]), 65)
            self.assertEqual((result["user_inputs"], result["issuance_inputs"]), (3, 1))
            last = fixtures["finalizer"] / "wallet.63"
            last.write_text("changed even outside this count-four prefix")
            with self.assertRaises(ValueError): C.validate_public_fixtures(fixtures, 4)
            last.write_text("63")
            (fixtures["finalizer"] / "height.json").write_text("524288")
            with self.assertRaises(ValueError): C.validate_public_fixtures(fixtures, 4)

    def test_controller_failure_preserves_its_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "controller.log"
            command = [C.sys.executable, "-c", "print('failure evidence', flush=True); raise SystemExit(7)"]
            with self.assertRaises(subprocess.CalledProcessError) as error:
                C.execute_controller(command, log, 10)
            self.assertEqual(error.exception.returncode, 7)
            self.assertIn("failure evidence", log.read_text())

    def test_timeout_signals_controller_cleanup_before_returning(self):
        with tempfile.TemporaryDirectory() as tmp:
            process = unittest.mock.Mock()
            process.wait.side_effect = [subprocess.TimeoutExpired(["test"], 1), 130]
            process.poll.return_value = None
            with patch.object(C.subprocess, "Popen", return_value=process):
                with self.assertRaises(subprocess.TimeoutExpired):
                    C.execute_controller(["test"], Path(tmp) / "controller.log", 1)
            process.send_signal.assert_called_once_with(C.signal.SIGINT)
            self.assertEqual(process.wait.call_args_list[-1].kwargs, {"timeout": 60})


if __name__ == "__main__":
    unittest.main()
