import copy
import json
import unittest

import prepared_reuse_ceiling as ceiling


def document():
    return {
        "passed": True, "blowup": 16, "num_queries": 128,
        "hiding": True, "original_profile": True,
        "context": {"session_closed": True, "policy": "gpu_required", "busy": False,
                    "prepared_entries": 0, "registrations": 2, "registration_seconds": 10.25},
        "measurement": {"schema": "pq-opencl-fresh-workflow-timing-v2",
                        "scope": ceiling.FULL_SCOPE, "run_wall_seconds": 1000.0},
    }


def receipt(ns=1_000_000_000, succeeded=True):
    return "proving_stage_report " + json.dumps({"entry_point": "block_v2_preprocessing",
                                                "elapsed_ns": ns, "succeeded": succeeded}) + "\n"


class PreparedReuseCeilingTests(unittest.TestCase):
    def test_retained_allocations_cross_idle_limit_at_large_shapes(self):
        for rows in (4096, 65536, 131072, 262144):
            self.assertEqual(sum(ceiling.device_lower_bound(rows)), 5248 * rows - 32)
            self.assertEqual(sum(ceiling.device_lower_bound(rows)) > ceiling.IDLE_LIMIT,
                             rows >= 131072)
        for rows in (0, 7, 15, True, 4096.0):
            with self.assertRaises(ValueError):
                ceiling.device_lower_bound(rows)

    def test_receipt_precedes_metadata_and_unrelated_events_do_not_consume_it(self):
        counts, times = ceiling.receipts([
            receipt(), "some other log line\n",
            "proving_stage_report {\"entry_point\": \"other\"}\n",
            "bounded_cached_prover_metadata rows=4096 device_salts=true\n",
            receipt(9_000_000_000),
            "bounded_cached_prover_metadata rows=131072 device_salts=true\n",
        ])
        self.assertEqual(dict(counts), {4096: 1, 131072: 1})
        self.assertEqual(dict(times), {4096: 1_000_000_000, 131072: 9_000_000_000})

    def test_unpaired_failed_or_wrong_storage_receipts_are_rejected(self):
        bad = [
            [receipt()], [receipt(), receipt()], [receipt(succeeded=False)],
            [receipt(-1)], [receipt(True)],
            ["bounded_cached_prover_metadata rows=4096 device_salts=true\n"],
            [receipt(), "bounded_cached_prover_metadata rows=4096 device_salts=false\n"],
        ]
        for lines in bad:
            with self.assertRaises(ValueError):
                ceiling.receipts(lines)

    def test_all_unattributed_core_time_is_assigned_to_small_shapes(self):
        report = ceiling.assess(document(), {4096: 1, 131072: 1},
                                {4096: 1_000_000_000, 131072: 9_000_000_000})
        self.assertEqual(report["small_core_setup_seconds_upper_bound"], 1.25)
        self.assertEqual(report["registrations_not_ruled_out"], 1)
        self.assertFalse(report["whole_setup_timing_available"])
        self.assertFalse(report["prepared_reuse_enabled"])
        self.assertIn("inconclusive_for_small_shapes", report["disposition"])
        self.assertEqual(report["additional_small_setup_seconds_needed_for_five_percent"], 48.75)

    def test_nonterminal_wrong_profile_or_partial_workflow_is_rejected(self):
        changes = [
            (None, "passed", False), (None, "blowup", 8), (None, "hiding", False),
            ("context", "session_closed", False), ("context", "busy", True),
            ("context", "prepared_entries", 1), ("context", "policy", "cpu"),
            ("context", "registrations", 1), ("context", "registration_seconds", 9.0),
            ("context", "registration_seconds", float("nan")),
            ("measurement", "scope", "final_aggregation"),
            ("measurement", "run_wall_seconds", 0),
            ("measurement", "run_wall_seconds", float("inf")),
        ]
        for section, key, value in changes:
            data = copy.deepcopy(document())
            (data if section is None else data[section])[key] = value
            with self.assertRaises(ValueError, msg=(section, key)):
                ceiling.assess(data, {4096: 1, 131072: 1},
                               {4096: 1_000_000_000, 131072: 9_000_000_000})

    def test_incomplete_or_unqualified_receipt_shapes_are_rejected(self):
        for counts, times in [({}, {}), ({4096: 2}, {}),
                              ({8192: 2}, {8192: 1}),
                              ({4096: 2}, {4096: -1}),
                              ({4096: 2.0}, {4096: 1})]:
            with self.assertRaises(ValueError):
                ceiling.assess(document(), counts, times)


if __name__ == "__main__":
    unittest.main()
