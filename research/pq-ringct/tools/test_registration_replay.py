import copy
import unittest

import registration_replay as replay


def document(identities, payload=1024, seconds=2.0, wall=100.0):
    rows = []
    last = {}
    for index, identity in enumerate(identities):
        distance = index - last[identity] - 1 if identity in last else None
        last[identity] = index
        rows.append([f"{identity:064x}", f"{identity + 1:064x}", 1 << 30, seconds,
                     1, distance, 3, 1 << 20, None, payload, False, False, True, 12, 32])
    return {"measurement": {"schema": "pq-opencl-fresh-workflow-timing-v2", "scope": replay.FULL_SCOPE,
                            "run_wall_seconds": wall},
            "context": {"identity_receipt_cache_bytes": 720896, "metadata_entry_size_bytes": 128,
                        "registration_telemetry_reserved_bytes": 5 << 20,
                        "registration_setup_seconds": seconds * len(rows),
                        "registration_telemetry": {
                            "schema": "pq-registration-access-trace-v1", "fields": replay.FIELDS,
                            "enabled": True, "complete": True, "maximum_accesses": 4096,
                            "attempted_accesses": len(rows), "recorded_accesses": len(rows),
                            "dropped_accesses": 0, "rows": rows}}}


class RegistrationReplayTests(unittest.TestCase):
    def test_legacy_counters_are_not_an_observed_sequence(self):
        result = replay.assess({"context": {"registrations": 3120, "identity_hint_hits": 2670}})
        self.assertEqual(result["sequence_status"], "not_observed")
        self.assertEqual(result["prepared_reuse_gate"], "inconclusive")
        self.assertFalse(result["prepared_reuse_enabled"])

    def test_exact_sequence_is_replayed_without_admission(self):
        result = replay.assess(document([1, 2, 1], seconds=10))
        self.assertEqual(result["sequence_status"], "complete")
        self.assertEqual(result["unadmitted_prepared_upper_bound"]["additional_hits"], 1)
        self.assertEqual(result["prepared_reuse_gate"], "inconclusive")
        self.assertFalse(result["prepared_reuse_enabled"])
        self.assertEqual(result["metadata_replay"][0]["hits"], 1)

    def test_optimistic_ceiling_can_reject_but_never_promote(self):
        result = replay.assess(document([1, 2, 1], seconds=1))
        self.assertEqual(result["prepared_reuse_gate"], "rejected_by_optimistic_time_ceiling")
        self.assertFalse(result["prepared_reuse_enabled"])

    def test_missing_complete_workflow_does_not_use_final_aggregation_time(self):
        data = document([1, 2, 1])
        data["measurement"]["scope"] = "final_aggregation_only"
        result = replay.assess(data)
        self.assertIsNone(result["complete_workflow_seconds"])
        self.assertIsNone(result["unadmitted_prepared_upper_bound"]["workflow_fraction"])
        self.assertEqual(result["prepared_reuse_gate"], "inconclusive")

    def test_truncation_failure_and_disabled_detail_are_inconclusive(self):
        base = document([1, 2, 1])
        for field, value in (("complete", False), ("enabled", False), ("dropped_accesses", 1), ("attempted_accesses", 4)):
            data = copy.deepcopy(base)
            data["context"]["registration_telemetry"][field] = value
            result = replay.assess(data)
            self.assertEqual(result["sequence_status"], "unusable")
            self.assertEqual(result["prepared_reuse_gate"], "inconclusive")
        for field, value in ((4, 5), (12, False), (3, float("nan")), (5, True)):
            data = copy.deepcopy(base)
            data["context"]["registration_telemetry"]["rows"][2][field] = value
            self.assertEqual(replay.assess(data)["sequence_status"], "unusable")

    def test_reordering_and_identity_or_payload_mutation_are_detected(self):
        for mutate in (
            lambda rows: rows.reverse(),
            lambda rows: rows[2].__setitem__(0, "f" * 64),
            lambda rows: rows[2].__setitem__(9, rows[2][9] + 1),
            lambda rows: rows[2].__setitem__(2, 2 << 30),
        ):
            data = document([1, 2, 1])
            mutate(data["context"]["registration_telemetry"]["rows"])
            self.assertEqual(replay.assess(data)["sequence_status"], "unusable")

    def test_host_allowance_is_part_of_prepared_compatibility(self):
        data = document([1, 2, 1])
        row = data["context"]["registration_telemetry"]["rows"][2]
        row[2], row[5] = 2 << 30, None
        result = replay.assess(data)
        self.assertEqual(result["unadmitted_prepared_upper_bound"]["additional_hits"], 0)
        self.assertEqual(result["metadata_replay"][0]["hits"], 1)

    def test_capacity_replay_uses_lru_and_keeps_byte_allowance(self):
        result = replay.assess(document(list(range(450)) * 2))
        small, large = result["metadata_replay"]
        self.assertEqual(small["hits"], 0)
        self.assertEqual(large["hits"], 450)
        self.assertGreater(small["capacity_evictions"], 0)
        self.assertEqual(large["capacity_evictions"], 0)
        self.assertLessEqual(large["peak_accounted_public_bytes"], replay.PUBLIC_LIMIT)

    def test_byte_limit_is_independent_of_entry_capacity(self):
        result = replay.assess(document(list(range(100)) * 2, payload=1 << 20))
        for candidate in result["metadata_replay"]:
            self.assertEqual(candidate["hits"], 0)
            self.assertGreater(candidate["byte_evictions"], 0)
            self.assertLessEqual(candidate["peak_accounted_public_bytes"], replay.PUBLIC_LIMIT)

    def test_exact_byte_boundary_and_oversized_entries(self):
        events = replay.parse_trace(document([1])["context"]["registration_telemetry"])
        fixed = 720896 + 256 * 128 + (5 << 20)
        events[0]["metadata_payload_bytes"] = replay.PUBLIC_LIMIT - fixed
        accepted = replay.metadata_replay(events, 256, 720896, 128, 5 << 20)
        self.assertEqual(accepted["peak_accounted_public_bytes"], replay.PUBLIC_LIMIT)
        events[0]["metadata_payload_bytes"] += 1
        rejected = replay.metadata_replay(events, 256, 720896, 128, 5 << 20)
        self.assertEqual(rejected["oversized_rejections"], 1)
        self.assertEqual(rejected["remaining_entries"], 0)


if __name__ == "__main__":
    unittest.main()
