#!/usr/bin/env python3
"""Cheap synthetic report checks; no proving, GPU work, or service lifecycle."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("fusion_report", Path(__file__).with_name("report-block-v2-fusion.py"))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def checkpoint(label):
    return f'performance_checkpoint label="{label}" elapsed_ms=9 spans_dropped=0 spans_open=0 timings=inclusive_nonadditive\n'


def span(target, name, calls=1, total=7, maximum=7):
    return f'performance_span target="{target}" name="{name}" calls={calls} total_ns={total} max_ns={maximum}\n'


def profiles(names=("node.1.0",), fused=True):
    text = ""
    for name in names:
        text += checkpoint(name)
        text += span("lattica_block_v2_perf", "native batch prove", total=100, maximum=100)
        text += span("p3_batch_stark::prover", "compute quotient", total=80, maximum=80)
        if fused:
            text += span("lattica_block_v2_perf", "fused quotient ldes", total=60, maximum=60)
            text += span("lattica_block_v2_perf", "fused quotient chunk", calls=16, total=50, maximum=9)
    return text + checkpoint("grouped process remainder")


def result(mode):
    return {"fusion": mode, "manifest_sha256": str(mode) * 64,
            "external": ["11"*32, "22"*32, "33"*32], "wallets": {"wallet.0": "synthetic"},
            "height_and_caps": {"height": 524288, "key.1": "synthetic"},
            "pins": {k: "0"*64 for k in ("fusion-controller.py", "grouped-controller.py", "accounting.py",
                      "handoff.json", "runner", "source-archive", "auditor")},
            "started_utc": "2026-10-01T10:00:00Z" if mode == 0 else "2026-10-01T11:00:00Z",
            "finished_utc": "2026-10-01T10:50:00Z" if mode == 0 else "2026-10-01T11:50:00Z",
            "recursive_command_ms": 1000 if mode == 0 else 750,
            "final_merge_ms": 100 if mode == 0 else 110,
            "peak_worker_cgroup_bytes": 1000, "peak_live_mapped_spill_bytes": 2000,
            "production_ready": False, "repeat_qualified": False, "recorded_preserved_cpu_audit": "PASS"}


class Profiling(unittest.TestCase):
    def test_nested_spans_remain_separate_nonadditive_observations(self):
        nodes = R.profile_nodes(profiles(), ["node.1.0"], 1)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["timings"], "inclusive_nonadditive")
        self.assertEqual(nodes[0]["checkpoint_elapsed_ms"], 9)
        self.assertEqual(sorted(s["total_ns"] for s in nodes[0]["spans"]), [50, 60, 80, 100])
        self.assertNotIn("total_ns", nodes[0])

    def test_off_profiles_are_supported(self):
        nodes = R.profile_nodes(profiles(fused=False), ["node.1.0"], 0)
        self.assertEqual(len(nodes[0]["spans"]), 2)

    def test_mode_is_checked_per_node_not_just_in_total(self):
        for text, mode in ((profiles(), 0), (profiles(fused=False), 1)):
            with self.assertRaisesRegex(ValueError, "per-node fusion"):
                R.profile_nodes(text, ["node.1.0"], mode)

    def test_incomplete_or_misordered_checkpoints_refused(self):
        text = profiles(("node.1.0", "node.1.1"))
        for expected in (["node.1.0"], ["node.1.1", "node.1.0"], ["node.1.0", "node.1.1", "node.1.2"]):
            with self.assertRaisesRegex(ValueError, "checkpoints"):
                R.profile_nodes(text, expected, 1)

    def test_dropped_open_or_duplicate_checkpoints_refused(self):
        for text in (profiles().replace("spans_dropped=0", "spans_dropped=1", 1),
                     profiles().replace("spans_open=0", "spans_open=1", 1),
                     profiles() + checkpoint("node.1.0")):
            with self.assertRaises(ValueError):
                R.profile_nodes(text, ["node.1.0"], 1)

    def test_duplicate_missing_or_unassigned_proving_spans_refused(self):
        native = span("lattica_block_v2_perf", "native batch prove", total=100, maximum=100)
        for text in (profiles().replace(native, native * 2), profiles().replace(native, ""),
                     native + profiles(), profiles() + native):
            with self.assertRaises(ValueError):
                R.profile_nodes(text, ["node.1.0"], 1)

    def test_chunk_geometry_and_single_call_lifetimes_checked(self):
        for text in (profiles().replace("calls=16", "calls=3"),
                     profiles().replace("calls=16", "calls=32"),
                     profiles().replace("total_ns=60 max_ns=60", "total_ns=60 max_ns=61"),
                     profiles().replace("total_ns=60 max_ns=60", "total_ns=60 max_ns=59")):
            with self.assertRaises(ValueError):
                R.profile_nodes(text, ["node.1.0"], 1)

    def test_strict_fields_and_numbers(self):
        self.assertEqual(R.fields('performance_span name="two words" calls=1'), {"name": "two words", "calls": "1"})
        for text in ("x a=1 a=2", "x no_key", "x =empty"):
            with self.assertRaises(ValueError):
                R.fields(text)
        for value in ("-1", "1.0", " 1", "+1", 1, True):
            with self.assertRaises(ValueError):
                R.natural(value)


class Comparisons(unittest.TestCase):
    def test_total_improvement_does_not_hide_slower_final_merge(self):
        report = R.compare(result(0), result(1))
        self.assertEqual(report["changes"]["recursive_command_ms"]["reduction_percent"], 25)
        self.assertEqual(report["changes"]["final_merge_ms"]["reduction_percent"], -10)
        self.assertEqual(report["pairs"], 1)
        self.assertEqual(report["order"], ["off", "on"])
        for flag in ("repeat_qualified", "depth_six_qualified", "production_ready"):
            self.assertFalse(report[flag])

    def test_on_first_order_is_supported(self):
        off, on = result(0), result(1)
        off["started_utc"], on["started_utc"] = on["started_utc"], off["started_utc"]
        off["finished_utc"], on["finished_utc"] = on["finished_utc"], off["finished_utc"]
        self.assertEqual(R.compare(off, on)["order"], ["on", "off"])

    def test_different_binary_or_controls_are_not_a_matched_pair(self):
        for key in result(1)["pins"]:
            on = result(1)
            on["pins"][key] = "1" * 64
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "different implementation"):
                R.compare(result(0), on)

    def test_different_inputs_or_keys_refused(self):
        for key in ("external", "wallets", "height_and_caps"):
            on = result(1)
            on[key] = "different"
            with self.assertRaisesRegex(ValueError, "different public inputs"):
                R.compare(result(0), on)

    def test_overlap_and_negative_intervals_refused(self):
        on = result(1)
        on["started_utc"] = "2026-10-01T10:49:59Z"
        with self.assertRaisesRegex(ValueError, "overlapped"):
            R.compare(result(0), on)
        on["started_utc"] = "2026-10-01T12:00:00Z"
        with self.assertRaisesRegex(ValueError, "negative trial interval"):
            R.compare(result(0), on)

    def test_uncertain_audit_and_invalid_metrics_refused(self):
        for key, value in (("recorded_preserved_cpu_audit", "PENDING"), ("production_ready", True),
                           ("repeat_qualified", True), ("final_merge_ms", 0), ("recursive_command_ms", True)):
            on = result(1)
            on[key] = value
            with self.assertRaises(ValueError):
                R.compare(result(0), on)

    def test_mismatched_modes_or_reused_record_refused(self):
        with self.assertRaises(ValueError):
            R.compare(result(1), result(0))
        on = result(1)
        on["manifest_sha256"] = result(0)["manifest_sha256"]
        with self.assertRaises(ValueError):
            R.compare(result(0), on)

    def test_timestamp_requires_utc_and_real_calendar_date(self):
        for value in ("2026-02-30T00:00:00Z", "2026-10-01T00:00:00+00:00", "2026-10-01", None):
            with self.assertRaises(ValueError):
                R.utc(value)

    def test_reporter_loads_only_supported_pinned_controller(self):
        R.load_trial_module()
        with patch.object(R, "TRIAL_SHA", "0" * 64), self.assertRaisesRegex(ValueError, "unsupported"):
            R.load_trial_module()

    def test_inflight_failed_and_registration_records_cannot_be_reported_as_proofs(self):
        for status in ("RUNNING", "FAILED_OR_INTERRUPTED", "FULL_SIZE_PREPROCESSING_REPRODUCED_RESEARCH_ONLY"):
            with patch.object(R, "pinned_json", return_value={"schema": 1, "status": status}), \
                    self.assertRaisesRegex(ValueError, "trial incomplete"):
                R.inspect(Path("/unused/manifest.json"), "0"*64, Path("/unused/registration.json"), "1"*64)

    def test_pin_checks_precede_parsing_untrusted_records(self):
        fusion, _ = R.load_trial_module()
        module = fusion.load_base()
        with patch.object(module, "regular_bytes", return_value=b"not-json"):
            with self.assertRaisesRegex(ValueError, "manifest SHA256 differs"):
                R.pinned_json(module, Path("/unused"), "0"*64)
            with self.assertRaisesRegex(ValueError, "invalid manifest SHA256"):
                R.pinned_json(module, Path("/unused"), "not-a-digest")

    def test_exported_audit_bundle_must_be_the_same_measured_root(self):
        root = {"bytes": 199, "sha256": "11"*32}
        artifacts = {"node.3.0": root, "height": {"bytes": 4, "sha256": "22"*32}}
        bundle = {name: info["sha256"] for name, info in artifacts.items()}
        R.bind_export(artifacts, root, bundle)
        with self.assertRaisesRegex(ValueError, "audit bundle differs"):
            R.bind_export(artifacts, root, {**bundle, "node.3.0": "33"*32})
        with self.assertRaisesRegex(ValueError, "root identity differs"):
            R.bind_export(artifacts, {"bytes": 199, "sha256": "33"*32}, bundle)


if __name__ == "__main__":
    unittest.main()
