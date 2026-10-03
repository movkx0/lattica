#!/usr/bin/env python3
import importlib.util
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("scalability", Path(__file__).with_name("block-v2-scalability.py"))
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)
ACCOUNTING_SPEC = importlib.util.spec_from_file_location("accounting", Path(__file__).with_name("block-v2-accounting.py"))
ACCOUNTING = importlib.util.module_from_spec(ACCOUNTING_SPEC)
ACCOUNTING_SPEC.loader.exec_module(ACCOUNTING)
PILOT_SPEC = importlib.util.spec_from_file_location("pilot", Path(__file__).with_name("report-retained-pilot.py"))
PILOT = importlib.util.module_from_spec(PILOT_SPEC)
PILOT_SPEC.loader.exec_module(PILOT)


def synthetic_log():
    lines = []
    for stage, names in enumerate(([f"node.0.{i}" for i in range(4)], ["node.1.0", "node.1.1", "node.2.0"]), 1):
        lines.append(f"Running as unit: lattica-v2-123-{stage}.service")
        for i, name in enumerate(names, 1):
            lines.extend([
                f"cached_node_complete artifact={name} elapsed_ms=200000",
                f'performance_checkpoint label="{name}" spans_dropped=0 spans_open=0',
                'performance_phase_counter target="p3_test" name="phase" counter=user_ticks delta=1 samples=1 scope=inclusive_process_nonadditive',
                f'host_timeline_checkpoint label="{name}" events=2 dropped=0 malformed=0 open_frames=0 clock=host_monotonic_relative',
                'host_timeline_interval thread=0 target="p3_test" name="outer" start_ns=0 end_ns=10',
                'host_timeline_interval thread=0 target="p3_test" name="child" start_ns=10 end_ns=20',
                f'bounded_gpu_checkpoint label="{name}" counters=cumulative uploaded_bytes={i*44_000_000_000} hashing_wall_ns={i*50_000_000_000} managed_peak_bytes=1000000',
                f'gpu_timeline_checkpoint label="{name}" events=3 dropped=0 clock=opencl_device',
                f'gpu_timeline_interval label="{name}" kind="upload" start_ns=100 end_ns=110 clock=opencl_device',
                f'gpu_timeline_interval label="{name}" kind="leaf" start_ns=105 end_ns=115 clock=opencl_device',
                f'gpu_timeline_interval label="{name}" kind="download" start_ns=115 end_ns=120 clock=opencl_device',
            ])
        lines.extend(['bounded_gpu_shutdown managed_live_bytes=0 lease_released=true', f'stage_elapsed_ms={len(names)*200000} spill_peak_bytes=1000'])
    lines.extend([
        'inner_proof_artifacts_removed=10',
        'two_level_recursive_verification=PASS inner_proofs_loaded=0 count=4 level=2',
        'artifact_audit=PASS native_mutation_rejections=38 registry_policy_rejections=4 inner_proofs_loaded=0',
        'bounded_gpu_recursive_trial=PASS',
    ])
    return '\n'.join(lines)


def retention_log(enabled=True):
    lines = []
    count = 0
    for line in synthetic_log().splitlines():
        if line.startswith("Running as unit:"):
            count = 0
        if line.startswith("bounded_gpu_checkpoint "):
            count += 1
            label = BENCH.fields(line)["label"]
            live, peak, trees = (320000, 640000, 2) if enabled else (0, 0, 0)
            copies, queries, wall, opened = (count * 8, count * 3, count * 12, count) if enabled else (0, 0, 0, 0)
            lines.append(f'bounded_gpu_retention_checkpoint label="{label}" enabled={str(enabled).lower()} '
                         f'counters=cumulative retained_live_bytes={live} retained_peak_bytes={peak} '
                         f'retained_trees={trees} copy_device_ns={copies} query_device_ns={queries} '
                         f'query_wall_ns={wall} queries={opened}')
            line += " managed_live_bytes=800000"
        if enabled and line.startswith("gpu_timeline_checkpoint "):
            line = line.replace("events=3", "events=5")
        lines.append(line)
        if enabled and line.startswith('gpu_timeline_interval ') and BENCH.fields(line).get("kind") == "download":
            lines.extend([f'gpu_timeline_interval label="{label}" kind="retain_copy" start_ns=121 end_ns=129 clock=opencl_device',
                          f'gpu_timeline_interval label="{label}" kind="path_gather" start_ns=130 end_ns=133 clock=opencl_device'])
    return "\n".join(lines)


def pipeline_log(retained=True, mode="serial"):
    lines, count = [], 0
    for line in retention_log(retained).splitlines():
        if line.startswith("Running as unit:"):
            count = 0
        lines.append(line)
        if line.startswith("bounded_gpu_checkpoint "):
            count += 1
            label = BENCH.fields(line)["label"]
            lines.append(f'bounded_gpu_pipeline_checkpoint label="{label}" mode={mode} counters=cumulative '
                         f'upload_device_ns={count * 10} download_device_ns={count * 5} '
                         f'upload_api_ns={count * 100} upload_wait_ns={count * 20} '
                         f'slot_wait_ns={count * 3} tiles={count * 2}')
    return "\n".join(lines)


class Tests(unittest.TestCase):
    def test_standalone_pilot_controller_suffix_is_separate_and_strictly_bound(self):
        unit = "lattica-v2-retained-pilot-test.service"
        proof = pipeline_log() + "\n"
        suffix = (f"stage_cgroup_accounting unit={unit} scope=exec_stop_post_snapshot "
                  "memory_peak=123 memory_swap_peak=0 memory_max=1024 memory_swap_max=0 cpu_usage_usec=42\n")
        raw = proof + suffix
        extracted, record = PILOT.separate_controller_snapshot(raw, unit)
        self.assertEqual(extracted, proof)
        self.assertEqual(record["cpu_usage_usec"], 42)
        # The strict proving parser must still reject that outer snapshot directly.
        with self.assertRaisesRegex(ValueError, "misbound"):
            self.parse(raw)
        for bad in (proof, raw + suffix, raw + "extra\n", raw.replace(unit, "lattica-v2-wrong.service"),
                    raw.replace("memory_peak=123", "memory_peak=2048"),
                    raw.replace("memory_max=1024", f"memory_max={4 * 2**30}"),
                    raw.replace("memory_swap_peak=0", "memory_swap_peak=1"),
                    raw.replace("cpu_usage_usec=42", "cpu_usage_usec=-1"),
                    raw.replace("cpu_usage_usec=42", "cpu_usage_usec=42 extra=0"),
                    raw.replace("cpu_usage_usec=42", "cpu_usage_usec=42 cpu_usage_usec=42"),
                    raw + "bounded_gpu_recursive_trial=PASS\n",
                    raw + "  bounded_gpu_recursive_trial=PASS  \n"):
            with self.subTest(bad=bad[-120:]), self.assertRaises(ValueError):
                PILOT.separate_controller_snapshot(bad, unit)
        with self.assertRaises(ValueError):
            PILOT.separate_controller_snapshot(raw, "unrelated.service")

    def test_pipeline_device_durations_reset_per_service_and_match_events(self):
        for mode in ("serial", "overlap"):
            result = self.parse(pipeline_log(mode=mode), expected_pipeline=mode == "overlap")
            self.assertEqual(result["gpu_transfer_mode"], mode)
            for node in result["nodes"].values():
                self.assertEqual(node["gpu_delta"]["upload_device_ns"], 10)
                self.assertEqual(node["gpu_delta"]["download_device_ns"], 5)
                self.assertEqual(node["gpu_pipeline"]["delta"], dict(upload_device_ns=10,
                                 download_device_ns=5, upload_api_ns=100, upload_wait_ns=20,
                                 slot_wait_ns=3, tiles=2))

    def test_missing_pipeline_measurement_is_unknown_not_zero(self):
        result = self.parse(synthetic_log())
        self.assertIsNone(result["gpu_transfer_mode"])
        for node in result["nodes"].values():
            self.assertIsNone(node["gpu_delta"]["upload_device_ns"])
            self.assertIsNone(node["gpu_delta"]["download_device_ns"])
        self.assertIsNone(BENCH.model(result)["four_tx_seconds_with_zero_upload_wall_holding_other_costs_fixed"])
        for expected in (False, True):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, "missing pipeline"):
                self.parse(synthetic_log(), expected_pipeline=expected)

    def test_pipeline_rejects_missing_duplicate_negative_misbound_and_mismatched_events(self):
        text = pipeline_log()
        marker = next(line for line in text.splitlines() if line.startswith("bounded_gpu_pipeline_checkpoint "))
        replacements = [(marker, marker.replace("bounded_gpu_pipeline_checkpoint", "missing")),
                        (marker, marker + "\n" + marker),
                        ("upload_device_ns=10", "upload_device_ns=11"),
                        ("download_device_ns=5", "download_device_ns=6"),
                        ("upload_api_ns=100", "upload_api_ns=-1"),
                        ("tiles=4", "tiles=0"),
                        ("mode=serial", "mode=invalid"),
                        ("mode=serial", "mode=overlap")]
        for old, new in replacements:
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.parse(text.replace(old, new, 1), expected_pipeline=False)
        stage = "Running as unit: lattica-v2-123-2.service"
        with self.assertRaisesRegex(ValueError, "wrong service"):
            self.parse(text.replace(stage, stage + "\n" + marker), expected_pipeline=False)
        with self.assertRaisesRegex(ValueError, "between proving services"):
            before, after = text.split(stage)
            self.parse(before + stage + after.replace("mode=serial", "mode=overlap"))
        with self.assertRaisesRegex(ValueError, "pinned experiment"):
            self.parse(pipeline_log(mode="overlap"), expected_pipeline=False)

    def test_comparison_variants_isolate_one_axis_and_override_inherited_environment(self):
        for retained in (False, True):
            experiment = BENCH.experiment_definition("transfer", retained)
            self.assertEqual([v["label"] for v in experiment["variants"]], ["serial", "overlap"])
            self.assertEqual([v["retain_trees"] for v in experiment["variants"]], [retained, retained])
        for mode in (None, "serial", "overlap"):
            experiment = BENCH.experiment_definition("retention", transfer_mode=mode)
            self.assertEqual([v["pipeline"] for v in experiment["variants"]], [mode == "overlap"] * 2)
            self.assertEqual([v["retain_trees"] for v in experiment["variants"]], [False, True])
            for variant in experiment["variants"]:
                inherited = dict(LATTICA_V2_GPU_PIPELINE="bad", LATTICA_V2_GPU_RETAIN_TREES="bad")
                env = BENCH.variant_environment(inherited, variant)
                self.assertEqual(env["LATTICA_V2_GPU_PIPELINE"], "1" if mode == "overlap" else "0")
                self.assertEqual(env["LATTICA_V2_GPU_RETAIN_TREES"], "1" if variant["retain_trees"] else "0")
                self.assertEqual(inherited["LATTICA_V2_GPU_PIPELINE"], "bad")
        for args in (("invalid",), ("retention", True), ("transfer", False, "serial"),
                     ("retention", False, "invalid")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                BENCH.experiment_definition(*args)

    def retention_results(self):
        records = []
        for pair in range(1, 6):
            for retained, label in ((False, "retention-off"), (True, "retention-on")):
                record = self.parse(pipeline_log(retained))
                record.update(pair=pair, mode=label, resource_telemetry_complete=True)
                if retained:
                    record.update(recursive_command_ms=1_120_000, final_merge_ms=150_000)
                records.append(record)
        return records

    def test_retention_summary_qualifies_only_five_fully_measured_matched_pairs(self):
        records = self.retention_results()
        experiment = BENCH.experiment_definition("retention")
        summary = BENCH.matched_summary(records, 5, experiment)
        self.assertTrue(summary["minimum_repetition_gate_passed"])
        self.assertEqual(summary["paired_speedup_ratios"], [1.25] * 5)
        self.assertAlmostEqual(summary["median_wall_reduction_percent"], 20)
        self.assertEqual(summary["candidate_timing"]["final_merge_worst_ms"], 150_000)
        self.assertNotIn("serial_median_ms", summary)
        self.assertNotIn("gpu_tree_retention_enabled", summary)
        records[0]["resource_telemetry_complete"] = False
        incomplete = BENCH.matched_summary(records, 5, experiment)
        self.assertFalse(incomplete["minimum_repetition_gate_passed"])
        self.assertEqual(incomplete["fully_measured_pairs"], [2, 3, 4, 5])
        self.assertIsNone(BENCH.matched_summary(records[:1], 5, experiment)["baseline_timing"]["median_ms"])

    def test_retention_comparison_rejects_wrong_axis_unknown_modes_and_relabeling(self):
        records = self.retention_results()
        experiment = BENCH.experiment_definition("retention")
        for key, value in (("gpu_transfer_mode", "overlap"), ("gpu_transfer_mode", None),
                           ("gpu_tree_retention_enabled", True), ("gpu_tree_retention_enabled", None),
                           ("mode", "serial"), ("pair", 6), ("final_merge_ms", 0)):
            changed = copy.deepcopy(records)
            changed[0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                BENCH.matched_summary(changed, 5, experiment)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            BENCH.matched_summary(records + records[:1], 5, experiment)

    def test_schema3_resume_binds_axis_modes_inputs_sources_and_profile(self):
        experiment = BENCH.experiment_definition("retention")
        manifest = dict(schema_version=3, experiment=experiment, planned_pairs=5, profile="pin",
                        sha256={"file": "digest"}, inputs={"runner": "binary", "gpu_device": "0",
                                                          "nvidia_inventory_csv": "uuid,bus,model,driver,VRAM"})
        def validate(value):
            BENCH.validate_resume(value, manifest["sha256"], manifest["inputs"], "pin", 5, experiment)
        validate(manifest)
        for key, value in (("schema_version", 2), ("profile", "wrong"), ("planned_pairs", 4),
                           ("sha256", {}), ("inputs", {}),
                           ("experiment", BENCH.experiment_definition("transfer")),
                           ("experiment", BENCH.experiment_definition("retention", transfer_mode="overlap"))):
            bad = copy.deepcopy(manifest)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(bad)
        for field, value in (("pipeline", 0), ("retain_trees", "false"), ("label", "renamed")):
            bad = copy.deepcopy(manifest)
            bad["experiment"]["variants"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(bad)
        for key, value in (("gpu_device", "1"), ("nvidia_inventory_csv", "different")):
            bad = copy.deepcopy(manifest)
            bad["inputs"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "pinned"):
                validate(bad)
        for schema in (1, 2):
            self.assertEqual(BENCH.manifest_experiment(dict(schema_version=schema, retain_trees=True)),
                             BENCH.experiment_definition("transfer", True))

    def test_recovery_reads_each_manifest_axis_without_launching_provers(self):
        for schema in (2, 3):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = dict(schema_version=schema, planned_pairs=1, retain_trees=True)
                if schema == 3:
                    manifest["experiment"] = BENCH.experiment_definition("retention")
                (root / "manifest.json").write_text(json.dumps(manifest))
                experiment = BENCH.manifest_experiment(manifest)
                for variant in experiment["variants"]:
                    (root / ("pair-1-" + variant["label"] + ".log")).write_text("preserved evidence")
                with patch.object(BENCH, "run_child") as child, \
                        patch.object(BENCH, "collect_result", return_value={"resource_telemetry_complete": True}) as collect, \
                        patch("builtins.print"):
                    BENCH.recover_reports(root)
                child.assert_not_called()
                self.assertEqual(collect.call_count, 2)
                for call, variant in zip(collect.call_args_list, experiment["variants"]):
                    self.assertEqual(call.args[3], variant["label"])
                    self.assertEqual(call.args[4], variant["retain_trees"] if schema == 3 else True)
                    self.assertEqual(call.args[5], variant["pipeline"] if schema == 3 else None)
                report = json.loads((root / "report-recovery.json").read_text())
                self.assertEqual(report["provers_started"], 0)
                self.assertEqual(len(report["recovered_reports"]), 2)

    def test_recovery_refuses_an_active_controller_lock_without_writing_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (root / ".controller.lock").open("a") as lock:
                BENCH.fcntl.flock(lock, BENCH.fcntl.LOCK_EX | BENCH.fcntl.LOCK_NB)
                with patch.object(BENCH, "recover_reports_locked") as recovery, self.assertRaises(BlockingIOError):
                    BENCH.recover_reports(root)
                recovery.assert_not_called()
            self.assertFalse((root / "report-recovery.json").exists())

    def test_existing_report_hashes_are_preserved_by_recovery_and_pilot_reporting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            prior = dict(root_sha256="root", log_sha256="log", raw_log_sha256="raw", controller_wall_seconds=7)
            BENCH.save(path, prior)
            for field in ("root_sha256", "log_sha256", "raw_log_sha256"):
                for missing in (False, True):
                    changed = dict(prior)
                    if missing:
                        del changed[field]
                    else:
                        changed[field] = "different"
                    with self.subTest(field=field, missing=missing), self.assertRaisesRegex(ValueError, "hashes"):
                        BENCH.save_verified_report(path, changed, ("root_sha256", "log_sha256", "raw_log_sha256"))
                    self.assertEqual(json.loads(path.read_text()), prior)
            refreshed = dict(root_sha256="root", log_sha256="log", new_measurement=5)
            BENCH.save_verified_report(path, refreshed)
            self.assertEqual(json.loads(path.read_text())["controller_wall_seconds"], 7)

    def test_recorded_trial_is_never_restarted_when_log_and_job_are_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(BENCH, "run_child") as child, self.assertRaisesRegex(ValueError, "recorded trial log"):
                BENCH.trial_result(root / "missing.log", root / "missing-job", 1, "serial", {}, root, "pin", recorded=True)
            child.assert_not_called()

    def test_two_interrupted_resumes_keep_unresolved_attempts_after_replaying_earlier_trials(self):
        experiment = BENCH.experiment_definition("retention")
        unresolved = "pair-2-retention-on"
        manifest = dict(schema_version=3, experiment=experiment, planned_pairs=5,
                        active_trial=unresolved, runs=[dict(pair=1, mode="retention-off")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            first = BENCH.remember_attempts(manifest)
            self.assertIn(unresolved, first)
            # First resume persists attempts, replays an earlier completed trial,
            # clears active_trial, then is interrupted before reaching unresolved.
            BENCH.save(path, manifest)
            manifest["active_trial"] = "pair-1-retention-off"
            BENCH.save(path, manifest)
            manifest.pop("active_trial")
            BENCH.save(path, manifest)
            second_manifest = json.loads(path.read_text())
            second = BENCH.remember_attempts(second_manifest)
            self.assertIn(unresolved, second)
            with patch.object(BENCH, "run_child") as child, self.assertRaisesRegex(ValueError, "recorded trial log"):
                BENCH.trial_result(root / (unresolved + ".log"), root / unresolved, 2, "retention-on",
                                   {}, root, "pin", recorded=unresolved in second)
            child.assert_not_called()
            second_manifest["attempted_trials"].append("pair-99-retention-on")
            with self.assertRaisesRegex(ValueError, "unknown attempted"):
                BENCH.remember_attempts(second_manifest)

    def test_timeline_frames_reject_relabeling_wrong_clock_duplicate_frames_and_fields(self):
        text = pipeline_log()
        device = next(line for line in text.splitlines() if line.startswith("gpu_timeline_interval "))
        host_frame = next(line for line in text.splitlines() if line.startswith("host_timeline_checkpoint "))
        device_frame = next(line for line in text.splitlines() if line.startswith("gpu_timeline_checkpoint "))
        host_event = next(line for line in text.splitlines() if line.startswith("host_timeline_interval "))
        replacements = [(device, device.replace('label="node.0.0"', 'label="node.0.1"')),
                        (device, device.replace("clock=opencl_device", "clock=host_monotonic_relative")),
                        (device, device + " clock=opencl_device"),
                        (host_event, host_event + ' label="wrong"'),
                        (host_event, host_event + ' clock=opencl_device'),
                        (host_frame, host_frame + "\n" + host_frame),
                        (device_frame, device_frame + "\n" + device_frame)]
        for old, new in replacements:
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.parse(text.replace(old, new, 1))
        stage = "Running as unit: lattica-v2-123-2.service"
        for event in (device, host_event):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, "unframed"):
                self.parse(text.replace(stage, stage + "\n" + event))

    def test_retention_deltas_reset_per_service_and_keep_live_gauges(self):
        result = self.parse(retention_log(), expected_retention=True)
        self.assertTrue(result["gpu_tree_retention_enabled"])
        for node in result["nodes"].values():
            record = node["gpu_retention"]
            self.assertEqual(record["delta"], dict(copy_device_ns=8, query_device_ns=3, query_wall_ns=12, queries=1))
            self.assertEqual(record["retained_live_bytes"], 320000)
            self.assertEqual(record["retained_peak_bytes"], 640000)
            self.assertEqual(record["retained_trees"], 2)

    def test_old_retention_telemetry_is_unknown_not_disabled(self):
        self.assertIsNone(self.parse(synthetic_log())["gpu_tree_retention_enabled"])
        for expected in (False, True):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, "missing retention"):
                self.parse(synthetic_log(), expected_retention=expected)
        result = self.parse(retention_log(False), expected_retention=False)
        self.assertFalse(result["gpu_tree_retention_enabled"])
        for node in result["nodes"].values():
            self.assertTrue(all(value == 0 for value in node["gpu_retention"]["delta"].values()))
        with self.assertRaisesRegex(ValueError, "pinned experiment"):
            self.parse(retention_log(False), expected_retention=True)

    def test_retention_rejects_partial_duplicate_misbound_or_negative_records(self):
        text = retention_log()
        marker = next(line for line in text.splitlines() if line.startswith("bounded_gpu_retention_checkpoint "))
        replacements = [
            (marker, marker.replace("bounded_gpu_retention_checkpoint", "missing")),
            (marker, marker + "\n" + marker),
            ("copy_device_ns=8", "copy_device_ns=-1"),
            ("queries=2", "queries=0"),
            ("retained_peak_bytes=640000", "retained_peak_bytes=319999"),
            ("retained_trees=2", "retained_trees=0"),
            ("enabled=true", "enabled=invalid"),
            ("counters=cumulative", "counters=unknown"),
        ]
        for old, new in replacements:
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.parse(text.replace(old, new, 1), expected_retention=True)
        second_stage = "Running as unit: lattica-v2-123-2.service"
        with self.assertRaisesRegex(ValueError, "wrong service"):
            self.parse(text.replace(second_stage, second_stage + "\n" + marker), expected_retention=True)

    def test_retention_device_events_and_managed_accounting_must_agree(self):
        text = retention_log()
        replacements = [
            ("copy_device_ns=8", "copy_device_ns=9"),
            ("query_device_ns=3", "query_device_ns=4"),
            ("queries=1", "queries=2"),
            ('kind="path_gather"', 'kind="unknown"'),
            ('kind="retain_copy"', 'kind="unknown"'),
            ("managed_peak_bytes=1000000", "managed_peak_bytes=600000"),
            ("managed_live_bytes=800000", "managed_live_bytes=300000"),
            ("enabled=true", "enabled=false"),
        ]
        for old, new in replacements:
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.parse(text.replace(old, new, 1), expected_retention=True)

    def test_comparison_rejects_mixed_retention_modes_or_unknown_telemetry(self):
        records = [dict(self.parse(retention_log(enabled)), pair=1, mode=mode, resource_telemetry_complete=True)
                   for enabled, mode in ((False, "serial"), (True, "overlap"))]
        with self.assertRaisesRegex(ValueError, "mixed retention"):
            BENCH.matched_summary(records, 1)
        records[0]["gpu_tree_retention_enabled"] = None
        with self.assertRaisesRegex(ValueError, "mixed retention"):
            BENCH.matched_summary(records, 1)

    def test_exact_accounting_snapshot_and_fail_closed_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in {"memory.peak": "123", "memory.swap.peak": "0", "memory.max": "1024",
                                "memory.swap.max": "0", "cpu.stat": "usage_usec 42\nuser_usec 30\n"}.items():
                (root / name).write_text(value)
            record = ACCOUNTING.snapshot(root, "lattica-v2-test-1.service")
            self.assertEqual(record["memory_peak"], 123)
            self.assertEqual(record["cpu_usage_usec"], 42)
            for name, bad in (("memory.max", "max"), ("memory.max", str(45 * 2**30)),
                              ("memory.swap.max", "1"), ("memory.swap.peak", "1"), ("memory.peak", "1025")):
                original = (root / name).read_text()
                (root / name).write_text(bad)
                with self.subTest(name=name, bad=bad), self.assertRaises(ValueError):
                    ACCOUNTING.snapshot(root, "lattica-v2-test-1.service")
                (root / name).write_text(original)
            with self.assertRaises(ValueError):
                ACCOUNTING.snapshot(root, "unrelated.service")

    def test_missing_accounting_is_unknown_not_zero(self):
        with patch.object(BENCH.subprocess, "check_output", return_value=""):
            result = BENCH.resources(["unit"], {})["unit"]
        self.assertEqual(result["source"], "unavailable")
        self.assertIsNone(result["memory_peak"])
        self.assertIsNone(result["cpu_usage_nsec"])

    def test_snapshot_fallback_is_explicit_and_journal_is_checked(self):
        snapshot = dict(memory_peak=123, memory_swap_peak=0, cpu_usage_usec=42)
        with patch.object(BENCH.subprocess, "check_output", return_value=""):
            result = BENCH.resources(["unit"], {"unit": snapshot})["unit"]
        self.assertEqual(result["cpu_usage_nsec"], 42000)
        self.assertTrue(result["excludes_cleanup_after_snapshot"])
        final = '{"MEMORY_PEAK":"124","MEMORY_SWAP_PEAK":"0","CPU_USAGE_NSEC":"43000"}'
        with patch.object(BENCH.subprocess, "check_output", return_value=final):
            result = BENCH.resources(["unit"], {"unit": snapshot})["unit"]
        self.assertEqual(result["source"], "final_systemd_journal")
        for bad in (final + "\n" + final, final.replace('"124"', '"122"'), final.replace('"43000"', '"41000"')):
            with patch.object(BENCH.subprocess, "check_output", return_value=bad), self.assertRaises(ValueError):
                BENCH.resources(["unit"], {"unit": snapshot})

    def test_resume_never_reproves_existing_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "existing.log"
            log.write_text("existing proof evidence")
            with patch.object(BENCH, "run_child") as child, patch.object(BENCH, "collect_result", return_value={"resource_telemetry_complete": True}):
                result = BENCH.trial_result(log, root / "job", 1, "serial", {}, root, "pin")
                child.assert_not_called()
                self.assertTrue(result["reused_completed_trial"])
            with patch.object(BENCH, "run_child") as child, patch.object(BENCH, "collect_result", side_effect=ValueError("incomplete")):
                with self.assertRaises(ValueError):
                    BENCH.trial_result(log, root / "job", 1, "serial", {}, root, "pin")
                child.assert_not_called()
            self.assertEqual(log.read_text(), "existing proof evidence")
            (root / "orphan-job").mkdir()
            with patch.object(BENCH, "run_child") as child, self.assertRaises(ValueError):
                BENCH.trial_result(root / "missing.log", root / "orphan-job", 1, "serial", {}, root, "pin")
            child.assert_not_called()

    def test_incomplete_accounting_cannot_qualify_comparison(self):
        base = self.parse(synthetic_log())
        results = [dict(base, pair=pair, mode=mode, resource_telemetry_complete=True)
                   for pair in range(1, 6) for mode in ("serial", "overlap")]
        self.assertTrue(BENCH.matched_summary(results, 5)["minimum_repetition_gate_passed"])
        results[0]["resource_telemetry_complete"] = False
        summary = BENCH.matched_summary(results, 5)
        self.assertFalse(summary["minimum_repetition_gate_passed"])
        self.assertEqual(summary["fully_measured_pairs"], [2, 3, 4, 5])
        self.assertEqual(BENCH.matched_summary(results[:1], 5)["serial_median_ms"], None)

    def test_accounting_markers_bound_to_their_service(self):
        marker = "stage_cgroup_accounting unit=lattica-v2-123-1.service scope=exec_stop_post_snapshot memory_peak=123 memory_swap_peak=0 memory_max=1024 memory_swap_max=0 cpu_usage_usec=42"
        text = synthetic_log().replace("stage_elapsed_ms=800000 spill_peak_bytes=1000", "stage_elapsed_ms=800000 spill_peak_bytes=1000\n" + marker)
        self.assertEqual(self.parse(text)["cgroup_snapshots"]["lattica-v2-123-1.service"]["cpu_usage_usec"], 42)
        for bad in (marker + "\n" + marker, marker.replace("123-1", "123-2"), marker.replace("memory_peak=123", "memory_peak=2048")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.parse(text.replace(marker, bad))

    def parse(self, text, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.log'
            path.write_text(text)
            return BENCH.parse_trial(path, **kwargs)

    def test_complete_trial_and_conditional_model(self):
        result = self.parse(synthetic_log())
        self.assertEqual(result['recursive_command_ms'], 1_400_000)
        self.assertEqual(result['final_merge_ms'], 200_000)
        self.assertEqual(len(result['nodes']), 7)
        for node in result['nodes'].values():
            self.assertEqual(node['gpu_delta']['uploaded_bytes'], 44_000_000_000)
            self.assertEqual(node['upload_compute_overlap_ns'], 5)
        model = BENCH.model(result)
        self.assertAlmostEqual(model['estimated_64_minutes'], 423.3333333333)
        self.assertEqual(model['four_tx_seconds_with_zero_hashing_holding_other_costs_fixed'], 1050)

    def test_interval_union_does_not_double_count_overlaps(self):
        self.assertEqual(BENCH.overlap_ns([(0, 5), (3, 10)], [(2, 4), (8, 12)]), 4)
        self.assertEqual(BENCH.overlap_ns([], [(2, 4)]), 0)
        with self.assertRaises(ValueError):
            BENCH.union([(5, 4)])

    def test_missing_correctness_and_cleanup_markers_fail(self):
        text = synthetic_log()
        for marker in ('artifact_audit=PASS', 'bounded_gpu_recursive_trial=PASS', 'inner_proof_artifacts_removed=10', 'two_level_recursive_verification=PASS'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                self.parse(text.replace(marker, 'missing'))
        with self.assertRaises(ValueError):
            self.parse(text.replace('managed_live_bytes=0', 'managed_live_bytes=1'))

    def test_missing_nodes_or_device_counters_fail(self):
        text = synthetic_log()
        with self.assertRaises(ValueError):
            self.parse(text.replace('artifact=node.2.0', 'artifact=node.0.0'))
        with self.assertRaises(ValueError):
            self.parse(text.replace('bounded_gpu_checkpoint ', 'absent_checkpoint '))

    def test_incomplete_or_overlapping_timeline_fails(self):
        text = synthetic_log()
        replacements = [
            ('dropped=0', 'dropped=1'),
            ('malformed=0', 'malformed=1'),
            ('open_frames=0', 'open_frames=1'),
            ('events=2', 'events=3'),
            ('events=3', 'events=4'),
            ('start_ns=10 end_ns=20', 'start_ns=9 end_ns=20'),
            ('kind="download"', 'kind="unknown"'),
            ('clock=opencl_device', 'clock=host_monotonic_relative'),
        ]
        for old, new in replacements:
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.parse(text.replace(old, new))


if __name__ == '__main__':
    unittest.main()
