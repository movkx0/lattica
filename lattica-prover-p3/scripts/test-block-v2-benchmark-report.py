#!/usr/bin/env python3
"""Reporting correctness checks; no proving, GPU, systemd or network required."""
import base64
import ast
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from benchmark_report.history import apply_metadata, discover, load_campaigns
from benchmark_report.measurements import Table, collect, flatten, unpack
from benchmark_report.model import (atomic_bytes, blank_run, exact, json_bytes,
                                   observed_throughput, read, transaction_rate, validate_run)
from benchmark_report.report import (check, dataset_lock, ingest, initial_catalog,
                                    render, store_run, update_coverage)
import block_v2_report_export as hooks


def run_record(rid="portable-run", count=8, elapsed=100):
    r = blank_run(rid, "Recorded fixture")
    r.update(status="succeeded", track="apple-silicon", measurement_scope="recursive_aggregation")
    r["platform"] = {"os": "macos", "architecture": "aarch64", "backend": "metal",
                     "memory_model": "unified", "unified_memory_bytes": 34359738368}
    r["workload"].update(user_transactions=count, issuance_transactions=2,
                         fixture_reuse=True, count_evidence="external public fixture manifest")
    r["timing"]["elapsed_seconds"] = elapsed
    r["verification"]["cpu_audited"] = True
    return r


class Rates(unittest.TestCase):
    def test_concurrent_window_once_and_issuance_excluded(self):
        a, b = run_record("a"), run_record("b")
        rate = observed_throughput([a, b], [{"run_ids": ["a", "b"], "elapsed_seconds": 150}])
        self.assertEqual(rate["processed_user_transactions"], 16)
        self.assertEqual(rate["measured_seconds"], 150)
        self.assertEqual(rate["transactions_per_minute"], 6.4)

    def test_failed_time_remains_in_denominator(self):
        a, b = run_record("a"), run_record("b")
        b["status"] = "failed"
        rate = observed_throughput([a, b], [{"run_ids": ["a"], "elapsed_seconds": 100},
                                           {"run_ids": ["b"], "elapsed_seconds": 100}])
        self.assertEqual(rate["transactions_per_minute"], 2.4)

    def test_failed_window_with_no_completed_attempt(self):
        rate = observed_throughput([], [{"run_ids": [], "elapsed_seconds": 20}])
        self.assertEqual(rate["transactions_per_minute"], 0)

    def test_duplicate_reference_not_extra_transaction(self):
        a = run_record()
        rate = observed_throughput([a], [{"run_ids": [a["run_id"]]*2, "elapsed_seconds": 100}])
        self.assertEqual(rate["processed_user_transactions"], 8)
        with self.assertRaises(ValueError):
            observed_throughput([a], [{"run_ids": [a["run_id"]], "elapsed_seconds": 100}]*2)

    def test_unknown_count_and_audit_not_assumed(self):
        r = run_record(count=None)
        self.assertIsNone(transaction_rate(r))
        self.assertIsNone(observed_throughput([r], [{"run_ids": [r["run_id"]], "elapsed_seconds": 100}]))
        r = run_record()
        r["verification"]["cpu_audited"] = None
        self.assertIsNone(transaction_rate(r))

    def test_scope_mismatch_rejected(self):
        a, b = run_record("a"), run_record("b")
        b["measurement_scope"] = "chain_acceptance"
        with self.assertRaises(ValueError):
            observed_throughput([a,b], [{"run_ids": ["a","b"], "elapsed_seconds": 10}])


class Format(unittest.TestCase):
    def test_portable_unified_memory(self):
        r = run_record()
        validate_run(r)
        self.assertNotIn("vram_bytes", r["platform"])
        self.assertEqual(r["platform"]["unified_memory_bytes"], 34359738368)

    def test_evidence_required_for_counts(self):
        r = run_record()
        r["workload"]["count_evidence"] = None
        with self.assertRaises(ValueError):
            validate_run(r)

    def test_payloads_rejected(self):
        r = run_record()
        r["configuration"]["private_key"] = "not-a-real-key"
        with self.assertRaises(ValueError):
            validate_run(r)

    def test_nonfinite_and_invalid_durations(self):
        for v in (float("nan"), float("inf"), -1, True, "100"):
            r = run_record(elapsed=v)
            with self.assertRaises(ValueError):
                validate_run(r)

    def test_timestamps_and_u64_exact(self):
        value = {"utc_ns": 1791066989123456789, "max": 2**64-1, "small": 100}
        decoded = json.loads(json_bytes(value))
        self.assertEqual(decoded["utc_ns"], "1791066989123456789")
        self.assertEqual(decoded["max"], str(2**64-1))
        self.assertEqual(decoded["small"], 100)

    def test_mixed_dictionary_types_roundtrip(self):
        rows = [{"mixed": 0, "name": "same"}, {"mixed": "later", "name": "same"},
                {"mixed": None, "name": "other", "new": "a"}, {"mixed": False}]
        t = Table("test", "fixture", "reported")
        for row in rows:
            t.add(row)
        table = t.finish()
        self.assertNotIn("mixed", table["dictionaries"])
        self.assertIn("name", table["dictionaries"])
        result = list(unpack(table))
        self.assertEqual(result[0]["mixed"], 0)
        self.assertIs(result[3]["mixed"], False)
        self.assertEqual(result[1]["mixed"], "later")

    def test_cgroup_and_per_device_samples(self):
        row = flatten({"time_ns": 1791066989123456789, "cpu.stat": "usage_usec 42\nuser_usec 30\n",
                       "gpu_processes": [{"uuid": "GPU-a", "pid": 99, "bytes": 1024}]})
        self.assertEqual(row["cpu.stat.usage_usec"], 42)
        self.assertEqual(row["gpu_processes.GPU-a.99.bytes"], 1024)
        self.assertEqual(row["time_ns"], "1791066989123456789")


class Retention(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_clock_domains_counter_resets_and_dropped_events(self):
        log = self.root / "measure.log"
        log.write_text('performance_checkpoint label="first" elapsed_ms=10 spans_open=1\n'
                       'bounded_gpu_checkpoint uploaded_bytes=100\n'
                       'performance_checkpoint label="second" elapsed_ms=20 spans_dropped=2\n'
                       'bounded_gpu_checkpoint uploaded_bytes=5\n'
                       'host_timeline_interval thread=1 start_ns=9 end_ns=10 name="cpu"\n'
                       'gpu_timeline_interval queue=0 start_ns=99 end_ns=199 name="gpu"\n')
        m, sources, warnings, _ = collect([log], self.root)
        gpu = next(t for t in m["tables"] if t["kind"] == "bounded_gpu_checkpoint")
        self.assertEqual([r["uploaded_bytes"] for r in unpack(gpu)], [100,5])
        self.assertEqual(m["timeline_events"], 2)
        self.assertTrue(any("spans_open=1" in w for w in warnings))
        self.assertEqual({t["clock"] for t in m["tables"] if t["kind"].endswith("_interval")},
                         {"host_monotonic_relative", "opencl_device_unaligned"})

    def test_malformed_samples_preserved_as_gap(self):
        p = self.root / "telemetry.jsonl"
        p.write_text('{"memory": null}\nnot JSON\n{"memory": 0}\n')
        m, _, warnings, _ = collect([p], self.root)
        self.assertEqual(m["resource_samples"], 2)
        self.assertEqual(len(warnings), 1)

    def test_legacy_audit_not_inferred(self):
        r = blank_run("legacy", "legacy")
        apply_metadata(r, {"root_sha256": "a", "recursive_command_ms": 1000,
                           "nodes": {}, "controller_wall_seconds": 2}, "legacy")
        self.assertIsNone(r["verification"]["cpu_audited"])
        self.assertEqual(r["timing"]["recursive_seconds"], 1)
        self.assertIsNone(transaction_rate(r))

    def test_missing_and_mismatched_pins(self):
        directory = self.root / "docs/evidence"
        directory.mkdir(parents=True)
        source = self.root / "lattica-prover-p3/target/fixture"
        source.parent.mkdir(parents=True)
        source.write_text("actual")
        (directory / "test.json").write_text(json.dumps({
            "files": [{"path": "lattica-prover-p3/target/fixture", "sha256": "0"*64},
                      {"path": "lattica-prover-p3/target/gone", "sha256": "1"*64}]}))
        c = load_campaigns(self.root)[0]
        self.assertIs(c["pins"][0]["matches"], False)
        self.assertEqual(c["pins"][1]["availability"], "missing")
        self.assertEqual(len(c["unavailable_references"]), 1)

    def test_identical_measurements_in_distinct_workers_are_retained(self):
        base = self.root / "archive"
        for name in ("a", "b"):
            d = base / name
            d.mkdir(parents=True)
            (d/"result.json").write_text(json.dumps({"cpu_audited": True, "budget": {},
                                                    "status": "succeeded", "elapsed_seconds": 10}))
            (d/"worker.log").write_text("performance_counter name=proofs delta=1\n")
        runs = list(discover(self.root, [base]))
        self.assertEqual(len(runs), 2)
        self.assertTrue(all(len(r["measurements"]["tables"]) == 1 for r in runs))

    def test_atomic_failure_preserves_original(self):
        p = self.root / "atomic.json"
        atomic_bytes(p, b"old")
        with patch("benchmark_report.model.os.replace", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError):
                atomic_bytes(p, b"new")
        self.assertEqual(p.read_bytes(), b"old")
        self.assertEqual(list(self.root.iterdir()), [p])

    def test_portable_ingest_idempotence_and_collision(self):
        p, out = self.root / "input.json", self.root / "out"
        p.write_bytes(json_bytes(run_record()))
        ingest(out, p, self.root)
        original = (out / "catalog.json").read_bytes()
        ingest(out, p, self.root)
        self.assertEqual(original, (out / "catalog.json").read_bytes())
        p.write_bytes(json_bytes(run_record(elapsed=101)))
        with self.assertRaisesRegex(ValueError, "collision"):
            ingest(out, p, self.root)
        self.assertEqual(check(out)["status"], "valid")

    def test_offline_render_has_exact_embedded_data_and_safe_text(self):
        out, r = self.root / "out", run_record()
        r["label"] = "</script><img src=https://example.invalid onerror=alert(1)>"
        c = initial_catalog()
        c["runs"] = [store_run(out, r)]
        update_coverage(c)
        atomic_bytes(out / "catalog.json", json_bytes(c))
        render(out)
        html = (out/"index.html").read_text()
        self.assertNotIn(r["label"], html)
        packed = re.search(r'id="data-portable-run"[^>]*>([^<]+)</script>', html)[1]
        self.assertEqual(json.loads(gzip.decompress(base64.b64decode(packed))), exact(r))
        before = (out/"index.html").read_bytes()
        render(out)
        self.assertEqual(before, (out/"index.html").read_bytes())
        self.assertIn("connect-src 'none'", html)

    def test_export_deferred_and_failure_does_not_change_benchmark(self):
        with patch.dict(os.environ, {hooks.DEFER_ENV: "1"}), patch.object(hooks.subprocess, "run") as proc:
            hooks.export_after_run(self.root)
            proc.assert_not_called()
        with patch.dict(os.environ, {}, clear=True), patch.object(hooks.subprocess, "run", side_effect=OSError("unavailable")):
            hooks.export_after_run(self.root)

    def test_export_lock_released_on_failure(self):
        with self.assertRaises(ValueError):
            with dataset_lock(self.root):
                raise ValueError("simulated failure")
        self.assertFalse((self.root / ".export-lock").exists())

    def test_comparison_defers_child_export_and_retains_failed_window(self):
        path = Path(__file__).with_name("block-v2-multi-gpu-compare.py")
        spec = importlib.util.spec_from_file_location("report_comparison_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        config, runner, evidence = self.root/"config.json", self.root/"runner.py", self.root/"campaign"
        config.write_text(json.dumps({"gpu_uuids": ["a","b"], "jobs": [{"reference": "fixture"}]}))
        runner.write_text("# never executed")
        called = []
        def child(*args, **kwargs):
            self.assertEqual(kwargs["env"][hooks.DEFER_ENV], "1")
            called.append("timed child")
            raise subprocess.CalledProcessError(1, args[0])
        def export(path):
            window = read(path/"01-sequential-result.json")
            self.assertEqual(window["status"], "failed")
            self.assertEqual(window["pair_makespan_seconds"], 25)
            called.append("export")
        argv = ["compare", "--config", str(config), "--runner", str(runner),
                "--evidence", str(evidence), "--single-gpu", "a", "--rounds", "1"]
        with patch.object(sys, "argv", argv), patch.object(module.time, "monotonic", side_effect=[10,35]), \
                patch.object(module.subprocess, "run", side_effect=child), \
                patch.object(hooks, "export_after_run", side_effect=export):
            with self.assertRaises(subprocess.CalledProcessError):
                module.main()
        self.assertEqual(called, ["timed child", "export"])

    def test_partial_worker_identity_survives_completion(self):
        base = self.root/"attempt"
        base.mkdir()
        (base/"attempt.json").write_text(json.dumps({"budget": {}, "config": {}, "job": {}}))
        initial = list(discover(self.root, [base]))[0]
        (base/"result.json").write_text(json.dumps({"budget": {}, "cpu_audited": True,
                                                   "status": "succeeded", "elapsed_seconds": 12}))
        completed = list(discover(self.root, [base]))[0]
        self.assertEqual(initial["run_id"], completed["run_id"])
        self.assertEqual(initial["status"], "incomplete")
        self.assertEqual(completed["status"], "succeeded")

    def test_generated_launcher_source_pins_match_updated_controller(self):
        scripts = Path(__file__).parent
        expected = hashlib.sha256((scripts/"block-v2-scratch-bench.py").read_bytes()).hexdigest()
        for name in ("prepare-block-v2-pipeline-bench.py", "prepare-block-v2-gpu-default-bench.py"):
            tree = ast.parse((scripts/name).read_text())
            pins = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "SOURCE_SHA" for t in n.targets)]
            self.assertEqual(pins, [expected])


if __name__ == "__main__":
    unittest.main()
