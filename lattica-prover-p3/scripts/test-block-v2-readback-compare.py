#!/usr/bin/env python3
"""Guard against timing comparisons with changed inputs, limits or reused proofs."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("compare", Path(__file__).with_name("block-v2-readback-compare.py"))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def budget(layout="banded"):
    return {"qualification_capacity_test": True, "readback_layout": layout,
            "gpu": {"uuid": "device", "managed_bytes": 8, "context_bytes": 1,
                    "total_bytes": 9, "max_allocation_bytes": 4},
            "cpu": {"rayon_threads": 12, "quota_percent": "1200%", "allowed_cpus": list(range(24))},
            "host": {"worker_bytes": 20, "spill_bytes": 16, "swap_bytes": 0,
                     "tmpfs": True, "scratch_device": 1, "scratch_path": "/tmp"}}


class Comparison(unittest.TestCase):
    def configs(self, root):
        fixture = root / "fixture"; fixture.mkdir()
        paths = []
        for name in C.FIXTURE_NAMES:
            p = fixture / name; p.write_text(name); paths.append(p)
        for name in ("gpu", "cpu", "audit", "runner.py"):
            p = root / name; p.write_text(name); paths.append(p)
        config = {"version": 1, "gpu_uuids": ["device"], "max_concurrency": 1, "worker_slots": 1,
                  "qualification_mode": True, "gpu_binary": str(root / "gpu"),
                  "cpu_binary": str(root / "cpu"), "auditor": str(root / "audit"), "scratch": "/tmp",
                  "pins": {str(p): C.digest(p) for p in paths},
                  "jobs": [{"source": str(fixture), "external": ["profile", "chain", "root"]}],
                  "workload": {"version": 1, "name": "banded", "height": 8, "page_bytes": 4096,
                               "geometry": {"logical_lde_rows": 256}, "phases": [{"heap_bytes": 20}]}}
        direct = copy.deepcopy(config)
        direct["workload"]["name"] = "direct"
        direct["workload"]["geometry"]["host_readback_layout"] = "direct"
        return {"banded": config, "direct": direct}, root / "runner.py"

    def test_controlled_layout_difference_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            configs, runner = self.configs(Path(directory))
            C.validate_configs(configs, runner)

    def test_changed_geometry_external_statement_model_or_worker_count_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            configs, runner = self.configs(Path(directory))
            for change in ("geometry", "statement", "model", "count", "mode", "layout", "scratch", "gpu"):
                altered = copy.deepcopy(configs); direct = altered["direct"]
                if change == "geometry": direct["workload"]["geometry"]["logical_lde_rows"] = 512
                if change == "statement": direct["jobs"][0]["external"][2] = "different-root"
                if change == "model": direct["workload"]["phases"][0]["heap_bytes"] = 19
                if change == "count": direct["worker_slots"] = 2
                if change == "mode": direct["qualification_mode"] = False
                if change == "layout": direct["workload"]["geometry"]["host_readback_layout"] = "banded"
                if change == "scratch": direct["scratch"] = "/disk"
                if change == "gpu": direct["gpu_uuids"] = ["different-device"]
                with self.subTest(change=change), self.assertRaises(ValueError):
                    C.validate_configs(altered, runner)

    def test_changed_fixture_or_binary_bytes_reject_even_if_configs_match(self):
        for file in ("fixture/wallet.0", "gpu", "runner.py"):
            with self.subTest(file=file), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); configs, runner = self.configs(root)
                (root / file).write_text("changed")
                with self.assertRaisesRegex(ValueError, "pin changed"):
                    C.validate_configs(configs, runner)

    def test_budget_identity_ignores_observations_but_keeps_assigned_limits(self):
        a, b = budget(), budget("direct")
        b["detected_host"] = {"available_bytes": 123}
        b["gpu"]["available_bytes"] = 456
        self.assertEqual(C.budget_signature(a), C.budget_signature(b))
        for section, key, value in (("gpu", "context_bytes", 2), ("gpu", "managed_bytes", 7),
                                    ("host", "spill_bytes", 15), ("host", "worker_bytes", 19),
                                    ("cpu", "rayon_threads", 11), ("cpu", "quota_percent", "1100%"),
                                    ("cpu", "allowed_cpus", [0, 1])):
            changed = copy.deepcopy(b); changed[section][key] = value
            self.assertNotEqual(C.budget_signature(a), C.budget_signature(changed))
        b["qualification_capacity_test"] = False
        with self.assertRaises(ValueError): C.budget_signature(b)

    def evidence(self, root):
        attempt = root / "001-job"; attempt.mkdir()
        result = {"status": "succeeded", "cpu_audited": True, "budget": budget(),
                  "elapsed_seconds": 1, "artifacts": {"node.3.0": "root"}}
        C.save(attempt / "result.json", result)
        # Match the real runner: accounting and the measured GPU peak are added
        # only by summarize(), never to the immutable worker result.json.
        accounting = {"memory.peak": "18", "memory.events":
                      "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0"}
        samples = [{"gpu_processes": [{"bytes": 3}, {"bytes": 4}], **accounting},
                   {"gpu_processes": []}]  # The worker cgroup has been removed.
        C.save(attempt / "accounting.json", accounting)
        (attempt / "telemetry.jsonl").write_text("\n".join(map(json.dumps, samples)) + "\n")
        result = {**result, "accounting": accounting, "gpu_process_peak_bytes": 7}
        for stage, nodes in (("pairs", [f"node.1.{i}" for i in range(4)]),
                             ("merges", ["node.2.0", "node.2.1", "node.3.0"])):
            (attempt / (stage + ".log")).write_text("bounded_lde_readback_layout layout=Banded matrices=1\n" + "\n".join(
                f"grouped_node_complete artifact={name} resumed=false elapsed_ms=1" for name in nodes))
        return attempt, {"status": "succeeded", "results": [result]}

    def test_summary_enrichment_is_checked_against_preserved_evidence(self):
        for field in ("accounting", "gpu_process_peak_bytes", "unexpected"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); attempt, summary = self.evidence(root)
                raw = json.loads((attempt / "result.json").read_text())
                self.assertNotIn("accounting", raw)
                self.assertNotIn("gpu_process_peak_bytes", raw)
                self.assertEqual(C.validate_result(root, summary, "banded"), summary["results"][0])
                summary["results"][0][field] = 99
                with self.assertRaisesRegex(ValueError, "differs from the preserved summary"):
                    C.validate_result(root, summary, "banded")

    def test_limit_events_and_peak_reject_even_when_summary_matches(self):
        for change in ("high", "max", "oom", "oom_kill", "oom_group_kill", "peak", "missing"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); attempt, summary = self.evidence(root)
                accounting = summary["results"][0]["accounting"]
                if change == "peak": accounting["memory.peak"] = "21"
                elif change == "missing": del accounting["memory.events"]
                else:
                    events = dict(line.split() for line in accounting["memory.events"].splitlines())
                    events[change] = "1"
                    accounting["memory.events"] = "\n".join(f"{key} {value}" for key, value in events.items())
                C.save(attempt / "accounting.json", accounting)
                with self.assertRaises(ValueError): C.validate_result(root, summary, "banded")

    def test_empty_telemetry_and_sample_limit_events_reject(self):
        for content in ("", json.dumps({"gpu_processes": [{"bytes": 7}], "memory.events":
                                       "low 0\nhigh 0\nmax 1\noom 0\noom_kill 0\noom_group_kill 0"})):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); attempt, summary = self.evidence(root)
                (attempt / "telemetry.jsonl").write_text(content)
                with self.assertRaises(ValueError): C.validate_result(root, summary, "banded")

    def test_accepts_only_seven_fresh_proofs_with_independent_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); attempt, summary = self.evidence(root)
            self.assertTrue(C.validate_result(root, summary, "banded")["cpu_audited"])
            log = attempt / "pairs.log"
            log.write_text(log.read_text().replace("resumed=false", "resumed=true", 1))
            with self.assertRaisesRegex(ValueError, "seven fresh"):
                C.validate_result(root, summary, "banded")

    def test_summary_tampering_missing_audit_and_wrong_layout_reject(self):
        for change in ("summary", "audit", "layout", "duplicate", "execution_layout"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); attempt, summary = self.evidence(root)
                expected = "banded"
                if change == "summary": summary["results"][0]["elapsed_seconds"] = 2
                if change == "audit": summary["results"][0]["cpu_audited"] = False
                if change == "layout": expected = "direct"
                if change == "duplicate":
                    log = attempt / "pairs.log"
                    log.write_text(log.read_text().replace("node.1.1", "node.1.0"))
                if change == "execution_layout":
                    log = attempt / "pairs.log"
                    log.write_text(log.read_text().replace("layout=Banded", "layout=Direct"))
                with self.assertRaises(ValueError): C.validate_result(root, summary, expected)

    def test_cli_retains_successes_and_rejects_actual_budget_drift(self):
        # A synthetic runner exercises orchestration only; it produces no proofs
        # and provides no hardware or cryptographic qualification evidence.
        fake_runner = '''import json, pathlib, sys
a = sys.argv[1:]
if "--summarize" in a:
    p = pathlib.Path(a[a.index("--summarize") + 1])
    print((p / "fake-summary.json").read_text())
    raise SystemExit(0)
c = json.loads(pathlib.Path(a[a.index("--config") + 1]).read_text())
b = c["fake_budget"]
layout = c["workload"]["geometry"].get("host_readback_layout", "banded")
b["readback_layout"] = layout
if "--plan" in a:
    print(json.dumps({"admitted_workers": 1, "budgets": {"device": b}}))
    raise SystemExit(0)
p = pathlib.Path(a[a.index("--evidence") + 1]); p.mkdir()
attempt = p / "001-job"; attempt.mkdir()
if c.get("fake_actual_drift") and layout == "direct":
    b["host"]["spill_bytes"] -= 1
r = {"status": "succeeded", "cpu_audited": True, "budget": b,
     "elapsed_seconds": 10 if layout == "banded" else 9,
     "artifacts": {"node.3.0": p.name + "-synthetic-root"}}
(attempt / "result.json").write_text(json.dumps(r))
accounting = {"memory.peak": "18", "memory.events": "low 0\\nhigh 0\\nmax 0\\noom 0\\noom_kill 0\\noom_group_kill 0"}
(attempt / "accounting.json").write_text(json.dumps(accounting))
(attempt / "telemetry.jsonl").write_text(json.dumps({"gpu_processes": [{"bytes": 7}], **accounting}) + "\\n")
r.update(accounting=accounting, gpu_process_peak_bytes=7)
for stage, names in (("pairs", [f"node.1.{i}" for i in range(4)]),
                     ("merges", ["node.2.0", "node.2.1", "node.3.0"])):
    (attempt / (stage + ".log")).write_text("bounded_lde_readback_layout layout=" + layout.title() + " matrices=1\\n" + "\\n".join(
        f"grouped_node_complete artifact={name} resumed=false elapsed_ms=1" for name in names))
(p / "fake-summary.json").write_text(json.dumps({"status": "succeeded", "results": [r]}))
'''
        for drift in (False, True):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); configs, runner = self.configs(root)
                runner.write_text(fake_runner)
                for name, config in configs.items():
                    config["pins"][str(runner)] = C.digest(runner)
                    config["fake_budget"] = budget()
                    config["fake_actual_drift"] = drift
                    C.save(root / (name + ".json"), config)
                result = subprocess.run([sys.executable, C.__file__, "--banded-config", root / "banded.json",
                    "--direct-config", root / "direct.json", "--runner", runner,
                    "--evidence", root / "evidence", "--rounds", "2"], capture_output=True, text=True,
                    env={**os.environ, "LATTICA_BENCHMARK_REPORT_DEFER": "1"})
                report = json.loads((root / "evidence/summary.json").read_text())
                if drift:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(report["status"], "failed")
                    self.assertIn("actual worker limits changed", report["failure"])
                    self.assertEqual([t["status"] for t in report["trials"]], ["succeeded", "failed"])
                    self.assertNotIn("median_worker_seconds", report)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(report["status"], "succeeded")
                    self.assertEqual([t["layout"] for t in report["trials"]],
                                     ["banded", "direct", "direct", "banded"])
                    self.assertEqual(report["median_worker_seconds"], {"banded": 10, "direct": 9})


if __name__ == "__main__":
    unittest.main()
