#!/usr/bin/env python3
"""Check the experiment matrix and CPU audit isolation without running proofs."""
import collections
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("bench", Path(__file__).with_name("bench-apple-metal.py"))
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)

class Experiment(unittest.TestCase):
    def test_screening_is_three_single_shared_18_thread_cases(self):
        trials = B.screening_schedule()
        self.assertEqual([t["level"] for t in trials], ["quotient", "quotient-deferred", "quotient-compact-deferred"])
        self.assertTrue(all(t["backend"] == "shared" and t["threads"] == 18 and t["repeat"] == 1 for t in trials))
        self.assertEqual([(t["compact"], t["defer_timing"]) for t in trials], [(0, 0), (0, 1), (1, 1)])

    def test_screening_reuses_only_audited_evidence_from_a_stopped_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; source.mkdir()
            trial = dict(B.arm("shared", 18, "quotient-compact-deferred", phase="pilot"), label="old-pilot", verified=True)
            stages = []
            for suffix, count in (("check", 0), ("pairs", 4), ("merges", 3), ("prune", 0), ("audit", 0)):
                label = trial["label"] + "-" + suffix
                log = source / (label + ".log"); log.write_text("grouped_artifact_audit=PASS\n")
                resources = source / (label + ".jsonl"); resources.write_text("{}\n")
                stages.append(dict(label=label, status="PASS", log=str(log), log_sha256=B.digest(log),
                    resource_log=str(resources), resource_sha256=B.digest(resources), nodes=[{"resumed":"false"}] * count))
            bundle = source / (trial["label"] + "-root-only"); bundle.mkdir()
            (bundle / "node.3.0").write_bytes(b"verified root"); trial["root_sha256"] = B.digest(bundle / "node.3.0")
            prior = {key:"same" for key in ("binary_sha256", "fixture_sha256", "external", "memory_policy", "timing_boundary", "hardware", "platform")}
            prior.update(source_hashes={"src/lib.rs":"same"}, status="FAILED", failure="controller signal 15", trials=[trial], stages=stages)
            reference = source / "result.json"; reference.write_text(json.dumps(prior))
            def reuse(name):
                out = root / name; out.mkdir()
                current = dict(prior, trials=[], stages=[], schedule=B.screening_schedule())
                B.reuse_screening_trial(reference, current, out, 18)
                return current
            current = reuse("valid")
            self.assertEqual(len(current["schedule"]), 2)
            self.assertEqual(current["trials"][0]["phase"], "pilot")
            self.assertTrue(current["trials"][0]["screening_reused"])
            self.assertEqual(current["screening_reference"]["status"], "FAILED")
            Path(stages[1]["log"]).write_text("tampered")
            with self.assertRaisesRegex(RuntimeError, "evidence changed"):
                reuse("tampered")

    def test_optimization_campaign_has_90_trials_and_four_largest_pipeline_pilots(self):
        trials = B.schedule((18,24), pipeline_threads=(18,24), optimizations=True)
        pilots = [c for c in trials if c["phase"] == "pilot"]
        measured = [c for c in trials if c["phase"] == "measured"]
        self.assertEqual(len(pilots), 4)
        self.assertEqual({(c["backend"], c["threads"]) for c in pilots}, {(b,t) for b in ("shared","copy") for t in (18,24)})
        self.assertTrue(all(c["compact"] and c["defer_timing"] and c["quotient"] for c in pilots))
        self.assertEqual(len(measured), 90)
        counts = collections.Counter((c["backend"],c["threads"],c["level"]) for c in measured)
        self.assertTrue(all(n == 3 for n in counts.values()))
        for config in trials:
            env = B.environment(config, Path("/tmp/example"), config["backend"] != "cpu")
            self.assertEqual(env["LATTICA_V2_GPU_COMPACT_PROVER_DATA"], str(config["compact"]))
            self.assertEqual(env["LATTICA_V2_METAL_DEFER_TIMING"], str(config["defer_timing"]))

    def test_inherited_experiment_flags_never_leak_into_control_or_auditor(self):
        from unittest.mock import patch
        with patch.dict("os.environ", {"LATTICA_V2_GPU_COMPACT_PROVER_DATA":"1", "LATTICA_V2_METAL_DEFER_TIMING":"1"}):
            config = B.arm("shared",18,"quotient-compact-deferred")
            cpu = B.environment(config, Path("/tmp/example"), False)
            control = B.environment(B.arm("shared",18,"quotient"), Path("/tmp/example"), True)
            for env in (cpu, control):
                self.assertEqual(env["LATTICA_V2_GPU_COMPACT_PROVER_DATA"], "0")
                self.assertEqual(env["LATTICA_V2_METAL_DEFER_TIMING"], "0")

    def test_schedule_has_45_balanced_measured_trials_after_two_pilots(self):
        schedule = B.schedule((8, 16, 24))
        self.assertEqual([a["phase"] for a in schedule[:2]], ["pilot", "pilot"])
        measured = schedule[2:]
        self.assertEqual(len(measured), 45)
        counts = collections.Counter((a["backend"], a["threads"], a["level"]) for a in measured)
        self.assertEqual(len(counts), 15)
        self.assertEqual(set(counts.values()), {3})
        first = [(a["backend"], a["threads"]) for a in measured[:9]]
        second = [(a["backend"], a["threads"]) for a in measured[9:18]]
        self.assertEqual(first, second[::-1])

    def test_default_matrix_adds_nine_18_thread_baselines_and_retains_24_threads(self):
        measured = B.schedule()[2:]
        self.assertEqual(len(measured), 54)
        counts = collections.Counter((a["backend"], a["threads"], a["level"]) for a in measured)
        self.assertEqual(len(counts), 18)
        self.assertEqual(set(counts.values()), {3})
        self.assertEqual({a["threads"] for a in measured if a["level"] == "baseline"}, {8, 16, 18, 24})

    def test_full_matrix_qualifies_quotient_at_24_threads_before_all_measurements(self):
        trials = B.schedule(pipeline_threads=(18,24), pilot_level="quotient")
        self.assertEqual(len(trials), 74)
        self.assertEqual({t["backend"] for t in trials[:2]}, {"shared", "copy"})
        self.assertTrue(all(t["phase"] == "pilot" and t["threads"] == 24 and t["quotient"] == 1 and t["fusion"] == 1 and t["readback"] == 1 for t in trials[:2]))
        measured = trials[2:]
        self.assertEqual(sum(t["threads"] == 18 for t in measured), 27)
        self.assertEqual(sum(t["threads"] == 24 for t in measured), 27)

    def test_18_thread_extension_is_fresh_balanced_and_reverses_second_round(self):
        trials = B.schedule((18,), baseline_only=True, pilots=False)
        self.assertEqual(len(trials), 9)
        self.assertTrue(all(t["phase"] == "measured" and t["threads"] == 18 for t in trials))
        self.assertEqual([t["backend"] for t in trials[:3]], [t["backend"] for t in trials[3:6]][::-1])
        full = B.schedule((18,), pipeline_threads=(18,), pilots=False)
        self.assertEqual(len(full), 27)
        self.assertEqual({t["threads"] for t in full}, {18})

    def test_extension_rejects_changed_binaries_fixtures_proof_sources_or_policy(self):
        prior = {"status":"COMPLETE_VERIFIED_COMPARISON", "trials":[
            {"phase":"pilot", "backend":mode, "verified":True} for mode in ("shared", "copy")],
            "source_hashes":{"src/lib.rs":"proof", "scripts/bench-apple-metal.py":"old-controller"}}
        for key in ("binary_sha256", "fixture_sha256", "external", "memory_policy", "timing_boundary", "hardware", "platform"):
            prior[key] = "unchanged"
        current = copy.deepcopy(prior)
        current["source_hashes"]["scripts/bench-apple-metal.py"] = "extension-controller"
        B.validate_extension(prior, current)
        for key in ("binary_sha256", "fixture_sha256", "external", "memory_policy", "timing_boundary", "hardware", "platform"):
            changed = copy.deepcopy(current); changed[key] = "different"
            with self.assertRaises(RuntimeError): B.validate_extension(prior, changed)
        changed = copy.deepcopy(current); changed["source_hashes"]["src/lib.rs"] = "different"
        with self.assertRaises(RuntimeError): B.validate_extension(prior, changed)
        prior["status"] = "RUNNING"
        with self.assertRaises(RuntimeError): B.validate_extension(prior, current)

    def test_cpu_audit_children_receive_all_gpu_and_fusion_switches_disabled(self):
        for config in B.schedule():
            env = B.environment(config, Path("/tmp/example"), False)
            self.assertTrue(all(env["LATTICA_V2_GPU_" + key] == "0" for key in B.GPU_KEYS))
            self.assertEqual(env["LATTICA_V2_QUOTIENT_FUSION"], "0")
            self.assertEqual(env["LATTICA_SPILL_MAX_BYTES"], str(34 << 30))

    def test_shared_copy_pairs_only_change_storage_mode(self):
        for level in ("baseline", "readback", "fusion", "quotient"):
            a = B.environment(B.arm("shared", 24, level), Path("/tmp/example"), True)
            b = B.environment(B.arm("copy", 24, level), Path("/tmp/example"), True)
            self.assertEqual({k for k in a if a[k] != b[k]}, {"LATTICA_V2_METAL_MEMORY"})
            self.assertEqual(a["LATTICA_V2_GPU_QUOTIENT_LDE"], str(int(level == "quotient")))
            if level == "quotient":
                self.assertEqual(a["LATTICA_V2_QUOTIENT_FUSION"], "1")
                self.assertEqual(a["LATTICA_V2_GPU_RESIDENT_LDE"], "1")

if __name__ == "__main__":
    unittest.main()
