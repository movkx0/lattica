#!/usr/bin/env python3
"""Synthetic controller tests; no cryptography, proving, service or GPU claims."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("fusion_trial", Path(__file__).with_name("block-v2-fusion-trial.py"))
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CONTROLLER = "lattica-v2-fusion-test.service"
UNIT = "lattica-v2-grouped-test-1.service"


class Controls(unittest.TestCase):
    def test_mode_requires_integer_zero_or_one(self):
        for mode in (0, 1):
            self.assertEqual(F.fusion_mode(mode), mode)
        for mode in (-1, 2, True, False, None, "1", 1.0):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                F.fusion_mode(mode)

    def test_explicit_mode_before_separator_and_auditor_disabled(self):
        for mode in (0, 1):
            for audit in (False, True):
                command = F.inject_mode(["systemd-run", "--wait", "--", "/runner", "prove"], mode, audit)
                self.assertEqual(command[2], f"--setenv=LATTICA_V2_QUOTIENT_FUSION={0 if audit else mode}")
                self.assertEqual(command[3:], ["--", "/runner", "prove"])

    def test_no_ambiguous_environment_or_separator(self):
        for command in (["systemd-run"], ["--", "--"],
                        ["--setenv=LATTICA_V2_QUOTIENT_FUSION=0", "--", "/runner"]):
            with self.assertRaises(ValueError):
                F.inject_mode(command, 1)

    def test_marker_exact_and_unique(self):
        for mode in (0, 1):
            correct = f"quotient_fusion_research enabled={str(bool(mode)).lower()} production_ready=false\n"
            F.validate_mode(correct, mode)
            for bad in ("", correct * 2, correct.replace("false\n", "true\n"),
                        correct.replace("enabled=", "enabled=wrong"), correct.rstrip() + " extra=1\n"):
                with self.subTest(mode=mode, bad=bad), self.assertRaises(ValueError):
                    F.validate_mode(bad, mode)
        with self.assertRaises(ValueError):
            F.validate_mode("quotient_fusion_research enabled=false production_ready=false\n", 1)

    def test_preserved_auditor_does_not_gain_a_fusion_marker(self):
        F.validate_mode("grouped_artifact_audit=PASS\n", 1, audit=True)
        with self.assertRaises(ValueError):
            F.validate_mode("quotient_fusion_research enabled=false production_ready=false\n", 1, audit=True)

    def test_base_controller_pin_is_checked(self):
        F.load_base()
        with patch.object(F, "BASE_SHA", "0" * 64), self.assertRaises(ValueError):
            F.load_base()

    def test_proving_requires_actual_fused_operations_not_just_environment(self):
        line = 'performance_span target="lattica_block_v2_perf" name="fused quotient ldes" calls=1 total_ns=7 max_ns=7\n'
        for name, count in (("pairs", 4), ("merges", 3)):
            F.validate_fusion_spans(line * count, 1, name)
            for text in ("", line * (count - 1), line * (count + 1),
                         (line.replace("calls=1", "calls=2")) * count,
                         (line.replace("max_ns=7", "max_ns=6")) * count):
                with self.assertRaises(ValueError):
                    F.validate_fusion_spans(text, 1, name)
        for mode, name in ((0, "pairs"), (0, "merges"), (1, "key-1"), (1, "audit"), (1, "root")):
            F.validate_fusion_spans("", mode, name)
            with self.assertRaises(ValueError):
                F.validate_fusion_spans(line, mode, name)

    def test_worker_limits_and_dependencies_are_preserved(self):
        module = F.load_base()
        F.configure(module, 1)
        config = {"mode": "prove", "runner": "/runner", "auditor": "/auditor", "job": "/job",
                  "evidence": "/evidence", "accounting": "/accounting", "external": ["11"*32]*3}
        for name, action in module.stages(config):
            if name == "export":
                continue
            command = module.stage_command(config, CONTROLLER, UNIT, name, action)
            for item in ("--property=MemoryMax=44G", "--property=MemoryHigh=40G",
                         "--property=MemorySwapMax=0", "--property=RuntimeMaxSec=7200",
                         f"--property=BindsTo={CONTROLLER}", f"--property=After={CONTROLLER}",
                         "--setenv=LATTICA_SPILL_MAX_BYTES=128849018880", "--setenv=RAYON_NUM_THREADS=8",
                         "--setenv=LATTICA_V2_GPU_DEVICE=4294967295", "--expand-environment=no"):
                self.assertIn(item, command)
            self.assertEqual(command[-3:], config["external"])
            self.assertIn(f"--setenv=LATTICA_V2_QUOTIENT_FUSION={0 if name == 'audit' else 1}", command)


class SyntheticReproduction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lattica-fusion-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module = F.load_base()
        F.configure(self.module, 1)
        self.shared, self.baseline = self.root / "shared", self.root / "baseline"
        self.shared.mkdir(mode=0o700)
        self.baseline.mkdir(mode=0o700)
        self.inputs = {}
        for name in self.module.WALLETS + self.module.ROOT_FILES[1:]:
            data = ("SYNTHETIC-" + name).encode()
            ((self.shared if name in self.module.WALLETS else self.baseline) / name).write_bytes(data)
            self.inputs[name] = F.identity(data)
        self.auditor = self.root / "block-v2-grouped-artifact-audit"
        self.auditor.write_bytes(b"SYNTHETIC-AUDITOR")
        self.handoff = self.root / "handoff.json"
        self.handoff.write_text(json.dumps({
            "status": "EXACT_SHARED_INPUTS_AND_BOTH_EXTERNAL_STATEMENTS_VALIDATED", "production_ready": False,
            "shared_wallet_directory": str(self.shared), "binary_directory": str(self.root),
            "binary_sha256": {self.auditor.name: self.module.digest(self.auditor)},
            "wallets": {n: self.inputs[n] for n in self.module.WALLETS},
            "variants": {"grouped": {"job": str(self.baseline), "inputs": self.inputs,
                "expected": {"level": 3, "count": 8, "mode": 3, "profile": "11"*32, "chain": "22"*32, "root": "00"*32}}}}))
        self.runner, self.archive = self.root / "runner", self.root / "sources.tar.gz"
        self.runner.write_bytes(b"SYNTHETIC-RUNNER")
        self.archive.write_bytes(b"SYNTHETIC-ARCHIVE")
        self.args = argparse.Namespace(action="reproduce", fusion=1, output=self.root / "output",
            runner=self.runner, source_archive=self.archive, runner_sha256=self.module.digest(self.runner),
            source_archive_sha256=self.module.digest(self.archive), registration=None, registration_sha256=None)
        self.commands = []
        self.corrupt_cap = False
        self.crash = False
        for target, name, value in (
            (F, "HANDOFF", self.handoff), (F, "HANDOFF_SHA", self.module.digest(self.handoff)),
            (self.module, "require_controller", lambda: CONTROLLER),
            (self.module, "require_no_other_work", lambda _: None),
            (self.module, "shared_lease_path", lambda: self.root / "lease"),
            (self.module, "capture_stage", self.capture)):
            active = patch.object(target, name, value)
            active.start()
            self.addCleanup(active.stop)

    def capture(self, command, log):
        self.commands.append(command)
        state = self.read_state()
        self.assertEqual(state["attempts"][-1]["status"], "attempted")
        self.assertTrue((self.args.output / "controller-sources/fusion-controller.py").is_file())
        if self.crash:
            raise InterruptedError("synthetic controller interruption")
        unit = next(s.removeprefix("--unit=") for s in command if s.startswith("--unit="))
        invocation = command[command.index("--") + 1:]
        action, job = invocation[1], Path(invocation[2])
        if action == "register":
            name = "key." + invocation[3]
            data = b"WRONG" if self.corrupt_cap else (self.baseline / name).read_bytes()
            (job / name).write_bytes(data)
        else:
            self.assertEqual(action, "check-registered")
            self.assertEqual(invocation[3:], ["11"*32, "22"*32, "00"*32])
        log.write_text("quotient_fusion_research enabled=true production_ready=false\n"
                       "grouped_stage_elapsed_ms=123 spill_peak_bytes=0 cpu_only=true production_ready=false\n"
                       f"stage_cgroup_accounting unit={unit} scope=exec_stop_post_snapshot memory_peak=17 "
                       f"memory_swap_peak=0 memory_max={44*self.module.GIB} memory_swap_max=0 cpu_usage_usec=42\n")
        return 0

    def read_state(self):
        return json.loads((self.args.output / "manifest.json").read_text())

    def test_success_reproduces_exact_caps_and_preserves_baseline(self):
        F.run(self.module, self.args)
        state = self.read_state()
        self.assertEqual(state["status"], "FULL_SIZE_PREPROCESSING_REPRODUCED_RESEARCH_ONLY")
        self.assertEqual(state["artifacts"], self.inputs)
        self.assertEqual(len(self.commands), 4)
        self.assertFalse(state["production_ready"])
        self.assertFalse(state["repeat_qualified"])
        self.assertFalse(state["level6_qualified"])
        self.assertEqual(sorted(p.name for p in self.shared.iterdir()), list(self.module.WALLETS))

    def test_existing_output_is_never_reused(self):
        self.args.output.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            F.run(self.module, self.args)
        self.assertEqual(self.commands, [])

    def test_cap_mismatch_is_terminal(self):
        self.corrupt_cap = True
        with self.assertRaisesRegex(ValueError, "cap differs"):
            F.run(self.module, self.args)
        self.assertEqual(self.read_state()["status"], "FAILED_OR_INTERRUPTED")
        self.assertEqual(len(self.commands), 1)
        with self.assertRaises(FileExistsError):
            F.run(self.module, self.args)
        self.assertEqual(len(self.commands), 1)

    def test_worker_interruption_records_failure_and_stops_unit(self):
        self.crash = True
        with patch.object(self.module.subprocess, "run") as stop, self.assertRaises(InterruptedError):
            F.run(self.module, self.args)
        self.assertEqual(stop.call_args.args[0][:3], ["systemctl", "--user", "stop"])
        state = self.read_state()
        self.assertEqual(state["status"], "FAILED_OR_INTERRUPTED")
        self.assertEqual(state["attempts"][0]["status"], "failed_or_interrupted")

    def test_runner_pin_mismatch_prevents_output_and_work(self):
        self.runner.write_bytes(b"CHANGED")
        with self.assertRaisesRegex(ValueError, "pinned file changed"):
            F.run(self.module, self.args)
        self.assertFalse(self.args.output.exists())
        self.assertEqual(self.commands, [])

    def test_wallet_tampering_prevents_work(self):
        (self.shared / "wallet.0").write_bytes(b"CHANGED")
        with self.assertRaisesRegex(ValueError, "wallet changed"):
            F.run(self.module, self.args)
        self.assertFalse(self.args.output.exists())

    def test_unsafe_output_overlap_prevents_work(self):
        self.args.output = self.shared / "output"
        with self.assertRaisesRegex(ValueError, "overlaps"):
            F.run(self.module, self.args)
        self.assertFalse(self.args.output.exists())

    def test_copy_refuses_symlink_output(self):
        target = self.root / "destination"
        target.symlink_to(self.shared / "wallet.0")
        with self.assertRaises(FileExistsError):
            F.copy_new(self.module, self.shared / "wallet.1", target, self.inputs["wallet.1"])

    def test_proof_requires_full_size_registration(self):
        self.args.action = "prove"
        with self.assertRaisesRegex(ValueError, "proof requires"):
            F.run(self.module, self.args)
        self.assertFalse(self.args.output.exists())

    def test_registration_revalidated_and_changed_caps_refused(self):
        F.run(self.module, self.args)
        path = self.args.output / "manifest.json"
        state = self.read_state()
        files = {k: (Path("/unused"), v) for k, v in state["pins"].items()}
        config = dict(state["config"], mode="prove", action="prove")
        supplied = {"inputs": self.inputs}
        F.validate_registration(self.module, path, self.module.digest(path), config, files, supplied)
        for key, value in (("quotient_fusion", 0), ("runner", "/wrong-runner")):
            with self.assertRaisesRegex(ValueError, "different configuration"):
                F.validate_registration(self.module, path, self.module.digest(path),
                                        dict(config, **{key: value}), files, supplied)
        with self.assertRaisesRegex(ValueError, "pin differs"):
            F.validate_registration(self.module, path, "0"*64, config, files, supplied)
        (self.args.output / "job/key.3").write_bytes(b"CHANGED")
        with self.assertRaisesRegex(ValueError, "caps or fixture changed"):
            F.validate_registration(self.module, path, self.module.digest(path), config, files, supplied)


if __name__ == "__main__":
    unittest.main()
