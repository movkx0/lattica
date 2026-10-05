#!/usr/bin/env python3
"""Tiny harness tests; no systemd command or native proof is executed."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import importlib.util

spec = importlib.util.spec_from_file_location(
    "eight_series_lifecycle", Path(__file__).with_name("test-block-v2-eight-series-lifecycle.py"))
life = importlib.util.module_from_spec(spec)
spec.loader.exec_module(life)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_busy_preflight_refuses_before_creating_evidence_or_services(self):
        output = self.directory / "new-evidence"
        with patch.object(life, "require_idle_manager", side_effect=ValueError("live worker")), \
                patch.object(life.subprocess, "run") as command, \
                patch.object(life.subprocess, "Popen") as process:
            with self.assertRaisesRegex(ValueError, "live worker"):
                life.run(output)
        command.assert_not_called()
        process.assert_not_called()
        self.assertFalse(output.exists())

    def test_existing_evidence_is_never_reused(self):
        preserved = self.directory / "preserve"
        preserved.write_bytes(b"existing evidence")
        with patch.object(life, "require_idle_manager"), \
                patch.object(life, "source_pins") as pins, \
                patch.object(life.subprocess, "run") as command:
            with self.assertRaisesRegex(ValueError, "new evidence directory"):
                life.run(self.directory)
        pins.assert_not_called()
        command.assert_not_called()
        self.assertEqual(preserved.read_bytes(), b"existing evidence")

    def test_record_is_durable_and_refuses_overwrite(self):
        life.record(self.directory, "record.json", {"test": 1})
        before = (self.directory / "record.json").read_bytes()
        self.assertEqual(json.loads(before), {"test": 1})
        with self.assertRaisesRegex(ValueError, "existing test record"):
            life.record(self.directory, "record.json", {"test": 2})
        self.assertEqual((self.directory / "record.json").read_bytes(), before)

    def test_external_idle_check_accepts_only_an_empty_live_service_inventory(self):
        with patch.object(life.subprocess, "check_output", return_value="") as check:
            life.require_idle_manager()
        self.assertIn("--state=active,activating,deactivating,reloading", check.call_args.args[0])
        for output in ["lattica-v2-pilot.service loaded active running pilot\n", "unexpected output\n"]:
            with patch.object(life.subprocess, "check_output", return_value=output):
                with self.assertRaisesRegex(ValueError, "live experiment services"):
                    life.require_idle_manager()

    def test_actual_series_records_failed_stub_after_durable_attempt(self):
        instance = life.fixture(self.directory, "synthetic-controller")
        state = life.new_state(instance.config)
        life.trial.save(instance.path, state)

        def stop_after_journal(config, resume):
            self.assertFalse(resume)
            saved = json.loads(life.trial.regular_bytes(instance.path))
            self.assertEqual(saved["attempts"][0]["status"], "attempted")
            self.assertTrue((self.directory / "synthetic-job-created.json").exists())
            raise InterruptedError("synthetic interruption")

        instance.helper.SINGLE.run = stop_after_journal
        with patch.object(life.trial, "require_no_other_work"), \
                patch.object(life.subprocess, "Popen") as process:
            with self.assertRaisesRegex(InterruptedError, "synthetic interruption"):
                instance.advance(state, "synthetic-controller")
        process.assert_not_called()
        saved = json.loads(life.trial.regular_bytes(instance.path))
        self.assertEqual(saved["status"], "FAILED_OR_INTERRUPTED")
        self.assertEqual(saved["attempts"][0]["status"], "failed_or_interrupted")
        with self.assertRaisesRegex(ValueError, "uncertain attempt"):
            instance.validate_completed(saved)

    def test_recovery_refuses_uncertain_trial_without_rewriting_journal(self):
        instance = life.fixture(self.directory, "synthetic-controller")
        state = life.new_state(instance.config)
        state["attempts"] = [{"pair": 1, "variant": "single", "status": "attempted"}]
        life.trial.save(instance.path, state)
        before = life.trial.regular_bytes(instance.path)
        with patch.object(life.trial, "require_controller", return_value="synthetic-controller"), \
                patch.object(life.trial, "require_no_other_work") as admission, \
                patch.object(life.trial, "stage_command") as stage, \
                patch.object(life.subprocess, "Popen") as process:
            life.recover(self.directory)
        admission.assert_not_called()
        stage.assert_not_called()
        process.assert_not_called()
        self.assertEqual(life.trial.regular_bytes(instance.path), before)
        report = json.loads(life.trial.regular_bytes(self.directory / "recovery-refused.json"))
        self.assertTrue(report["uncertain_trial_refused"])
        self.assertTrue(report["journal_unchanged"])
        self.assertFalse((self.directory / "synthetic-job-created.json").exists())

    def test_live_overlap_refusal_requires_the_expected_admission_failure(self):
        with patch.object(life.trial, "require_controller", side_effect=ValueError("wrong limits")):
            with self.assertRaisesRegex(ValueError, "unexpected admission error"):
                life.refuse_live_overlap(self.directory)
        self.assertFalse((self.directory / "overlap-refused.json").exists())
        with patch.object(life.trial, "require_controller",
                          side_effect=ValueError("other experiment services remain live: synthetic")):
            life.refuse_live_overlap(self.directory)
        self.assertTrue(json.loads((self.directory / "overlap-refused.json").read_bytes())["refused"])

    def test_controller_service_is_explicitly_bounded_and_non_proving(self):
        command = life.service("lattica-v2-eight-series-lifecycle-test.service", "recover", self.directory)
        for option in ("--property=MemoryMax=3G", "--property=MemorySwapMax=0",
                       "--property=RuntimeMaxSec=90", "--property=LimitCORE=0",
                       "--slice=" + life.trial.RESOURCE_SLICE, "--expand-environment=no"):
            self.assertIn(option, command)
        payload = command[command.index("--") + 1:]
        self.assertEqual(payload[1:], ["-B", str(life.HERE), "recover", str(self.directory)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
