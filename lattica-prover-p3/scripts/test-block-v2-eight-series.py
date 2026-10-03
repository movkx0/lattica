#!/usr/bin/env python3
"""Synthetic orchestration tests: no real proofs, services, or existing fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import importlib.util

spec = importlib.util.spec_from_file_location(
    "eight_series", Path(__file__).with_name("block-v2-eight-series.py"))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def result(variant):
    return {"production_ready": False, "recursive_proofs": 15 if variant == "single" else 7,
            "recursive_command_ms": 2000 if variant == "single" else 1200,
            "final_merge_ms": 200, "root": {"bytes": 128, "sha256": "a" * 64}}


def state_with(count=0):
    return {"schema": 1, "config": {}, "status": "READY_FOR_NEXT_TRIAL", "attempts": [
        {"pair": pair, "variant": variant, "status": "complete", "config": {"variant": variant},
         "result": result(variant)} for pair, variant in s.order(5)[:count]],
        "prune": None, "replays": [], "shared_fixture_pruned": False,
        "repeat_qualified": False, "production_ready": False}


class SyntheticModule:
    WALLETS = tuple(f"wallet.{i}" for i in range(8))

    def __init__(self):
        self.saved = []
        self.runs = []
        self.captures = []
        self.failure = False
        self.replay_failure = False

    def save(self, path, state):
        self.saved.append(copy.deepcopy(state))

    def require_no_other_work(self, controller):
        if controller != "synthetic-controller":
            raise ValueError("unexpected controller")

    def run(self, config, resume):
        assert resume is False
        self.runs.append(config)
        if self.failure:
            raise RuntimeError("synthetic child failure")

    @staticmethod
    def sync_directory(path):
        assert path.is_dir()

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def regular_bytes(path):
        assert path.is_file() and not path.is_symlink()
        return path.read_bytes()

    @staticmethod
    def private_directory(path):
        s.require(path.is_dir() and not path.is_symlink() and path.stat().st_mode & 0o777 == 0o700,
                  "private directory required")

    @staticmethod
    def stage_command(config, controller, unit, name, action):
        assert name == "audit" and action == ["root-eight"]
        return [unit, config["variant"]]

    def capture_stage(self, command, log):
        self.captures.append(command)
        log.write_text("synthetic audit record\n")
        return 1 if self.replay_failure else 0

    @staticmethod
    def validate_log(path, unit, name):
        assert path.read_text() == "synthetic audit record\n" and name == "audit"
        return {"audit_proof_bytes": 128, "accounting": {"memory_swap_peak": 0}, "unit": unit}


class SeriesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.module = SyntheticModule()
        self.series = s.Series.__new__(s.Series)
        self.series.module = self.module
        self.series.config = {"pairs": 5}
        self.series.output = self.directory
        self.series.path = self.directory / "manifest.json"
        self.series.helper = SimpleNamespace(
            SINGLE=self.module, GROUPED=self.module,
            verify_completed_trial=lambda module, config, variant: result(variant),
        )
        self.series.validate_pins = lambda shared_required=True: None
        self.series.validate_source_archive = lambda: None
        self.series.validate_completed = lambda state: s.prefix(state, 5)
        self.pilot = {"attempts": [
            {"construction": variant, "config": {"variant": variant}}
            for variant in ("single", "grouped")],
            "results": {variant: result(variant) for variant in ("single", "grouped")}}
        self.series.validate_pilot = lambda: self.pilot
        self.series.trial_config = lambda pair, variant: {"pair": pair, "variant": variant}
        self.created = []
        self.series.create_job = lambda config, variant: self.created.append(config)
        shared = self.directory / "shared"
        shared.mkdir()
        for name in self.module.WALLETS:
            (shared / name).write_bytes(b"synthetic wallet, not a proof")
        self.series.handoff = {"shared_wallet_directory": str(shared), "wallets": {}}

    def test_exact_alternating_order_and_minimum_repetitions(self):
        self.assertEqual(s.order(5)[:4], [(1, "single"), (1, "grouped"),
                                        (2, "grouped"), (2, "single")])
        for invalid in [0, 1, 4, 21, True, 5.0]:
            with self.assertRaises(ValueError):
                s.order(invalid)

    def test_one_pair_per_controller_invocation(self):
        state = state_with()
        self.series.advance(state, "synthetic-controller")
        self.assertEqual(len(self.module.runs), 2)
        self.assertEqual(s.prefix(state, 5), 2)
        self.assertFalse(state["repeat_qualified"])
        self.series.advance(state, "synthetic-controller")
        self.assertEqual([a["variant"] for a in state["attempts"]],
                         ["single", "grouped", "grouped", "single"])

    def test_clean_odd_prefix_finishes_only_its_pair(self):
        state = state_with(1)
        self.series.advance(state, "synthetic-controller")
        self.assertEqual(len(self.module.runs), 1)
        self.assertEqual(state["attempts"][-1]["variant"], "grouped")
        self.assertEqual(s.prefix(state, 5), 2)

    def test_attempt_is_journaled_before_job_creation(self):
        state = state_with()

        def inspect(config, variant):
            self.assertEqual(self.module.saved[-1]["attempts"][-1]["status"], "attempted")
            self.assertEqual(self.module.saved[-1]["attempts"][-1]["config"], config)

        self.series.create_job = inspect
        self.series.advance(state, "synthetic-controller")

    def test_uncertain_trial_is_never_rerun(self):
        for status in ["attempted", "failed_or_interrupted"]:
            state = state_with(1)
            state["attempts"][0]["status"] = status
            with self.assertRaises(ValueError):
                self.series.advance(state, "synthetic-controller")
        self.assertEqual(self.module.runs, [])

    def test_failed_child_is_recorded_and_resume_refused(self):
        state = state_with()
        self.module.failure = True
        with self.assertRaises(RuntimeError):
            self.series.advance(state, "synthetic-controller")
        self.assertEqual(state["status"], "FAILED_OR_INTERRUPTED")
        self.assertEqual(state["attempts"][0]["status"], "failed_or_interrupted")
        with self.assertRaises(ValueError):
            self.series.advance(state, "synthetic-controller")
        self.assertEqual(len(self.module.runs), 1)

    def test_failed_copy_is_also_an_uncertain_attempt(self):
        state = state_with()
        self.series.create_job = lambda *_: (_ for _ in ()).throw(OSError("partial copy"))
        with self.assertRaises(OSError):
            self.series.advance(state, "synthetic-controller")
        self.assertEqual(state["attempts"][0]["status"], "failed_or_interrupted")
        self.assertEqual(self.module.runs, [])

    def test_completed_series_is_measured_not_qualified_before_pruning(self):
        state = state_with(8)
        self.series.advance(state, "synthetic-controller")
        self.assertEqual(state["status"], "MEASURED_SHARED_FIXTURE_RETAINED")
        self.assertFalse(state["repeat_qualified"])
        self.assertEqual(state["metrics"]["median_total_reduction_percent"], 40.0)

    def test_summary_rejects_missing_duplicate_reordered_or_misclassified_trials(self):
        mutations = [
            lambda state: state["attempts"].pop(),
            lambda state: state["attempts"].reverse(),
            lambda state: state["attempts"].append(state["attempts"][-1]),
            lambda state: state["attempts"][0]["result"].update(recursive_proofs=7),
            lambda state: state["attempts"][0]["result"].update(recursive_command_ms=0),
            lambda state: state["attempts"][0]["result"].update(final_merge_ms=2001),
            lambda state: state["attempts"][0]["result"].update(production_ready=True),
            lambda state: state["attempts"][0].update(pair=True),
        ]
        for mutate in mutations:
            state = state_with(10)
            mutate(state)
            with self.assertRaises(ValueError):
                s.summary(state, 5)

    def test_finalize_requires_all_five_pairs(self):
        with self.assertRaises(ValueError):
            self.series.finalize(state_with(8), "synthetic-controller")
        self.assertEqual(len(list((self.directory / "shared").iterdir())), 8)

    def test_all_ten_roots_and_both_pilot_roots_replayed_after_pruning(self):
        state = state_with(10)
        original_capture = self.module.capture_stage

        def capture(command, log):
            self.assertFalse(any((self.directory / "shared").iterdir()))
            self.assertTrue(self.module.saved[-1]["shared_fixture_pruned"])
            self.assertEqual(self.module.saved[-1]["replays"][-1]["status"], "attempted")
            return original_capture(command, log)

        self.module.capture_stage = capture
        self.series.finalize(state, "synthetic-controller")
        self.assertEqual(len(self.module.captures), 12)
        self.assertEqual([r["target"]["label"] for r in state["replays"][-2:]],
                         ["pilot-single", "pilot-grouped"])
        self.assertTrue(state["repeat_qualified"])
        self.assertFalse(state["production_ready"])
        self.assertFalse(state["metrics"]["tail_latency_qualified"])
        # A fully verified finalization is idempotent, not a new set of audits.
        self.series.finalize(state, "synthetic-controller")
        self.assertEqual(len(self.module.captures), 12)

    def test_partial_prune_refuses_automatic_continuation(self):
        state = state_with(10)
        state["prune"] = {"status": "attempted"}
        with self.assertRaises(ValueError):
            self.series.finalize(state, "synthetic-controller")
        self.assertEqual(len(list((self.directory / "shared").iterdir())), 8)
        self.assertEqual(self.module.captures, [])

    def test_failed_replay_is_not_qualified_or_retried(self):
        state = state_with(10)
        self.module.replay_failure = True
        with patch.object(s.subprocess, "run") as stop:
            with self.assertRaises(ValueError):
                self.series.finalize(state, "synthetic-controller")
            stop.assert_called_once()
        self.assertEqual(state["status"], "FAILED_OR_INTERRUPTED")
        self.assertFalse(state["repeat_qualified"])
        with self.assertRaises(ValueError):
            self.series.finalize(state, "synthetic-controller")
        self.assertEqual(len(self.module.captures), 1)

    def test_changed_replay_log_is_rejected(self):
        state = state_with(10)
        self.series.finalize(state, "synthetic-controller")
        (self.directory / state["replays"][0]["log"]).write_text("changed\n")
        with self.assertRaises(ValueError):
            self.series.finalize(state, "synthetic-controller")

    def test_no_more_proving_after_pruning(self):
        state = state_with(10)
        self.series.finalize(state, "synthetic-controller")
        with self.assertRaises(ValueError):
            self.series.advance(state, "synthetic-controller")

    def test_copy_new_checks_exact_content_before_creating_destination(self):
        source, destination = self.directory / "source", self.directory / "destination"
        source.write_bytes(b"correct fixture")
        module = SimpleNamespace(regular_bytes=lambda path: path.read_bytes())
        expected = {"bytes": 15, "sha256": hashlib.sha256(b"correct fixture").hexdigest()}
        s.copy_new(module, source, destination, expected)
        self.assertEqual(destination.read_bytes(), b"correct fixture")
        source.write_bytes(b"changed fixture")
        other = self.directory / "other"
        with self.assertRaises(ValueError):
            s.copy_new(module, source, other, expected)
        self.assertFalse(other.exists())

    def test_copy_new_never_overwrites_existing_or_symlink_destination(self):
        source = self.directory / "source"
        source.write_bytes(b"fixture")
        module = SimpleNamespace(regular_bytes=lambda path: path.read_bytes())
        expected = {"bytes": 7, "sha256": hashlib.sha256(b"fixture").hexdigest()}
        existing = self.directory / "existing"
        existing.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            s.copy_new(module, source, existing, expected)
        link = self.directory / "link"
        link.symlink_to(existing)
        with self.assertRaises(FileExistsError):
            s.copy_new(module, source, link, expected)
        self.assertEqual(existing.read_bytes(), b"preserve")

    def test_completed_validation_recomputes_report_and_exact_config(self):
        state = state_with(2)
        state["config"] = self.series.config
        for attempt in state["attempts"]:
            attempt["config"] = self.series.trial_config(attempt["pair"], attempt["variant"])
        self.assertEqual(s.Series.validate_completed(self.series, state), 2)
        changed = copy.deepcopy(state)
        changed["attempts"][0]["result"]["recursive_command_ms"] += 1
        with self.assertRaises(ValueError):
            s.Series.validate_completed(self.series, changed)
        changed = copy.deepcopy(state)
        changed["attempts"][0]["config"]["pair"] += 1
        with self.assertRaises(ValueError):
            s.Series.validate_completed(self.series, changed)

    def test_changed_replay_target_is_rejected(self):
        state = state_with(10)
        self.series.finalize(state, "synthetic-controller")
        state["replays"][0]["target"] = copy.deepcopy(state["replays"][0]["target"])
        state["replays"][0]["target"]["root"]["sha256"] = "b" * 64
        with self.assertRaises(ValueError):
            self.series.finalize(state, "synthetic-controller")

    def test_archived_sources_preserve_pins_and_reject_changed_membership_or_bytes(self):
        source = self.directory / "source.py"
        source.write_text("# synthetic source\n")
        pin = self.module.digest(source)
        self.series.source_files = lambda: {"series.py": (source, pin)}
        self.series.validate_source_archive = lambda: s.Series.validate_source_archive(self.series)
        self.series.archive_sources()
        directory = self.directory / "controller-sources"
        self.assertEqual((directory / "series.py").read_bytes(), source.read_bytes())
        (directory / "extra.py").write_text("extra\n")
        with self.assertRaises(ValueError):
            self.series.validate_source_archive()
        (directory / "extra.py").unlink()
        (directory / "series.py").write_text("changed\n")
        with self.assertRaises(ValueError):
            self.series.validate_source_archive()

    def test_archived_source_directory_must_be_private(self):
        directory = self.directory / "controller-sources"
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o755)
        self.series.source_files = lambda: {}
        with self.assertRaises(ValueError):
            s.Series.validate_source_archive(self.series)

    def test_helper_executes_exactly_the_hashed_bytes_without_a_second_read(self):
        source = self.directory / "helper.py"
        source.write_text("value = 1\n")
        pin = self.module.digest(source)
        original = s.importlib.util.module_from_spec

        def change_after_read(spec):
            source.write_text("value = 2\n")
            return original(spec)

        with patch.object(s.importlib.util, "module_from_spec", side_effect=change_after_read):
            helper = s.load_helper(source, pin)
        self.assertEqual(helper.value, 1)
        self.assertEqual(source.read_text(), "value = 2\n")

    def test_helper_rejects_bad_hash_and_symlink_before_execution(self):
        source = self.directory / "helper.py"
        source.write_text("raise AssertionError('must not execute')\n")
        with self.assertRaises(ValueError):
            s.load_helper(source, "0" * 64)
        link = self.directory / "helper-link.py"
        link.symlink_to(source)
        with self.assertRaises(ValueError):
            s.load_helper(link, self.module.digest(source))

    def test_handoff_constructor_checks_the_consumed_bytes_against_external_pin(self):
        handoff = self.directory / "handoff.json"
        handoff.write_text('{"status": "fixture"}\n')
        pin = self.module.digest(handoff)
        helper = SimpleNamespace(GROUPED=self.module, HANDOFF=handoff, HANDOFF_SHA=pin)
        config = {"output": str(self.directory), "handoff_sha256": pin}
        self.assertEqual(s.Series(helper, config).handoff, {"status": "fixture"})
        handoff.write_text('{"status": "changed"}\n')
        with self.assertRaises(ValueError):
            s.Series(helper, config)

    def test_pilot_record_pin_checks_the_consumed_bytes_before_status(self):
        pilot_dir = self.directory / "pilot"
        pilot_dir.mkdir()
        record = pilot_dir / "manifest.json"
        record.write_text('{"status": "RUNNING"}\n')
        self.series.helper.OUTPUT = pilot_dir
        self.series.config["pilot_manifest_sha256"] = self.module.digest(record)
        with self.assertRaisesRegex(ValueError, "pilot has not completed"):
            s.Series.validate_pilot(self.series)
        record.write_text('{"status": "tampered"}\n')
        with self.assertRaisesRegex(ValueError, "pilot record changed"):
            s.Series.validate_pilot(self.series)


if __name__ == "__main__":
    unittest.main(verbosity=2)
