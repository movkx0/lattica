#!/usr/bin/env python3
"""Synthetic filesystem/lifecycle tests, not proving or real service qualification."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("fusion_prune", "block-v2-fusion-prune.py")
R = load("prune_report_test", "report-block-v2-fusion.py")
F, _ = R.load_trial_module()
B = F.load_base()


class Pruning(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.shared = self.root / "shared"
        self.shared.mkdir(mode=0o700)
        self.wallets = {name: self.write(self.shared / name, name.encode()) for name in P.WALLETS}
        self.caps_data = {name: ("cap-" + name).encode() for name in P.CAPS}
        self.caps = {name: P.identity(data) for name, data in self.caps_data.items()}
        self.references, self.reports, self.jobs, self.proof_jobs = [], [], [], []
        for mode in (0, 1):
            registration = self.root / f"registration-{mode}"
            trial = self.root / f"trial-{mode}"
            for directory in (registration, trial):
                directory.mkdir(mode=0o700)
                (directory / "job").mkdir(mode=0o700)
                (directory / "job/scratch").mkdir(mode=0o700)
                for name, data in self.caps_data.items():
                    self.write(directory / "job" / name, data)
            job, proof_job = registration / "job", trial / "job"
            for name in P.WALLETS:
                self.write(job / name, name.encode())
            root = self.write(proof_job / "node.3.0", f"synthetic-root-{mode}".encode())
            reg = {"config": {"job": str(job), "quotient_fusion": mode},
                   "artifacts": {**self.wallets, **self.caps}}
            proof = {"config": {"job": str(proof_job), "quotient_fusion": mode},
                     "artifacts": {"node.3.0": root, **self.caps}}
            self.write(registration / "manifest.json", json.dumps(reg).encode())
            self.write(trial / "manifest.json", json.dumps(proof).encode())
            reference = {"trial": trial / "manifest.json", "trial_sha256": B.digest(trial / "manifest.json"),
                         "registration": registration / "manifest.json",
                         "registration_sha256": B.digest(registration / "manifest.json")}
            self.references.append(reference)
            self.reports.append({
                "fusion": mode, "manifest": str(reference["trial"]), "manifest_sha256": reference["trial_sha256"],
                "registration_manifest": str(reference["registration"]), "registration_sha256": reference["registration_sha256"],
                "wallets": self.wallets, "height_and_caps": self.caps, "root": root,
                "external": ["1" * 64, "2" * 64, "3" * 64],
                "pins": {name: "0" * 64 for name in ("fusion-controller.py", "grouped-controller.py", "accounting.py",
                         "handoff.json", "runner", "source-archive", "auditor")},
                "started_utc": f"2026-10-01T1{mode}:00:00Z", "finished_utc": f"2026-10-01T1{mode}:10:00Z",
                "recursive_command_ms": 100, "final_merge_ms": 20,
                "peak_worker_cgroup_bytes": 100, "peak_live_mapped_spill_bytes": 100,
                "production_ready": False, "repeat_qualified": False, "depth_six_qualified": False,
                "recorded_preserved_cpu_audit": "PASS"})
            self.jobs.append(job)
            self.proof_jobs.append(proof_job)
        # Cryptographic/report validation is explicitly stubbed; real reporter has its own tests.
        self.reporter = Mock()
        self.reporter.inspect.side_effect = lambda path, *_: copy.deepcopy(
            self.reports[[r["trial"] for r in self.references].index(path)])
        self.reporter.pinned_json = R.pinned_json
        self.reporter.compare = R.compare
        self.output = self.root / "receipt"

    def write(self, path, data):
        path.write_bytes(data)
        path.chmod(0o600)
        return P.identity(data)

    def plan(self):
        return P.make_plan(self.reporter, B, self.references, self.shared)

    def wallet_count(self):
        return sum((job / name).exists() for job in self.jobs for name in P.WALLETS)

    def receipt(self):
        return json.loads((self.output / "manifest.json").read_bytes())

    def test_plan_is_read_only_and_binds_both_consumers(self):
        plan = self.plan()
        self.assertEqual(plan["status"], "READ_ONLY_REGISTRATION_PRUNE_PLAN")
        self.assertEqual(plan["wallet_files_to_remove"], 16)
        self.assertEqual(self.wallet_count(), 16)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.reporter.inspect.call_count, 2)
        self.assertFalse(plan["fresh_cpu_replay_performed"])
        self.assertFalse(plan["production_ready"])

    def test_apply_removes_only_registration_wallets_and_preserves_pins(self):
        plan = self.plan()
        state = P.apply_plan(B, plan, self.output, Mock())
        self.assertTrue(state["registration_wallets_pruned"])
        self.assertEqual(len(state["removed"]), 16)
        self.assertEqual(self.wallet_count(), 0)
        P.check_preserved(B, plan, pruned=True)
        for flag in ("shared_fixture_pruned", "fresh_cpu_replay_performed", "production_ready", "repeat_qualified", "depth_six_qualified"):
            self.assertFalse(state[flag])
        self.assertEqual(self.receipt(), state)

    def test_invalid_consumer_stops_before_any_deletion(self):
        self.reporter.inspect.side_effect = ValueError("trial incomplete")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.plan()
        self.assertEqual(self.wallet_count(), 16)

    def test_wrong_mode_is_rejected(self):
        self.reports[0]["fusion"] = 1
        with self.assertRaisesRegex(ValueError, "mode"):
            self.plan()

    def test_overlapping_trials_are_not_accepted(self):
        self.reports[1]["started_utc"] = "2026-10-01T10:05:00Z"
        with self.assertRaisesRegex(ValueError, "overlapped"):
            self.plan()

    def test_changed_manifest_pin_is_rejected(self):
        self.references[0]["registration_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "SHA256 differs"):
            self.plan()

    def test_extra_reference_fields_and_invalid_pins_rejected(self):
        for key, value in (("extra", "bad"), ("trial_sha256", "invalid")):
            old = copy.deepcopy(self.references)
            self.references[0][key] = value
            with self.assertRaises(ValueError):
                self.plan()
            self.references = old

    def test_symlink_manifest_refused(self):
        original = self.references[0]["registration"]
        moved = original.with_name("preserved.json")
        original.rename(moved)
        original.symlink_to(moved)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.plan()

    def test_symlink_parent_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.references[0]["registration"].parent, target_is_directory=True)
        self.references[0]["registration"] = alias / "manifest.json"
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.plan()

    def test_misbound_job_refused(self):
        path = self.references[0]["registration"]
        data = json.loads(path.read_bytes())
        data["config"]["job"] = str(self.jobs[1])
        self.write(path, json.dumps(data).encode())
        self.references[0]["registration_sha256"] = B.digest(path)
        with self.assertRaisesRegex(ValueError, "misbound"):
            self.plan()

    def test_extra_registration_file_refused(self):
        self.write(self.jobs[1] / "unexpected", b"extra")
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.plan()

    def test_missing_wallet_refused(self):
        (self.jobs[1] / "wallet.7").unlink()
        with self.assertRaisesRegex(ValueError, "registration artifacts"):
            self.plan()

    def test_modified_cap_refused(self):
        self.write(self.jobs[0] / "key.1", b"different")
        with self.assertRaisesRegex(ValueError, "registration artifacts"):
            self.plan()

    def test_hard_link_refused(self):
        os.link(self.jobs[0] / "wallet.0", self.root / "other-link")
        with self.assertRaisesRegex(ValueError, "hard-linked"):
            self.plan()

    def test_wallet_permissions_refused(self):
        (self.jobs[1] / "wallet.0").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            self.plan()

    def test_shared_fixture_tampering_refused(self):
        self.write(self.shared / "wallet.7", b"changed")
        with self.assertRaisesRegex(ValueError, "shared fixture identity"):
            self.plan()

    def test_existing_output_not_resumed(self):
        plan = self.plan()
        self.output.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "cannot be resumed"):
            P.apply_plan(B, plan, self.output, Mock())
        self.assertEqual(self.wallet_count(), 16)

    def test_output_must_not_be_inside_protected_input(self):
        plan = self.plan()
        with self.assertRaisesRegex(ValueError, "nested"):
            P.apply_plan(B, plan, self.jobs[0] / "receipt", Mock())
        self.assertEqual(self.wallet_count(), 16)

    def test_busy_guard_refuses_before_receipt_creation(self):
        with self.assertRaisesRegex(ValueError, "live service"):
            P.apply_plan(B, self.plan(), self.output, Mock(side_effect=ValueError("other live service")))
        self.assertFalse(self.output.exists())
        self.assertEqual(self.wallet_count(), 16)

    def test_late_wallet_change_prevents_all_deletions(self):
        plan = self.plan()
        self.write(self.jobs[-1] / "wallet.7", b"changed-after-plan")
        with self.assertRaisesRegex(ValueError, "membership/content"):
            P.apply_plan(B, plan, self.output, Mock())
        self.assertEqual(self.wallet_count(), 16)
        self.assertFalse(self.output.exists())

    def test_directory_replacement_rejected_even_with_identical_contents(self):
        plan = self.plan()
        old = self.jobs[0].with_name("old-job")
        self.jobs[0].rename(old)
        self.jobs[0].mkdir(mode=0o700)
        (self.jobs[0] / "scratch").mkdir(mode=0o700)
        for path in old.iterdir():
            if path.is_file():
                self.write(self.jobs[0] / path.name, path.read_bytes())
        with self.assertRaisesRegex(ValueError, "directory replaced"):
            P.apply_plan(B, plan, self.output, Mock())
        self.assertEqual(self.wallet_count(), 16)

    def test_interrupted_deletion_is_journaled_and_never_resumed(self):
        plan = self.plan()
        unlink = os.unlink
        count = 0

        def interrupt(name, *, dir_fd=None):
            nonlocal count
            count += 1
            self.assertEqual(self.receipt()["status"], "PRUNE_ATTEMPTED")
            if count == 2:
                raise InterruptedError("injected interruption")
            unlink(name, dir_fd=dir_fd)

        with patch.object(P.os, "unlink", side_effect=interrupt), self.assertRaises(InterruptedError):
            P.apply_plan(B, plan, self.output, Mock())
        receipt = self.receipt()
        self.assertEqual(receipt["status"], "FAILED_OR_INTERRUPTED_MANUAL_INSPECTION_REQUIRED")
        self.assertFalse(receipt["registration_wallets_pruned"])
        self.assertEqual(len(receipt["removed"]), 1)
        self.assertEqual(self.wallet_count(), 15)
        with self.assertRaisesRegex(ValueError, "cannot be resumed"):
            P.apply_plan(B, plan, self.output, Mock())
        self.assertEqual(self.wallet_count(), 15)

    def test_root_changed_during_pruning_prevents_success(self):
        count = 0

        def guard():
            nonlocal count
            count += 1
            if count == 3:
                self.write(self.proof_jobs[0] / "node.3.0", b"changed")

        with self.assertRaisesRegex(ValueError, "root artifacts"):
            P.apply_plan(B, self.plan(), self.output, guard)
        self.assertEqual(self.receipt()["status"], "FAILED_OR_INTERRUPTED_MANUAL_INSPECTION_REQUIRED")

    def test_symlink_swap_after_open_is_refused(self):
        count = 0

        def guard():
            nonlocal count
            count += 1
            if count == 2:
                old = self.jobs[0].with_name("old-job")
                self.jobs[0].rename(old)
                self.jobs[0].symlink_to(old, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlink"):
            P.apply_plan(B, self.plan(), self.output, guard)
        self.assertEqual(self.wallet_count(), 16)
        self.assertEqual(self.receipt()["removed"], [])

    def cli_args(self, action):
        args = ["fusion-prune", action]
        for label, ref in zip(("off", "on"), self.references):
            args.extend(["--" + label, str(ref["trial"]), "--" + label + "-sha256", ref["trial_sha256"],
                         "--" + label + "-registration", str(ref["registration"]),
                         "--" + label + "-registration-sha256", ref["registration_sha256"]])
        return args

    def test_plan_cli_never_requires_or_creates_services(self):
        with patch("sys.argv", self.cli_args("plan")), patch.object(P, "load_runtime", return_value=(self.reporter, B, self.shared)), \
                patch.object(B, "require_controller") as controller, patch("sys.stdout", new_callable=io.StringIO) as output:
            P.main()
            controller.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["wallet_files_to_remove"], 16)
        self.assertEqual(self.wallet_count(), 16)

    def test_apply_cli_refuses_live_work_before_inspection_or_writes(self):
        args = self.cli_args("apply") + ["--output", str(self.output)]
        with patch("sys.argv", args), patch.object(P, "load_runtime", return_value=(self.reporter, B, self.shared)), \
                patch.object(B, "require_controller", side_effect=ValueError("live proving service")), \
                self.assertRaisesRegex(ValueError, "live proving"):
            P.main()
        self.reporter.inspect.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.wallet_count(), 16)


if __name__ == "__main__":
    unittest.main()
