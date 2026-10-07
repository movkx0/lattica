#!/usr/bin/env python3
"""Recovery-controller unit checks with synthetic bytes; no proving evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("typed_recovery_test", Path(__file__).with_name("qualify-block-v2-typed-recovery.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class RecoveryController(unittest.TestCase):
    def test_negative_inputs_do_not_collide_with_process_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            root, budget_path = out / "root.proof", out / "budget.json"
            root.write_bytes(b"synthetic root metadata test")
            budget = {"host": {"worker_bytes": 4096}}
            budget_path.write_text(json.dumps(budget))
            original = (root.read_bytes(), budget_path.read_bytes())
            head = "ab" * 32
            cases = M.negative_cases(out, budget, budget_path, root, head)
            self.assertEqual(len(cases), 4)
            self.assertEqual(budget["host"]["worker_bytes"], 4096)
            for name, budget_file, proof, current_head, epoch in cases:
                self.assertTrue(budget_file.is_file())
                self.assertTrue(proof.is_file())
                self.assertEqual(sum((budget_file != budget_path, proof != root,
                                      current_head != head, epoch != 2)), 1)
                result = M.execute([sys.executable, "-c", "raise SystemExit(7)"],
                                   out / name, M.T.clean_environment(), False)
                self.assertEqual(result["exit_code"], 7)
            self.assertEqual((root.read_bytes(), budget_path.read_bytes()), original)
            self.assertNotEqual(cases[-1][2].read_bytes(), original[0])

    def test_archive_preserves_original_bytes_and_detects_later_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / "checkpoint").write_bytes(b"synthetic original")
            retained = M.archive(runtime, root / "before.tar.gz")
            M.assert_unchanged(runtime, retained["members"])
            (runtime / "checkpoint").write_bytes(b"synthetic changed")
            with self.assertRaisesRegex(ValueError, "mutated"):
                M.assert_unchanged(runtime, retained["members"])
            with tarfile.open(root / "before.tar.gz") as archive:
                self.assertEqual(archive.extractfile("checkpoint").read(), b"synthetic original")

    def test_archive_rejects_links_empty_roots_and_retention_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            with self.assertRaisesRegex(ValueError, "empty"):
                M.inventory(runtime)
            (runtime / "checkpoint").write_bytes(b"synthetic")
            with patch.object(M, "MAX_RUNTIME_BYTES", 1), self.assertRaisesRegex(ValueError, "bound"):
                M.inventory(runtime)
            (runtime / "linked").symlink_to(runtime / "checkpoint")
            with self.assertRaisesRegex(ValueError, "symlink"):
                M.inventory(runtime)
            (root / "linked-root").symlink_to(runtime, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "nonsymlink"):
                M.inventory(root / "linked-root")

    def test_recovery_receipt_requires_exact_identity_no_work_and_identical_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / "expected-root"
            proof.write_bytes(b"synthetic root metadata test")
            (root / "recovered-root").write_bytes(proof.read_bytes())
            result = {"record_type": "typed_gpu_journal_recovery", "status": "succeeded",
                      "recovery_epoch": 2, "count": 4, "verified_cached_nodes": 4,
                      "root_bytes": proof.stat().st_size, "cpu_audited_root": True,
                      "original_gpu_journal": True, "root_identical": True,
                      "wrong_head_rejected": True, "resources_released": True,
                      "unresolved_attempts": 0, "unresolved_workspaces": 0, "prover_jobs_started": 0,
                      "fresh_recursive_proofs": 0, "native_blocks_applied": 0,
                      "production_ready": False, "arrival_backend_integrated": False}
            (root / "summary.json").write_text(json.dumps(result))
            M.checked_result(root, proof, 4, 2, 4)
            for key, value in (("recovery_epoch", 3), ("verified_cached_nodes", 3),
                               ("cpu_audited_root", False), ("unresolved_workspaces", 1),
                               ("unresolved_attempts", False), ("prover_jobs_started", 1),
                               ("fresh_recursive_proofs", 1), ("arrival_backend_integrated", True)):
                changed = copy.deepcopy(result)
                changed[key] = value
                (root / "summary.json").write_text(json.dumps(changed))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    M.checked_result(root, proof, 4, 2, 4)
            (root / "summary.json").write_text(json.dumps(result))
            (root / "recovered-root").write_bytes(b"different")
            with self.assertRaisesRegex(ValueError, "root bytes"):
                M.checked_result(root, proof, 4, 2, 4)

    def test_child_exit_is_observed_and_failed_expectations_retain_process_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = [sys.executable, "-c", "raise SystemExit(7)"]
            result = M.execute(command, root / "negative", M.T.clean_environment(), False)
            self.assertEqual(result["exit_code"], 7)
            self.assertGreater(result["pid"], 0)
            with self.assertRaisesRegex(ValueError, "exit differs"):
                M.execute(command, root / "failed-positive", M.T.clean_environment(), True)
            self.assertEqual(json.loads((root / "failed-positive/process.json").read_text())["exit_code"], 7)


if __name__ == "__main__":
    unittest.main()
