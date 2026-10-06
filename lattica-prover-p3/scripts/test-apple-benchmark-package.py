#!/usr/bin/env python3
"""Check package integrity, qualification coverage and isolated execution policy."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("package", Path(__file__).with_name("run-apple-benchmark-package.py"))
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
spec = importlib.util.spec_from_file_location("prepare_package", Path(__file__).with_name("prepare-apple-benchmark-package.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class Package(unittest.TestCase):
    def test_selected_revision_is_frozen_to_an_exact_commit(self):
        with patch.object(P.subprocess, 'check_output', return_value='b' * 40 + '\n') as resolve:
            self.assertEqual(P.resolve_revision('HEAD'), 'b' * 40)
            self.assertEqual(resolve.call_args.args[0][-2:], ['--end-of-options', 'HEAD^{commit}'])
        with patch.object(P.subprocess, 'check_output', return_value='HEAD\n'):
            with self.assertRaises(ValueError):
                P.resolve_revision('HEAD')

    def test_package_verifies_bytes_and_rejects_missing_or_escaped_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "controller.py"
            payload.write_text("pinned")
            manifest = {"schema": "lattica-apple-benchmark-package-v1",
                        "payload_sha256": {payload.name: B.digest(payload)}}
            B.save(root / "manifest.json", manifest)
            B.verify_package(root)
            payload.write_text("changed")
            with self.assertRaisesRegex(ValueError, "missing or changed"):
                B.verify_package(root)
            payload.unlink()
            with self.assertRaisesRegex(ValueError, "missing or changed"):
                B.verify_package(root)
            manifest["payload_sha256"] = {"../controller.py": "anything"}
            B.save(root / "manifest.json", manifest)
            with self.assertRaises(ValueError):
                B.verify_package(root)

    def test_nine_trials_are_fresh_balanced_and_fit_actual_cpu_count(self):
        for cpus, expected in ((8, 8), (12, 8), (16, 16), (18, 18), (24, 18)):
            self.assertEqual(B.select_threads(cpus), expected)
        self.assertEqual(B.select_threads(24, 24), 24)
        for cpus, requested in ((4, None), (16, 18), (24, 20)):
            with self.assertRaises(ValueError):
                B.select_threads(cpus, requested)
        schedule = B.schedule(18)
        self.assertEqual(len(schedule), 9)
        self.assertEqual([t["level"] for t in schedule[:3]],
                         [t["level"] for t in schedule[3:6]][::-1])
        for level in B.LEVELS:
            self.assertEqual([t["repeat"] for t in schedule if t["level"] == level], [1, 2, 3])

    def test_environment_does_not_inherit_unqualified_experiments_or_build_flags(self):
        with patch.dict(os.environ, {"LATTICA_V2_GPU_DIRECT_READBACK": "1",
                                     "RAYON_NUM_THREADS": "99", "CARGO_ENCODED_RUSTFLAGS": "wrong",
                                     "CARGO_BUILD_TARGET": "x86_64-apple-darwin",
                                     "RUSTFLAGS": "wrong", "RUSTC_WRAPPER": "wrong",
                                     "PATH": "/tools/bin", "RUSTUP_HOME": "/tools/rustup"}):
            env = B.clean_environment()
        self.assertFalse(any(key.startswith(("LATTICA_", "RAYON_")) for key in env))
        self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", env)
        self.assertNotIn("CARGO_BUILD_TARGET", env)
        self.assertNotIn("RUSTC_WRAPPER", env)
        self.assertEqual(env["RUSTFLAGS"], "-C target-cpu=native")
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], "1.96.0")
        self.assertEqual(env["RUSTUP_HOME"], "/tools/rustup")

    def test_qualification_requires_four_complete_matching_unique_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "tests"; binary.write_bytes(b"compiled")
            build = {"source_hashes": {"src/lib.rs": "source"}}
            reports = [{"status": "PASS", "timing": timing, "binary_sha256": B.digest(binary),
                        "proof_source_sha256": build["source_hashes"],
                        "tests": [{"test": f"test_{i}", "memory": memory, "passed": True}
                                  for memory in ("shared", "copy") for i in range(32)]}
                       for timing in ("immediate", "deferred")]
            paths = [root / "immediate.json", root / "deferred.json"]

            def check(data):
                for path, report in zip(paths, data):
                    B.save(path, report)
                return B.combine_qualification(paths, build, binary)

            self.assertEqual(len(check(reports)["tests"]), 128)
            for change in ("duplicate", "missing", "failed", "source", "binary", "timing"):
                altered = copy.deepcopy(reports)
                if change == "duplicate": altered[1]["tests"].append(altered[1]["tests"][0])
                if change == "missing": altered[1]["tests"].pop()
                if change == "failed": altered[0]["tests"][0]["passed"] = False
                if change == "source": altered[0]["proof_source_sha256"] = {"src/lib.rs": "changed"}
                if change == "binary": altered[1]["binary_sha256"] = "changed"
                if change == "timing": altered[1]["timing"] = "immediate"
                with self.subTest(change=change), self.assertRaises(ValueError):
                    check(altered)

    def test_test_executable_is_selected_from_cargo_json_without_guessing(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            artifact = {"reason": "compiler-artifact", "target": {"name": "lattica_prover_p3"},
                        "profile": {"test": True}, "executable": "/target/tests"}
            log.write_text("compiler warning\n" + json.dumps(artifact) + "\n")
            self.assertEqual(B.test_executable(log), Path("/target/tests"))
            log.write_text(log.read_text() + json.dumps(dict(artifact, executable="/another/tests")))
            with self.assertRaises(ValueError): B.test_executable(log)

    def test_plan_does_not_create_checkout_or_start_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "new-output"
            manifest = {"source_commit": "a" * 40, "fixture_files": [], "memory_policy": {}}
            with patch("sys.argv", ["runner", "--repo", directory, "--out", str(out), "--plan"]), \
                    patch.object(B, "verify_package", return_value=manifest), \
                    patch.object(B, "digest", return_value="manifest"), \
                    patch.object(B.os, "cpu_count", return_value=18), \
                    patch.object(B.subprocess, "run") as run, \
                    patch("sys.stdout", new_callable=io.StringIO) as output:
                run.return_value.returncode = 0
                B.main()
                self.assertEqual(len(json.loads(output.getvalue())["schedule"]), 9)
                self.assertEqual(run.call_count, 1)
                self.assertIn("cat-file", run.call_args.args[0])
                self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
