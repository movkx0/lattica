#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("cpu_prepare", Path(__file__).with_name("block-v2-typed-cpu-prepare.py"))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class CpuPreparation(unittest.TestCase):
    def test_reused_public_leaves_get_fresh_keys_and_wrong_binary_is_rejected(self):
        for construction, keys, correct in ((name, keys, ok) for name, keys in (("finalizer", 6), ("paired", 12)) for ok in (True, False)):
            with self.subTest(construction=construction, correct=correct), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); out = root / "out"; out.mkdir()
                source = root / "public"; source.mkdir()
                for name in ("body.json", *(f"wallet.{i}" for i in range(64))):
                    (source / name).write_text("synthetic public artifact " + name)
                binary = root / "cpu"; binary.write_text("synthetic CPU driver")
                pins = dict(map(P.T.pin, [binary, *P.leaf_files(source)]))
                packet = out / "packet.json"
                packet.write_text(json.dumps({"config": {"cpu_binary": str(binary), "pins": pins,
                    "construction": construction, "public_fixture": str(source)},
                    "budget": {"cpu": {"rayon_threads": 3}, "host": {"worker_bytes": 4096}}}))
                commands = []
                def execute(argv, log, env):
                    commands.append(argv[1]); fixture = Path(argv[2])
                    if argv[1] == "geometry":
                        (fixture / "height.json").write_text("262144")
                        log.write_text(json.dumps({"event": "typed_geometry", "registry_keys": keys if correct else 5,
                            "construction": f"typed-{construction}-v1" if correct else "typed-reference-v1"}))
                    else:
                        self.assertEqual(argv[1], "register")
                        (fixture / f"key.{argv[3]}").write_text("new key")
                        log.write_text("synthetic registration")
                with patch.object(P.T, "execute_logged", side_effect=execute):
                    if correct: P.worker(packet)
                    else:
                        with self.assertRaises(ValueError): P.worker(packet)
                result = json.loads((out / "worker-result.json").read_text())
                self.assertTrue(result["fixture_reuse"])
                if correct:
                    self.assertEqual(commands, ["geometry"] + ["register"] * keys)
                    self.assertEqual(result["status"], "succeeded")
                    self.assertEqual(len(result["artifacts"]), 66 + keys)
                    self.assertEqual((out / "fixture/wallet.63").read_bytes(), (source / "wallet.63").read_bytes())
                else:
                    self.assertEqual(commands, ["geometry"])
                    self.assertEqual(result["status"], "failed")
                    self.assertFalse((out / "fixture/key.1").exists())
                P.T.check_pins(pins)

    def test_all_cpu_stages_are_pinned_and_partial_failures_are_retained(self):
        for failing_mode in (None, 3):
            with self.subTest(failing_mode=failing_mode), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                binary = out / "cpu"; binary.write_text("CPU-only synthetic test driver")
                packet = out / "packet.json"
                packet.write_text(json.dumps({"config": {"cpu_binary": str(binary), "pins": dict([P.T.pin(binary)])},
                                              "budget": {"cpu": {"rayon_threads": 3}, "host": {"worker_bytes": 4096}}}))

                def execute(argv, log, env):
                    self.assertEqual(env["RAYON_NUM_THREADS"], "3")
                    self.assertFalse(any(key.startswith("LATTICA_V2_GPU_") for key in env))
                    fixture = Path(argv[2])
                    log.write_text("synthetic orchestration test; no proof evidence")
                    if argv[1] == "fixture":
                        fixture.mkdir()
                        (fixture / "body.json").write_text("public body")
                        for i in range(64): (fixture / f"wallet.{i}").write_text("synthetic wallet")
                    elif argv[1] == "geometry":
                        (fixture / "height.json").write_text("262144")
                        log.write_text(json.dumps({"event": "typed_geometry"}))
                    else:
                        self.assertEqual(argv[4], 4096)
                        if argv[3] == failing_mode: raise subprocess.CalledProcessError(1, argv)
                        (fixture / f"key.{argv[3]}").write_text("synthetic verifier key")

                with patch.object(P.T, "execute_logged", side_effect=execute):
                    if failing_mode is None:
                        P.worker(packet)
                    else:
                        with self.assertRaises(subprocess.CalledProcessError): P.worker(packet)
                result = json.loads((out / "worker-result.json").read_text())
                self.assertFalse(result["recursive_root_produced"])
                if failing_mode is None:
                    self.assertEqual(result["status"], "succeeded")
                    self.assertEqual(len(result["artifacts"]), 71)
                    self.assertEqual(len(result["stages"]), 7)
                    P.T.check_pins(result["artifacts"])
                else:
                    self.assertEqual(result["status"], "failed")
                    self.assertEqual([stage["status"] for stage in result["stages"]], ["succeeded"] * 4 + ["failed"])
                    self.assertTrue((out / "fixture/key.2").is_file())
                    self.assertFalse((out / "fixture/key.4").exists())
                    self.assertNotIn("cpu_registered", result)

    def test_refused_restart_preserves_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root / "cpu"; binary.write_text("binary")
            out = root / "out"; out.mkdir(); summary = out / "summary.json"; summary.write_text("retained")
            with patch.object(sys, "argv", ["prepare", "--cpu-binary", str(binary), "--evidence", str(out)]), \
                    patch.object(P.G, "lock_fleet", return_value=[]), patch.object(P.G, "systemctl", return_value="[]"):
                with self.assertRaises(FileExistsError): P.main()
            self.assertEqual(summary.read_text(), "retained")


if __name__ == "__main__":
    unittest.main()
