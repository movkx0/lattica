#!/usr/bin/env python3
"""No proving or GPU initialization: validate generated commands and stop gates."""
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("block-v2-scratch-bench.py")
spec = importlib.util.spec_from_file_location("scratch_bench", SCRIPT)
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class ScratchBenchTests(unittest.TestCase):
    def controller(self, threads=16):
        code = B.derive_controller(B.TEMPLATE.read_text(), threads, Path("/tmp/private-scratch"))
        module = types.ModuleType("derived")
        module.__file__ = str(B.TEMPLATE)  # Frozen helper lookup; no main execution.
        exec(compile(code, str(B.TEMPLATE), "exec"), module.__dict__)
        return module

    def test_generated_commands_hold_compute_and_resource_settings(self):
        baseline = json.loads(B.BASELINE.read_text())["config"]
        for threads in (8, 16):
            controller = self.controller(threads)
            cfg = {**baseline, "scratch_dir": "/tmp/private-scratch"}
            for name, action in (("pairs", ["wrap-all"]), ("merges", ["merge-all"])):
                argv = controller.stage_command(cfg, "lattica-v2-test.service", "worker.service", name, action)
                for value in (f"--setenv=RAYON_NUM_THREADS={threads}",
                              "--setenv=LATTICA_SPILL_DIR=/tmp/private-scratch",
                              f"--setenv=LATTICA_SPILL_MAX_BYTES={34 * B.GIB}",
                              "--setenv=LATTICA_V2_GPU_OPENING_COMPACT=1",
                              "--setenv=LATTICA_V2_GPU_RESIDENT_LDE=1",
                              "--property=MemoryMax=44G", "--property=MemorySwapMax=0"):
                    self.assertIn(value, argv)
                self.assertEqual(argv[argv.index("--") + 1], cfg["gpu_runner"])
            audit = controller.stage_command(cfg, "lattica-v2-test.service", "worker.service", "audit", ["root-eight"])
            self.assertEqual(audit[audit.index("--") + 1], cfg["auditor"])
            self.assertIn("--setenv=LATTICA_V2_GPU_DEVICE=4294967295", audit)

    def test_template_drift_rejected(self):
        with self.assertRaisesRegex(ValueError, "template drift"):
            B.derive_controller(B.TEMPLATE.read_text().replace("RAYON_NUM_THREADS=8", "RAYON_NUM_THREADS=4"),
                                16, Path("/tmp/private-scratch"))

    def test_failed_attempt_is_never_automatically_repeated(self):
        plan = {"repeat_blocks": [list(B.ARMS)]}
        for status in ("attempted", "failed_or_interrupted"):
            state = {"attempts": [{"label": "register-disk8", "arm": "disk8", "status": status}]}
            with self.assertRaisesRegex(ValueError, "never automatically retry"):
                B.validate_progress(state, plan)
        good = {"attempts": [{"label": "register-disk8", "arm": "disk8", "status": "complete"}]}
        self.assertEqual(B.validate_progress(good, plan), 1)

    def test_no_proving_before_reboot(self):
        with patch.object(B, "boot_id", return_value="same-boot"), patch.object(B, "command_output") as command:
            with self.assertRaisesRegex(ValueError, "reboot has not happened"):
                B.preflight(Path("/unused"), {"prepared_boot_id": "same-boot"}, None)
            command.assert_not_called()

    def test_low_ram_rejected_before_external_commands(self):
        plan = {"prepared_boot_id": "old", "minimum_available_ram_bytes": 46 * B.GIB}
        with patch.object(B, "boot_id", return_value="new"), patch.object(B, "memory_available", return_value=40 * B.GIB), patch.object(B, "command_output") as command:
            with self.assertRaisesRegex(ValueError, "46 GiB"):
                B.preflight(Path("/unused"), plan, None)
            command.assert_not_called()

    def test_default_tmp_capacity_rejected(self):
        plan = {"prepared_boot_id": "old", "minimum_available_ram_bytes": 46 * B.GIB,
                "minimum_tmp_free_bytes": 35 * B.GIB}
        with patch.object(B, "boot_id", return_value="new"), patch.object(B, "memory_available", return_value=52 * B.GIB), patch.object(B, "filesystem_type", return_value="tmpfs"), patch.object(B.os, "statvfs", return_value=types.SimpleNamespace(f_bavail=31 * B.GIB, f_frsize=1)):
            with self.assertRaisesRegex(ValueError, "35 GiB free"):
                B.preflight(Path("/unused"), plan, None)

    def test_duplicate_mounts_must_agree(self):
        with patch.object(B, "command_output", return_value="tmpfs\ntmpfs"):
            self.assertEqual(B.filesystem_type("/tmp"), "tmpfs")
        with patch.object(B, "command_output", return_value="tmpfs\nbtrfs"):
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                B.filesystem_type("/tmp")

    def test_verified_own_compositor_is_recorded(self):
        group = f"/user.slice/user-{B.os.getuid()}.slice/user@{B.os.getuid()}.service/session.slice/plasma-kwin_wayland.service"
        def contents(path):
            return "kwin_wayland\n" if path.name == "comm" else "0::" + group + "\n"
        with patch.object(Path, "read_text", contents), patch.object(Path, "stat", return_value=types.SimpleNamespace(st_uid=B.os.getuid())), patch.object(B, "command_output", return_value="ActiveState=active\nControlGroup=" + group):
            rows = B.desktop_gpu_processes("GPU-test,123,/usr/bin/kwin_wayland,42", "GPU-test")
            self.assertEqual(rows[0]["gpu_memory_mib"], 42)

    def test_compute_process_cannot_impersonate_compositor(self):
        with patch.object(Path, "stat", return_value=types.SimpleNamespace(st_uid=B.os.getuid())), patch.object(Path, "read_text", return_value="other-compute\n"):
            with self.assertRaisesRegex(ValueError, "competing compute"):
                B.desktop_gpu_processes("GPU-test,123,/usr/bin/kwin_wayland,42", "GPU-test")
        with patch.object(Path, "stat", return_value=types.SimpleNamespace(st_uid=B.os.getuid()+1)):
            with self.assertRaisesRegex(ValueError, "competing compute"):
                B.desktop_gpu_processes("GPU-test,123,/usr/bin/kwin_wayland,42", "GPU-test")

    def test_compositor_name_outside_desktop_service_is_rejected(self):
        group = f"/user.slice/user-{B.os.getuid()}.slice/user@{B.os.getuid()}.service/session.slice/plasma-kwin_wayland.service"
        def contents(path):
            return "kwin_wayland\n" if path.name == "comm" else "0::/unrelated.service\n"
        with patch.object(Path, "read_text", contents), patch.object(Path, "stat", return_value=types.SimpleNamespace(st_uid=B.os.getuid())), patch.object(B, "command_output", return_value="ActiveState=active\nControlGroup=" + group):
            with self.assertRaisesRegex(ValueError, "outside the verified desktop"):
                B.desktop_gpu_processes("GPU-test,123,/usr/bin/kwin_wayland,42", "GPU-test")

    def test_host_sampler_preserves_missing_cgroup_as_missing(self):
        controller = self.controller()
        with tempfile.TemporaryDirectory() as scratch:
            row = controller.sample_bench_host("/not-a-real-benchmark-cgroup", scratch)
            self.assertIsNone(row["memory.current"])
            self.assertIsNone(row["io.stat"])
            self.assertGreater(row["host_mem_available_bytes"], 0)

    def test_monitor_writes_host_evidence_without_gpu_initialization(self):
        controller = self.controller()
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "vram.jsonl"
            monitor = controller.VramMonitor("missing.service", "test-uuid", path)
            sample = {"utc_ns": 1, "memory.current": None}
            with patch.object(controller, "sample_bench_host", return_value=sample), patch.object(controller.subprocess, "run", return_value=types.SimpleNamespace(stdout="")):
                monitor.sample()
            monitor.close()
            self.assertEqual(json.loads(monitor.host_path.read_text()), sample)
            self.assertTrue(monitor.host_output.closed)

    def test_benchmark_invocation_uses_same_pinned_inputs(self):
        cfg = json.loads(B.BASELINE.read_text())["config"]
        plan = {"config": cfg, "arms": {"ram16": {"controller": "/frozen/controller.py"}}}
        argv = B.invocation(Path("/persistent"), plan, "ram16", "round-1-ram16", False)
        self.assertEqual(argv[3:6], ["prove", "/persistent/jobs/round-1-ram16", "/persistent/evidence/round-1-ram16"])
        self.assertEqual(argv[argv.index("--reference") + 1], cfg["reference"])
        self.assertEqual(argv[argv.index("--registration") + 1], "/persistent/evidence/register-ram16/manifest.json")


if __name__ == "__main__":
    unittest.main()
