#!/usr/bin/env python3
"""Synthetic pipeline-controller checks; no GPU, services, or proofs."""
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest

PATH = Path(__file__).with_name("prepare-block-v2-pipeline-bench.py")
spec = importlib.util.spec_from_file_location("pipeline_bench", PATH)
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
B = P.load_module(P.SOURCE)


class PipelineBenchTests(unittest.TestCase):
    def controller(self, parallel, quotient=0):
        source = B.derive_controller(B.TEMPLATE.read_text(), 16, Path("/tmp/private-pipeline"))
        source = P.configure_controller(source, parallel, quotient)
        module = types.ModuleType("pipeline_controller")
        module.__file__ = str(B.TEMPLATE)
        exec(compile(source, str(B.TEMPLATE), "exec"), module.__dict__)
        return module

    def config(self):
        return dict(backend="resident", gpu_openings=1, gpu_compact=1,
                    quotient_fusion=0, gpu_index=0, job="/tmp/job", evidence="/tmp/evidence",
                    scratch_dir="/tmp/private-pipeline",
                    reference="/tmp/reference", accounting="/tmp/accounting.py",
                    gpu_runner="/tmp/gpu", cpu_runner="/tmp/cpu", auditor="/tmp/auditor",
                    external=["00" * 32] * 3)

    def test_worker_policy_reaches_every_gpu_stage_and_cpu_stays_off(self):
        for parallel in (0, 1):
            controller = self.controller(parallel)
            for name, action, gpu in [("key-1", ["register", "1"], True),
                                      ("pairs", ["wrap-all"], True),
                                      ("merges", ["merge-all"], True),
                                      ("audit", ["root-eight"], False),
                                      ("check", ["check-registered"], False)]:
                argv = controller.stage_command(self.config(), "controller.service", "worker.service", name, action)
                self.assertIn(f"--setenv=LATTICA_V2_GPU_PARALLEL_READBACK={parallel if gpu else 0}", argv)
                self.assertIn("--setenv=RAYON_NUM_THREADS=24", argv)
                self.assertIn("--property=MemoryMax=44G", argv)
                self.assertIn("--property=MemorySwapMax=0", argv)
                self.assertIn("--setenv=LATTICA_V2_GPU_OPENING_PINNED=0", argv)
                self.assertIn(f"--setenv=LATTICA_SPILL_MAX_BYTES={34 * B.GIB}", argv)

    def test_launcher_is_two_arms_five_alternating_pairs(self):
        _, source = P.launcher_source(Path("/tmp/candidate"), Path("/tmp/plan"), 5, 0, 1, 0)
        module = types.ModuleType("pipeline_launcher")
        module.__file__ = "/tmp/launcher.py"
        exec(compile(source, module.__file__, "exec"), module.__dict__)
        blocks = [list(P.ARMS if i % 2 == 0 else reversed(P.ARMS)) for i in range(5)]
        steps = module.steps({"repeat_blocks": blocks})
        self.assertEqual(len(steps), 12)
        self.assertEqual(sum(item[2] for item in steps), 2)
        for arm in P.ARMS:
            plan = {"config": {**self.config(), "gpu_uuid": "GPU-test", "source_archive": "/old/source"},
                    "arms": {arm: {"controller": "/tmp/controller.py", "config_overrides": {
                        "gpu_runner": "/tmp/candidate/gpu", "source_archive": "/tmp/candidate/source.tar.gz",
                        "quotient_fusion": 1 if arm == "ram-candidate" else 0}}}}
            argv = module.invocation(Path("/tmp/plan"), plan, arm, "round", False)
            self.assertEqual(argv[argv.index("--gpu-runner") + 1], "/tmp/candidate/gpu")
            self.assertEqual(argv[argv.index("--quotient-fusion") + 1], "1" if arm == "ram-candidate" else "0")
        bad = {"attempts": [{"label": "register-ram-reference", "arm": "ram-reference", "status": "attempted"}]}
        with self.assertRaisesRegex(ValueError, "never automatically retry"):
            module.validate_progress(bad, {"repeat_blocks": blocks})

    def test_observed_readback_work_required(self):
        for parallel in (0, 1):
            controller = self.controller(parallel)
            controller.validate_original_gpu_log = lambda *args: {"original_checks": "passed"}
            policy = f"gpu_readback_research parallel={str(bool(parallel)).lower()} production_ready=false\n"
            final = ('bounded_gpu_readback_checkpoint label="GPU grouped process remainder" '
                     f'counters=cumulative parallel_decode_bytes={4096 * parallel} parallel_decode_chunks={parallel}\n')
            with tempfile.TemporaryDirectory() as directory:
                log = Path(directory) / "proof.log"
                quotient = ('gpu_quotient_research enabled=false production_ready=false\n'
                            'bounded_gpu_quotient_checkpoint label="GPU grouped process remainder" commits=0 mask_ns=0\n')
                log.write_text(policy + final + quotient)
                self.assertEqual(controller.validate_gpu_log(log)["readback"]["parallel_decode_chunks"], parallel)
                for bad in [final, policy, policy + policy + final,
                            policy + final.replace("parallel_decode_chunks=" + str(parallel),
                                                   "parallel_decode_chunks=" + str(1 - parallel))]:
                    log.write_text(bad + quotient)
                    with self.assertRaises(ValueError):
                        controller.validate_gpu_log(log)

    def test_template_drift_and_invalid_policy_rejected(self):
        source = B.derive_controller(B.TEMPLATE.read_text(), 16, Path("/tmp/private-pipeline"))
        with self.assertRaisesRegex(ValueError, "qualified source changed"):
            P.configure_controller(source.replace("RAYON_NUM_THREADS=16", "RAYON_NUM_THREADS=8"), 1)
        for invalid in (True, -1, 2, "1"):
            with self.assertRaises(ValueError):
                P.configure_controller(source, invalid)


    def test_gpu_quotient_is_pinned_per_arm_and_disabled_for_cpu_children(self):
        _, source = P.launcher_source(Path("/tmp/candidate"), Path("/tmp/plan"), 5, 1, 1, 1, 1, 1)
        self.assertIn('"quotient_fusion": 1 if arm == "ram-reference" else 1', source)
        controller = self.controller(1, 1)
        for name, operation, gpu in [("key-1", ["register", "1"], True), ("pairs", ["wrap-all"], True), ("audit", ["root-eight"], False)]:
            argv = controller.stage_command(self.config(), "controller.service", "worker.service", name, operation)
            self.assertIn(f"--setenv=LATTICA_V2_GPU_QUOTIENT_LDE={int(gpu)}", argv)

    def test_gpu_quotient_counters_reject_fallback_and_registration_work(self):
        controller = self.controller(0, 1)
        controller.validate_original_gpu_log = lambda *args: {}
        base = ('gpu_readback_research parallel=false production_ready=false\n'
                'bounded_gpu_readback_checkpoint label="GPU grouped process remainder" parallel_decode_bytes=0 parallel_decode_chunks=0\n'
                'gpu_quotient_research enabled=true production_ready=false\n')
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "proof.log"
            for stage, expected in [("pairs", 4), ("merges", 3), ("key-1", 0)]:
                for actual in [expected, expected + 1]:
                    log.write_text(base + f'bounded_gpu_quotient_checkpoint label="GPU grouped process remainder" commits={actual} mask_ns=100\n')
                    if actual == expected:
                        self.assertEqual(controller.validate_gpu_log(log, "unit", stage)["gpu_quotient_commits"], actual)
                    else:
                        with self.assertRaises(ValueError):
                            controller.validate_gpu_log(log, "unit", stage)

if __name__ == "__main__":
    unittest.main()
