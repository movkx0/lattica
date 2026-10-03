#!/usr/bin/env python3
"""Native controller-policy tests. No GPU, prover, systemd service or proof benchmark."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location("gpu_grouped", Path(__file__).with_name("block-v2-gpu-grouped-trial.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
UUID = "GPU-00000000-0000-0000-0000-000000000000"
UNIT = "lattica-v2-gpu-grouped-17-3.service"


def config(mode="register", backend="resident", openings=0):
    return {"mode": mode, "backend": backend, "job": "/tmp/gpu-job", "evidence": "/tmp/gpu-evidence",
            "reference": "/tmp/cpu-reference", "gpu_runner": "/tmp/gpu-worker", "cpu_runner": "/tmp/cpu-worker",
            "auditor": "/tmp/cpu-auditor", "accounting": "/tmp/accounting.py", "source_archive": "/tmp/source.tar.gz",
            "external": ["00" * 32] * 3, "gpu_index": 0, "gpu_uuid": UUID, "quotient_fusion": 0, "gpu_openings": openings}


def artifacts(names):
    return {name: {"bytes": 1, "sha256": name} for name in names}


def gpu_log(name="key-1", resident=True, openings=False):
    enabled = str(resident).lower()
    opened = str(openings).lower()
    calls = (4 if name == "pairs" else 3 if name == "merges" else 0) if openings else 0
    lines = [
        f'bounded_gpu_initialized device_index=0 name="NVIDIA GeForce RTX 5080" contexts=1 job_lease=exclusive managed_limit_bytes={8 * M.GIB} driver_reserve_bytes={4 * M.GIB}',
        f"gpu_grouped_research resident_lde={enabled} gpu_openings={opened} retained_trees=true transfer_overlap=false cpu_only=false production_ready=false",
        'bounded_gpu_checkpoint label="GPU grouped process remainder" commits=7 managed_peak_bytes=8192 uploaded_bytes=1000 downloaded_bytes=20',
        f'bounded_gpu_lde_checkpoint label="GPU grouped process remainder" commits={3 if resident else 0}',
        f'bounded_gpu_opening_checkpoint label="GPU grouped process remainder" counters=cumulative calls={calls} tiles={calls * 3} uploaded_bytes={calls * 100} downloaded_bytes={calls * 6} kernel_ns={calls * 10} wall_ns={calls * 20}',
    ]
    if name.startswith("key-"):
        lines.append(f"grouped_key_generated mode={name[-1]} cpu_only=false approval=false")
    nodes = M.H.PAIRS if name == "pairs" else M.H.MERGES if name == "merges" else ()
    for node in nodes:
        lines.append(f"grouped_node_complete artifact={node} resumed=false elapsed_ms=2 setups=1 cache_hits=0 production_ready=false")
    lines += ["bounded_gpu_shutdown managed_live_bytes=0 lease_released=true",
              f"grouped_stage_elapsed_ms=25 spill_peak_bytes=32 cpu_only=false resident_lde={enabled} gpu_openings={opened} production_ready=false",
              f"stage_cgroup_accounting unit={UNIT} scope=exec_stop_post_snapshot memory_peak=100 memory_swap_peak=0 memory_max={44 * M.GIB} memory_swap_max=0 cpu_usage_usec=5"]
    return "\n".join(lines) + "\n"


class ControllerPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def parse_log(self, text, name="key-1", resident=True, openings=False):
        path = self.root / "stage.log"
        path.write_text(text)
        return M.validate_gpu_log(path, UNIT, name, resident, openings)

    def test_opening_mode_is_explicit_and_cpu_stages_always_disable_it(self):
        c = config("prove", openings=1)
        for name, action in M.stages(c):
            if name in ("seed", "export"): continue
            args = M.stage_command(c, "lattica-v2-controller.service", UNIT, name, action)
            self.assertIn(f"--setenv=LATTICA_V2_GPU_OPENINGS={int(M.gpu_stage(name))}", args)
        for value in (True, False, "1", 2, -1, None):
            with self.assertRaises(ValueError): M.validate_opening_mode(config(openings=value))
        with self.assertRaises(ValueError): M.validate_opening_mode(config(backend="retained", openings=1))
        with self.assertRaises(KeyError): M.validate_opening_mode({"backend": "resident"})

    def test_opening_work_and_transfer_totals_are_bound_without_timing_double_count(self):
        result = self.parse_log(gpu_log("pairs", openings=True), "pairs", openings=True)
        self.assertEqual(result["opening"]["calls"], 4)
        self.assertEqual(result["recorded_host_device_transfers"]["uploaded_bytes"], 1400)
        self.assertEqual(result["recorded_host_device_transfers"]["downloaded_bytes"], 44)
        self.assertEqual(result["duration"]["elapsed_ms"], 25)
        self.assertIn("nonadditive", result["opening_timing_scope"])
        registered = self.parse_log(gpu_log(openings=True), openings=True)
        self.assertTrue(all(value == 0 for value in registered["opening"].values()))

    def test_opening_telemetry_rejects_inactive_missing_duplicate_and_corrupt_work(self):
        original = gpu_log("pairs", openings=True)
        opening = next(line for line in original.splitlines() if line.startswith("bounded_gpu_opening_checkpoint"))
        changed = [original.replace(opening + "\n", ""), original + opening + "\n"]
        for before, after in [("calls=4", "calls=3"), ("tiles=12", "tiles=0"),
                              ("uploaded_bytes=400", "uploaded_bytes=0"),
                              ("downloaded_bytes=24", "downloaded_bytes=-1"),
                              ("kernel_ns=40", "kernel_ns=81"),
                              ("wall_ns=80", "wall_ns=26000000"),
                              ("counters=cumulative", "counters=delta"),
                              ("gpu_openings=true", "gpu_openings=false")]:
            changed.append(original.replace(before, after))
        for text in changed:
            with self.subTest(text=text), self.assertRaises((ValueError, KeyError)):
                self.parse_log(text, "pairs", openings=True)
        with self.assertRaises(ValueError): self.parse_log(original, "pairs")
        with self.assertRaises(ValueError): self.parse_log(gpu_log("pairs"), "pairs", openings=True)
        with self.assertRaises(ValueError): self.parse_log(gpu_log().replace("calls=0", "calls=1"))

    def test_proof_transfer_summary_uses_complete_process_totals_once(self):
        attempts = [{"name": name, "telemetry": self.parse_log(gpu_log(name, openings=True), name, openings=True)}
                    for name in ("pairs", "merges")]
        totals = M.proof_transfer_totals(attempts)
        self.assertEqual(totals["opening_calls"], 7)
        self.assertEqual(totals["uploaded_bytes"], 2700)
        self.assertEqual(totals["downloaded_bytes"], 82)
        for bad in (attempts[:1], list(reversed(attempts)), attempts + attempts):
            with self.assertRaises(ValueError): M.proof_transfer_totals(bad)

    def test_exact_plans_keep_cpu_checks_pruning_and_audits_separate(self):
        self.assertEqual([name for name, _ in M.stages(config())],
                         ["seed", "reference-check", "key-1", "key-2", "key-3", "check"])
        self.assertEqual([name for name, _ in M.stages(config("prove"))],
                         ["seed", "check", "pairs", "merges", "prune", "root", "export", "audit"])
        for name in ["seed", "reference-check", "check", "prune", "root", "export", "audit"]:
            self.assertFalse(M.gpu_stage(name))

    def test_gpu_worker_flags_and_resource_controls_are_explicit(self):
        for backend in ["retained", "resident"]:
            c = config(backend=backend)
            args = M.stage_command(c, "lattica-v2-controller.service", UNIT, "pairs", ["wrap-all"])
            for arg in ["--property=MemoryMax=44G", "--property=MemorySwapMax=0", "--property=RuntimeMaxSec=7200",
                        "--property=BindsTo=lattica-v2-controller.service", "--property=KillMode=control-group",
                        "--setenv=LATTICA_V2_GPU_HASH=1", "--setenv=LATTICA_V2_GPU_RETAIN_TREES=1",
                        "--setenv=LATTICA_V2_GPU_PIPELINE=0",
                        f"--setenv=LATTICA_V2_GPU_RESIDENT_LDE={int(backend == 'resident')}"]:
                self.assertIn(arg, args)
            self.assertEqual(args[args.index("--") + 1:], [c["gpu_runner"], "wrap-all", c["job"], *c["external"]])

    def test_cpu_stages_never_select_the_gpu_worker(self):
        c = config("prove")
        for name, action in M.stages(c):
            if name in ["seed", "export"] or M.gpu_stage(name): continue
            args = M.stage_command(c, "lattica-v2-controller.service", UNIT, name, action)
            self.assertNotIn(c["gpu_runner"], args)
            self.assertIn("--setenv=LATTICA_V2_GPU_RESIDENT_LDE=0", args)
            self.assertIn("--setenv=LATTICA_V2_GPU_RETAIN_TREES=0", args)
            self.assertIn("--setenv=LATTICA_V2_GPU_DEVICE=4294967295", args)
            self.assertIn(f"--setenv=LATTICA_V2_GPU_HASH={int(name == 'audit')}", args)
        self.assertEqual(M.invocation(c, "reference-check", ["check-registered"])[2], c["reference"])

    def test_keyless_seed_and_independent_cpu_cap_equivalence(self):
        source = artifacts(M.INPUT_NAMES)
        before = artifacts(M.KEYLESS_NAMES)
        M.validate_transition(config(), "seed", None, before, source)
        after = {**before, "key.1": source["key.1"]}
        M.validate_transition(config(), "key-1", before, after, source)
        for field in ["key.1", "wallet.0"]:
            bad = copy.deepcopy(after)
            bad[field]["sha256"] = "changed"
            with self.assertRaises(ValueError): M.validate_transition(config(), "key-1", before, bad, source)
        with self.assertRaises(ValueError): M.validate_transition(config(), "seed", {}, before, source)
        with self.assertRaises(ValueError): M.validate_transition(config(), "seed", None, source, source)

    def test_proof_artifact_transitions_and_local_pruning(self):
        source = artifacts(M.INPUT_NAMES)
        pairs = {**source, **artifacts(M.H.PAIRS)}
        merged = {**pairs, **artifacts(M.H.MERGES)}
        root = {name: merged[name] for name in M.H.ROOT_FILES}
        M.validate_transition(config("prove"), "pairs", source, pairs, source)
        M.validate_transition(config("prove"), "merges", pairs, merged, source)
        M.validate_transition(config("prove"), "prune", merged, root, source)
        with self.assertRaises(ValueError): M.validate_transition(config("prove"), "prune", merged, merged, source)

    def test_gpu_logs_bind_mode_resources_node_sequence_and_teardown(self):
        for name in ["key-1", "key-2", "key-3", "pairs", "merges"]:
            for resident in [False, True]:
                result = self.parse_log(gpu_log(name, resident), name, resident)
                self.assertEqual(result["duration"]["elapsed_ms"], 25)
                self.assertEqual(result["gpu"]["name"], "NVIDIA GeForce RTX 5080")

    def test_missing_duplicate_or_changed_gpu_markers_are_rejected(self):
        original = gpu_log()
        for line in original.splitlines():
            if line.startswith("grouped_key_generated") or line.startswith("bounded_gpu") or line.startswith("gpu_grouped") or line.startswith("stage_cgroup") or line.startswith("grouped_stage"):
                with self.assertRaises(ValueError): self.parse_log(original.replace(line + "\n", ""))
                with self.assertRaises(ValueError): self.parse_log(original + line + "\n")
        for old, new in [("memory_swap_peak=0", "memory_swap_peak=1"),
                         ("managed_peak_bytes=8192", f"managed_peak_bytes={8 * M.GIB + 1}"),
                         ("cpu_only=false", "cpu_only=true"), ("managed_live_bytes=0", "managed_live_bytes=1"),
                         ("commits=3", "commits=0"), ("mode=1", "mode=2"),
                         ("resident_lde=true", "resident_lde=false")]:
            with self.assertRaises(ValueError): self.parse_log(original.replace(old, new))

    def test_resumed_or_incomplete_timed_proofs_are_rejected(self):
        text = gpu_log("pairs")
        with self.assertRaises(ValueError): self.parse_log(text.replace("resumed=false", "resumed=true", 1), "pairs")
        with self.assertRaises(ValueError): self.parse_log(text.replace("artifact=node.1.3", "artifact=node.1.2"), "pairs")
        with self.assertRaises(ValueError): self.parse_log(text + "FAILED: bad proof\n", "pairs")

    def test_vram_aggregation_excludes_unrelated_processes(self):
        output = f"{UUID}, 7, 6000\n{UUID}, 8, 6000\n{UUID}, 99, N/A\n"
        total, pids = M.parse_vram_rows(output, lambda pid: pid in [7, 8], UUID)
        self.assertEqual((total, pids), (12000, [7, 8]))
        self.assertEqual(M.parse_vram_rows("", lambda _: True, UUID), (0, []))

    def test_vram_errors_fail_closed(self):
        for output in [f"{UUID}, 7, 12289", f"{UUID}, 7, N/A", f"{UUID}, x, 1",
                       f"{UUID}, 7, 1\n{UUID}, 7, 1", "GPU-wrong, 7, 1", "malformed"]:
            with self.assertRaises(ValueError): M.parse_vram_rows(output, lambda _: True, UUID)
        self.assertEqual(M.parse_vram_rows(f"{UUID}, 7, 12288", lambda _: True, UUID)[0], 12288)

    def test_vram_summary_is_recomputed_from_bounded_samples(self):
        path = self.root / "vram.jsonl"
        rows = [{"utc_ns": 1, "total_mib": 0, "pids": []}, {"utc_ns": 2, "total_mib": 500, "pids": [7]}]
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        self.assertEqual(M.summarize_vram(path), {"samples": 2, "positive_samples": 1, "peak_mib": 500,
                                               "limit_mib": 12288, "scope": M.VRAM_SCOPE})
        for row in [{"utc_ns": 1, "total_mib": 1, "pids": []},
                    {"utc_ns": 1, "total_mib": 12289, "pids": [7]},
                    {"utc_ns": 1, "total_mib": 0, "pids": []},
                    {"utc_ns": 1, "total_mib": 1, "pids": [7, 7]}]:
            path.write_text(json.dumps(row) + "\n")
            with self.assertRaises(ValueError): M.summarize_vram(path)

    def test_resume_never_retries_attempted_or_failed_stages(self):
        plan = M.stages(config())
        for status in ["attempted", "failed_or_interrupted"]:
            with self.assertRaises(ValueError): M.H.validate_prefix({"attempts": [{"name": "seed", "status": status}]}, plan)
        with self.assertRaises(ValueError): M.H.validate_prefix({"attempts": [{"name": "key-1", "status": "complete"}]}, plan)

    def test_configuration_requires_distinct_tools_external_inputs_and_safe_paths(self):
        c = config()
        with patch.object(M.os, "access", return_value=True):
            M.validate_configuration(c)
            for key, value in [("gpu_index", True), ("gpu_uuid", "GPU-wrong"), ("quotient_fusion", True),
                               ("backend", "auto"), ("external", ["00" * 32]),
                               ("job", c["reference"] + "/nested"), ("job", "/tmp/job%j"),
                               ("cpu_runner", c["gpu_runner"])]:
                bad = copy.deepcopy(c)
                bad[key] = value
                with self.assertRaises((ValueError, KeyError)): M.validate_configuration(bad)

    def test_saved_completed_stages_require_logs_not_just_success_labels(self):
        state = {"config": config(), "attempts": [{"name": "key-1", "status": "complete", "log": "01-key-1.log"}]}
        with self.assertRaises(ValueError): M.verify_evidence(state, self.root)
        state["attempts"][0]["log"] = "../outside.log"
        with self.assertRaises(ValueError): M.verify_evidence(state, self.root)

    def test_seed_intent_is_durable_before_any_artifact_mutation(self):
        evidence = self.root / "evidence"
        evidence.mkdir(mode=0o700)
        c = config()
        c.update(job=str(self.root / "job"), evidence=str(evidence))
        state = {"artifacts": None, "source_artifacts": artifacts(M.INPUT_NAMES), "attempts": [], "status": "RUNNING"}
        state_path = evidence / "manifest.json"
        def fail_seed(*_):
            on_disk = json.loads(state_path.read_text())
            self.assertEqual(on_disk["attempts"][0]["status"], "attempted")
            self.assertIsNone(on_disk["artifacts"])
            raise InterruptedError("synthetic interruption before seed")
        with patch.object(M, "seed_job", side_effect=fail_seed):
            with self.assertRaises(InterruptedError): M.run_stage(c, "controller", "seed", [], evidence, state, state_path)
        saved = json.loads(state_path.read_text())
        self.assertEqual(saved["status"], "FAILED_OR_INTERRUPTED")
        self.assertEqual(saved["attempts"][0]["status"], "failed_or_interrupted")
        self.assertFalse(Path(c["job"]).exists())


class QualificationEvidence(unittest.TestCase):
    """Exercise real parsers and hashes, not a mocked registration success."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("run", "Popen", "check_output"):
            guard = patch.object(M.subprocess, name, side_effect=AssertionError("unexpected external command"))
            guard.start()
            self.addCleanup(guard.stop)

    def fixture(self, backend="resident", openings=0):
        registered = config(backend=backend, openings=openings)
        source = artifacts(M.INPUT_NAMES)
        pins = {name: "ab" * 32 for name in ("gpu_runner", "cpu_runner", "auditor", "accounting",
                                            "source_archive", "helpers", "controller")}
        state = {"schema": M.SCHEMA, "status": "GPU_KEYS_MATCH_CPU_RESEARCH_ONLY", "production_ready": False,
                 "config": registered, "pins": pins, "source_artifacts": source, "artifacts": source,
                 "attempts": []}
        for number, (name, _) in enumerate(M.stages(registered), 1):
            unit = f"lattica-v2-gpu-grouped-17-{number}.service"
            record = {"name": name, "status": "complete", "unit": unit, "log": f"{number:02d}-{name}.log"}
            if name != "seed":
                log = self.root / record["log"]
                if M.gpu_stage(name):
                    log.write_text(gpu_log(name, backend == "resident", bool(openings)).replace(UNIT, unit))
                    record["telemetry"] = M.validate_gpu_log(log, unit, name, backend == "resident", bool(openings))
                    record["cpu_key_equivalence"] = source["key." + name[-1]]
                    record["vram_log"] = f"{number:02d}-{name}-vram.jsonl"
                    vram = self.root / record["vram_log"]
                    vram.write_text(json.dumps({"utc_ns": number, "total_mib": 500, "pids": [17]}) + "\n")
                    record["vram_log_sha256"] = M.H.digest(vram)
                    record["vram"] = M.summarize_vram(vram)
                else:
                    log.write_text("grouped_stage_elapsed_ms=1 spill_peak_bytes=0 cpu_only=true production_ready=false\n"
                                   f"stage_cgroup_accounting unit={unit} scope=exec_stop_post_snapshot memory_peak=100 "
                                   f"memory_swap_peak=0 memory_max={44 * M.GIB} memory_swap_max=0 cpu_usage_usec=5\n")
                    record["telemetry"] = M.H.validate_log(log, unit, name)
                record["log_sha256"] = M.H.digest(log)
            state["attempts"].append(record)
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps(state))
        proving = config("prove", backend, openings)
        proving["registration"] = str(manifest)
        return proving, pins, source, state

    def gate(self, proving, pins, source, state):
        Path(proving["registration"]).write_text(json.dumps(state))
        M.registration_gate(proving, pins, source)

    def test_complete_registration_gate_accepts_both_explicit_backends(self):
        for backend in ("resident", "retained"):
            with self.subTest(backend=backend):
                self.gate(*self.fixture(backend))


    def test_opening_registration_requires_exact_typed_mode_binding(self):
        proving, pins, source, state = self.fixture(openings=1)
        self.gate(proving, pins, source, state)
        for value in (0, True, "1", None):
            changed = copy.deepcopy(state)
            changed["config"]["gpu_openings"] = value
            with self.subTest(value=value), self.assertRaises((ValueError, KeyError)):
                self.gate(proving, pins, source, changed)
        changed = copy.deepcopy(state)
        changed["schema"] = "gpu-grouped-eight-v1"
        with self.assertRaises(ValueError):
            self.gate(proving, pins, source, changed)

    def test_registration_gate_rejects_each_external_and_implementation_binding(self):
        proving, pins, source, state = self.fixture()
        for key, value in (("schema", "other"), ("status", "RUNNING"), ("production_ready", True),
                           ("source_artifacts", {}), ("artifacts", {})):
            changed = copy.deepcopy(state)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.gate(proving, pins, source, changed)
        for key, value in (("mode", "prove"), ("external", ["01" * 32] * 3), ("backend", "retained"),
                           ("gpu_index", 1), ("gpu_uuid", UUID[:-1] + "1"), ("quotient_fusion", 1), ("gpu_openings", 1)):
            changed = copy.deepcopy(state)
            changed["config"][key] = value
            with self.subTest(config=key), self.assertRaises(ValueError):
                self.gate(proving, pins, source, changed)
        for key in pins:
            changed = copy.deepcopy(state)
            changed["pins"][key] = "cd" * 32
            with self.subTest(pin=key), self.assertRaises(ValueError):
                self.gate(proving, pins, source, changed)

    def test_registration_gate_requires_complete_order_and_each_cpu_key_match(self):
        proving, pins, source, state = self.fixture()
        for index in range(len(state["attempts"])):
            changed = copy.deepcopy(state)
            changed["attempts"].pop(index)
            with self.subTest(missing=index), self.assertRaises(ValueError):
                self.gate(proving, pins, source, changed)
            changed = copy.deepcopy(state)
            changed["attempts"][index]["status"] = "attempted"
            with self.subTest(incomplete=index), self.assertRaises(ValueError):
                self.gate(proving, pins, source, changed)
        for index in (2, 3, 4):
            changed = copy.deepcopy(state)
            changed["attempts"][index]["cpu_key_equivalence"] = {"bytes": 1, "sha256": "wrong"}
            with self.subTest(key=index), self.assertRaises(ValueError):
                self.gate(proving, pins, source, changed)

    def test_evidence_rejects_changed_log_even_when_parsed_telemetry_is_unchanged(self):
        proving, pins, source, state = self.fixture()
        log = self.root / state["attempts"][2]["log"]
        log.write_text(log.read_text() + "unbound extra output\n")
        with self.assertRaisesRegex(ValueError, "completed log changed"):
            self.gate(proving, pins, source, state)

    def test_evidence_rechecks_device_even_with_self_consistent_log_and_hash(self):
        proving, pins, source, state = self.fixture()
        record = state["attempts"][2]
        log = self.root / record["log"]
        log.write_text(log.read_text().replace("device_index=0", "device_index=1"))
        record["telemetry"] = M.validate_gpu_log(log, record["unit"], record["name"], True)
        record["log_sha256"] = M.H.digest(log)
        with self.assertRaisesRegex(ValueError, "saved GPU selection"):
            self.gate(proving, pins, source, state)

    def test_evidence_requires_actual_vram_samples_and_recomputes_summary(self):
        proving, pins, source, state = self.fixture()
        record = state["attempts"][2]
        path = self.root / record["vram_log"]
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.gate(proving, pins, source, state)
        path.write_bytes(original)
        record["vram"]["peak_mib"] = 1
        with self.assertRaisesRegex(ValueError, "summary differs"):
            self.gate(proving, pins, source, state)
        record["vram"] = M.summarize_vram(path)
        path.write_text(json.dumps({"utc_ns": 3, "total_mib": 501, "pids": [17]}) + "\n")
        with self.assertRaisesRegex(ValueError, "VRAM evidence changed"):
            self.gate(proving, pins, source, state)
        record["vram_log_sha256"] = M.H.digest(path)
        with self.assertRaisesRegex(ValueError, "summary differs"):
            self.gate(proving, pins, source, state)


class ControllerFaults(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("run", "Popen", "check_output"):
            guard = patch.object(M.subprocess, name, side_effect=AssertionError("unexpected external command"))
            guard.start()
            self.addCleanup(guard.stop)

    def monitor(self):
        with patch.object(Path, "read_text", return_value="0::/test/lattica-v2-grouped.slice/controller.service\n"):
            monitor = M.VramMonitor(UNIT, UUID, self.root / "vram.jsonl")
        self.addCleanup(monitor.close)
        return monitor

    def test_monitor_scopes_exact_worker_and_descendants_only(self):
        monitor = self.monitor()
        for suffix, expected in (("", True), ("/child", True), ("-other", False)):
            with patch.object(Path, "read_text", return_value="0::" + monitor.group + suffix + "\n"):
                self.assertEqual(monitor.belongs(17), expected)
        with patch.object(Path, "read_text", side_effect=FileNotFoundError):
            self.assertFalse(monitor.belongs(17))
        with patch.object(Path, "read_text", side_effect=PermissionError):
            with self.assertRaises(PermissionError): monitor.belongs(17)

    def test_monitor_three_query_failures_abort_and_incomplete_observation_fails(self):
        monitor = self.monitor()
        with patch.object(M.subprocess, "run", side_effect=M.subprocess.TimeoutExpired("nvidia-smi", 5)) as run:
            for _ in range(2):
                monitor.next_sample = 0
                monitor.sample()
            monitor.next_sample = 0
            with self.assertRaisesRegex(ValueError, "failed repeatedly"): monitor.sample()
            self.assertEqual(run.call_count, 3)
        with self.assertRaises(ValueError): monitor.result()

    def test_monitor_recovers_transient_error_and_persists_bounded_samples(self):
        monitor = self.monitor()
        success = M.subprocess.CompletedProcess([], 0, stdout=f"{UUID}, 17, 500\n")
        with patch.object(M.subprocess, "run", side_effect=[OSError("temporary"), success]), \
                patch.object(monitor, "belongs", return_value=True):
            monitor.sample()
            monitor.next_sample = 0
            monitor.sample()
        monitor.close()
        self.assertEqual(monitor.result(), M.summarize_vram(monitor.path))

    def test_monitor_overlimit_and_log_bound_abort(self):
        monitor = self.monitor()
        with patch.object(M.subprocess, "run", return_value=M.subprocess.CompletedProcess([], 0, stdout=f"{UUID}, 17, 12289\n")), \
                patch.object(monitor, "belongs", return_value=True):
            with self.assertRaisesRegex(ValueError, "exceeds 12 GiB"): monitor.sample()
        monitor.next_sample = 0
        with patch.object(M.subprocess, "run", return_value=M.subprocess.CompletedProcess([], 0, stdout=f"{UUID}, 17, 1\n")), \
                patch.object(monitor, "belongs", return_value=True), patch.object(M, "MAX_VRAM_LOG", 1):
            with self.assertRaisesRegex(ValueError, "bounded log"): monitor.sample()

    def test_monitor_close_releases_file_even_when_fsync_fails(self):
        monitor = self.monitor()
        with patch.object(M.os, "fsync", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError): monitor.close()
        self.assertTrue(monitor.output.closed)
        monitor.close()  # Idempotent cleanup must preserve the original error.

    def test_capture_preserves_exit_status_and_output(self):
        process, monitor, selector = MagicMock(), MagicMock(), MagicMock()
        process.wait.return_value = 7
        process.poll.return_value = 7
        selector.__enter__.return_value.select.return_value = [True]
        with patch.object(M.subprocess, "Popen", return_value=process), \
                patch.object(M.selectors, "DefaultSelector", return_value=selector), \
                patch.object(M.os, "read", side_effect=[b"diagnostic\n", b""]):
            code = M.capture_gpu_stage(["synthetic"], self.root / "stage.log", monitor)
        self.assertEqual(code, 7)
        self.assertEqual((self.root / "stage.log").read_bytes(), b"diagnostic\n")
        process.terminate.assert_not_called()
        process.stdout.close.assert_called_once()

    def test_capture_monitor_failure_terminates_and_kills_only_capture_process(self):
        process, monitor, selector = MagicMock(), MagicMock(), MagicMock()
        process.poll.return_value = None
        process.wait.side_effect = [M.subprocess.TimeoutExpired("synthetic", 10), -9]
        monitor.sample.side_effect = ValueError("monitor failure")
        with patch.object(M.subprocess, "Popen", return_value=process), \
                patch.object(M.selectors, "DefaultSelector", return_value=selector):
            with self.assertRaisesRegex(ValueError, "monitor failure"):
                M.capture_gpu_stage(["synthetic"], self.root / "stage.log", monitor)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        process.stdout.close.assert_called_once()

    def test_capture_timeout_and_log_limit_fail_closed(self):
        for timeout, read, message in ((0, b"", "deadline"), (1, b"too large", "log exceeds")):
            process, monitor, selector = MagicMock(), MagicMock(), MagicMock()
            process.poll.return_value = 0
            selector.__enter__.return_value.select.return_value = [True]
            with self.subTest(case=message), patch.object(M.subprocess, "Popen", return_value=process), \
                    patch.object(M.selectors, "DefaultSelector", return_value=selector), \
                    patch.object(M.os, "read", return_value=read), patch.object(M.H, "MAX_STAGE_LOG", 1):
                with self.assertRaisesRegex(ValueError, message):
                    M.capture_gpu_stage(["synthetic"], self.root / (message.replace(" ", "-") + ".log"), monitor, timeout)
            process.stdout.close.assert_called_once()

    def test_stage_failure_is_durable_before_cleanup_and_retains_original_error(self):
        for cleanup_error in (None, M.subprocess.TimeoutExpired("systemctl", 30), ValueError("worker still active")):
            with self.subTest(cleanup=type(cleanup_error).__name__):
                evidence = self.root / (type(cleanup_error).__name__ + "-evidence")
                evidence.mkdir(mode=0o700)
                c = config()
                c.update(job=str(self.root / "job"), evidence=str(evidence))
                state = {"artifacts": artifacts(M.KEYLESS_NAMES), "source_artifacts": artifacts(M.INPUT_NAMES),
                         "attempts": [], "status": "RUNNING"}
                path = evidence / "manifest.json"
                monitor = MagicMock()
                monitor.output.closed = False
                def stop(*args, **kwargs):
                    saved = json.loads(path.read_text())
                    self.assertEqual(saved["attempts"][0]["error"], "original capture interruption")
                    self.assertEqual(saved["status"], "FAILED_OR_INTERRUPTED")
                    if isinstance(cleanup_error, M.subprocess.TimeoutExpired): raise cleanup_error
                    return M.subprocess.CompletedProcess([], 0)
                with patch.object(M, "VramMonitor", return_value=monitor), \
                        patch.object(M, "capture_gpu_stage", side_effect=InterruptedError("original capture interruption")), \
                        patch.object(M.subprocess, "run", side_effect=stop) as stopped, \
                        patch.object(M.H, "require_no_other_work", side_effect=cleanup_error if isinstance(cleanup_error, ValueError) else None):
                    with self.assertRaisesRegex(InterruptedError, "original capture interruption"):
                        M.run_stage(c, "controller", "key-1", ["register", "1"], evidence, state, path)
                stopped.assert_called_once()
                self.assertEqual(stopped.call_args.args[0][:3], ["systemctl", "--user", "stop"])
                saved = json.loads(path.read_text())
                record = saved["attempts"][0]
                self.assertEqual(record["status"], "failed_or_interrupted")
                self.assertEqual(record["cleanup_no_active_worker"], cleanup_error is None)
                monitor.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
