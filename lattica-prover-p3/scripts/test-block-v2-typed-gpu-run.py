#!/usr/bin/env python3
"""Controller-only tests. Synthetic results never count as proof qualification."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("typed_gpu", Path(__file__).with_name("block-v2-typed-gpu-run.py"))
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)
PROFILE = Path(__file__).with_name("block-v2-multi-gpu-direct-readback-workload.json")


def host():
    return {"physical_bytes": 64 * T.R.GIB, "available_bytes": 58 * T.R.GIB,
            "cgroup_memory_headroom": None, "cpu_capacity": "24", "effective_cpus": list(range(24)),
            "scratch": {"capacity_bytes": 32 * T.R.GIB, "available_bytes": 30 * T.R.GIB,
                        "quota_bytes": None, "device": 9, "path": "/tmp", "tmpfs": True}}


def device():
    return {"uuid": "GPU-typed", "opencl": {"global_bytes": 16 * T.R.GIB,
            "max_allocation_bytes": 4 * T.R.GIB, "driver": "CL"},
            "nvidia": {"total_bytes": 16 * T.R.GIB, "free_bytes": 15 * T.R.GIB, "driver": "NV"}}


def fixture(root):
    source = root / "source"
    source.mkdir()
    for name in (*T.PUBLIC_NAMES, "wallet.0"):
        (source / name).write_text("262144" if name == "height.json" else name)
    return source


class TypedGpu(unittest.TestCase):
    def test_opening_denominator_cache_has_explicit_profile_identity(self):
        original = T.resource_profile(PROFILE, 'paired', 'compact')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'workload.json'
            source = json.loads(PROFILE.read_text())
            source['geometry']['opening_denominator_cache'] = True
            path.write_text(json.dumps(source))
            cached = T.resource_profile(path, 'paired', 'compact')
            self.assertTrue(cached['geometry']['opening_denominator_cache'])
            self.assertNotEqual(T.G.profile_digest({'workload': original}),
                                T.G.profile_digest({'workload': cached}))
            source['geometry']['main_columns'] += 1
            path.write_text(json.dumps(source))
            with self.assertRaisesRegex(ValueError, 'resource geometry'):
                T.resource_profile(path, 'paired', 'compact')

    def test_persistent_process_requires_distinct_child_and_confirmed_exit(self):
        config = {"construction": "paired", "execution_backend": "typed-process-dag"}
        self.assertEqual(T.execution_command(config), "prove-process-gpu")
        result = {"execution_backend": "typed_process_dag_v1",
                  "workspace_released_after_gpu_teardown": True, "arrival_backend_integrated": False,
                  "worker_pid": 101, "coordinator_pid": 100, "worker_process_exited": True}
        T.validate_execution_result(config, result)
        for field, value in (("worker_pid", 100), ("worker_pid", True), ("worker_pid", 0),
                             ("coordinator_pid", None), ("worker_process_exited", False),
                             ("execution_backend", "typed_inline_dag_v1")):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                T.validate_execution_result(config, {**result, field: value})
        for construction in ("reference", "finalizer"):
            with self.assertRaises(ValueError):
                T.execution_command({**config, "construction": construction})

    def test_typed_execution_is_explicit_and_requires_teardown_evidence(self):
        self.assertEqual(T.execution_command({"construction": "paired"}), "prove-gpu")
        config = {"construction": "paired", "execution_backend": "typed-dag"}
        self.assertEqual(T.execution_command(config), "prove-execution-gpu")
        for construction in ("reference", "finalizer", None):
            with self.assertRaises(ValueError):
                T.execution_command({**config, "construction": construction})
        with self.assertRaises(ValueError):
            T.execution_command({**config, "execution_backend": "unknown"})
        result = {"execution_backend": "typed_inline_dag_v1",
                  "workspace_released_after_gpu_teardown": True, "arrival_backend_integrated": False}
        T.validate_execution_result(config, result)
        for field in result:
            changed = dict(result); del changed[field]
            with self.assertRaises(ValueError):
                T.validate_execution_result(config, changed)

    def test_query_layout_is_optional_pinned_and_preserves_resource_limits(self):
        baseline = T.resource_profile(PROFILE, "paired", "compact")
        original = T.assigned_budget(host(), device(), baseline)
        self.assertEqual(original["query_readback_layout"], "rows")
        self.assertNotIn("query_readback_layout", baseline["geometry"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workload.json"
            profile = json.loads(PROFILE.read_text())
            profile["geometry"]["query_readback_layout"] = "gather"
            path.write_text(json.dumps(profile))
            candidate = T.resource_profile(path, "paired", "compact")
            budget = T.assigned_budget(host(), device(), candidate)
            self.assertEqual(budget["query_readback_layout"], "gather")
            self.assertEqual(T.resource_signature(budget), T.resource_signature(original))
            self.assertNotEqual(T.G.profile_digest({"workload": candidate}),
                                T.G.profile_digest({"workload": baseline}))

    def test_query_layout_cannot_relax_geometry_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workload.json"
            source = json.loads(PROFILE.read_text())
            for layout in ("unknown", None, True, 1, {}, []):
                profile = copy.deepcopy(source)
                profile["geometry"]["query_readback_layout"] = layout
                path.write_text(json.dumps(profile))
                with self.assertRaisesRegex(ValueError, "query readback layout"):
                    T.resource_profile(path, "paired", "compact")
            for change in ({"main_columns": 99}, {"extra_option": True}, {"host_readback_layout": "banded"}):
                profile = copy.deepcopy(source)
                profile["geometry"].update(query_readback_layout="gather", **change)
                path.write_text(json.dumps(profile))
                with self.assertRaisesRegex(ValueError, "resource geometry"):
                    T.resource_profile(path, "paired", "compact")

    def test_compact_admission_has_distinct_identity_and_keeps_full_default(self):
        full = T.resource_profile(PROFILE, "finalizer")
        compact = T.resource_profile(PROFILE, "finalizer", "compact")
        self.assertEqual(T.minimum_ram(full), 31675383808)
        self.assertEqual(T.minimum_ram(compact), 11844714496)
        self.assertEqual(compact["name"], "typed-finalizer-compact-depth-six-bootstrap-v1")
        second = copy.deepcopy(device())
        second["uuid"] = "GPU-typed-2"
        budgets = T.R.plan(host(), [device(), second], 2, compact)
        self.assertEqual(len(budgets), 2)
        for budget in budgets.values():
            with self.assertRaises(ValueError): T.admit_budget(copy.deepcopy(budget), full)
            admitted = T.admit_budget(copy.deepcopy(budget), compact)
            self.assertEqual(admitted["typed_ram_admission"], "compact")
            self.assertEqual(admitted["workload_kind"], compact["name"])
            self.assertLess(admitted["host"]["worker_bytes"], T.minimum_ram(full))

    def test_compact_payload_bound_cannot_replace_phase_or_spill_admission(self):
        profile = T.resource_profile(PROFILE, "finalizer", "compact")
        budget = T.assigned_budget(host(), device(), profile)
        too_small = copy.deepcopy(budget)
        too_small["host"]["worker_bytes"] = T.minimum_ram(profile)
        with self.assertRaises(ValueError): T.admit_budget(too_small, profile)
        too_small = copy.deepcopy(budget)
        too_small["host"]["spill_bytes"] = T.R.GIB
        with self.assertRaises(ValueError): T.admit_budget(too_small, profile)
        with self.assertRaises(ValueError): T.resource_profile(PROFILE, "finalizer", "unknown")

    def test_fixed_assignment_survives_json_and_preserves_limits_across_constructions(self):
        profile = T.resource_profile(PROFILE)
        budget = T.assigned_budget(host(), device(), profile)
        assignment = json.loads(json.dumps(T.comparison_assignment(budget, profile)))
        for construction in ("reference", "finalizer", "paired"):
            with self.subTest(construction=construction):
                active = T.resource_profile(PROFILE, construction)
                live_host = host()
                live_host["available_bytes"] -= 2 * T.R.GIB
                live = T.assigned_budget(live_host, device(), active)
                pinned = T.apply_resource_assignment(live, assignment, active)
                self.assertEqual(T.resource_signature(pinned), assignment["limits"])
                self.assertEqual(pinned["detected_host"], live_host)
                self.assertEqual(pinned["workload_kind"], T.construction_spec(construction)["workload"])

    def test_fixed_assignment_rejects_capacity_loss_or_system_change(self):
        profile = T.resource_profile(PROFILE)
        assignment = T.comparison_assignment(T.assigned_budget(host(), device(), profile), profile)
        for change in ("ram", "spill", "cpu", "gpu_driver", "gpu_memory", "filesystem"):
            with self.subTest(change=change):
                h, d = host(), device()
                if change == "ram": h["available_bytes"] = 42 * T.R.GIB
                elif change == "spill": h["scratch"]["available_bytes"] = 24 * T.R.GIB
                elif change == "cpu": h.update(cpu_capacity="20", effective_cpus=list(range(20)))
                elif change == "gpu_driver": d["nvidia"]["driver"] = "different"
                elif change == "gpu_memory": d["nvidia"]["free_bytes"] -= T.R.GIB
                else: h["scratch"]["device"] += 1
                with self.assertRaises(ValueError):
                    T.apply_resource_assignment(T.assigned_budget(h, d, profile), assignment, profile)

    def test_single_worker_can_retain_the_cpu_share_of_a_two_worker_assignment(self):
        profile = T.resource_profile(PROFILE, 'paired', 'compact')
        live = T.assigned_budget(host(), device(), profile)
        assignment = T.comparison_assignment(live, profile)
        assignment['limits']['cpu'].update(rayon_threads=11, quota_percent='1100%')
        actual = T.apply_resource_assignment(live, assignment, profile)
        self.assertEqual(T.resource_signature(actual), assignment['limits'])
        self.assertEqual(live['cpu']['rayon_threads'], 23)

    def test_fixed_cpu_limits_cannot_increase_capacity_or_undersupply_threads(self):
        profile = T.resource_profile(PROFILE, 'paired', 'compact')
        live = T.assigned_budget(host(), device(), profile)
        for threads, quota in [(12, '1100%'), (24, '2400%'), (1, '2400%'),
                               (0, '100%'), (True, '100%'), (1, 'nan%'),
                               (1, 'inf%'), (1, '100'), (1, 100), (1, '0%')]:
            with self.subTest(threads=threads, quota=quota):
                assignment = T.comparison_assignment(live, profile)
                assignment['limits']['cpu'].update(rayon_threads=threads, quota_percent=quota)
                with self.assertRaises(ValueError):
                    T.apply_resource_assignment(live, assignment, profile)

    def test_fixed_gpu_limits_survive_increased_free_vram_without_growing(self):
        profile = T.resource_profile(PROFILE)
        original = T.assigned_budget(host(), device(), profile)
        assignment = T.comparison_assignment(original, profile)
        freer = device()
        freer["nvidia"]["free_bytes"] += T.R.GIB
        current = T.assigned_budget(host(), freer, profile)
        self.assertGreater(current["gpu"]["managed_bytes"], original["gpu"]["managed_bytes"])
        fixed = T.apply_resource_assignment(current, assignment, profile)
        self.assertEqual(T.resource_signature(fixed), assignment["limits"])
        self.assertEqual(fixed["gpu"]["available_bytes"], current["gpu"]["available_bytes"])

    def test_fixed_assignment_cannot_relax_margins_or_full_storage_guard(self):
        profile = T.resource_profile(PROFILE)
        live = T.assigned_budget(host(), device(), profile)
        original = T.comparison_assignment(live, profile)
        edits = [("host", "worker_bytes", 31675383807),
                 ("host", "coordinator_bytes", 1),
                 ("host", "fleet_bytes", 100 * T.R.GIB),
                 ("host", "spill_bytes", 100 * T.R.GIB),
                 ("host", "spill_bytes", True),
                 ("host", "os_headroom_bytes", 1),
                 ("host", "filesystem_headroom_bytes", 1),
                 ("host", "swap_bytes", T.R.GIB),
                 ("gpu", "context_bytes", 1),
                 ("gpu", "headroom_bytes", 1),
                 ("cpu", "rayon_threads", 30)]
        for section, key, value in edits:
            with self.subTest(section=section, key=key):
                modified = copy.deepcopy(original)
                modified["limits"][section][key] = value
                with self.assertRaises(ValueError):
                    T.apply_resource_assignment(live, modified, profile)

    def test_finalizer_requires_six_keys_and_its_own_plan_and_admission(self):
        profile = T.resource_profile(PROFILE, "finalizer")
        budget = T.assigned_budget(host(), device(), profile)
        self.assertEqual(profile["geometry"]["registry_programs"], 6)
        self.assertEqual(budget["workload_kind"], "typed-finalizer-depth-six-bootstrap-v1")
        plan = {"construction": "typed-finalizer-v1", "registry_keys": 6}
        T.validate_plan(plan, "finalizer")
        with self.assertRaises(ValueError): T.validate_plan(plan, "reference")
        with self.assertRaises(ValueError): T.validate_plan({}, "finalizer")
        with self.assertRaises(ValueError): T.construction_spec("unknown")
        with tempfile.TemporaryDirectory() as directory:
            source = fixture(Path(directory))
            with self.assertRaises(ValueError): T.fixture_files(source, 1, "finalizer")
            (source / "key.6").write_text("sixth trusted key")
            self.assertEqual(len(T.fixture_files(source, 1, "finalizer")), 9)

    def test_paired_requires_twelve_keys_and_its_own_plan_and_admission(self):
        profile = T.resource_profile(PROFILE, "paired", "compact")
        budget = T.assigned_budget(host(), device(), profile)
        self.assertEqual(profile["geometry"]["registry_programs"], 12)
        self.assertEqual(budget["workload_kind"], "typed-paired-compact-depth-six-bootstrap-v1")
        T.validate_plan({"construction": "typed-paired-v1", "registry_keys": 12}, "paired")
        for construction, keys in (("reference", 5), ("finalizer", 6)):
            with self.assertRaises(ValueError):
                T.validate_plan({"construction": f"typed-{construction}-v1", "registry_keys": keys}, "paired")
        with tempfile.TemporaryDirectory() as directory:
            source = fixture(Path(directory))
            for mode in range(6, 12):
                (source / f"key.{mode}").write_text("synthetic trusted key")
            with self.assertRaises(ValueError):
                T.fixture_files(source, 1, "paired")
            (source / "key.12").write_text("synthetic finalizer key")
            self.assertEqual(len(T.fixture_files(source, 1, "paired")), 15)

    def test_budget_uses_actual_system_and_a_distinct_profile(self):
        profile = T.resource_profile(PROFILE)
        self.assertEqual(profile["geometry"]["registry_programs"], 5)
        budget = T.assigned_budget(host(), device(), profile)
        self.assertEqual(budget["workload_kind"], T.WORKLOAD)
        self.assertEqual(budget["slice"], T.G.SLICE)
        self.assertEqual(budget["gpu"]["uuid"], "GPU-typed")
        self.assertEqual(budget["cpu"]["rayon_threads"], 23)
        self.assertGreaterEqual(budget["host"]["worker_bytes"], 31675383808)
        limited = host(); limited.update(cpu_capacity="8", effective_cpus=list(range(8)))
        self.assertEqual(T.assigned_budget(limited, device(), profile)["cpu"]["rayon_threads"], 7)
        limited["available_bytes"] = 28 * T.R.GIB
        with self.assertRaises(ValueError): T.assigned_budget(limited, device(), profile)
        small = device(); small["opencl"]["max_allocation_bytes"] = 64 * T.R.MIB
        with self.assertRaises(ValueError): T.assigned_budget(host(), small, profile)

    def test_inputs_require_five_keys_exact_geometry_and_fresh_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = fixture(root)
            paths = T.fixture_files(source, 1)
            pins = dict(map(T.pin, paths)); T.check_pins(pins)
            (source / "key.5").write_text("changed")
            with self.assertRaises(ValueError): T.check_pins(pins)
            (source / "key.5").unlink()
            with self.assertRaises(ValueError): T.fixture_files(source, 1)
            (source / "key.5").symlink_to(source / "key.1")
            with self.assertRaises(ValueError): T.fixture_files(source, 1)
            (source / "key.5").unlink(); (source / "key.5").write_text("key")
            (source / "height.json").write_text("524288")
            with self.assertRaises(ValueError): T.fixture_files(source, 1)

    def test_plan_cannot_count_duplicate_missing_or_reordered_fresh_nodes(self):
        plan = {"fresh_proofs": 2, "tasks": [{"file": "node.0.0", "mode": 1, "count": 1},
                {"file": "node.6.0", "mode": 3, "count": 1}]}
        events = [{"event": "fresh_typed_node", "level": 0, "index": 0, "mode": 1, "count": 1},
                  {"event": "fresh_typed_node", "level": 6, "index": 0, "mode": 3, "count": 1}]
        finish = {"event": "typed_gpu_work_complete", "recursive_proofs": 2}
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "prove.log"
            log.write_text("\n".join(map(json.dumps, [*events, finish])))
            T.validate_fresh_nodes(plan, log, log)
            for altered in (events[:1], events[::-1], [events[0], events[0]],
                            [*events, events[1]], events):
                counters = {**finish, "recursive_proofs": 1} if altered is events else finish
                log.write_text("\n".join(map(json.dumps, [*altered, counters])))
                with self.assertRaises(ValueError): T.validate_fresh_nodes(plan, log, log)

    def test_memory_and_context_evidence_must_match_the_worker(self):
        valid = {"memory.peak": "18", "memory.events":
                 "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0"}
        budget = {"host": {"worker_bytes": 20}}
        T.validate_accounting(valid, budget)
        for change in ("max 1", "oom 1", "high 1"):
            altered = copy.deepcopy(valid)
            altered["memory.events"] = altered["memory.events"].replace(change[:-1] + "0", change)
            with self.assertRaises(ValueError): T.validate_accounting(altered, budget)
        with self.assertRaises(ValueError): T.validate_accounting({**valid, "memory.peak": "21"}, budget)
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "prove.log"
            log.write_text('bounded_gpu_context {"uuid":"GPU-typed","context_bytes":123}\n')
            self.assertEqual(T.measured_context(log, "GPU-typed")["peak_context_bytes"], 123)
            with self.assertRaises(ValueError): T.measured_context(log, "GPU-other")
            log.write_text("")
            with self.assertRaises(ValueError): T.measured_context(log, "GPU-typed")

    def test_cpu_audit_receives_only_root_body_policy_and_registry(self):
        for audit_passes in (True, False):
            with self.subTest(audit_passes=audit_passes), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); source = fixture(root)
                gpu, cpu = root / "gpu", root / "cpu"; gpu.write_text("gpu"); cpu.write_text("cpu")
                expected, plan_file = root / "expected.json", root / "plan.json"
                expected.write_text("expected")
                plan_file.write_text(json.dumps({"fresh_proofs": 1, "tasks": [{"file": "node.6.0", "mode": 3, "count": 1}]}))
                budget = T.assigned_budget(host(), device(), T.resource_profile(PROFILE))
                budget["unit"] = "lattica-v2-multi-test-typed.service"
                attempt = root / "attempt"; attempt.mkdir()
                config = {"fixture": str(source), "count": 1, "expected": str(expected), "plan": str(plan_file),
                          "gpu_binary": str(gpu), "cpu_binary": str(cpu), "workload": T.resource_profile(PROFILE)}
                config["pins"] = dict(map(T.pin, [*T.fixture_files(source, 1), gpu, cpu, expected, plan_file]))
                packet = attempt / "attempt.json"
                packet.write_text(json.dumps({"config": config, "budget": budget}))

                def execute(argv, log, env):
                    if argv[1] == "prove-gpu":
                        self.assertEqual(env["LATTICA_V2_GPU_HASH"], "1")
                        proof_dir = Path(argv[4]); proof_dir.mkdir()
                        (proof_dir / "node.6.0").write_text("synthetic-root")
                        (proof_dir / "result.json").write_text(json.dumps({"fresh_proofs": 1,
                            "backend": "gpu", "production_ready": False}))
                        log.write_text(json.dumps({"event": "fresh_typed_node", "level": 6, "index": 0, "mode": 3, "count": 1}) + "\n" +
                                       json.dumps({"event": "typed_gpu_work_complete", "recursive_proofs": 1}))
                    else:
                        self.assertEqual(argv[1], "audit-root")
                        self.assertFalse(any(key.startswith("LATTICA_") for key in env))
                        self.assertEqual({p.name for p in Path(argv[2]).iterdir()}, set(T.PUBLIC_NAMES) | {"expected.json", "node.6.0"})
                        log.write_text(json.dumps({"event": "independent_cpu_root_audit", "count": 1, "passed": audit_passes}))

                with patch.object(T, "execute_logged", side_effect=execute):
                    if audit_passes:
                        T.worker(packet)
                        result = json.loads((attempt / "result.json").read_text())
                        self.assertTrue(result["cpu_audited"])
                        self.assertFalse(result["durable_host_applied"])
                    else:
                        with self.assertRaises(ValueError): T.worker(packet)
                        self.assertFalse((attempt / "result.json").exists())

    def test_existing_evidence_is_never_overwritten_on_refused_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = fixture(root)
            binary = root / "binary"; binary.write_text("binary")
            out = root / "evidence"; out.mkdir(); summary = out / "summary.json"
            summary.write_text("preserved previous failure")
            argv = ["controller", "--gpu-binary", str(binary), "--cpu-binary", str(binary),
                    "--fixture", str(source), "--gpu-uuid", "GPU-typed", "--count", "1", "--evidence", str(out)]
            with patch.object(sys, "argv", argv), patch.object(T.G, "lock_fleet", return_value=[]), \
                    patch.object(T.G, "systemctl", return_value="[]"):
                with self.assertRaises(FileExistsError): T.main()
            self.assertEqual(summary.read_text(), "preserved previous failure")

    def test_alternate_worker_requires_a_pin_before_any_launch_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); worker = root / "worker.py"; worker.write_text("# worker")
            target = root / "attempt"
            with self.assertRaises(ValueError):
                T.G.launch({"pins": {}}, {}, {}, target, worker_script=worker)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
