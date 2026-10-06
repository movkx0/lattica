#!/usr/bin/env python3
"""Synthetic fleet-admission tests; no fixture is a successful proving run."""

import copy
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


F = module("typed_fleet", "block-v2-typed-multi-gpu-run.py")
H = module("typed_fixtures", "test-block-v2-typed-gpu-run.py")


class TypedFleet(unittest.TestCase):
    def inputs(self):
        second = H.device()
        second["uuid"] = "GPU-second"
        second["nvidia"]["free_bytes"] -= 2 * F.R.GIB
        return H.host(), [H.device(), second], F.T.resource_profile(H.PROFILE, "finalizer", "compact")

    def calibrated_inputs(self):
        host, devices, profile = self.inputs()
        original = F.plan_budgets(host, devices, profile)
        assignment = {"schema": "lattica-typed-fleet-assignment-v1",
                      "limits_by_gpu": {uuid: F.T.resource_signature(b) for uuid, b in original.items()}}
        calibrations = {d["uuid"]: {"uuid": d["uuid"], "driver": d["nvidia"]["driver"],
            "runtime": d["opencl"]["driver"], "peak_context_bytes": (200 if i == 0 else 600) * F.R.MIB}
            for i, d in enumerate(devices)}
        current = F.plan_budgets(host, devices, profile, calibrations=calibrations)
        for uuid, limits in assignment["limits_by_gpu"].items():
            gpu = limits["gpu"]
            gpu.update(bootstrap=False, context_bytes=current[uuid]["gpu"]["context_bytes"])
            gpu["total_bytes"] = gpu["managed_bytes"] + gpu["context_bytes"]
        return host, devices, profile, assignment, calibrations

    def test_calibrated_contexts_keep_device_margins_and_fixed_managed_capacity(self):
        host, devices, profile, assignment, calibrations = self.calibrated_inputs()
        budgets = F.plan_budgets(host, devices, profile, assignment, calibrations)
        for uuid, budget in budgets.items():
            self.assertEqual(F.T.resource_signature(budget), assignment["limits_by_gpu"][uuid])
            self.assertFalse(budget["gpu"]["bootstrap"])
            self.assertGreaterEqual(budget["gpu"]["context_bytes"], 512 * F.R.MIB)
            self.assertGreaterEqual(budget["gpu"]["context_bytes"], calibrations[uuid]["peak_context_bytes"] * 1.25)
        self.assertEqual(len({b["gpu"]["context_bytes"] for b in budgets.values()}), 2)

    def test_calibrated_assignment_rejects_driver_change_missing_calibration_and_reduced_margin(self):
        host, devices, profile, assignment, calibrations = self.calibrated_inputs()
        with self.assertRaises(ValueError): F.plan_budgets(host, devices, profile, assignment)
        for key in ("driver", "runtime"):
            changed = copy.deepcopy(calibrations)
            changed[devices[0]["uuid"]][key] = "different"
            with self.assertRaises(ValueError): F.plan_budgets(host, devices, profile, assignment, changed)
        changed = copy.deepcopy(assignment)
        gpu = changed["limits_by_gpu"][devices[0]["uuid"]]["gpu"]
        gpu["context_bytes"] -= 1
        gpu["total_bytes"] -= 1
        with self.assertRaises(ValueError): F.plan_budgets(host, devices, profile, changed, calibrations)

    def calibration_trial(self, directory, budget, profile):
        directory.mkdir()
        work = directory / "001-typed"
        work.mkdir()
        (work / "root-only").mkdir()
        for name in ("summary.json", "plan.json"):
            (directory / name).write_text("{}")
        config = {"pins": {}, "workload": profile, "ram_admission": profile["typed_ram_admission"]}
        assignment_path = directory / "resource-assignment.json"
        assignment_path.write_text(json.dumps({
            "schema": "lattica-typed-resource-assignment-v1", "limits": F.T.resource_signature(budget)}))
        assignment_sha = F.G.digest(assignment_path)
        config.update(resource_assignment=str(assignment_path), resource_assignment_sha256=assignment_sha)
        config["pins"][str(assignment_path)] = assignment_sha
        (directory / "config.json").write_text(json.dumps(config))
        (work / "result.json").write_text(json.dumps({"budget": budget,
            "profile_sha256": F.G.profile_digest(config)}))
        for name in ("accounting.json", "audit.log"):
            (work / name).write_text("{}")
        (work / "prove.log").write_text("bounded_gpu_context " + json.dumps({
            "uuid": budget["gpu"]["uuid"], "context_bytes": 200 * F.R.MIB}) + "\n")
        return directory

    def test_context_calibration_requires_complete_trial_validation_and_pins_raw_measurements(self):
        host, devices, profile, assignment, _ = self.calibrated_inputs()
        budgets = F.plan_budgets(host, devices, profile)
        with tempfile.TemporaryDirectory() as tmp:
            dirs = [self.calibration_trial(Path(tmp) / str(i), b, profile) for i, b in enumerate(budgets.values())]
            with patch.object(F.C, "checked_trial", return_value={}) as validate:
                calibrations, pins = F.load_calibrations(dirs, "binary", profile, "finalizer", 4, assignment, list(budgets))
            self.assertEqual(validate.call_count, 2)
            self.assertEqual(set(calibrations), set(budgets))
            with self.assertRaisesRegex(ValueError, "different execution backend"):
                F.load_calibrations(dirs, "binary", profile, "paired", 4, assignment,
                                    list(budgets), execution_backend="typed-dag")
            for directory in dirs:
                self.assertIn(str(directory / "001-typed/prove.log"), pins)
            F.T.check_pins(pins)
            with patch.object(F.C, "checked_trial", side_effect=ValueError("CPU audit failed")):
                with self.assertRaisesRegex(ValueError, "CPU audit failed"):
                    F.load_calibrations(dirs, "binary", profile, "finalizer", 4, assignment, list(budgets))
            (dirs[0] / "001-typed/prove.log").write_text("changed")
            with self.assertRaises(ValueError): F.T.check_pins(pins)

    def test_calibration_resolves_pinned_external_assignment_from_comparison_config(self):
        host, devices, profile, assignment, _ = self.calibrated_inputs()
        budgets = F.plan_budgets(host, devices, profile)
        with tempfile.TemporaryDirectory() as tmp, patch.object(F.C, "checked_trial", return_value={}) as validate:
            dirs = [self.calibration_trial(Path(tmp) / str(i), b, profile) for i, b in enumerate(budgets.values())]
            paths = []
            for i, directory in enumerate(dirs):
                local = directory / "resource-assignment.json"
                external = Path(tmp) / f"shared-assignment-{i}.json"
                local.rename(external)
                config_path = directory / "config.json"
                config = json.loads(config_path.read_text())
                sha = config["pins"].pop(str(local))
                config["pins"][str(external)] = sha
                config["resource_assignment"] = str(external)
                config_path.write_text(json.dumps(config))
                paths.append(external)
            calibrations, pins = F.load_calibrations(dirs, "binary", profile, "finalizer", 4, assignment, list(budgets))
            self.assertEqual(set(calibrations), set(budgets))
            for i, external in enumerate(paths):
                self.assertEqual(pins[str(external)], F.G.digest(external))
                self.assertEqual(validate.call_args_list[i].args[4], F.G.digest(external))
            F.T.check_pins(pins)

    def test_calibration_rejects_unpinned_or_inconsistent_assignment_reference(self):
        host, devices, profile, assignment, _ = self.calibrated_inputs()
        budgets = F.plan_budgets(host, devices, profile)
        for mutation in ("missing_pin", "declared_hash", "changed_file"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp, patch.object(F.C, "checked_trial", return_value={}):
                dirs = [self.calibration_trial(Path(tmp) / str(i), b, profile) for i, b in enumerate(budgets.values())]
                path = dirs[0] / "config.json"
                config = json.loads(path.read_text())
                if mutation == "missing_pin":
                    config["pins"].clear()
                elif mutation == "declared_hash":
                    config["resource_assignment_sha256"] = "0" * 64
                else:
                    Path(config["resource_assignment"]).write_text("{}")
                path.write_text(json.dumps(config))
                with self.assertRaises(ValueError):
                    F.load_calibrations(dirs, "binary", profile, "finalizer", 4, assignment, list(budgets))

    def automatic_calibration_trial(self, directory, budget, profile):
        directory = self.calibration_trial(directory, budget, profile)
        path = directory / "config.json"
        config = json.loads(path.read_text())
        Path(config.pop("resource_assignment")).unlink()
        config.pop("resource_assignment_sha256")
        config["pins"].clear()
        path.write_text(json.dumps(config))
        (directory / "001-typed/budget.json").write_text(json.dumps(budget))
        (directory / "admission.json").write_text(json.dumps({"budget": budget}))
        (directory / "001-typed/attempt.json").write_text(json.dumps({"budget": budget, "config": config}))
        return directory

    def test_calibration_accepts_consistent_automatic_worker_budget_and_pins_its_records(self):
        host, devices, profile, assignment, _ = self.calibrated_inputs()
        budgets = F.plan_budgets(host, devices, profile)
        with tempfile.TemporaryDirectory() as tmp, patch.object(F.C, "checked_trial", return_value={}) as validate:
            dirs = [self.automatic_calibration_trial(Path(tmp) / str(i), b, profile) for i, b in enumerate(budgets.values())]
            calibrations, pins = F.load_calibrations(dirs, "binary", profile, "finalizer", 4, assignment, list(budgets))
            self.assertEqual(set(calibrations), set(budgets))
            for i, directory in enumerate(dirs):
                self.assertIsNone(validate.call_args_list[i].args[4])
                for name in ("001-typed/budget.json", "admission.json", "001-typed/attempt.json"):
                    self.assertIn(str(directory / name), pins)
            F.T.check_pins(pins)

    def test_calibration_rejects_inconsistent_automatic_budget_or_assignment_hash(self):
        host, devices, profile, assignment, _ = self.calibrated_inputs()
        budgets = F.plan_budgets(host, devices, profile)
        for mutation in ("budget", "admission", "attempt", "config", "hash"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp, patch.object(F.C, "checked_trial", return_value={}):
                dirs = [self.automatic_calibration_trial(Path(tmp) / str(i), b, profile) for i, b in enumerate(budgets.values())]
                if mutation == "hash":
                    path = dirs[0] / "001-typed/result.json"
                    data = json.loads(path.read_text()); data["resource_assignment_sha256"] = "0" * 64
                else:
                    name = {"budget": "001-typed/budget.json", "admission": "admission.json",
                            "attempt": "001-typed/attempt.json", "config": "001-typed/attempt.json"}[mutation]
                    path = dirs[0] / name; data = json.loads(path.read_text())
                    if mutation == "budget": data["host"]["worker_bytes"] += 1
                    elif mutation == "config": data["config"]["count"] = 63
                    else: data["budget"]["host"]["worker_bytes"] += 1
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    F.load_calibrations(dirs, "binary", profile, "finalizer", 4, assignment, list(budgets))

    def test_calibration_rejects_missing_device_duplicate_trial_profile_drift_and_capacity_change(self):
        host, devices, profile, assignment, _ = self.calibrated_inputs()
        budgets = F.plan_budgets(host, devices, profile)
        with tempfile.TemporaryDirectory() as tmp, patch.object(F.C, "checked_trial", return_value={}):
            dirs = [self.calibration_trial(Path(tmp) / str(i), b, profile) for i, b in enumerate(budgets.values())]
            def load(paths=dirs, fixed=assignment):
                return F.load_calibrations(paths, "binary", profile, "finalizer", 4, fixed, list(budgets))
            for paths in ([], dirs[:1], dirs + dirs[:1]):
                with self.assertRaises(ValueError): load(paths)
            changed = copy.deepcopy(assignment)
            changed["limits_by_gpu"][devices[0]["uuid"]]["gpu"]["managed_bytes"] += F.R.MIB
            with self.assertRaisesRegex(ValueError, "managed GPU capacity"): load(fixed=changed)
            config_path = dirs[0] / "config.json"
            config = json.loads(config_path.read_text())
            config["workload"]["geometry"]["tree_depth"] = 5
            config_path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "different proof profile"): load()

    def test_device_specific_limits_share_actual_cpu_ram_and_spill_capacity(self):
        host, devices, profile = self.inputs()
        budgets = F.plan_budgets(host, devices, profile)
        self.assertEqual(set(budgets), {d["uuid"] for d in devices})
        self.assertEqual(sum(b["cpu"]["rayon_threads"] for b in budgets.values()), 23)
        self.assertNotEqual(budgets[devices[0]["uuid"]]["gpu"]["managed_bytes"],
                            budgets[devices[1]["uuid"]]["gpu"]["managed_bytes"])
        common = next(iter(budgets.values()))["host"]
        self.assertLessEqual(sum(b["host"]["worker_bytes"] for b in budgets.values()) + common["coordinator_bytes"],
                             common["fleet_bytes"])
        self.assertLessEqual(sum(b["host"]["spill_bytes"] for b in budgets.values()), host["scratch"]["available_bytes"])
        with self.assertRaises(ValueError): F.plan_budgets(host, [devices[0], devices[0]], profile)

    def test_fixed_fleet_assignment_is_revalidated_and_never_silently_reduced(self):
        host, devices, profile = self.inputs()
        original = F.plan_budgets(host, devices, profile)
        assignment = json.loads(json.dumps({"schema": "lattica-typed-fleet-assignment-v1",
            "limits_by_gpu": {uuid: F.T.resource_signature(b) for uuid, b in original.items()}}))
        grown = copy.deepcopy(host)
        grown["available_bytes"] += F.R.GIB
        budgets = F.plan_budgets(grown, devices, profile, assignment)
        self.assertEqual({u: F.T.resource_signature(b) for u, b in budgets.items()}, assignment["limits_by_gpu"])
        reduced = copy.deepcopy(host)
        reduced["available_bytes"] -= 2 * F.R.GIB
        with self.assertRaises(ValueError): F.plan_budgets(reduced, devices, profile, assignment)
        wrong = copy.deepcopy(assignment)
        wrong["limits_by_gpu"].pop(devices[0]["uuid"])
        with self.assertRaises(ValueError): F.plan_budgets(host, devices, profile, wrong)

    def test_parent_memory_events_or_accounting_reset_fail_qualification(self):
        before = {"max": 7, "oom": 1, "oom_kill": 1}
        self.assertEqual(F.event_deltas(before, dict(before)), {key: 0 for key in before})
        for after in ({**before, "max": 8}, {**before, "oom_kill": 2}, {**before, "max": 0}, {"max": 7}):
            with self.assertRaises(ValueError): F.event_deltas(before, after)

    def test_cleanup_retains_scratch_until_worker_and_gpu_context_are_gone(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scratch = root / "lattica-v2-multi-test"
            scratch.mkdir()
            artifact = scratch / "lat-spill-test"
            artifact.write_text("retain me")
            attempt_dir = root / "attempt"
            attempt_dir.mkdir()
            (attempt_dir / "scratch").symlink_to(scratch, target_is_directory=True)
            attempt = {"unit": "lattica-v2-multi-test.service", "directory": str(attempt_dir)}
            budget = {"host": {"scratch_path": str(root)}}
            with patch.object(F.G, "unit_state", return_value={}), patch.object(F.G, "systemctl"), \
                    patch.object(F.G, "terminated", return_value=True), \
                    patch.object(F.G, "gpu_processes", return_value=[(123, "GPU-test", 1)]), \
                    patch.object(F.time, "sleep"):
                with self.assertRaises(ValueError): F.cleanup(attempt, budget, {123})
            self.assertTrue(artifact.exists())
            with patch.object(F.G, "unit_state", return_value={}), patch.object(F.G, "terminated", return_value=True), \
                    patch.object(F.G, "gpu_processes", return_value=[]):
                F.cleanup(attempt, budget, {123})
            self.assertFalse(scratch.exists())

    def exercise_controller(self, mode, fail_second_launch=False, execution_backend="bootstrap"):
        host, devices, profile = self.inputs()
        construction = "paired" if execution_backend != "bootstrap" else "finalizer"
        spec = F.T.construction_spec(construction)
        fresh_proofs = 4 if construction == "paired" else 8
        order = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "fixture"
            fixture.mkdir()
            for name in (*F.T.public_names(construction), *(f"wallet.{i}" for i in range(4))):
                (fixture / name).write_text("262144" if name == "height.json" else "synthetic unit-test input")
            gpu, cpu = root / "gpu", root / "cpu"
            gpu.write_text("synthetic GPU executable identity")
            cpu.write_text("synthetic CPU executable identity")
            out = root / "evidence"

            def execute(argv, log, env):
                if argv[1] == "expected":
                    Path(argv[-1]).write_text("{}")
                    log.write_text("synthetic expected-policy test")
                else:
                    log.write_text(json.dumps({"construction": f"typed-{construction}-v1",
                                               "registry_keys": spec["keys"], "fresh_proofs": fresh_proofs}))

            def launch(config, job, budget, directory, **kwargs):
                order.append(("launch", budget["gpu"]["uuid"]))
                directory.mkdir()
                self.assertEqual(config["execution_backend"], execution_backend)
                self.assertEqual(F.T.execution_command(config),
                                 {"typed-dag": "prove-execution-gpu", "typed-process-dag": "prove-process-gpu",
                                  "bootstrap": "prove-gpu"}[execution_backend])
                (directory / "result.json").write_text(json.dumps({"status": "succeeded",
                    "execution_backend": execution_backend,
                              "execution_result": {"execution_backend": "typed_process_dag_v1" if execution_backend == "typed-process-dag" else "typed_inline_dag_v1",
                                                   "worker_pid": 101, "coordinator_pid": 100, "worker_process_exited": True,
                        "workspace_released_after_gpu_teardown": True, "arrival_backend_integrated": False}}))
                (directory / "accounting.json").write_text(json.dumps({"memory.peak": "1",
                    "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\nsock_throttled 0\n"}))
                (directory / "retained-failure-evidence").write_text("preserve this artifact")
                if fail_second_launch and sum(event == "launch" for event, _ in order) == 2:
                    raise RuntimeError("synthetic launch failure")

            def validate(directory, construction, count, assignment, assignment_sha, gpu_sha):
                config = json.loads((directory / "config.json").read_text())
                self.assertEqual(config["ram_admission"], "compact")
                self.assertEqual(F.G.digest(directory / "resource-assignment.json"), assignment_sha)
                uuid = assignment["limits"]["gpu"]["uuid"]
                order.append(("validate", uuid))
                return {"worker_seconds": 1.0, "fresh_proofs": fresh_proofs, "cpu_audited": True}

            def systemctl(*args):
                if args[0] == "list-units": return "[]"
                if args[0] == "show": return "/synthetic-test-group"
                return ""

            argv = ["typed-fleet", "--gpu-binary", str(gpu), "--cpu-binary", str(cpu),
                    "--construction", construction, "--execution-backend", execution_backend,
                    "--fixture", str(fixture), "--mode", mode, "--workload", str(H.PROFILE),
                    "--scratch", str(root), "--evidence", str(out)]
            for device in devices:
                argv += ["--gpu-uuid", device["uuid"]]
            with ExitStack() as stack:
                stack.enter_context(patch.object(sys, "argv", argv))
                for owner, name, replacement in [
                    (F.G, "lock_fleet", lambda: []), (F.G, "systemctl", systemctl),
                    (F.G, "detect_worker_host", lambda path: host), (F.R, "detect_gpus", lambda path: devices),
                    (F.T, "execute_logged", execute), (F.G, "launch", launch),
                    (F.G, "telemetry", lambda attempt, budget: {"unit": {}, "pids": [1]}),
                    (F.G, "terminated", lambda state: True), (F.G, "gpu_processes", lambda: []),
                    (F.G, "attempt_succeeded", lambda directory, state: True),
                    (F.T, "measured_context", lambda log, uuid: {"uuid": uuid, "samples": 1, "peak_context_bytes": 1}),
                    (F.C, "checked_trial", validate), (F, "event_counters", lambda path: {"max": 0, "oom": 0}),
                    (F, "cleanup", lambda attempt, budget, pids: order.append(("cleanup", attempt["uuid"]))),
                ]:
                    stack.enter_context(patch.object(owner, name, replacement))
                stack.enter_context(patch("builtins.print"))
                if fail_second_launch:
                    with self.assertRaisesRegex(RuntimeError, "synthetic launch failure"):
                        F.main()
                else:
                    F.main()
            report = json.loads((out / "summary.json").read_text())
            self.assertTrue(all((Path(a["directory"]) / "retained-failure-evidence").exists() for a in report["attempts"]))
            return report, order

    def test_both_execution_orders_finish_and_account_for_two_independent_roots(self):
        for mode in ("sequential", "concurrent"):
            with self.subTest(mode=mode):
                report, order = self.exercise_controller(mode)
                self.assertEqual(report["status"], "succeeded")
                self.assertEqual(report["cpu_audited_roots"], 2)
                self.assertEqual(report["fresh_recursive_proofs"], 16)
                self.assertFalse(report["delivered_transactions_measured"])
                operations = [event for event, _ in order]
                self.assertEqual(operations[:2], ["launch", "launch"] if mode == "concurrent" else ["launch", "validate"])

    def test_paired_cached_workers_use_typed_dispatch_in_both_execution_orders(self):
        for mode in ("sequential", "concurrent"):
            with self.subTest(mode=mode):
                report, _ = self.exercise_controller(mode, execution_backend="typed-dag")
                self.assertEqual(report["status"], "succeeded")
                self.assertEqual(report["execution_backend"], "typed-dag")
                self.assertEqual(report["cpu_audited_roots"], 2)
                self.assertEqual(report["fresh_recursive_proofs"], 8)
                for trial in report["trials"]:
                    self.assertEqual(trial["execution_backend"], "typed-dag")
                    self.assertTrue(trial["execution_result"]["workspace_released_after_gpu_teardown"])

    def test_persistent_process_workers_preserve_backend_in_both_orders(self):
        for mode in ("sequential", "concurrent"):
            with self.subTest(mode=mode):
                report, _ = self.exercise_controller(mode, execution_backend="typed-process-dag")
                self.assertEqual(report["status"], "succeeded")
                self.assertEqual(report["cpu_audited_roots"], 2)
                for trial in report["trials"]:
                    self.assertEqual(trial["execution_backend"], "typed-process-dag")
                    self.assertEqual(trial["execution_result"]["execution_backend"], "typed_process_dag_v1")
                    self.assertTrue(trial["execution_result"]["worker_process_exited"])

    def test_backend_validation_rejects_wrong_dispatch_or_missing_teardown(self):
        config = {"construction": "paired", "execution_backend": "typed-dag"}
        result = {"execution_backend": "typed-dag", "execution_result": {
            "execution_backend": "typed_inline_dag_v1", "workspace_released_after_gpu_teardown": True,
            "arrival_backend_integrated": False}}
        F.validate_backend_result(config, result)
        for change in ({}, {"execution_backend": "bootstrap"},
                       {**result, "execution_result": {}},
                       {**result, "execution_result": {**result["execution_result"],
                           "workspace_released_after_gpu_teardown": False}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                F.validate_backend_result(config, change)

    def test_partial_launch_failure_stops_both_attempts_and_retains_artifacts(self):
        report, order = self.exercise_controller("concurrent", fail_second_launch=True)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["trials"]), 0)
        self.assertTrue(all(attempt["status"] == "failed" for attempt in report["attempts"]))
        self.assertEqual(sum(event == "cleanup" for event, _ in order), 2)


if __name__ == "__main__":
    unittest.main()
