#!/usr/bin/env python3
"""Cheap synthetic orchestration tests only: NO keys, proofs, GPU or services."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import io
from contextlib import redirect_stdout
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("single_eight_trial", Path(__file__).with_name("block-v2-single-eight-trial.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
UNIT = "lattica-v2-single-eight-123-1.service"
CONTROLLER = "lattica-v2-single-eight-test.service"
ACCOUNT = (f"stage_cgroup_accounting unit={UNIT} scope=exec_stop_post_snapshot memory_peak=17 "
           f"memory_swap_peak=0 memory_max={44*M.GIB} memory_swap_max=0 cpu_usage_usec=42\n")
DURATION = "single_eight_stage_elapsed_ms=123 spill_peak_bytes=0 cpu_only=true production_ready=false\n"
ROOT = "single_eight_root_verification=PASS level=3 count=8 inner_proofs_loaded=0 full_tree_security=UNREVIEWED production_ready=false\n"
AUDIT = ("grouped_artifact_audit=PASS kind=level3-count8-subtree proof_bytes=199 "
         "native_mutation_rejections=38 registry_policy_rejections=4 expected_statement_policy_rejections=2 "
         "bundle_files=5 inner_proofs_loaded=0 level6_qualified=false full_tree_security=UNREVIEWED production_ready=false\n")


def node_lines(names):
    return "".join(f"single_eight_node_complete artifact={name} resumed=false elapsed_ms=100 setups=1 cache_hits={i} production_ready=false\n"
                   for i, name in enumerate(names))


class TestController(unittest.TestCase):
    def test_single_eight_layout_has_fifteen_proofs_and_twenty_two_inners(self):
        leaves = tuple(f"node.0.{i}" for i in range(8))
        merges = tuple(f"node.{level}.{index}"
                       for level in (1, 2, 3) for index in range(8 >> level))
        self.assertEqual(M.LEAVES, leaves)
        self.assertEqual(M.MERGES, merges)
        self.assertEqual(len(set(leaves + merges)), 15)
        inners = set(M.WALLETS + leaves + merges[:-1])
        self.assertEqual(len(inners), 22)
        self.assertNotIn("node.3.0", inners)
        self.assertEqual(set(M.ROOT_FILES), {"node.3.0", "height", "key.1", "key.2", "key.3"})

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lattica-single-eight-controller-test-")
        self.root = Path(self.temp.name)
        self.config = {"mode": "prove", "job": str(self.root / "job"),
                       "evidence": str(self.root / "evidence"), "external": ["11"*32, "22"*32, "00"*32]}
        for key in ("runner", "auditor", "accounting", "source_archive"):
            path = self.root / key
            path.write_bytes(b"SYNTHETIC-NOT-A-PROVER")
            self.config[key] = str(path)
        # Any accidental service inventory call is stubbed for synthetic flows.
        # Parser/command tests below exercise the actual guard separately.
        self.inventory = patch.object(M, "require_no_other_work", return_value=None)
        self.inventory.start()
        self.addCleanup(self.inventory.stop)

    def tearDown(self):
        self.temp.cleanup()

    def parse(self, text, name="check"):
        log = self.root / "parse.log"
        log.write_text(text)
        return M.validate_log(log, UNIT, name)

    def job(self, names):
        job = Path(self.config["job"])
        job.mkdir(mode=0o700)
        (job / "scratch").mkdir(mode=0o700)
        for name in names:
            (job / name).write_bytes(name.encode())
        return job

    def test_external_inputs_are_strict_and_root_is_canonical_little_endian(self):
        self.assertEqual(M.external_hex("AB"*32), "ab"*32)
        self.assertEqual(M.external_hex("0100000000000000" + "00"*24, root=True)[:16], "0100000000000000")
        for bad in ("00"*31, "00"*33, "g0"*32, "é"*32, "0"*63 + "\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                M.external_hex(bad)
        for slot in range(4):
            value = bytearray(32)
            value[slot*8:slot*8+8] = M.MODULUS.to_bytes(8, "little")
            with self.assertRaises(ValueError):
                M.external_hex(value.hex(), root=True)

    def test_proving_commands_all_have_external_inputs(self):
        for name, action in M.stages(self.config):
            if name != "export":
                command = M.invocation(self.config, name, action)
                self.assertEqual(command[-3:], self.config["external"])
        setup = dict(self.config, mode="prepare", external=[])
        self.assertEqual(M.invocation(setup, "key-2", ["register", "2"]),
                         [setup["runner"], "register", setup["job"], "2"])
        self.assertNotIn("finish-registry", str(M.stages(setup)))

    def test_stage_limits_controller_binding_and_cpu_isolation(self):
        for name, action in M.stages(self.config):
            if name == "export":
                continue
            command = M.stage_command(self.config, CONTROLLER, UNIT, name, action)
            for expected in ("--property=MemoryMax=44G", "--property=MemorySwapMax=0",
                             "--property=RuntimeMaxSec=7200", "--expand-environment=no",
                             f"--property=BindsTo={CONTROLLER}", "--setenv=RAYON_NUM_THREADS=8",
                             "--setenv=LATTICA_SPILL_MAX_BYTES=128849018880",
                             "--setenv=LATTICA_V2_GPU_DEVICE=4294967295",
                             f"--slice={M.RESOURCE_SLICE}"):
                self.assertIn(expected, command)
            self.assertIn(f"--setenv=LATTICA_V2_GPU_HASH={1 if name == 'audit' else 0}", command)
        with self.assertRaises(ValueError):
            M.stage_command(dict(self.config, accounting="/tmp/%n bad.py"), CONTROLLER, UNIT, "check", ["check-registered"])

    def test_valid_accounting_and_both_proof_sequences(self):
        for name, nodes in (("leaves", M.LEAVES), ("merges", M.MERGES)):
            result = self.parse(ACCOUNT + node_lines(nodes) + DURATION, name)
            self.assertEqual(tuple(n["artifact"] for n in result["nodes"]), nodes)
            self.assertEqual(result["duration"]["elapsed_ms"], 123)

    def test_accounting_is_required_unique_and_bound_to_unit(self):
        for value in (DURATION, ACCOUNT + ACCOUNT + DURATION,
                      ACCOUNT.replace(UNIT, "lattica-v2-other.service") + DURATION,
                      ACCOUNT.replace("memory_peak=17", "memory_peak=17 memory_peak=17") + DURATION,
                      ACCOUNT.replace("memory_peak=17", "memory_peak=-1") + DURATION,
                      ACCOUNT.replace("exec_stop_post_snapshot", "unknown") + DURATION):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.parse(value)

    def test_resource_failures_do_not_pass(self):
        for value in (ACCOUNT.replace("memory_swap_peak=0", "memory_swap_peak=1") + DURATION,
                      ACCOUNT.replace("memory_swap_max=0", "memory_swap_max=1") + DURATION,
                      ACCOUNT.replace(f"memory_max={44*M.GIB}", f"memory_max={45*M.GIB}") + DURATION,
                      ACCOUNT.replace("memory_peak=17", f"memory_peak={44*M.GIB+1}") + DURATION,
                      ACCOUNT + DURATION.replace("spill_peak_bytes=0", f"spill_peak_bytes={120*M.GIB+1}")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.parse(value)

    def test_missing_duplicate_or_misclassified_duration_rejected(self):
        for value in (ACCOUNT, ACCOUNT + DURATION*2,
                      ACCOUNT + DURATION.replace("cpu_only=true", "cpu_only=false"),
                      ACCOUNT + DURATION.replace("production_ready=false", "production_ready=true")):
            with self.assertRaises(ValueError):
                self.parse(value)

    def test_proof_nodes_must_be_new_ordered_and_complete(self):
        valid = ACCOUNT + node_lines(M.LEAVES) + DURATION
        for value in (valid.replace("resumed=false", "resumed=true", 1),
                      ACCOUNT + node_lines(M.LEAVES[:-1]) + DURATION,
                      ACCOUNT + node_lines(tuple(reversed(M.LEAVES))) + DURATION,
                      ACCOUNT + node_lines(M.LEAVES + M.LEAVES[:1]) + DURATION):
            with self.assertRaises(ValueError):
                self.parse(value, "leaves")

    def test_exact_root_and_audit_scopes(self):
        self.parse(ACCOUNT + ROOT + DURATION, "root")
        self.parse(ACCOUNT + ROOT + DURATION, "prune")
        self.parse(ACCOUNT + AUDIT, "audit")
        for name, value in (("root", ACCOUNT + DURATION), ("root", ACCOUNT + ROOT*2 + DURATION),
                            ("audit", ACCOUNT + AUDIT*2), ("audit", ACCOUNT + AUDIT.replace("count8", "count4")),
                            ("audit", ACCOUNT + AUDIT.replace("=38", "=37")),
                            ("audit", ACCOUNT + AUDIT.replace("proof_bytes=199", f"proof_bytes={M.MAX_ARTIFACT+1}")),
                            ("audit", ACCOUNT + AUDIT.replace("inner_proofs_loaded=0", "inner_proofs_loaded=1"))):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                self.parse(value, name)

    def test_failed_output_never_becomes_success(self):
        for failure in ("FAILED: broken\n", "grouped_artifact_audit=FAIL broken\n"):
            with self.assertRaises(ValueError):
                self.parse(ACCOUNT + DURATION + failure)

    def test_durable_attempt_prefix_cannot_forget_an_interruption(self):
        plan = M.stages(self.config)
        state = {"attempts": [{"name": "check", "status": "complete"},
                              {"name": "leaves", "status": "attempted"}]}
        original = copy.deepcopy(state)
        for _ in range(2):
            with self.assertRaises(ValueError):
                M.validate_prefix(state, plan)
            self.assertEqual(state, original)
        state["attempts"][1]["status"] = "complete"
        self.assertEqual(M.validate_prefix(state, plan), 2)
        state["attempts"][0]["name"] = "leaves"
        with self.assertRaises(ValueError):
            M.validate_prefix(state, plan)

    def test_snapshot_rejects_unknown_symlink_and_nonempty_scratch(self):
        job = self.job(M.WALLETS)
        self.assertEqual(set(M.snapshot(job)), set(M.WALLETS))
        extra = job / "profile.hex"
        extra.write_text("untrusted")
        with self.assertRaises(ValueError):
            M.snapshot(job)
        extra.unlink()
        wallet = job / "wallet.0"
        wallet.unlink()
        wallet.symlink_to(job / "wallet.1")
        with self.assertRaises(ValueError):
            M.snapshot(job)
        wallet.unlink()
        wallet.write_text("restored synthetic")
        (job / "scratch" / "leftover").write_text("leftover")
        with self.assertRaises(ValueError):
            M.snapshot(job)

    def test_regular_reader_rejects_fifo_and_oversize(self):
        path = self.root / "input"
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            M.regular_bytes(path)
        path.unlink()
        path.write_bytes(b"12345")
        with self.assertRaises(ValueError):
            M.regular_bytes(path, 4)

    def test_export_is_exact_and_never_overwrites(self):
        job = self.job(M.ROOT_FILES)
        output = self.root / "root-only"
        hashes = M.export_bundle(job, output)
        self.assertEqual(set(hashes), set(M.ROOT_FILES))
        self.assertEqual(set(p.name for p in output.iterdir()), set(M.ROOT_FILES))
        for name in M.ROOT_FILES:
            self.assertEqual(M.digest(output / name), M.digest(job / name))
        with self.assertRaises(FileExistsError):
            M.export_bundle(job, output)

    def test_transitions_preserve_existing_artifacts_and_prune_only_inners(self):
        before = {name: name for name in M.WALLETS + M.ROOT_FILES[1:]}
        after = dict(before, **{name: name for name in M.LEAVES})
        M.validate_transition("leaves", before, after)
        modified = dict(after, **{"wallet.0": "changed"})
        with self.assertRaises(ValueError):
            M.validate_transition("leaves", before, modified)
        complete = dict(after, **{name: name for name in M.MERGES})
        pruned = {name: name for name in M.ROOT_FILES}
        M.validate_transition("prune", complete, pruned)
        with self.assertRaises(ValueError):
            M.validate_transition("prune", complete, dict(pruned, **{"wallet.0": "wallet.0"}))

    def test_attempt_is_saved_before_process_and_failure_blocks_resume(self):
        job = self.job(M.WALLETS + M.ROOT_FILES[1:])
        evidence = Path(self.config["evidence"])
        evidence.mkdir(mode=0o700)
        state = {"attempts": [], "artifacts": M.snapshot(job)}
        path = evidence / "manifest.json"
        def failed(command, log):
            saved = json.loads(path.read_text())
            self.assertEqual(saved["attempts"][0]["status"], "attempted")
            return 1
        with patch.object(M, "capture_stage", side_effect=failed), \
             patch.object(M.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
             self.assertRaises(ValueError):
            M.run_stage(self.config, CONTROLLER, "check", ["check-registered"], evidence, state, path)
        saved = json.loads(path.read_text())
        self.assertEqual(saved["attempts"][0]["status"], "failed_or_interrupted")
        with self.assertRaises(ValueError):
            M.validate_prefix(saved, M.stages(self.config))

    def test_atomic_state_refuses_orphaned_temporary_file(self):
        path = self.root / "state.json"
        M.save(path, {"version": 1})
        path.with_name("state.json.new").write_text("orphaned")
        with self.assertRaises(FileExistsError):
            M.save(path, {"version": 2})
        self.assertEqual(json.loads(path.read_text()), {"version": 1})

    def synthetic_process(self, command, **kwargs):
        """Emulates file/telemetry transitions only; never verifies any proof."""
        self.assertEqual(command[0], "systemd-run")
        actual = command[command.index("--") + 1:]
        action, job = actual[1], Path(actual[2])
        unit = next(word.split("=", 1)[1] for word in command if word.startswith("--unit="))
        text = ACCOUNT.replace(UNIT, unit)
        if action == "prepare":
            job.mkdir(mode=0o700)
            (job / "scratch").mkdir(mode=0o700)
            for name in M.WALLETS:
                (job / name).write_bytes(b"SYNTHETIC WALLET")
        elif action == "common-height":
            (job / "height").write_bytes((524288).to_bytes(4, "little"))
        elif action == "register":
            (job / f"key.{actual[3]}").write_bytes(b"SYNTHETIC UNAPPROVED KEY")
        elif action in ("wrap-all", "merge-all"):
            names = M.LEAVES if action == "wrap-all" else M.MERGES
            for name in names:
                (job / name).write_bytes(b"SYNTHETIC NOT A PROOF")
            text += node_lines(names)
        elif action == "remove-inners":
            for name in M.WALLETS + M.LEAVES + M.MERGES[:-1]:
                (job / name).unlink()
            text += ROOT
        elif action == "verify-root":
            text += ROOT
        elif action == "root-eight":
            self.assertEqual(set(p.name for p in job.iterdir()), set(M.ROOT_FILES))
            text += AUDIT.replace("proof_bytes=199", f"proof_bytes={(job / 'node.3.0').stat().st_size}")
        elif action not in ("describe-registry", "check-registered"):
            self.fail(f"unexpected synthetic action {action}")
        if action != "root-eight":
            text += DURATION
        kwargs["stdout"].write(text)
        return subprocess.CompletedProcess(command, 0)

    def synthetic_capture(self, command, log):
        with log.open("x") as output:
            return self.synthetic_process(command, stdout=output).returncode

    def test_synthetic_prepare_prove_prune_audit_and_completed_resume(self):
        setup = {key: value for key, value in dict(self.config, mode="prepare", external=[]).items() if key != "auditor"}
        setup["evidence"] = str(self.root / "setup-evidence")
        with patch.object(M, "require_controller", return_value=CONTROLLER), \
             patch.object(M, "shared_lease_path", return_value=self.root / "lease"), \
             patch.object(M, "capture_stage", side_effect=self.synthetic_capture) as process, \
             redirect_stdout(io.StringIO()):
            M.run(setup, False)
            prepared = json.loads((Path(setup["evidence"]) / "manifest.json").read_text())
            self.assertEqual(prepared["status"], "PREPARED_UNAPPROVED")
            self.assertEqual(prepared["config"]["external"], [])
            M.run(self.config, False)
            state = json.loads((Path(self.config["evidence"]) / "manifest.json").read_text())
            self.assertEqual(state["status"], "PROOF_VERIFIED_RESEARCH_ONLY")
            self.assertFalse(state["production_ready"])
            self.assertFalse(state["level6_qualified"])
            self.assertEqual(state["recursive_command_ms"], 246)
            self.assertEqual(len(state["attempts"]), 7)
            self.assertEqual(set(state["artifacts"]), set(M.ROOT_FILES))
            completed_calls = process.call_count
            M.run(self.config, True)
            self.assertEqual(process.call_count, completed_calls)
            (Path(self.config["evidence"]) / "root-only" / "node.3.0").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                M.run(self.config, True)
            self.assertEqual(process.call_count, completed_calls)

    def test_synthetic_resume_rejects_changed_pin_before_any_command(self):
        setup = {key: value for key, value in dict(self.config, mode="prepare", external=[]).items() if key != "auditor"}
        with patch.object(M, "require_controller", return_value=CONTROLLER), \
             patch.object(M, "shared_lease_path", return_value=self.root / "lease"), \
             patch.object(M, "capture_stage", side_effect=self.synthetic_capture) as process, \
             redirect_stdout(io.StringIO()):
            M.run(setup, False)
            count = process.call_count
            Path(setup["runner"]).write_bytes(b"CHANGED SYNTHETIC EXECUTABLE")
            with self.assertRaises(ValueError):
                M.run(setup, True)
            self.assertEqual(process.call_count, count)

    def test_two_full_resumes_never_retry_a_failed_proving_attempt(self):
        self.job(M.WALLETS + M.ROOT_FILES[1:])
        def process(command, log):
            actual = command[command.index("--") + 1:]
            if actual[1] == "wrap-all":
                return 1
            return self.synthetic_capture(command, log)
        with patch.object(M, "require_controller", return_value=CONTROLLER), \
             patch.object(M, "shared_lease_path", return_value=self.root / "lease"), \
             patch.object(M, "capture_stage", side_effect=process) as calls, \
             patch.object(M.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
             redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                M.run(self.config, False)
            manifest = Path(self.config["evidence"]) / "manifest.json"
            preserved = manifest.read_bytes()
            count = calls.call_count
            for _ in range(2):
                with self.assertRaises(ValueError):
                    M.run(self.config, True)
                self.assertEqual(manifest.read_bytes(), preserved)
                self.assertEqual(calls.call_count, count)
            state = json.loads(preserved)
            self.assertEqual([r["name"] for r in state["attempts"]], ["check", "leaves"])
            self.assertEqual(state["attempts"][1]["status"], "failed_or_interrupted")

    def test_resume_reuses_a_completed_prefix_without_reproving(self):
        self.job(M.WALLETS + M.ROOT_FILES[1:])
        original = M.run_stage
        def between_stages(config, controller, name, *args):
            if name == "merges":
                raise InterruptedError("synthetic interruption before attempt")
            return original(config, controller, name, *args)
        with patch.object(M, "require_controller", return_value=CONTROLLER), \
             patch.object(M, "shared_lease_path", return_value=self.root / "lease"), \
             patch.object(M, "capture_stage", side_effect=self.synthetic_capture) as calls, \
             redirect_stdout(io.StringIO()):
            with patch.object(M, "run_stage", side_effect=between_stages), self.assertRaises(InterruptedError):
                M.run(self.config, False)
            evidence = Path(self.config["evidence"])
            prior = json.loads((evidence / "manifest.json").read_text())["attempts"]
            self.assertEqual([r["name"] for r in prior], ["check", "leaves"])
            M.run(self.config, True)
            after = json.loads((evidence / "manifest.json").read_text())
            self.assertEqual(after["attempts"][:2], prior)
            actions = [call.args[0][call.args[0].index("--") + 2] for call in calls.call_args_list]
            self.assertEqual(actions.count("wrap-all"), 1)
            self.assertEqual(actions.count("merge-all"), 1)
            self.assertEqual(after["status"], "PROOF_VERIFIED_RESEARCH_ONLY")

    def test_small_local_stdout_capture_preserves_output(self):
        # A tiny Python print process only; not a service, prover or GPU process.
        log = self.root / "stdout.log"
        code = M.capture_stage([sys.executable, "-B", "-c", "print('synthetic stdout')"], log, maximum=128)
        self.assertEqual(code, 0)
        self.assertEqual(log.read_bytes(), b"synthetic stdout\n")

    def test_stdout_cap_rejects_without_exceeding_file_budget(self):
        log = self.root / "stdout-too-large.log"
        with self.assertRaisesRegex(ValueError, "log limit"):
            M.capture_stage([sys.executable, "-B", "-c", "print('x' * 4096)"], log, maximum=128)
        self.assertLessEqual(log.stat().st_size, 128)

    def test_aggregate_and_controller_memory_limits_are_both_required(self):
        valid = (str(3*M.GIB), "0", M.RESOURCE_SLICE, str(48*M.GIB), "0")
        M.validate_memory_limits(*valid)
        for index, replacement in ((0, "max"), (0, "0"), (0, str(3*M.GIB+1)),
                                   (1, "1"), (2, "app.slice"), (3, "max"),
                                   (3, str(49*M.GIB)), (4, "1")):
            values = list(valid)
            values[index] = replacement
            with self.subTest(index=index, value=replacement), self.assertRaises(ValueError):
                M.validate_memory_limits(*values)

    def test_controller_runtime_requires_a_positive_bounded_deadline(self):
        group = f"/user.slice/{M.RESOURCE_SLICE}/{CONTROLLER}"
        for span, expected in (("6h", 21_600_000_000), ("1h 30min", 5_400_000_000),
                               ("1s 2ms 3us", 1_002_003), ("1us", 1)):
            with self.subTest(span=span):
                properties = f"RuntimeMaxUSec={span}\nControlGroup={group}\n"
                self.assertEqual(M.validate_controller_properties(properties, group), expected)
        for span in ("", "infinity", "0", "0s", "6h 1us", "7h", "1d", "-1s",
                     "1.5h", "1h 1h", "1s 1min", "2h garbage", "600000000000us"):
            with self.subTest(span=span), self.assertRaises(ValueError):
                M.validate_controller_properties(f"RuntimeMaxUSec={span}\nControlGroup={group}\n", group)

    def test_controller_properties_cannot_omit_duplicate_or_misbind_a_limit(self):
        group = f"/user.slice/{M.RESOURCE_SLICE}/{CONTROLLER}"
        valid = f"RuntimeMaxUSec=6h\nControlGroup={group}\n"
        for properties in ("", "RuntimeMaxUSec=6h\n", f"ControlGroup={group}\n",
                           valid + "RuntimeMaxUSec=6h\n", valid + "unexpected=1\n",
                           valid.replace(group, "/different.service"), valid + "malformed\n"):
            with self.subTest(properties=properties), self.assertRaises(ValueError):
                M.validate_controller_properties(properties, group)

    def test_controller_preflight_reads_runtime_limit_before_allowing_work(self):
        # Real tiny fixture files, but no cgroups or services are created.
        relative = f"/user.slice/{M.RESOURCE_SLICE}/{CONTROLLER}"
        proc = self.root / "proc-cgroup"
        proc.write_text(f"0::{relative}\n")
        tree = self.root / "fake-cgroup-root"
        group = tree / relative.lstrip("/")
        group.mkdir(parents=True)
        for directory, maximum in ((group, 3*M.GIB), (group.parent, 48*M.GIB)):
            (directory / "memory.max").write_text(str(maximum))
            (directory / "memory.swap.max").write_text("0")
        def path(value):
            return {"/proc/self/cgroup": proc, "/sys/fs/cgroup": tree}.get(value, Path(value))
        properties = f"RuntimeMaxUSec=6h\nControlGroup={relative}\n"
        with patch.object(M, "Path", side_effect=path), \
             patch.object(M.subprocess, "check_output", return_value=properties) as show, \
             patch.object(M, "require_no_other_work") as admission:
            self.assertEqual(M.require_controller(), CONTROLLER)
            self.assertIn("--property=ControlGroup,RuntimeMaxUSec", show.call_args.args[0])
            admission.assert_called_once_with(CONTROLLER)
            admission.reset_mock()
            show.return_value = properties.replace("6h", "infinity")
            with self.assertRaises(ValueError):
                M.require_controller()
            admission.assert_not_called()

    def test_active_inventory_rejects_stopping_workers_and_other_controllers(self):
        own = f"{CONTROLLER} loaded active running controller\n"
        M.validate_active_units(CONTROLLER, own)
        for state in ("active", "activating", "deactivating", "reloading"):
            for name in ("lattica-v2-old-worker.service", "lattica-v2-retention-controller.service"):
                with self.subTest(state=state, name=name), self.assertRaisesRegex(ValueError, "refuse overlap"):
                    M.validate_active_units(CONTROLLER, own + f"{name} loaded {state} stop-sigterm description\n")

    def test_active_inventory_cannot_fail_open_on_missing_or_ambiguous_output(self):
        own = f"{CONTROLLER} loaded active running controller\n"
        for value in ("", "unexpected header\n", own + own,
                      own.replace("loaded", "not-found"), own.replace("active", "failed"),
                      own.replace("active", "deactivating"), "other.service loaded active running description\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                M.validate_active_units(CONTROLLER, value)

    def test_overlap_preflight_prevents_artifact_preparation_or_stage_launch(self):
        setup = {key: value for key, value in dict(self.config, mode="prepare", external=[]).items() if key != "auditor"}
        with patch.object(M, "require_controller", return_value=CONTROLLER), \
             patch.object(M, "shared_lease_path", return_value=self.root / "lease"), \
             patch.object(M, "require_no_other_work", side_effect=ValueError("other live worker")), \
             patch.object(M, "capture_stage") as capture, self.assertRaises(ValueError):
            M.run(setup, False)
        capture.assert_not_called()
        self.assertFalse(Path(setup["job"]).exists())
        self.assertFalse((Path(setup["evidence"]) / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
