#!/usr/bin/env python3
"""Lifecycle and qualification contracts. Synthetic records never enter the report."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from benchmark_report.campaign import analyze, distribution
from benchmark_report.model import digest, json_bytes, read
from benchmark_report.report import check, ingest, render
from block_v2_throughput import (DEFAULT_CONTRACT, GATES, TYPES, COUNTS, arrival_schedule,
                                evaluate, load_contract, resource_snapshot)

SCRIPTS = Path(__file__).resolve().parent
SECOND = 1_000_000_000
ZERO = "0" * 64


def hexid(n):
    return f"{n:064x}"


def campaign():
    return {"schema_version": 1, "record_type": "transaction_campaign", "campaign_id": "test-only",
            "label": "Synthetic accounting test", "track": "apple-silicon",
            "resource_profile_id": "test-unified-memory", "measurement_scope": "durable_test_chain",
            "initial_tip": ZERO, "sources": [{"path": "public-test-log.json", "sha256": hexid(9)}],
            "window": {"clock": "coordinator_monotonic_ns", "started_ns": "0",
                       "finished_ns": str(60 * SECOND)}, "events": []}


def event(c, seconds, kind, **fields):
    e = dict(event_id=f"e-{len(c['events'])}", at_ns=str(int(seconds * SECOND)), type=kind, **fields)
    c["events"].append(e)
    return e


def application(c, n=1, at=30, kinds=("joinsplit",), parent=ZERO):
    ids = [hexid(n * 100 + i) for i in range(len(kinds))]
    for tid, kind in zip(ids, kinds):
        event(c, at-25, "submitted", transaction_id=tid, transaction_kind=kind)
    for tid in ids:
        event(c, at-24, "wallet_proof_ready", transaction_id=tid)
    for tid in ids:
        event(c, at-23, "admitted", transaction_id=tid)
    event(c, at-20, "sealed", block_id=hexid(n), transaction_ids=ids)
    event(c, at-10, "root_verified", block_id=hexid(n), cpu_audited=True,
          expected_statement_verified=True, level=6, proof_bytes=100,
          proof_sha256=hexid(3), profile_sha256=hexid(4))
    event(c, at, "block_applied", block_id=hexid(n), durable=True, host_validated=True,
          parent_block_id=parent, state_commit_sha256=hexid(5))
    return ids


def close(c):
    event(c, int(c["window"]["finished_ns"]) / SECOND, "window_closed")


class Accounting(unittest.TestCase):
    def test_issuance_and_exact_closed_window(self):
        c = campaign()
        application(c, kinds=tuple(TYPES))
        close(c)
        m = analyze(c)
        self.assertEqual(m["user_transactions_per_minute"], 3)
        self.assertEqual(m["issuance_transactions"], 1)
        self.assertEqual(m["measured_seconds"], 60)
        self.assertEqual(m["latencies"]["accepted_latency"]["median_seconds"], 25)
        self.assertEqual(m["latencies"]["wallet_latency"]["median_seconds"], 1)
        self.assertEqual(m["latencies"]["queue_latency"]["median_seconds"], 3)
        self.assertEqual(m["longest_user_application_gap_seconds"], 30)
        self.assertEqual(m["final_pending_user_transactions"], 0)
        self.assertFalse(m["sustained_service_qualified"])

    def test_outage_does_not_shrink_denominator(self):
        c = campaign()
        event(c, 1, "failed", reason="worker stopped")
        event(c, 2, "recovered", reason="worker returned")
        application(c)
        close(c)
        self.assertEqual(analyze(c)["user_transactions_per_minute"], 1)
        self.assertEqual(analyze(c)["failures"], 1)

    def test_reorg_removes_useful_rate_and_reapplication_is_unique(self):
        c = campaign()
        application(c)
        event(c, 40, "block_reverted", block_id=hexid(1), durable=True, state_commit_sha256=hexid(6))
        close(c)
        m = analyze(c)
        self.assertEqual(m["unique_application_transactions_per_minute"], 1)
        self.assertEqual(m["user_transactions_per_minute"], 0)
        self.assertEqual(m["final_pending_user_transactions"], 1)
        self.assertEqual(m["user_reversal_events"], 1)
        c["events"].pop()
        event(c, 50, "block_applied", block_id=hexid(1), durable=True, host_validated=True,
              parent_block_id=ZERO, state_commit_sha256=hexid(7))
        close(c)
        self.assertEqual(analyze(c)["user_transactions_per_minute"], 1)
        self.assertEqual(analyze(c)["reapplications"], 1)

    def test_replay_and_duplicate_submission_do_not_inflate_rate(self):
        c = campaign()
        ids = application(c)
        c["events"].append(copy.deepcopy(c["events"][0]))
        event(c, 40, "submitted", transaction_id=ids[0], transaction_kind="joinsplit")
        close(c)
        self.assertEqual(analyze(c)["user_transactions_per_minute"], 1)
        self.assertEqual(analyze(c)["duplicate_submissions"], 1)
        c["events"][-2]["event_id"] = c["events"][0]["event_id"]
        with self.assertRaisesRegex(ValueError, "conflicting replay"):
            analyze(c)

    def test_block_identity_cannot_change_parent_after_reorg(self):
        c = campaign()
        application(c)
        event(c, 31, "block_reverted", block_id=hexid(1), durable=True, state_commit_sha256=hexid(6))
        application(c, n=2, at=57)
        event(c, 58, "block_applied", block_id=hexid(1), durable=True, host_validated=True,
              parent_block_id=hexid(2), state_commit_sha256=hexid(7))
        close(c)
        with self.assertRaisesRegex(ValueError, "cannot change its parent"):
            analyze(c)

    def test_end_boundary_and_drain_excluded(self):
        for at in (60, 61):
            with self.subTest(at=at):
                c = campaign()
                application(c, at=at)
                c["events"].sort(key=lambda e: int(e["at_ns"]))
                close(c)
                c["events"].sort(key=lambda e: int(e["at_ns"]))
                m = analyze(c)
                self.assertEqual(m["user_transactions_per_minute"], 0)
                self.assertEqual(m["final_pending_user_transactions"], 1)
                self.assertEqual(m["longest_user_application_gap_seconds"], 60)

    def test_initial_backlog_and_old_applications(self):
        c = campaign()
        application(c)
        c["window"]["started_ns"] = str(10 * SECOND)
        close(c)
        self.assertEqual(analyze(c)["initial_pending_user_transactions"], 1)
        self.assertEqual(analyze(c)["user_transactions_per_minute"], 1.2)
        c["window"]["started_ns"] = str(40 * SECOND)
        self.assertEqual(analyze(c)["user_transactions_per_minute"], 0)
        self.assertEqual(analyze(c)["initial_pending_user_transactions"], 0)

    def test_incomplete_is_not_zero_or_success(self):
        c = campaign()
        application(c)
        self.assertIsNone(analyze(c)["user_transactions_per_minute"])
        c["window"]["finished_ns"] = None
        self.assertEqual(analyze(c)["status"], "incomplete")
        self.assertIsNone(analyze(c)["target_met_in_pilot"])

    def test_rejection_accounting(self):
        c = campaign()
        tid = hexid(33)
        event(c, 1, "submitted", transaction_id=tid, transaction_kind="joinsplit")
        event(c, 2, "rejected", transaction_id=tid, reason="deferred")
        event(c, 3, "rejected", transaction_id=tid, reason="duplicate")
        event(c, 4, "rejected", transaction_id=tid, reason="invalid")
        close(c)
        m = analyze(c)
        self.assertEqual((m["deferral_events"], m["duplicate_rejections"], m["invalid_transactions"]), (1, 1, 1))
        self.assertEqual(m["final_pending_user_transactions"], 0)

    def test_invalid_lifecycle_rejected(self):
        base = campaign()
        application(base)
        close(base)
        mutations = [
            (2, "at_ns", "1"), (2, "type", "root_verified"),
            (3, "transaction_ids", [hexid(100), hexid(100)]),
            (4, "cpu_audited", False), (4, "expected_statement_verified", False),
            (4, "level", 5), (4, "proof_bytes", 2097153), (4, "proof_bytes", True),
            (4, "profile_sha256", "bad"), (5, "parent_block_id", hexid(8)),
            (5, "durable", False), (5, "host_validated", False), (6, "at_ns", "99"),
        ]
        for i, key, value in mutations:
            with self.subTest(i=i, key=key):
                c = copy.deepcopy(base)
                c["events"][i][key] = value
                with self.assertRaises((ValueError, KeyError)):
                    analyze(c)

    def test_secret_and_unsafe_ids_rejected(self):
        for change in ({"campaign_id": "../escape"}, {"campaign_id": None},
                       {"extra": [{"private_key": "test"}]}, {"measurement_scope": "recursive_aggregation"}):
            with self.subTest(change=change):
                c = campaign()
                c.update(change)
                with self.assertRaises(ValueError):
                    analyze(c)

    def test_large_clock_is_exact(self):
        c = campaign()
        application(c)
        close(c)
        baseline = analyze(c)
        offset = 10**19
        for key in ("started_ns", "finished_ns"):
            c["window"][key] = str(int(c["window"][key]) + offset)
        for e in c["events"]:
            e["at_ns"] = str(int(e["at_ns"]) + offset)
        m = analyze(c)
        self.assertEqual(m["user_transactions_per_minute"], baseline["user_transactions_per_minute"])
        self.assertEqual(m["latencies"], baseline["latencies"])
        self.assertEqual(m["backlog_samples"][0]["at_ns"], str(offset + 5*SECOND))

    def test_percentiles_small_samples(self):
        self.assertIsNone(distribution([])["p95_seconds"])
        self.assertEqual(distribution([1, 2])["median_seconds"], 1.5)
        self.assertEqual(distribution(list(range(1, 21)))["p95_seconds"], 19)


def resource_plan():
    budget = {"gpu": {"uuid": "gpu-a", "bootstrap": False, "managed_bytes": 12, "context_bytes": 1},
              "host": {"worker_bytes": 20, "spill_bytes": 10}, "cpu": {"rayon_threads": 2}}
    second = copy.deepcopy(budget)
    second["gpu"]["uuid"] = "gpu-b"
    return {"plan_version": 1, "captured_ns": "1", "host": {}, "binary_sha256": hexid(7),
            "profile_sha256": hexid(8), "budgets": {"gpu-a": budget, "gpu-b": second}}


class Qualification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.contract = load_contract()
        self.resources = resource_snapshot(resource_plan(), self.contract)
        source = self.root / "test-source.json"
        source.write_text("{}")
        self.evidence = {"contract_sha256": digest(DEFAULT_CONTRACT)}
        for gate in GATES:
            self.evidence[gate] = {"status": "passed", "contract_sha256": digest(DEFAULT_CONTRACT),
                                  "sources": [{"path": source.name, "sha256": digest(source)}], "measurement": {}}
        measurements = {
            "typed_leaf_verification": dict(transaction_types=TYPES, cpu_audited=True, context_and_policy_mutation_tests=True),
            "mixed_recursive_registry_and_cpu_replay": dict(transaction_types=TYPES, counts=COUNTS, depth=6,
                                                            cpu_root_replay_without_inner_artifacts=True),
            "durable_candidate_host_application": dict(real_candidate_root_verified=True, durable_restart_replay=True),
            "per_geometry_device_qualification": dict(all_required_geometries=True, individually_cpu_audited=True,
                                                       gpu_uuids=["gpu-a", "gpu-b"], binary_sha256=hexid(7), profile_sha256=hexid(8)),
            "restart_reorg_and_resource_failure_recovery": dict(passed_cases=["worker_termination", "coordinator_restart",
                                                                            "reorg", "resource_exhaustion", "stale_results"]),
        }
        for gate, scope in (("full_count_cold_64", "cold_64_wallet_ready_to_audited_root"),
                            ("complete_post_seal_finalization", "seal_to_host_ready_root_and_body")):
            measurements[gate] = dict(elapsed_seconds=100, root_bytes=100, cpu_audited=True,
                                      binary_sha256=hexid(7), profile_sha256=hexid(8), gpu_uuids=["gpu-a", "gpu-b"],
                                      resource_profile_id=self.contract["resource_policy"]["profile_id"],
                                      scope=scope, transaction_count=64)
        for gate, measurement in measurements.items():
            self.evidence[gate]["measurement"] = measurement

    def evaluate(self):
        return evaluate(self.contract, self.evidence, self.root, resources=self.resources)

    def test_schedule_exact_burst_and_participants(self):
        s = arrival_schedule(self.contract)
        self.assertEqual(len(s), 504)
        self.assertEqual([s[i]["offset_ns"] for i in (0, 191, 192, 263, 264, 503)],
                         [str(n*SECOND) for n in (0, 2865, 2880, 3590, 3600, 7185)])
        self.assertEqual([sum(e["wallet_participant"] == n for e in s) for n in range(4)], [126]*4)

    def test_all_gates_required(self):
        self.assertEqual(self.evaluate()["status"], "ready_for_research_pilot")
        for gate in GATES:
            with self.subTest(gate=gate):
                record = self.evidence.pop(gate)
                self.assertEqual(self.evaluate()["status"], "blocked")
                self.evidence[gate] = record

    def test_contract_cannot_match_an_arbitrary_hash(self):
        self.evidence["contract_sha256"] = ZERO
        for gate in GATES:
            self.evidence[gate]["contract_sha256"] = ZERO
        with self.assertRaisesRegex(ValueError, "actual qualification contract"):
            self.evaluate()

    def test_missing_stale_and_outside_sources_block(self):
        for path in ("missing.json", "../outside.json"):
            self.evidence[GATES[0]]["sources"][0]["path"] = path
            self.assertEqual(self.evaluate()["status"], "blocked")
        self.evidence[GATES[0]]["sources"] = []
        self.assertEqual(self.evaluate()["status"], "blocked")

    def test_partial_boundaries_and_failed_coverage_block(self):
        changes = [
            ("typed_leaf_verification", "transaction_types", ["joinsplit"]),
            ("mixed_recursive_registry_and_cpu_replay", "counts", [8]),
            ("mixed_recursive_registry_and_cpu_replay", "depth", 3),
            ("full_count_cold_64", "transaction_count", 8),
            ("full_count_cold_64", "elapsed_seconds", 601),
            ("full_count_cold_64", "binary_sha256", ZERO),
            ("complete_post_seal_finalization", "elapsed_seconds", 181),
            ("complete_post_seal_finalization", "elapsed_seconds", float("nan")),
            ("complete_post_seal_finalization", "scope", "last_merge_only"),
            ("durable_candidate_host_application", "durable_restart_replay", False),
            ("per_geometry_device_qualification", "gpu_uuids", ["gpu-a", "other-gpu"]),
            ("per_geometry_device_qualification", "binary_sha256", ZERO),
            ("restart_reorg_and_resource_failure_recovery", "passed_cases", ["reorg"]),
        ]
        for gate, key, value in changes:
            with self.subTest(gate=gate, key=key):
                previous = self.evidence[gate]["measurement"][key]
                self.evidence[gate]["measurement"][key] = value
                self.assertEqual(self.evaluate()["status"], "blocked")
                self.evidence[gate]["measurement"][key] = previous

    def test_resource_fallback_blocks_without_replacing_adaptive_budgets(self):
        p = resource_plan()
        p["budgets"].pop("gpu-b")
        r = resource_snapshot(p, self.contract)
        self.assertEqual(r["status"], "blocked")
        self.assertEqual(r["detected"], p)
        self.assertEqual(evaluate(self.contract, self.evidence, self.root, resources=r)["status"], "blocked")
        p["budgets"]["gpu-a"]["gpu"]["bootstrap"] = True
        self.assertIn("calibration", resource_snapshot(p, self.contract)["reasons"][-1])

    def test_blocked_cli_retains_planned_schedule_and_never_launches(self):
        evidence = self.root / "blocked.json"
        evidence.write_bytes(json_bytes({"contract_sha256": digest(DEFAULT_CONTRACT)}))
        plan = self.root / "resources.json"
        plan.write_bytes(json_bytes(resource_plan()))
        output = self.root / "readiness.json"
        result = subprocess.run([sys.executable, str(SCRIPTS / "block-v2-throughput-pilot.py"), "prepare",
                                 "--evidence", str(evidence), "--resource-plan", str(plan),
                                 "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        data = read(output)
        self.assertEqual(data["planned_user_requests"], 504)
        self.assertFalse(data["pilot_started"])
        self.assertFalse(data["schedule_is_measured_data"])
        report = self.root / "report"
        ingest(report, output)
        self.assertEqual(check(report)["status"], "valid")
        render(report)
        self.assertIn('id="qualification-data"', (report / "index.html").read_text())


class PortableImport(unittest.TestCase):
    def test_campaign_is_immutable_embedded_and_recomputed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            c = campaign()
            application(c)
            close(c)
            source = root / "input.json"
            source.write_bytes(json_bytes(c))
            output = root / "report"
            ingest(output, source)
            self.assertEqual(check(output)["transaction_campaigns"], 1)
            first = (output / "catalog.json").read_bytes()
            ingest(output, source)
            self.assertEqual(first, (output / "catalog.json").read_bytes())
            render(output)
            self.assertIn('id="campaign-data-test-only"', (output / "index.html").read_text())
            c["label"] = "Changed"
            source.write_bytes(json_bytes(c))
            with self.assertRaisesRegex(ValueError, "collision"):
                ingest(output, source)
            catalog = read(output / "catalog.json")
            catalog["transaction_campaigns"][0]["metrics"]["user_transactions_per_minute"] = 999
            (output / "catalog.json").write_bytes(json_bytes(catalog))
            with self.assertRaisesRegex(ValueError, "stale campaign"):
                check(output)


if __name__ == "__main__":
    unittest.main()
