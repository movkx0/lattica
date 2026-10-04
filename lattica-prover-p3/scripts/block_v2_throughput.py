"""Qualification contract and admission for the two-hour research pilot."""
import copy
import math
from fractions import Fraction
from pathlib import Path

from benchmark_report.model import digest, read, reject_payloads

DEFAULT_CONTRACT = Path(__file__).with_name("block-v2-throughput-contract.json")
GATES = ["typed_leaf_verification", "mixed_recursive_registry_and_cpu_replay",
         "durable_candidate_host_application", "per_geometry_device_qualification",
         "full_count_cold_64", "complete_post_seal_finalization",
         "restart_reorg_and_resource_failure_recovery"]
TYPES = ["joinsplit", "htlc_redeem", "htlc_refund", "issuance"]
COUNTS = [1, 2, 3, 4, 8, 16, 32, 63, 64]


def load_contract(path=DEFAULT_CONTRACT):
    contract = read(path)
    if contract.get("schema_version") != 1 or contract.get("scope") != "durable_test_chain":
        raise ValueError("unsupported qualification contract")
    if contract["production_ready"] is not False or contract["pilot"]["sustained_service_qualification"] is not False:
        raise ValueError("pilot cannot authorize production or sustained-service qualification")
    if contract["limits"] != {"total_transactions_per_root": 64, "tree_depth": 6, "root_bytes": 2097152,
                               "cold_64_seconds": 600, "post_seal_seconds": 180, "cycle_seconds": 720}:
        raise ValueError("unexpected proof/latency gate change")
    if (contract["required_gates"] != GATES or contract["required_transaction_types"] != TYPES
            or contract["required_counts"] != COUNTS or contract["resource_policy"]["workers"] != 2):
        raise ValueError("qualification coverage differs from the approved pilot")
    pilot = contract["pilot"]
    if any(pilot[k] != v for k, v in {"duration_seconds": 7200, "wallet_participants": 4,
                                     "expected_user_requests": 504, "user_transactions_per_minute_target": 4,
                                     "issuance_per_cycle": 4}.items()):
        raise ValueError("pilot workload differs from the approved schedule")
    if pilot["arrival_segments"] != [
            {"start_minute": 0, "end_minute": 48, "user_requests_per_minute": 4},
            {"start_minute": 48, "end_minute": 60, "user_requests_per_minute": 6},
            {"start_minute": 60, "end_minute": 120, "user_requests_per_minute": 4}]:
        raise ValueError("burst placement differs from the approved schedule")
    arrival_schedule(contract)
    return contract


def arrival_schedule(contract):
    pilot = contract["pilot"]
    if type(pilot["wallet_participants"]) is not int or pilot["wallet_participants"] <= 0:
        raise ValueError("invalid wallet participant count")
    schedule = []
    previous_end = 0
    for segment in pilot["arrival_segments"]:
        start, end, rate = (segment[k] for k in ("start_minute", "end_minute", "user_requests_per_minute"))
        if any(type(v) is not int for v in (start, end, rate)) or start != previous_end or end <= start or rate <= 0:
            raise ValueError("arrival segments must be positive and cover one contiguous window")
        for minute in range(start, end):
            for i in range(rate):
                offset = Fraction(minute*60*1_000_000_000) + Fraction(i*60*1_000_000_000, rate)
                if offset.denominator != 1:
                    raise ValueError("arrival spacing must fit integer nanoseconds")
                n = len(schedule)
                schedule.append({"request_id": f"pilot-user-{n+1:04d}", "offset_ns": str(int(offset)),
                                 "wallet_participant": n % pilot["wallet_participants"]})
        previous_end = end
    if previous_end*60 != pilot["duration_seconds"] or len(schedule) != pilot["expected_user_requests"]:
        raise ValueError("arrival schedule differs from declared duration/count")
    return schedule


def resource_snapshot(plan, contract):
    """Retain the actual plan without replacing it with a fixed RAM/VRAM cap."""
    if not isinstance(plan.get("host"), dict) or not isinstance(plan.get("budgets"), dict):
        raise ValueError("expected output of the multi-GPU runner --plan")
    budgets = plan["budgets"]
    reasons = []
    if len(budgets) != contract["resource_policy"]["workers"]:
        reasons.append(f"Pilot requires {contract['resource_policy']['workers']} GPU workers; planner admitted {len(budgets)}")
    if plan.get("plan_version") != 1 or not plan.get("captured_ns"):
        reasons.append("Current versioned inventory capture is missing")
    for uuid, budget in budgets.items():
        if budget["gpu"]["uuid"] != uuid:
            raise ValueError("worker GPU identity differs")
        if budget["gpu"]["bootstrap"] is not False:
            reasons.append("Worker context calibration is not qualified: " + uuid)
        for n in (budget["gpu"]["managed_bytes"], budget["gpu"]["context_bytes"],
                  budget["host"]["worker_bytes"], budget["host"]["spill_bytes"], budget["cpu"]["rayon_threads"]):
            if type(n) is not int or n <= 0:
                raise ValueError("invalid adaptive resource allocation")
    return {"profile_id": contract["resource_policy"]["profile_id"],
            "status": "admitted" if not reasons else "blocked", "reasons": reasons,
            "selected_gpu_uuids": sorted(budgets),
            "scope": "current inventory and existing grouped-eight geometry only",
            "new_geometry_requires_requalification": True, "detected": copy.deepcopy(plan)}


def evaluate(contract, evidence, root, *, contract_path=DEFAULT_CONTRACT, resources=None):
    """Check explicit qualification records; never promote a partial milestone."""
    if load_contract(contract_path) != contract or evidence.get("contract_sha256") != digest(contract_path):
        raise ValueError("evidence is not bound to the actual qualification contract")
    reject_payloads(evidence)
    results = []
    root = Path(root).resolve()
    for name in contract["required_gates"]:
        record = evidence.get(name)
        reasons = []
        if not record:
            reasons.append("No qualifying evidence record")
        else:
            if record.get("status") != "passed":
                reasons.append(record.get("reason", "Gate is not passed"))
            if record.get("contract_sha256") != evidence.get("contract_sha256"):
                reasons.append("Qualification contract differs")
            sources = record.get("sources", [])
            if not sources:
                reasons.append("Source provenance is missing")
            for source in sources:
                p = (root / source["path"]).resolve()
                if not p.is_relative_to(root) or not p.is_file() or digest(p) != source.get("sha256"):
                    reasons.append("Source missing or changed: " + source["path"])
            measured = record.get("measurement", {})
            if name == "typed_leaf_verification":
                if not set(TYPES) <= set(measured.get("transaction_types", [])) or measured.get("cpu_audited") is not True:
                    reasons.append("Actual proofs and CPU verification of every required leaf type are missing")
                if measured.get("context_and_policy_mutation_tests") is not True:
                    reasons.append("Context/policy rejection evidence is missing")
            if name == "mixed_recursive_registry_and_cpu_replay":
                if not set(contract["required_transaction_types"]) <= set(measured.get("transaction_types", [])):
                    reasons.append("Required recursive transaction types are not covered")
                if not set(contract["required_counts"]) <= set(measured.get("counts", [])):
                    reasons.append("Required block counts are not covered")
                if measured.get("depth") != 6 or measured.get("cpu_root_replay_without_inner_artifacts") is not True:
                    reasons.append("Depth-six independent root replay is missing")
            if name in ("full_count_cold_64", "complete_post_seal_finalization"):
                seconds = measured.get("elapsed_seconds")
                limit = contract["limits"]["cold_64_seconds" if name == "full_count_cold_64" else "post_seal_seconds"]
                if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= limit:
                    reasons.append("Complete measured duration is absent or exceeds the gate")
                size = measured.get("root_bytes")
                if measured.get("cpu_audited") is not True or type(size) is not int or not 0 < size <= contract["limits"]["root_bytes"]:
                    reasons.append("CPU audit or root-size gate is missing")
                if measured.get("resource_profile_id") != contract["resource_policy"]["profile_id"]:
                    reasons.append("Measured resource profile differs")
                if (resources is None
                        or measured.get("binary_sha256") != resources["detected"].get("binary_sha256")
                        or measured.get("profile_sha256") != resources["detected"].get("profile_sha256")
                        or set(measured.get("gpu_uuids", [])) != set(resources["selected_gpu_uuids"])):
                    reasons.append("Complete timing must match the admitted binary, geometry and GPU fleet")
                expected_scope = "cold_64_wallet_ready_to_audited_root" if name == "full_count_cold_64" else "seal_to_host_ready_root_and_body"
                if measured.get("scope") != expected_scope or measured.get("transaction_count") != 64:
                    reasons.append("Timing does not cover the required complete 64-transaction boundary")
            if name == "durable_candidate_host_application":
                if measured.get("real_candidate_root_verified") is not True or measured.get("durable_restart_replay") is not True:
                    reasons.append("Actual candidate application and durable replay are not established")
            if name == "per_geometry_device_qualification":
                if measured.get("all_required_geometries") is not True or measured.get("individually_cpu_audited") is not True:
                    reasons.append("Existing grouped-eight device qualification does not cover new geometries")
                if (resources is None or set(measured.get("gpu_uuids", [])) != set(resources["selected_gpu_uuids"])
                        or len(set(measured.get("gpu_uuids", []))) != contract["resource_policy"]["workers"]):
                    reasons.append("Qualification must cover the actual selected GPU UUIDs")
                if resources and (measured.get("binary_sha256") != resources["detected"].get("binary_sha256")
                                  or measured.get("profile_sha256") != resources["detected"].get("profile_sha256")):
                    reasons.append("GPU qualification binary or geometry differs from the resource plan")
            if name == "restart_reorg_and_resource_failure_recovery":
                required = {"worker_termination", "coordinator_restart", "reorg", "resource_exhaustion", "stale_results"}
                if not required <= set(measured.get("passed_cases", [])):
                    reasons.append("Recovery case coverage is incomplete")
        results.append({"gate": name, "status": "passed" if not reasons else "blocked", "reasons": reasons})
    if resources is None or resources["status"] != "admitted":
        results.append({"gate": "current_resource_admission", "status": "blocked",
                        "reasons": resources["reasons"] if resources else ["No current resource plan"]})
    else:
        results.append({"gate": "current_resource_admission", "status": "passed", "reasons": []})
    return {"status": "ready_for_research_pilot" if all(g["status"] == "passed" for g in results) else "blocked",
            "pilot_started": False, "production_ready": False, "gates": results}
