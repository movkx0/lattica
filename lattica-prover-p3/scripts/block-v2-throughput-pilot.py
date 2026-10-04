#!/usr/bin/env python3
"""Prepare and check the research pilot; blocked gates never launch workloads."""
import argparse
import hashlib
from pathlib import Path
import sys

from benchmark_report.model import DEFAULT_ROOT, atomic_bytes, digest, json_bytes, read, reference
from block_v2_throughput import DEFAULT_CONTRACT, arrival_schedule, evaluate, load_contract, resource_snapshot


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("prepare", "check"))
    p.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    p.add_argument("--resource-plan", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    contract = load_contract(args.contract)
    evidence = read(args.evidence)
    if evidence.get("contract_sha256") != digest(args.contract):
        raise ValueError("evidence is not bound to this qualification contract")
    resources = resource_snapshot(read(args.resource_plan), contract)
    result = evaluate(contract, evidence, DEFAULT_ROOT, contract_path=args.contract, resources=resources)
    result.update(contract=contract, contract_source=reference(args.contract),
                  evidence_source=reference(args.evidence), resource_plan_source=reference(args.resource_plan),
                  resource_profile=resources, evidence=evidence, schema_version=1,
                  record_type="qualification_snapshot",
                  snapshot_id="throughput-" + hashlib.sha256(json_bytes({
                      "contract": digest(args.contract), "evidence": digest(args.evidence),
                      "resources": digest(args.resource_plan), "action": args.action})).hexdigest()[:16])
    if args.action == "prepare":
        if not args.resource_plan or not args.output:
            p.error("prepare requires --resource-plan and --output")
        result["arrival_schedule"] = arrival_schedule(contract)
        result["planned_user_requests"] = len(result["arrival_schedule"])
        result["schedule_is_measured_data"] = False
    if args.output:
        atomic_bytes(args.output, json_bytes(result))
    print(json_bytes(result if args.action == "check" else
                     {"status": result["status"], "pilot_started": False, "output": str(args.output)}).decode(), end="")
    return 0 if result["status"] == "ready_for_research_pilot" else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"throughput pilot: {error}", file=sys.stderr)
        sys.exit(1)
