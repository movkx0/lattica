"""Lossless public records for the Apple proof and field-component controllers."""
import hashlib
import json
from pathlib import Path
import re

from benchmark_report.measurements import Table, collect
from benchmark_report.model import (DEFAULT_ROOT, atomic_bytes, blank_run, digest,
                                    json_bytes, reference, validate_run)


def fingerprint(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def export_campaign(result_path, output):
    result_path, output = Path(result_path), Path(output)
    campaign = json.loads(result_path.read_text())
    if campaign["status"] not in ("COMPLETE_VERIFIED_COMPARISON", "COMPLETE_VERIFIED_PILOTS", "COMPLETE_VERIFIED_EXTENSION", "COMPLETE_VERIFIED_SCREENING"):
        raise ValueError("Apple export requires a completed, verified controller result")
    if not campaign["trials"] or not all(t["verified"] for t in campaign["trials"]):
        raise ValueError("unverified Apple trial")
    campaign_id = "apple-" + digest(result_path)[:20]
    # Counts come from the independently checked public statements, not seven
    # newly generated recursive proofs or the number of artifact filenames.
    public_stage = next(s for s in campaign["stages"] if s["label"] == "fixture-publics")
    public_path = result_path.parent / Path(public_stage["log"]).name
    if digest(public_path) != public_stage["log_sha256"]:
        raise ValueError("public statement log hash changed")
    public_header = public_path.read_text().splitlines()[0]
    match = re.search(r"VERIFIED_WALLET_STATEMENTS count=(\d+) fields=\d+ kind=(\d+)", public_header)
    if not match or match.groups() != ("8", "1") or public_stage["status"] != "PASS":
        raise ValueError("expected eight independently verified non-issuance statements")
    hardware = campaign["hardware"]
    memory = re.search(r"hw.memsize:\s*(\d+)", hardware)
    cpu = re.search(r"machdep.cpu.brand_string:\s*(.+)", hardware)
    profile = fingerprint({name: sha for name, sha in campaign["fixture_sha256"].items() if name.startswith("key.")})
    paths = []
    for trial in campaign["trials"]:
        stages = [s for s in campaign["stages"] if s["label"].startswith(trial["label"] + "-")]
        if len(stages) != 5 or any(s["status"] != "PASS" for s in stages):
            raise ValueError("trial must retain all five successful stages")
        for stage in stages:
            if digest(result_path.parent / Path(stage["log"]).name) != stage["log_sha256"]:
                raise ValueError("stage log hash changed: " + stage["label"])
            if stage.get("resource_log") and digest(result_path.parent / Path(stage["resource_log"]).name) != stage["resource_sha256"]:
                raise ValueError("resource sample hash changed: " + stage["label"])
        sources = [result_path.parent / Path(s["log"]).name for s in stages]
        sources += [result_path.parent / Path(s["resource_log"]).name for s in stages if s.get("resource_log")]
        measurements, refs, warnings, proofs = collect(sources, DEFAULT_ROOT)
        if len(proofs) != 7 or any(p["resumed"] is not False for p in proofs):
            raise ValueError("expected seven fresh measured recursive proofs")
        run = blank_run(campaign_id + "-" + trial["label"],
                        f"Apple {trial['threads']}t {trial['backend']} {trial['level']} · {trial['phase']} {trial['repeat']}",
                        "solving" if trial["phase"] == "measured" else "diagnostic")
        run.update(status="succeeded", track="apple-silicon", measurement_scope="recursive_aggregation",
                   campaign_ids=[campaign_id], milestones=["P0"], adapter="apple-metal")
        run["platform"] = {"os":"macos", "architecture":"aarch64", "backend":"cpu" if trial["backend"] == "cpu" else "metal",
                           "memory_model":"unified", "unified_memory_bytes":int(memory[1]) if memory else None,
                           "cpu":cpu[1] if cpu else hardware, "gpu":cpu[1] if cpu else None, "recorded_platform":campaign["platform"]}
        role = "cpu" if trial["backend"] == "cpu" else "metal"
        run["revision"] = {"git_commit":campaign["git_base"], "dirty":bool(campaign["git_diff"].strip()),
                           "binary_sha256":campaign["binary_sha256"][role], "profile_sha256":profile,
                           "source_archive_sha256":campaign["source_archive_sha256"], "source_hashes":campaign["source_hashes"]}
        run["workload"] = {"user_transactions":8, "issuance_transactions":0, "fixture_reuse":True,
                           "count_evidence":{"source":reference(public_path), "public_header":public_header},
                           "description":"Eight already-created non-issuance wallet proofs, reused as fixtures; four wrappers and three merges produce seven fresh recursive proofs. CPU root audit follows every trial."}
        run["timing"] = {"elapsed_seconds":trial["controller_seconds"], "recursive_seconds":trial["recursive_seconds"],
                         "wrappers_seconds":trial["wrappers_seconds"], "merges_seconds":trial["merges_seconds"],
                         "started_utc":stages[0].get("started_utc"), "completed_utc":stages[-1].get("completed_utc"),
                         "boundary":campaign["timing_boundary"]}
        run["verification"] = {"cpu_audited":True, "root_bytes":trial["root_bytes"], "root_sha256":trial["root_sha256"],
                               "audit_binary_sha256":campaign["binary_sha256"]["audit"]}
        config = {k:trial.get(k, 0) for k in ("backend","threads","level","readback","fusion","quotient","compact","defer_timing","repeat","phase")}
        config.update(campaign_id=campaign_id, peak_rss_bytes=trial["peak_rss_bytes"], peak_mapped_bytes=trial["peak_mapped_bytes"],
                      pairs_metal=trial.get("pairs_metal"), merges_metal=trial.get("merges_metal"))
        if campaign.get("suite") == "screening":
            config.update(screening=True, screening_reused=trial.get("screening_reused", False))
        run["configuration"] = {"apple_metal":config, "memory_limits":{"mmap_bytes":34 << 30, "managed_gpu_bytes":8 << 30,
                                 "sampled_rss_bytes":44 << 30}, "stage_timeout_seconds":7200, "fixture_sha256":campaign["fixture_sha256"],
                                 "memory_policy":campaign["memory_policy"], "build":campaign["build"]}
        if campaign.get("screening_reference"):
            run["configuration"]["screening_reference"] = campaign["screening_reference"]
        run["stages"] = [{"name":s["label"], "status":s["status"], "wall_seconds":s["wall_seconds"],
                          "reported_seconds":s["reported_seconds"], "started_utc":s.get("started_utc"), "completed_utc":s.get("completed_utc"),
                          "maximum_resident_bytes":s["maximum_resident_bytes"], "spill_peak_bytes":s["spill_peak_bytes"]} for s in stages]
        run["measurements"], run["proofs"] = measurements, proofs
        run["sources"] = [reference(result_path), reference(public_path), *refs]
        run["limitations"] = ["Research eight-wallet recursive aggregation, not a 64-transaction block or accepted-chain throughput.",
                               "Wallet proof creation, registry preparation and networking are excluded. Whole-job time includes checks and CPU audit; bars use recursive command time.",
                               "One physical unified-memory pool; mmap, GPU allocations and process RSS overlap and must not be added.",
                               "Shared/copy pairs isolate storage and explicit transfer behavior on this Mac. Cross-platform differences also include hardware, kernels and source revisions.",
                               "GPU and host timing clocks are not aligned. Profiling counters overlap and are not additive wall time.", *warnings]
        if campaign.get("suite") == "screening":
            run["limitations"].append("Screening only: one observation per configuration, without repeats or statistical confidence. A reused pilot retains its original phase and time; order and thermal effects are not controlled.")
        validate_run(run)
        path = output / (run["run_id"] + ".json")
        atomic_bytes(path, json_bytes(run)); paths.append(path)
    return paths


def export_component(result_path, metadata_path, output):
    result_path, metadata_path, output = Path(result_path), Path(metadata_path), Path(output)
    data, metadata = json.loads(result_path.read_text()), json.loads(metadata_path.read_text())
    if data["status"] != "PASS" or not all(s["verified"] for s in data["samples"]):
        raise ValueError("component verification failed")
    paths = []
    for backend, elements in sorted({(s["backend"],s["elements"]) for s in data["samples"]}):
        samples = [s for s in data["samples"] if (s["backend"],s["elements"]) == (backend,elements)]
        run = blank_run("apple-field-" + digest(result_path)[:16] + f"-{backend}-{elements}", f"Apple field multiply · {backend} · {elements} elements", "component")
        run.update(status="succeeded", track="apple-silicon", measurement_scope="goldilocks_multiply", adapter="apple-field")
        run["platform"] = metadata["platform"]
        run["revision"] = metadata["revision"]
        run["configuration"] = {"apple_field":{"backend":backend, "elements":elements, "samples":samples},
                                 "cpu_threads":1, "streaming_u64_lanes":data["streaming_u64_lanes"], "p3_packing_width":data["p3_packing_width"]}
        run["verification"]["integer_oracle_verified"] = True
        table = Table("component_samples", result_path.name, "host_elapsed")
        for sample in samples: table.add(sample)
        run["measurements"]["tables"] = [table.finish()]
        run["sources"] = [reference(result_path), reference(metadata_path)]
        run["limitations"] = data["limitations"]
        validate_run(run)
        path = output / (run["run_id"] + ".json")
        atomic_bytes(path, json_bytes(run)); paths.append(path)
    return paths
