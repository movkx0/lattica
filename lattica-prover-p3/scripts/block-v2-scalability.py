#!/usr/bin/env python3
"""Research-only matched recursive trials; never builds or changes proof parameters."""
import argparse
import csv
import fcntl
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shlex
import signal
import statistics
import subprocess
import time

SCRIPT_DIR = Path(__file__).resolve().parent
EXPECTED_NODES = {f"node.0.{i}" for i in range(4)} | {"node.1.0", "node.1.1", "node.2.0"}
PUBLIC_FILES = [*(f"wallet.{i}" for i in range(4)), "key.1", "key.2", "key.3", "expected", "height", "profile.hex"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def save_verified_report(path, value, artifact_fields=("root_sha256", "log_sha256")):
    if path.exists():
        previous = json.loads(path.read_text())
        require(all(key in previous and key in value and previous[key] == value[key]
                    for key in artifact_fields), "completed report evidence hashes changed or missing")
        if "controller_wall_seconds" in previous and "controller_wall_seconds" not in value:
            value["controller_wall_seconds"] = previous["controller_wall_seconds"]
    save(path, value)


def fields(line):
    pairs = [token.split("=", 1) for token in shlex.split(line) if "=" in token]
    require(len({key for key, _ in pairs}) == len(pairs), "duplicate log field")
    return dict(pairs)


def union(intervals):
    result = []
    for start, end in sorted(intervals):
        require(0 <= start <= end, "invalid device interval")
        if result and start <= result[-1][1]:
            result[-1][1] = max(result[-1][1], end)
        else:
            result.append([start, end])
    return result


def overlap_ns(a, b):
    a, b = union(a), union(b)
    i = j = total = 0
    while i < len(a) and j < len(b):
        total += max(0, min(a[i][1], b[j][1]) - max(a[i][0], b[j][0]))
        if a[i][1] <= b[j][1]:
            i += 1
        else:
            j += 1
    return total


RETENTION_COUNTERS = ("copy_device_ns", "query_device_ns", "query_wall_ns", "queries")
RETENTION_GAUGES = ("retained_live_bytes", "retained_peak_bytes", "retained_trees")
PIPELINE_COUNTERS = ("upload_device_ns", "download_device_ns", "upload_api_ns",
                     "upload_wait_ns", "slot_wait_ns", "tiles")


def pipeline_record(line, previous):
    f = fields(line)
    require(f.get("mode") in ("serial", "overlap") and f.get("counters") == "cumulative",
            "invalid pipeline checkpoint format")
    values = {key: int(f[key]) for key in PIPELINE_COUNTERS}
    require(all(value >= 0 for value in values.values()), "negative pipeline counter")
    if previous is not None:
        require(f["mode"] == previous["mode"], "transfer mode changed within a service")
        require(all(values[key] >= previous[key] for key in PIPELINE_COUNTERS),
                "pipeline cumulative counter regressed")
    delta = {key: value - (previous[key] if previous else 0) for key, value in values.items()}
    return dict(mode=f["mode"], **values), dict(mode=f["mode"], delta=delta)


def retention_record(line, previous):
    f = fields(line)
    require(f.get("enabled") in ("true", "false") and f.get("counters") == "cumulative",
            "invalid retention checkpoint format")
    values = {key: int(f[key]) for key in RETENTION_COUNTERS + RETENTION_GAUGES}
    require(all(value >= 0 for value in values.values()), "negative retention counter")
    enabled = f["enabled"] == "true"
    require(enabled or not any(values.values()), "disabled retention has device work or allocations")
    require(values["retained_live_bytes"] <= values["retained_peak_bytes"], "retention peak below live bytes")
    require((values["retained_live_bytes"] == 0) == (values["retained_trees"] == 0),
            "retention tree-count/live-byte mismatch")
    if previous is not None:
        require(enabled == previous["enabled"], "retention mode changed within a service")
        require(all(values[key] >= previous[key] for key in RETENTION_COUNTERS + ("retained_peak_bytes",)),
                "retention cumulative counter regressed")
    delta = {key: values[key] - (previous[key] if previous else 0) for key in RETENTION_COUNTERS}
    return dict(enabled=enabled, **values), dict(enabled=enabled, delta=delta,
                                                **{key: values[key] for key in RETENTION_GAUGES})


def parse_trial(path, require_timeline=True, expected_retention=None, expected_pipeline=None):
    nodes, stages, units, gpu_previous = {}, [], [], {}
    phase_counters, host, device, accounting = {}, {}, {}, {}
    retention_previous, retention_seen = {}, set()
    pipeline_previous, pipeline_seen = {}, set()
    unit, stage_nodes, host_group, device_group = None, [], None, None
    audit = root_verified = pruned = completed = False
    shutdowns = 0
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        match = re.search(r"Running as unit: (lattica-v2-[\w-]+\.service)", line)
        if match:
            unit = match[1]
            units.append(unit)
            stage_nodes = []
            host_group = device_group = None
        elif line.startswith("cached_node_complete "):
            f = fields(line)
            name = f["artifact"]
            require(name in EXPECTED_NODES and name not in nodes, "unexpected/duplicate node")
            nodes[name] = {"elapsed_ms": int(f["elapsed_ms"]), "unit": unit}
            stage_nodes.append(name)
        elif line.startswith("stage_elapsed_ms="):
            f = fields(line)
            stages.append({"unit": unit, "nodes": stage_nodes.copy(), "elapsed_ms": int(f["stage_elapsed_ms"]), "spill_peak_bytes": int(f["spill_peak_bytes"])})
        elif line.startswith("stage_cgroup_accounting "):
            f = fields(line)
            require(f["unit"] == unit and unit not in accounting, "misbound/duplicate cgroup snapshot")
            require(f["scope"] == "exec_stop_post_snapshot", "unknown cgroup snapshot scope")
            values = {k: int(v) for k, v in f.items() if k not in ("unit", "scope")}
            require(all(v >= 0 for v in values.values()), "negative cgroup snapshot")
            require(values["memory_max"] <= 44 * 2**30 and values["memory_swap_max"] == 0, "cgroup limit mismatch")
            require(values["memory_peak"] <= values["memory_max"] and values["memory_swap_peak"] == 0, "cgroup snapshot resource gate failure")
            accounting[unit] = dict(scope=f["scope"], **values)
        elif line.startswith("bounded_gpu_retention_checkpoint "):
            f = fields(line)
            key = (unit, f["label"])
            require(unit is not None and key not in retention_seen, "unbound/duplicate retention checkpoint")
            retention_seen.add(key)
            previous, record = retention_record(line, retention_previous.get(unit))
            retention_previous[unit] = previous
            if f["label"] in nodes:
                require(nodes[f["label"]]["unit"] == unit, "retention checkpoint bound to wrong service")
                nodes[f["label"]]["gpu_retention"] = record
        elif line.startswith("bounded_gpu_pipeline_checkpoint "):
            f = fields(line)
            key = (unit, f["label"])
            require(unit is not None and key not in pipeline_seen, "unbound/duplicate pipeline checkpoint")
            pipeline_seen.add(key)
            previous, record = pipeline_record(line, pipeline_previous.get(unit))
            pipeline_previous[unit] = previous
            if f["label"] in nodes:
                require(nodes[f["label"]]["unit"] == unit, "pipeline checkpoint bound to wrong service")
                nodes[f["label"]]["gpu_pipeline"] = record
        elif line.startswith("bounded_gpu_checkpoint "):
            f = fields(line)
            values = {k: int(v) for k, v in f.items() if k not in ("label", "counters")}
            previous = gpu_previous.get(unit, {})
            if f["label"] in nodes:
                nodes[f["label"]]["gpu_delta"] = {k: v - previous.get(k, 0) for k, v in values.items() if k not in ("managed_live_bytes", "managed_peak_bytes", "allocations", "staging_bytes")}
                nodes[f["label"]]["managed_gpu_peak_bytes"] = values["managed_peak_bytes"]
                if "managed_live_bytes" in values:
                    nodes[f["label"]]["managed_gpu_live_bytes"] = values["managed_live_bytes"]
            gpu_previous[unit] = values
        elif line.startswith("performance_checkpoint "):
            f = fields(line)
            require(int(f["spans_dropped"]) == int(f["spans_open"]) == 0, "incomplete inclusive profile")
            phase_counters.setdefault(f["label"], [])
            phase_label = f["label"]
        elif line.startswith("performance_phase_counter "):
            phase_counters[phase_label].append(fields(line))
        elif line.startswith("host_timeline_checkpoint "):
            f = fields(line)
            require(all(int(f[k]) == 0 for k in ("dropped", "malformed", "open_frames")), "incomplete host timeline")
            require(f["clock"] == "host_monotonic_relative", "host clock domain")
            key = (unit, f["label"])
            require(unit is not None and key not in host, "unbound/duplicate host timeline frame")
            host_group = {"unit": unit, "label": f["label"], "expected": int(f["events"]),
                          "seen": 0, "last": {}, "entered_wall_ns_by_phase": {}}
            host[key] = host_group
        elif line.startswith("host_timeline_interval "):
            require(host_group is not None, "unframed host event")
            f = fields(line)
            require(host_group["unit"] == unit and f.get("label", host_group["label"]) == host_group["label"]
                    and f.get("clock", "host_monotonic_relative") == "host_monotonic_relative",
                    "host interval frame/clock mismatch")
            thread, start, end = int(f["thread"]), int(f["start_ns"]), int(f["end_ns"])
            require(0 <= start <= end and host_group["last"].get(thread, 0) <= start, "overlapping host thread intervals")
            host_group["last"][thread] = end
            host_group["seen"] += 1
            key = f["target"] + "::" + f["name"]
            totals = host_group["entered_wall_ns_by_phase"]
            totals[key] = totals.get(key, 0) + end - start
        elif line.startswith("gpu_timeline_checkpoint "):
            f = fields(line)
            require(int(f["dropped"]) == 0 and f["clock"] == "opencl_device", "incomplete/device clock timeline")
            key = (unit, f["label"])
            require(unit is not None and key not in device, "unbound/duplicate device timeline frame")
            device_group = {"unit": unit, "label": f["label"], "expected": int(f["events"]), "events": []}
            device[key] = device_group
        elif line.startswith("gpu_timeline_interval "):
            require(device_group is not None, "unframed device event")
            f = fields(line)
            require(device_group["unit"] == unit and f.get("label") == device_group["label"]
                    and f.get("clock") == "opencl_device", "device interval frame/clock mismatch")
            device_group["events"].append((f["kind"], int(f["start_ns"]), int(f["end_ns"])))
        elif line.startswith("bounded_gpu_shutdown "):
            require(fields(line)["managed_live_bytes"] == "0", "GPU managed allocation leak")
            shutdowns += 1
        elif line.startswith("artifact_audit=PASS "):
            f = fields(line)
            require(f["inner_proofs_loaded"] == "0" and f["native_mutation_rejections"] == "38" and f["registry_policy_rejections"] == "4", "incomplete CPU artifact audit")
            audit = True
        elif line.startswith("two_level_recursive_verification=PASS "):
            require(fields(line)["inner_proofs_loaded"] == "0", "root verification used inners")
            root_verified = True
        elif line == "inner_proof_artifacts_removed=10":
            pruned = True
        elif line == "bounded_gpu_recursive_trial=PASS":
            completed = True
    require(set(nodes) == EXPECTED_NODES, "missing recursive nodes")
    require(all("gpu_delta" in n for n in nodes.values()), "missing GPU counters")
    if pipeline_seen or expected_pipeline is not None:
        require(all("gpu_pipeline" in n for n in nodes.values()), "missing pipeline checkpoint")
        modes = {n["gpu_pipeline"]["mode"] for n in nodes.values()}
        require(len(modes) == 1, "transfer mode changed between proving services")
        if expected_pipeline is not None:
            require(modes == {"overlap" if expected_pipeline else "serial"},
                    "transfer mode differs from pinned experiment")
    if retention_seen or expected_retention is not None:
        require(all("gpu_retention" in n for n in nodes.values()), "missing retention checkpoint")
        modes = {n["gpu_retention"]["enabled"] for n in nodes.values()}
        require(len(modes) == 1, "retention mode changed between proving services")
        if expected_retention is not None:
            require(modes == {expected_retention}, "retention mode differs from pinned experiment")
    require(audit and root_verified and pruned and completed and shutdowns == 2, "trial correctness/cleanup gate missing")
    for h in host.values():
        require(h["seen"] == h["expected"], "missing host timeline records")
    for d in device.values():
        require(len(d["events"]) == d["expected"], "missing device timeline records")
        union([(start, end) for _, start, end in d["events"]])
    for name, node in nodes.items():
        key = (node["unit"], name)
        pipeline = node.get("gpu_pipeline")
        # Historical missing device-duration telemetry remains unknown, never zero.
        for field in ("upload_device_ns", "download_device_ns"):
            node["gpu_delta"][field] = pipeline["delta"][field] if pipeline else None
        retention = node.get("gpu_retention")
        if retention is not None:
            require(retention["retained_peak_bytes"] <= node["managed_gpu_peak_bytes"],
                    "retained allocations exceed managed GPU peak")
            require("managed_gpu_live_bytes" in node and
                    retention["retained_live_bytes"] <= node["managed_gpu_live_bytes"],
                    "retained allocations exceed managed GPU live bytes")
        if require_timeline:
            require(key in host and key in device, "node timeline missing")
            node["thread_entered_wall_ns_nonadditive_across_threads"] = host[key]["entered_wall_ns_by_phase"]
            events = device[key]["events"]
            uploads = [(a, b) for k, a, b in events if k == "upload"]
            compute = [(a, b) for k, a, b in events if k in ("leaf", "compress")]
            require(uploads and compute and any(k == "download" for k, _, _ in events), "missing device event category")
            node["upload_compute_overlap_ns"] = overlap_ns(uploads, compute)
            if pipeline is not None:
                for kind in ("upload", "download"):
                    measured = sum(b - a for k, a, b in events if k == kind)
                    require(measured == pipeline["delta"][kind + "_device_ns"],
                            f"{kind} device counter/timeline disagreement")
            node["process_phase_deltas_inclusive_nonadditive"] = phase_counters[name]
            if retention is not None:
                copies = [(a, b) for k, a, b in events if k == "retain_copy"]
                queries = [(a, b) for k, a, b in events if k == "path_gather"]
                require(sum(b - a for a, b in copies) == retention["delta"]["copy_device_ns"],
                        "retained-copy counter/timeline disagreement")
                require(sum(b - a for a, b in queries) == retention["delta"]["query_device_ns"] and
                        len(queries) == retention["delta"]["queries"],
                        "retained-query counter/timeline disagreement")
                require(not retention["enabled"] or (copies and queries),
                        "enabled retained-tree proof lacks copy/query events")
                require(retention["enabled"] or not (copies or queries),
                        "disabled retention has copy/query events")
    proving = [s for s in stages if s["nodes"]]
    require(len(proving) == 2 and sum(len(s["nodes"]) for s in proving) == 7, "unexpected proving command structure")
    require(len(units) == len(set(units)), "duplicate service unit")
    return {"nodes": nodes, "stages": stages, "units": units, "cgroup_snapshots": accounting,
            "gpu_tree_retention_enabled": nodes["node.2.0"].get("gpu_retention", {}).get("enabled"),
            "gpu_transfer_mode": nodes["node.2.0"].get("gpu_pipeline", {}).get("mode"),
            "recursive_command_ms": sum(s["elapsed_ms"] for s in proving), "final_merge_ms": nodes["node.2.0"]["elapsed_ms"]}


def resources(units, snapshots):
    result = {}
    for unit in units:
        raw = subprocess.check_output(["journalctl", "--user", "-u", unit, "-o", "json", "--no-pager"], text=True)
        entries = [json.loads(line) for line in raw.splitlines()]
        records = [e for e in entries if "MEMORY_PEAK" in e]
        require(len(records) <= 1, f"ambiguous cgroup accounting: {unit}")
        if records:
            e = records[0]
            values = {k.lower(): int(e[k]) for k in ("MEMORY_PEAK", "MEMORY_SWAP_PEAK", "CPU_USAGE_NSEC")}
            require(all(v >= 0 for v in values.values()), "negative journal accounting")
            values["source"] = "final_systemd_journal"
            if unit in snapshots:
                require(values["memory_peak"] >= snapshots[unit]["memory_peak"], "journal/snapshot peak disagreement")
                require(values["cpu_usage_nsec"] >= snapshots[unit]["cpu_usage_usec"] * 1000, "journal/snapshot CPU disagreement")
        elif unit in snapshots:
            s = snapshots[unit]
            values = dict(memory_peak=s["memory_peak"], memory_swap_peak=s["memory_swap_peak"],
                          cpu_usage_nsec=s["cpu_usage_usec"] * 1000, source="exec_stop_post_snapshot",
                          excludes_cleanup_after_snapshot=True)
        else:
            # Old logs remain useful evidence, but missing telemetry is not zero
            # and does not qualify a fully measured comparison pair.
            result[unit] = dict(source="unavailable", memory_peak=None,
                                memory_swap_peak=None, cpu_usage_nsec=None)
            continue
        require(values["memory_peak"] <= 44 * 2**30 and values["memory_swap_peak"] == 0, "resource gate failure")
        result[unit] = values
    return result


def model(trial):
    ms = trial["recursive_command_ms"]
    gpu = [n["gpu_delta"] for n in trial["nodes"].values()]
    upload_wall = [g.get("upload_wall_ns") for g in gpu]
    return {
        "kind": "conditional_unchanged_geometry_serial_extrapolation_not_measurement",
        "recursive_proofs_for_64": 127,
        "estimated_64_minutes": ms / 1000 / 7 * 127 / 60,
        "target_average_seconds_per_recursive_proof": 600 / 127,
        "required_speedup_over_this_serial_trial": ms / 1000 / 7 * 127 / 600,
        "four_tx_seconds_with_zero_hashing_holding_other_costs_fixed": ms / 1000 - sum(g["hashing_wall_ns"] for g in gpu) / 1e9,
        "four_tx_seconds_with_zero_upload_wall_holding_other_costs_fixed": (
            ms / 1000 - sum(upload_wall) / 1e9 if all(v is not None for v in upload_wall) else None),
        "cache_hit_upload_bytes_per_node": min(g["uploaded_bytes"] for g in gpu),
        "estimated_64_cache_hit_upload_bytes": min(g["uploaded_bytes"] for g in gpu) * 127,
        "pcie4_x4_theoretical_upload_floor_seconds_if_link_and_volume_unchanged": min(g["uploaded_bytes"] for g in gpu) * 127 / (16e9 * 4 * 128 / 130 / 8),
    }


def observed_vram(path):
    samples = {}
    readings = 0
    with path.open() as source:
        for row in csv.DictReader(source):
            readings += 1
            samples[row["utc_epoch_ns"]] = samples.get(row["utc_epoch_ns"], 0) + int(row["used_mib"])
    require(readings > 0 and max(samples.values()) <= 12288, "sampled VRAM gate failed")
    return {"readings": readings, "largest_sampled_prover_sum_mib": max(samples.values()), "physical_quota": False}


def collect_result(log, job, pair, mode, expected_retention=None, expected_pipeline=None):
    result = parse_trial(log, expected_retention=expected_retention, expected_pipeline=expected_pipeline)
    result.update(pair=pair, mode=mode, job_directory=str(job), cgroups=resources(result["units"], result["cgroup_snapshots"]), root_bytes=(job / "node.2.0").stat().st_size, root_sha256=digest(job / "node.2.0"), log_sha256=digest(log), vram=observed_vram(job / "vram.csv"))
    result["missing_accounting_units"] = [u for u, record in result["cgroups"].items() if record["source"] == "unavailable"]
    result["resource_telemetry_complete"] = not result["missing_accounting_units"]
    proving_units = {s["unit"] for s in result["stages"] if s["nodes"]}
    result["proving_resource_telemetry_complete"] = not proving_units.intersection(result["missing_accounting_units"])
    require(result["root_bytes"] <= 2**21, "root envelope exceeds 2 MiB")
    require(all(s["spill_peak_bytes"] <= 120 * 2**30 for s in result["stages"]), "scratch budget exceeded")
    require(all(n["managed_gpu_peak_bytes"] <= 8 * 2**30 for n in result["nodes"].values()), "managed GPU budget exceeded")
    return result


def recover_reports(series):
    """Read completed logs only. Never infer process death or restart any prover."""
    with (series / ".controller.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return recover_reports_locked(series)


def recover_reports_locked(series):
    manifest = json.loads((series / "manifest.json").read_text())
    experiment = manifest_experiment(manifest)
    recovered, failed = [], []
    for pair in range(1, manifest["planned_pairs"] + 1):
        for variant in experiment["variants"]:
            mode = variant["label"]
            label = f"pair-{pair}-{mode}"
            log = series / (label + ".log")
            if log.exists():
                try:
                    strict = manifest["schema_version"] == 3
                    result = collect_result(log, series / label, pair, mode,
                                            variant["retain_trees"] if strict else manifest.get("retain_trees"),
                                            variant["pipeline"] if strict else None)
                    save_verified_report(series / (label + ".json"), result)
                    recovered.append(dict(label=label, resource_telemetry_complete=result["resource_telemetry_complete"]))
                except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
                    failed.append(dict(label=label, error=str(error)))
    report = dict(recovered_reports=recovered, incomplete_reports=failed, provers_started=0)
    save(series / "report-recovery.json", report)
    print(json.dumps(report))


def require_controller():
    line = next(l for l in Path("/proc/self/cgroup").read_text().splitlines() if l.startswith("0::"))
    group = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
    maximum = (group / "memory.max").read_text().strip()
    require(maximum.isdigit() and int(maximum) <= 3 * 2**30, "controller requires MemoryMax<=3G")
    require((group / "memory.swap.max").read_text().strip() == "0", "controller requires no swap")


def run_child(command, env, log):
    with log.open("x") as output:
        process = subprocess.Popen(command, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            require(process.wait() == 0, f"child failed; inspect {log}")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def experiment_definition(comparison="transfer", retain_trees=False, transfer_mode=None):
    require(comparison in ("transfer", "retention"), "unknown comparison axis")
    if comparison == "transfer":
        require(transfer_mode is None, "--transfer-mode requires --comparison retention")
        variants = [dict(label=label, pipeline=pipeline, retain_trees=retain_trees)
                    for label, pipeline in (("serial", False), ("overlap", True))]
    else:
        require(not retain_trees, "--retain-trees is incompatible with --comparison retention")
        require(transfer_mode in (None, "serial", "overlap"), "invalid fixed transfer mode")
        variants = [dict(label=label, pipeline=transfer_mode == "overlap", retain_trees=retained)
                    for label, retained in (("retention-off", False), ("retention-on", True))]
    return dict(comparison=comparison, variants=variants)


def manifest_experiment(manifest):
    schema = manifest["schema_version"]
    require(schema in (1, 2, 3), "unsupported comparison manifest schema")
    if schema < 3:
        return experiment_definition(retain_trees=manifest.get("retain_trees", False))
    value = manifest["experiment"]
    require(isinstance(value, dict) and isinstance(value.get("variants"), list)
            and len(value["variants"]) == 2, "invalid comparison manifest shape")
    require(all(isinstance(v, dict) and type(v.get("pipeline")) is bool
                and type(v.get("retain_trees")) is bool for v in value["variants"]),
            "comparison switches must be booleans")
    first = value["variants"][0]
    expected = experiment_definition(value["comparison"],
                                    first["retain_trees"] if value["comparison"] == "transfer" else False,
                                    ("overlap" if first["pipeline"] else "serial")
                                    if value["comparison"] == "retention" else None)
    require(value == expected, "invalid comparison configuration in manifest")
    return value


def validate_resume(manifest, hashes, inputs, profile, pairs, experiment):
    require(manifest["schema_version"] == 3, "old series is recovery-only; start a separately pinned comparison")
    require(manifest["sha256"] == hashes and manifest["inputs"] == inputs,
            "pinned source/artifact/input changed; refusing resume")
    require(manifest["profile"] == profile and manifest["planned_pairs"] == pairs,
            "resume configuration mismatch")
    require(manifest_experiment(manifest) == experiment, "resume comparison configuration mismatch")


def remember_attempts(manifest):
    """Keep unresolved launch history across arbitrarily many interrupted resumes."""
    experiment = manifest_experiment(manifest)
    allowed = {f"pair-{pair}-{variant['label']}"
               for pair in range(1, manifest["planned_pairs"] + 1) for variant in experiment["variants"]}
    attempted = set(manifest.get("attempted_trials", []))
    attempted.update(f"pair-{r['pair']}-{r['mode']}" for r in manifest.get("runs", []))
    if manifest.get("active_trial") is not None:
        attempted.add(manifest["active_trial"])
    require(attempted <= allowed, "unknown attempted trial in manifest")
    manifest["attempted_trials"] = sorted(attempted)
    return attempted


def variant_environment(env, variant):
    return dict(env, LATTICA_V2_GPU_PIPELINE="1" if variant["pipeline"] else "0",
                LATTICA_V2_GPU_RETAIN_TREES="1" if variant["retain_trees"] else "0")


def gpu_inventory():
    value = subprocess.check_output(["nvidia-smi", "--query-gpu=uuid,pci.bus_id,name,driver_version,memory.total",
                                     "--format=csv,noheader,nounits"], text=True).strip()
    require(bool(value), "GPU identity inventory is unavailable")
    return value


def matched_summary(results, pairs, experiment=None):
    legacy = experiment is None
    experiment = experiment or experiment_definition()
    variants = experiment["variants"]
    labels = [variant["label"] for variant in variants]
    retention_modes = {r.get("gpu_tree_retention_enabled") for r in results}
    if experiment["comparison"] == "transfer":
        require(len(retention_modes) <= 1, "mixed retention settings cannot qualify a matched series")
    require(all(1 <= r["pair"] <= pairs and r["mode"] in labels for r in results),
            "unexpected comparison result label/pair")
    if not legacy:
        by_label = {variant["label"]: variant for variant in variants}
        for result in results:
            variant = by_label[result["mode"]]
            require(result.get("gpu_tree_retention_enabled") is variant["retain_trees"],
                    "result retention mode differs from pinned comparison")
            require(result.get("gpu_transfer_mode") == ("overlap" if variant["pipeline"] else "serial"),
                    "result transfer mode differs from pinned comparison")
    require(all(r["recursive_command_ms"] > 0 and r["final_merge_ms"] > 0 for r in results),
            "nonpositive proof timing")
    by_pair = {(r["pair"], r["mode"]): r for r in results}
    require(len(by_pair) == len(results), "duplicate trial result")
    qualified = [pair for pair in range(1, pairs + 1)
                 if all((pair, mode) in by_pair and by_pair[pair, mode]["resource_telemetry_complete"]
                        for mode in labels)]
    baseline = [by_pair[pair, labels[0]] for pair in qualified]
    candidate = [by_pair[pair, labels[1]] for pair in qualified]
    def timing(rows):
        return dict(median_ms=statistics.median(r["recursive_command_ms"] for r in rows) if rows else None,
                    worst_ms=max((r["recursive_command_ms"] for r in rows), default=None),
                    final_merge_median_ms=statistics.median(r["final_merge_ms"] for r in rows) if rows else None,
                    final_merge_worst_ms=max((r["final_merge_ms"] for r in rows), default=None))
    baseline_timing, candidate_timing = timing(baseline), timing(candidate)
    summary = {
        "comparison": experiment,
        "completed_pairs": sum(all((pair, mode) in by_pair for mode in labels) for pair in range(1, pairs + 1)),
        "fully_measured_pairs": qualified,
        "minimum_repetition_gate_passed": len(qualified) >= 5,
        "baseline_timing": baseline_timing,
        "candidate_timing": candidate_timing,
        "paired_speedup_ratios": [a["recursive_command_ms"] / b["recursive_command_ms"] for a, b in zip(baseline, candidate)],
        "paired_wall_reduction_percent": [(1 - b["recursive_command_ms"] / a["recursive_command_ms"]) * 100
                                           for a, b in zip(baseline, candidate)],
        "median_wall_reduction_percent": ((1 - candidate_timing["median_ms"] / baseline_timing["median_ms"]) * 100
                                          if baseline else None),
        "baseline_cost_models": [model(r) for r in baseline] if not variants[0]["pipeline"] else [],
        "depth_six_qualified": False, "incremental_qualified": False,
        "architecture_decision": "REQUIRES_REVIEW_OF_MEASUREMENTS_AND_STRUCTURAL_PROTOTYPES",
    }
    if experiment["comparison"] == "transfer":
        summary.update(serial_median_ms=baseline_timing["median_ms"],
                       overlap_median_ms=candidate_timing["median_ms"],
                       gpu_tree_retention_enabled=next(iter(retention_modes), None),
                       serial_cost_models=summary["baseline_cost_models"])
    return summary


def trial_result(log, job, pair, mode, env, fixture, profile, expected_retention=None, expected_pipeline=None,
                 recorded=False):
    # Existing evidence is inspected, never overwritten or treated as permission
    # to retry a possibly live/incomplete prover. Complete trials are reused.
    reused = log.exists()
    require(not recorded or reused, "recorded trial log is missing; investigate without re-proving")
    started = time.monotonic()
    if not reused:
        require(not job.exists(), "job exists without a log; investigate before resuming")
        run_child(["bash", str(SCRIPT_DIR / "block-v2-gpu-trial.sh"), str(fixture), str(job), profile], env, log)
    result = collect_result(log, job, pair, mode, expected_retention, expected_pipeline)
    require(result["resource_telemetry_complete"], "trial resource telemetry incomplete; recover report without re-proving")
    if not reused:
        result["controller_wall_seconds"] = time.monotonic() - started
    result["reused_completed_trial"] = reused
    return result


def run(args):
    os.umask(0o077)
    require_controller()
    experiment = experiment_definition(args.comparison, args.retain_trees, args.transfer_mode)
    require(re.fullmatch(r"[0-9a-f]{64}", args.profile), "independent profile must be lowercase hex")
    require(1 <= args.pairs <= 20, "pairs must be 1..20; qualification needs at least five")
    fixture, series = args.fixture.resolve(strict=True), args.series.resolve()
    runner, auditor = args.runner.resolve(strict=True), args.auditor.resolve(strict=True)
    gpu_device = os.environ.get("LATTICA_V2_GPU_DEVICE", "0")
    require(re.fullmatch(r"[0-9]+", gpu_device), "GPU device must be an explicit numeric index")
    require(os.access(runner, os.X_OK) and os.access(auditor, os.X_OK), "binaries must be executable")
    require((fixture / "profile.hex").read_text().strip() == args.profile, "fixture differs from independent pin")
    for name in PUBLIC_FILES:
        p = fixture / name
        require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 2**21, "invalid public fixture")
    source_files = sorted(p for p in (SCRIPT_DIR.parent / "src").rglob("*") if p.is_file())
    pinned = [runner, auditor, *source_files, SCRIPT_DIR.parent / "Cargo.toml", SCRIPT_DIR.parent / "Cargo.lock",
              SCRIPT_DIR.parent / ".cargo" / "config.toml",
              *(SCRIPT_DIR / name for name in ("block-v2-scalability.py", "block-v2-two-level.sh",
                                              "block-v2-gpu-trial.sh", "block-v2-accounting.py")),
              *(fixture / n for n in PUBLIC_FILES)]
    hashes = {str(p): digest(p) for p in pinned}
    if args.resume:
        require(series.is_dir(), "resume requires an existing series")
    else:
        series.mkdir(mode=0o700)
    with (series / ".controller.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inputs = dict(fixture=str(fixture), runner=str(runner), auditor=str(auditor), gpu_device=gpu_device,
                      nvidia_inventory_csv=gpu_inventory())
        if args.resume:
            manifest = json.loads((series / "manifest.json").read_text())
            validate_resume(manifest, hashes, inputs, args.profile, args.pairs, experiment)
        else:
            manifest = {
                "schema_version": 3, "inputs": inputs, "profile": args.profile,
                "planned_pairs": args.pairs, "sha256": hashes, "runs": [],
                "experiment": experiment,
                "production_ready": False, "full_tree_security": "UNREVIEWED",
                "limits": {"controller_ram_bytes": 3 * 2**30, "prover_ram_bytes": 44 * 2**30,
                           "prover_memory_high_bytes": 40 * 2**30, "scratch_bytes": 120 * 2**30,
                           "swap_bytes": 0, "managed_gpu_bytes": 8 * 2**30,
                           "driver_reserve_bytes": 4 * 2**30, "rayon_threads": 8, "physical_vram_quota": False},
                "environment": {
                    "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "kernel": platform.release(),
                    "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), "unknown"),
                    "gpu_snapshot_csv": subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total,pcie.link.gen.current,pcie.link.width.current", "--format=csv,noheader,nounits"], text=True).strip(),
                    "gpu_snapshot_columns": ["name", "driver_version", "memory_mib", "pcie_generation", "pcie_width"],
                    "memory_total_kib": int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))),
                },
            }
        # Persist this union BEFORE overwriting/clearing active_trial while replaying
        # completed earlier trials. A second interrupted resume must not forget it.
        attempted_trials = remember_attempts(manifest)
        manifest["status"] = "RUNNING"
        manifest["controller_pid"] = os.getpid()
        manifest.setdefault("controller_invocations", []).append(dict(
            started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), resume=args.resume))
        save(series / "manifest.json", manifest)
        env = dict(os.environ, LATTICA_V2_RUNNER=str(runner), LATTICA_V2_AUDITOR=str(auditor),
                   LATTICA_PROFILE="1", LATTICA_PROFILE_TIMELINE="1", LATTICA_V2_CAPTURE_ACCOUNTING="1",
                   LATTICA_V2_GPU_DEVICE=gpu_device)
        try:
            for pair in range(1, args.pairs + 1):
                for index in ([0, 1] if pair % 2 else [1, 0]):
                    variant = experiment["variants"][index]
                    require(gpu_inventory() == inputs["nvidia_inventory_csv"],
                            "GPU identity, enumeration or driver changed during comparison")
                    require(all(digest(p) == h for p, h in hashes.items()), "pinned source/artifact changed during series")
                    mode_name = variant["label"]
                    label = f"pair-{pair}-{mode_name}"
                    job, log = series / label, series / (label + ".log")
                    output = series / (label + ".json")
                    recorded = label in attempted_trials or output.exists()
                    trial_env = variant_environment(env, variant)
                    attempted_trials.add(label)
                    manifest["attempted_trials"] = sorted(attempted_trials)
                    manifest["active_trial"] = label
                    save(series / "manifest.json", manifest)
                    print(f"trial_start label={label} log={log} existing={log.exists()}", flush=True)
                    result = trial_result(log, job, pair, mode_name, trial_env, fixture, args.profile,
                                          variant["retain_trees"], variant["pipeline"], recorded=recorded)
                    require(all(digest(p) == h for p, h in hashes.items()), "pinned source/artifact changed during trial")
                    if result["reused_completed_trial"] and output.exists():
                        previous = json.loads(output.read_text())
                        require(previous["root_sha256"] == result["root_sha256"] and previous["log_sha256"] == result["log_sha256"], "completed trial changed since report")
                        if "controller_wall_seconds" in previous:
                            result["controller_wall_seconds"] = previous["controller_wall_seconds"]
                    save_verified_report(output, result)
                    manifest["runs"] = [r for r in manifest["runs"] if (r["pair"], r["mode"]) != (pair, mode_name)]
                    manifest["runs"].append({"pair": pair, "mode": mode_name, "result": label + ".json"})
                    manifest.pop("active_trial", None)
                    save(series / "manifest.json", manifest)
                    print(f"trial_complete label={label} recursive_ms={result['recursive_command_ms']} reused={result['reused_completed_trial']}", flush=True)
            results = [json.loads((series / r["result"]).read_text()) for r in manifest["runs"]]
            summary = matched_summary(results, args.pairs, experiment)
            save(series / "summary.json", summary)
            manifest["status"] = "MATCHED_TRIALS_COMPLETE_SHARED_FIXTURE_NOT_PRUNED"
            manifest.pop("last_error", None)
            save(series / "manifest.json", manifest)
            print(json.dumps(summary, sort_keys=True), flush=True)
        except BaseException as error:
            manifest["status"] = "FAILED_OR_INTERRUPTED_PRESERVE_ARTIFACTS"
            manifest["last_error"] = dict(type=type(error).__name__, message=str(error))
            save(series / "manifest.json", manifest)
            raise


def main():
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "--recover-reports":
        recover_reports(Path(sys.argv[2]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("series", type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--auditor", required=True, type=Path)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--comparison", choices=("transfer", "retention"), default="transfer",
                        help="compare transfer modes, or retention off/on at one fixed transfer mode")
    parser.add_argument("--transfer-mode", choices=("serial", "overlap"),
                        help="fixed transfer mode for --comparison retention (default: serial)")
    parser.add_argument("--retain-trees", action="store_true", help="pin device-tree retention on for BOTH transfer modes; requires retention-capable binaries")
    parser.add_argument("--resume", action="store_true", help="reuse complete trials in an identically pinned schema-3 series; never retry incomplete logs")
    args = parser.parse_args()
    def terminate(*_):
        raise KeyboardInterrupt("benchmark controller received SIGTERM")
    signal.signal(signal.SIGTERM, terminate)
    run(args)


if __name__ == "__main__":
    main()
