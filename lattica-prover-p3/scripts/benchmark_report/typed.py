"""Typed research evidence: transaction mix comes from the audited public body."""
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path

from .model import digest, read, reference, relative

GPU_SCHEMA = "lattica-typed-gpu-bootstrap-v1"
SHARED_SCHEMA = "lattica-typed-shared-gpu-v1"
CPU_SCHEMA = "lattica-typed-cpu-preparation-v1"


def classify(data, path):
    if (path.name == 'summary.json' and data.get('schema') == SHARED_SCHEMA
            and data.get('status') == 'failed' and data.get('native_head_change')
            and not (path.parent / 'owner/result.json').exists()):
        return 'typed-controller'
    if path.name == "result.json" and data.get("schema") in (GPU_SCHEMA, SHARED_SCHEMA):
        return "typed-worker"
    if path.name == "worker-result.json" and data.get("schema") == CPU_SCHEMA:
        return "typed-preparation"
    if path.name == "attempt.json" and data.get("config", {}).get("workload", {}).get("name") in (
            "typed-depth-six-bootstrap-v1", "typed-finalizer-depth-six-bootstrap-v1",
            "typed-compact-depth-six-bootstrap-v1", "typed-finalizer-compact-depth-six-bootstrap-v1",
            "typed-paired-depth-six-bootstrap-v1", "typed-paired-compact-depth-six-bootstrap-v1"):
        return "typed-attempt"
    return None


def metadata(run, data, adapter):
    run["adapter"] = adapter
    run["retained_metadata"] = data
    run["status"] = data.get("status", "unknown")
    construction = data.get("construction", data.get("config", {}).get("construction", "reference"))
    construction = {'typed-paired-v1': 'paired'}.get(construction, construction)
    run["configuration"] = {"budget": data.get("budget"), "construction": construction,
        "execution_backend": data.get("execution_backend", data.get("config", {}).get("execution_backend", "bootstrap")),
        "execution_result": data.get("execution_result"),
                            "ram_admission": data.get("ram_admission", data.get("config", {}).get("ram_admission", "full")),
        "registry_keys": data.get("registry_keys", {"reference": 5, "finalizer": 6, "paired": 12}.get(construction, 5)),
        "recorded_fresh_proofs": data.get("fresh_proofs")}
    run["timing"]["elapsed_seconds"] = data.get("elapsed_seconds")
    run["timing"]["recursive_seconds"] = data.get("proving_seconds")
    run["workload"]["user_transactions"] = None
    run["workload"]["issuance_transactions"] = None
    run["workload"]["count_evidence"] = None
    if adapter == "typed-preparation":
        run.update(kind="diagnostic", track="linux-cpu", measurement_scope="typed_registry_preparation")
        run["label"] = f"Typed public fixture and {data.get('registry_keys', 5)} CPU verifier keys"
        run["platform"] = {"os": "linux", "backend": "cpu", "memory_model": "host_ram"}
        run["stages"] = [{**stage, "wall_seconds": stage.get("elapsed_seconds")}
                         for stage in data.get("stages", [])]
        run["limitations"].append("Leaf generation and CPU registration only; no recursive root or delivered transaction is measured.")
    else:
        run["configuration"]["query_readback_layout"] = (data.get("budget") or {}).get("query_readback_layout", "rows")
        run.update(track="linux-opencl", measurement_scope="typed_recursive_aggregation")
        run["label"] = "Mixed depth-six GPU bootstrap" + (" with finalizer" if construction == "finalizer" else "")
        if run["configuration"]["execution_backend"] == "typed-dag":
            run["label"] = "Mixed depth-six typed GPU DAG"
            run["limitations"].append("Each typed DAG has one owner and cached worker in the same process; persistent cross-process dispatch and arrival integration are unqualified.")
        elif run["configuration"]["execution_backend"] == "typed-process-dag":
            run["label"] = "Mixed depth-six typed DAG with persistent GPU child"
            run["limitations"].append("The DAG owner and persistent GPU worker are separate processes in one bounded service. Native arrival integration and active-worker recovery remain unqualified.")
        elif run["configuration"]["execution_backend"] == "typed-shared-process-dag":
            run["label"] = "Mixed depth-six root / shared GPU DAG"
            run["stages"] = [
                {"name": "Shared DAG proving", "status": data.get("status"),
                 "wall_seconds": data.get("proving_seconds")},
                {"name": "Independent CPU root audit", "status": "passed" if data.get("cpu_audited") else "unqualified",
                 "wall_seconds": data.get("cpu_audit_seconds")}]
            run["limitations"].append("One DAG owner dispatches independently bounded persistent GPU services. Native arrival integration and active-worker/coordinator recovery remain unqualified. Worker services contribute to one audited root.")
        run["workload"]["fixture_reuse"] = True
        run["platform"].update(os="linux", backend="opencl", memory_model="host_ram_and_vram")
        run["verification"].update(cpu_audited=data.get("cpu_audited"), root_bytes=data.get("root_bytes"),
                                  root_sha256=data.get("artifacts", {}).get("node.6.0"))
        run["limitations"].extend([
            "Research root verification; durable host application and delivered transactions are not measured.",
            "Worker time includes fixture copying, proving and an independent CPU root audit. CPU registration is excluded.",
            "This root alone does not qualify every transaction count, concurrent mixed proving, cold full-64, or the pilot."])


def native_intake(run, data, controller):
    if data.get("durable_arrival_intake") is not True:
        return
    intake = data.get("arrival_application", {})
    binding = data.get("native_host_binding", {})
    receipt = data.get("native_application", {})
    try:
        document = {key: value for key, value in intake.items() if key not in ("selection_id", "status", "application")}
        token = hashlib.sha256((json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()).hexdigest()
        requests = intake["request_ids"]
        valid = (run["verification"].get("native_applied") is True
                 and controller.get("arrival_application_independently_confirmed") is True
                 and data.get("arrival_publication_status") == "applied"
                 and intake.get("schema") == "lattica-native-arrivals-v1"
                 and intake.get("status") == "applied" and intake.get("application") == receipt
                 and intake.get("native_host_binding") == binding
                 and intake.get("host_configuration_sha256") == receipt.get("host_configuration_sha256")
                 and intake.get("manifest_sha256") == bytes(binding["preparation_sha256"]).hex()
                 and intake.get("selection_id") == token
                 and data.get("arrival_selection") == controller.get("arrival_selection") == token
                 and isinstance(requests, list) and len(requests) == data.get("count")
                 and all(isinstance(request, str) and request for request in requests)
                 and len(set(requests)) == len(requests))
    except (KeyError, ValueError, TypeError, OverflowError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("durable intake application is not independently confirmed or is inconsistent")
    run["verification"]["durable_intake_applied"] = True
    run["configuration"]["arrival_application"] = intake
    run["stages"].append({"name": "Durable intake application receipt", "status": "passed",
                          "wall_seconds": data.get("intake_publication_seconds")})
    run["limitations"].append("The sealed intake selection was marked applied after native replay. Active proving recovery remains unqualified.")
    if data.get('preseal_dispatch') is not True:
        run['limitations'].append('This run does not qualify pre-seal dispatch.')


def preseal_evidence(run, data, controller, path, root):
    """Keep subtree audits and reused work separate from fresh root accounting."""
    execution = data.get('execution_result') or {}
    reused = data.get('reused_proofs', 0)
    records = execution.get('reused_nodes', [])
    if (type(reused) is not int or reused < 0 or reused != execution.get('reused_proofs', 0)
            or not isinstance(records, list) or len(records) != reused
            or any(not isinstance(node, dict) or node.get('cpu_reverified') is not True for node in records)):
        raise ValueError('pre-seal reuse accounting or CPU reverification differs')
    run['configuration']['recorded_reused_proofs'] = reused
    if execution.get('coordinator_recovery') is not None:
        if data.get('preseal_only') or controller.get('preseal_dispatch'):
            raise ValueError('coordinator recovery cannot be reported as pre-seal reuse')
        return
    if reused:
        pinned = read(path.parent.parent / 'config.json')['pins']
        retained = []
        for node in records:
            source = Path(node['source'])
            name = f'node.{node["level"]}.{node["index"]}'
            copied = path.parent / 'proofs' / name
            if source.name != name or digest(source) != pinned.get(str(source)) or digest(copied) != digest(source):
                raise ValueError('reused subtree differs from pinned cache or copied artifact')
            source_result = source.parent.parent / 'result.json'
            prefix = read(source_result)
            if (prefix.get('preseal_only') is not True or prefix.get('cpu_prefix_audited') is not True
                    or prefix.get('status') != 'succeeded' or prefix.get('artifacts', {}).get(name) != digest(source)):
                raise ValueError('reused subtree has no matching successful prefix audit')
            run['sources'].extend(reference(p, root) for p in [source, copied, source_result, source.parent / 'result.json'])
            retained.append({**node, 'source': relative(source, root), 'sha256': digest(source)})
        run['configuration']['preseal_reuse'] = {'count': reused, 'nodes': retained,
            'fresh_proofs': data.get('fresh_proofs'), 'cpu_reverified': True}
        if run['verification'].get('native_applied') is True:
            run['measurement_scope'] = 'typed_native_candidate_application_with_preseal_reuse'
        run['sources'].append(reference(path.parent.parent / 'config.json', root))
        run['limitations'].append('The recursive command includes fresh CPU verification of cached subtrees. Prefix proving and preparation occurred before this owner window. Reused proofs are counted separately from fresh proofs. This staged qualification is not a matched speedup measurement.')
    if data.get('preseal_only') is not True:
        return
    if controller.get('status') != 'succeeded':
        run.update(status=controller.get('status', 'failed'), measurement_scope='typed_native_preseal_subtrees',
                   label=f'Typed {data.get("count")}-arrival prefix with unconfirmed controller completion')
        run['verification'].update(cpu_audited=None, root_bytes=0, root_sha256=None)
        run['configuration']['preseal_prefix'] = {'arrivals': data.get('count'), 'controller_confirmed': False}
        run['stages'] = [{'name': 'Unsealed subtree proving', 'status': data.get('status'), 'wall_seconds': data.get('proving_seconds')},
                         {'name': 'Controller completion', 'status': controller.get('status')}]
        run['limitations'] = [controller.get('failure', 'The outer controller did not confirm prefix completion.'),
                              'Retained subtree proofs and CPU audit do not establish a qualified complete phase, root, or native application.']
        for source in [path.parent / 'prefix-audit.json', path.parent / 'proofs/result.json']:
            if source.is_file():
                run['sources'].append(reference(source, root))
        return
    audit_path = path.parent / 'prefix-audit.json'
    audit = read(audit_path)
    if (controller.get('status') != 'succeeded' or controller.get('prefix_independently_confirmed') is not True
            or controller.get('cpu_audited_roots') != 0 or data.get('cpu_audited') is not False
            or data.get('cpu_prefix_audited') is not True or data.get('native_blocks_applied') != 0
            or data.get('durable_host_applied') is not False or execution.get('preseal_only') is not True
            or execution.get('root_file') is not None or audit != data.get('prefix_audit')
            or audit.get('status') != 'passed' or audit.get('cpu_audited_roots') != 0
            or len(audit.get('nodes', [])) != data.get('fresh_proofs', 0) + reused
            or (path.parent / 'proofs/node.6.0').exists()):
        raise ValueError('unsealed prefix audit cannot establish a root or native application')
    for node in audit['nodes']:
        name = f'node.{node["level"]}.{node["index"]}'
        source = path.parent / 'proofs' / name
        if digest(source) != data.get('artifacts', {}).get(name):
            raise ValueError('audited prefix subtree changed')
        run['sources'].append(reference(source, root))
    run['sources'].extend(reference(p, root) for p in [audit_path, path.parent / 'proofs/result.json'])
    run.update(measurement_scope='typed_native_preseal_subtrees',
               label=f'Typed {data.get("count")}-arrival unsealed GPU subtrees')
    run['verification'].update(cpu_audited=None, cpu_prefix_audited=True, root_bytes=0, root_sha256=None)
    run['configuration']['preseal_prefix'] = {'arrivals': data.get('count'), 'audit': audit,
                                            'native_head_unchanged': True, 'arrival_claims': 0}
    run['stages'] = [
        {'name': 'Unsealed subtree proving', 'status': 'passed', 'wall_seconds': data.get('proving_seconds')},
        {'name': 'Independent CPU subtree audit and native checks', 'status': 'passed', 'wall_seconds': data.get('cpu_audit_seconds')}]
    run['limitations'] = ['Complete subtrees were CPU audited while arrivals remained unclaimed. No root or native application was produced in this phase.',
                          'Wallet proofs were retained inputs. Transaction throughput and active proving recovery remain unqualified.']


def pending_preparation(run, data, root):
    if run["verification"].get("durable_intake_applied") is not True:
        return
    intake = data.get("arrival_application", {})
    fixture = intake.get("fixture")
    if not isinstance(fixture, str) or not fixture:
        return
    manifest_path = Path(fixture) / "manifest.json"
    if not manifest_path.is_file():
        return
    manifest = read(manifest_path)
    if manifest.get("preparation_backend") != "durable-pending-arrivals":
        return
    binding = run["configuration"].get("native_host_binding", {})
    seconds = manifest.get("elapsed_seconds")
    try:
        valid = (
            digest(manifest_path) == intake.get("manifest_sha256") == bytes(binding["preparation_sha256"]).hex()
            and manifest.get("record_type") == "native_delivery_preparation"
            and manifest.get("status") == "succeeded"
            and manifest.get("native_state_preflight_passed") is True
            and manifest.get("independently_cpu_verified_wallets") == data.get("count")
            and manifest.get("fresh_leaf_proofs") == 0
            and manifest.get("reused_leaf_proofs") == data.get("count")
            and manifest.get("request_ids") == intake.get("request_ids")
            and manifest.get("parent_head_token") == bytes(binding["head_token"]).hex()
            and manifest.get("host_configuration_sha256") == intake.get("host_configuration_sha256")
            and type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0
        )
    except (KeyError, ValueError, TypeError, OverflowError):
        valid = False
    if not valid:
        raise ValueError("pending preparation differs from the native applied selection")
    run["configuration"]["pending_preparation"] = manifest
    run["sources"].append(reference(manifest_path, root))
    run["stages"].insert(0, {"name": "Pending transaction preparation (before controller)",
                              "status": "passed", "wall_seconds": seconds})
    run["limitations"].append("Pending preparation includes native state preflight and CPU authentication of existing wallet proofs. It precedes the separately measured GPU controller window; fresh wallet proving is excluded.")


def native_application(run, data, controller):
    if data.get("durable_host_applied") is not True:
        return
    if controller.get("status") != "succeeded" or data.get("status") != "succeeded":
        run["limitations"].append("The owner recorded native application, but the outer controller did not confirm its published state.")
        return
    receipt, binding = data.get("native_application", {}), data.get("native_host_binding", {})
    execution = data.get("execution_result", {})
    try:
        head = bytes(binding["head_token"]).hex()
        body = bytes(binding["complete_body_sha256"]).hex()
        valid = (len(head) == 64 and len(body) == 64
            and data.get("native_application_status") == "applied"
            and type(data.get("native_blocks_applied")) is int and data["native_blocks_applied"] == 1
            and execution.get("native_host_bound") is True and execution.get("native_host") == binding
            and controller.get("native_host_binding") == binding
            and receipt.get("record_type") == "native_shared_candidate_application"
            and receipt.get("durability_confirmed") is True
            and receipt.get("native_verifier", {}).get("kind") == "native-root-replay-v1"
            and receipt.get("parent_head_token") == head
            and receipt.get("complete_body_sha256") == body
            and receipt.get("root_sha256") == data.get("artifacts", {}).get("node.6.0")
            and type(receipt.get("count")) is int and receipt["count"] == data.get("count")
            and receipt["count"] == binding["expected"]["count"]
            and type(receipt.get("generation")) is int and type(binding["generation"]) is int
            and receipt.get("generation") == binding["generation"] + 1
            and receipt.get("state", {}).get("height") == binding["expected"]["block_height"])
    except (KeyError, ValueError, TypeError, OverflowError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("native shared application receipt is inconsistent")
    recovered = data.get('native_application_recovered', False)
    fresh_blocks = data.get('fresh_native_blocks_applied', 1)
    if (type(recovered) is not bool or type(fresh_blocks) is not int
            or fresh_blocks != int(not recovered)
            or (recovered and (data.get('cached_native_continuation') is not True
                               or execution.get('cached_native_continuation') is not True))):
        raise ValueError('native application recovery marker or fresh block count is inconsistent')
    run["measurement_scope"] = "typed_native_candidate_application"
    run["verification"]["native_applied"] = True
    run["configuration"].update(native_application=receipt, native_host_binding=binding,
                                native_application_recovered=recovered, fresh_native_blocks_applied=fresh_blocks)
    run["stages"].append({"name": "Recover published native application receipt" if recovered else "Fenced native journal application", "status": "passed",
                          "wall_seconds": data.get("native_application_seconds")})
    run["limitations"] = [item for item in run["limitations"] if not item.startswith((
        "One DAG owner dispatches", "Research root verification;", "Worker time includes"))]
    run["limitations"].extend([
        "One local native candidate was applied and its published state was independently replayed. Sustained arrival-driven throughput and active-worker/coordinator recovery remain unqualified.",
        "Owner time includes native head replay, fixture copying, proving, CPU root audit and fenced application. Fresh wallet preparation and the outer controller's journal replay are outside this interval."])
    if recovered:
        run['limitations'] = [item for item in run['limitations'] if not item.startswith('One local native candidate')]
        run['limitations'].append('An already published native block was independently replayed and its receipt recovered; this phase applied zero new blocks. Sustained arrival-driven throughput and broader failure recovery remain unqualified.')
    native_intake(run, data, controller)


def retained_recovery_proof(previous, runtime, name, after):
    """Match the CPU recovery receipt to retained bytes, including failed exports.

    Rust recovery establishes journal acceptance and CPU verification. This
    importer checks byte identity and pins the original artifact and journal;
    it does not implement a second journal parser or proof verifier.
    """
    before = previous / name
    if before.is_symlink() or after.is_symlink() or not after.is_file():
        raise ValueError('recovered node differs from the retained accepted proof')
    if before.is_file():
        if digest(before) != digest(after):
            raise ValueError('recovered node differs from the retained accepted proof')
        return before, None
    artifacts, journal = runtime / 'artifacts', runtime / 'journal/state'
    if (not artifacts.is_dir() or artifacts.is_symlink() or not journal.is_file()
            or journal.is_symlink()):
        raise ValueError('unexported recovered proof lacks its retained artifact journal')
    matches = []
    expected, size = digest(after), after.stat().st_size
    for item in artifacts.iterdir():
        if (re.fullmatch(r'n-[0-9a-f]{64}\.proof', item.name) and not item.is_symlink()
                and item.is_file() and item.stat().st_size == size and digest(item) == expected):
            matches.append(item)
    if len(matches) != 1:
        raise ValueError('unexported recovered proof lacks one exact retained artifact')
    return matches[0], journal


def coordinator_recovery(run, data, path, root):
    execution = data.get('execution_result') or {}
    receipt = execution.get('coordinator_recovery')
    if receipt is None:
        return
    if (receipt != data.get('coordinator_recovery') or run['verification'].get('native_applied') is not True
            or any(receipt.get(key) is not True for key in (
                'old_coordinator_quiescent', 'old_workers_quiescent', 'old_launches_revoked',
                'old_workspace_reservations_released', 'original_resource_assignments_preserved'))
            or receipt.get('coordinator_pid') != execution.get('coordinator_pid')
            or type(receipt.get('previous_epoch')) is not int or receipt['previous_epoch'] < 1
            or receipt.get('recovery_epoch') != receipt['previous_epoch'] + 1
            or receipt.get('recovery_epoch') != execution.get('recovery_epoch')):
        raise ValueError('coordinator recovery lacks complete reconciliation and native application')
    previous = Path(receipt['source'])
    old = read(previous / 'coordinator.json')
    current = read(path.parent / 'proofs/coordinator.json')
    state = read(previous / 'recovery-state.json')
    current_state = read(path.parent / 'proofs/recovery-state.json')
    recorded_receipt = read(path.parent / 'proofs/coordinator-recovery.json')
    if (old['identity']['pid'] != receipt.get('previous_coordinator_pid')
            or current['identity']['pid'] != receipt['coordinator_pid']
            or old['identity']['pid'] == current['identity']['pid']
            or old['executable'] != current['executable']
            or state['epoch'] != receipt['previous_epoch']
            or state['durable_runtime'] != receipt['durable_runtime']
            or current_state['epoch'] != receipt['recovery_epoch']
            or current_state['durable_runtime'] != state['durable_runtime']
            or recorded_receipt != receipt):
        raise ValueError('coordinator recovery identity or journal origin differs')
    nodes = []
    unexported = 0
    for node in execution.get('reused_nodes', []):
        name = f'node.{node["level"]}.{node["index"]}'
        after = path.parent / 'proofs' / name
        if (node.get('recovered_from_journal') is not True or node.get('cpu_reverified') is not True
                or node.get('source') != state['durable_runtime']
                or not after.is_file() or node.get('bytes') != after.stat().st_size):
            raise ValueError('recovered node differs from the retained accepted proof')
        before, journal = retained_recovery_proof(previous, Path(state['durable_runtime']), name, after)
        retained = {**node, 'source': relative(before, root), 'sha256': digest(after)}
        if journal is not None:
            unexported += 1
            retained.update(previous_export_missing=True, source_kind='durable_artifact')
            run['sources'].append(reference(journal, root))
        nodes.append(retained)
        run['sources'].extend(reference(source, root) for source in [before, after])
    for source in [previous / 'coordinator.json', previous / 'recovery-state.json',
            previous / 'fleet-plan.json', path.parent / 'proofs/coordinator.json',
            path.parent / 'proofs/coordinator-recovery.json', path.parent / 'proofs/recovery-state.json']:
        run['sources'].append(reference(source, root))
    run['configuration']['coordinator_recovery'] = {**receipt, 'nodes': nodes,
        'reused_proofs': len(nodes), 'fresh_proofs': data.get('fresh_proofs'), 'cpu_reverified': True,
        'recovered_unexported_proofs': unexported}
    cached_only = execution.get('cached_native_continuation', False)
    if type(cached_only) is not bool or data.get('cached_native_continuation', False) is not cached_only:
        raise ValueError('cached native continuation marker differs from the execution receipt')
    if cached_only:
        if (data.get('cached_native_continuation') is not True or not nodes
                or data.get('fresh_proofs') != 0 or execution.get('fresh_proofs') != 0
                or execution.get('gpu_workers_started') != 0 or execution.get('workers') != []
                or execution.get('maximum_active_jobs') != 0 or execution.get('backend') != 'cpu'):
            raise ValueError('cached native continuation contains new GPU work')
        run['configuration']['coordinator_recovery'].update(cached_native_continuation=True,
            recovery_seconds=data.get('proving_seconds'))
        run.update(track='linux-cpu', platform={'os': 'linux', 'backend': 'cpu'},
            measurement_scope='typed_native_cached_root_application_after_coordinator_restart')
        if run['configuration'].get('native_application_recovered'):
            run['measurement_scope'] = 'typed_native_cached_application_receipt_recovery_after_coordinator_restart'
        elif unexported:
            run['measurement_scope'] = 'typed_native_cached_root_export_recovery_after_coordinator_restart'
        run['label'] = 'Cached root recovery and native application'
        run['timing']['recursive_seconds'] = None
        for stage in run['stages']:
            if stage['name'] == 'Shared DAG proving':
                stage['name'] = 'Cached root recovery and CPU reverification'
        run['limitations'].append('All proofs were produced before this continuation. No GPU worker, fresh proof or new proving throughput was measured; the retained GPU assignments identify the earlier workers.')
    else:
        run['measurement_scope'] = 'typed_native_candidate_application_after_coordinator_restart'
        run['stages'].append({'name': 'Original journal recovery and CPU reverification',
            'status': 'passed', 'wall_seconds': None})
    run['limitations'] = [item for item in run['limitations'] if not item.startswith(
        'One local native candidate was applied and its published state was independently replayed.')]
    run['limitations'].append('This row measures the resumed coordinator phase. Earlier interruptions and rejected attempts are retained separately. Automatic supervision, coordinator bootstrap interruptions, resource exhaustion, active reorg/stale results, all-worker failure and sustained transaction throughput remain unqualified.')


def worker_memory_failure(worker):
    if 'memory_failure' not in worker:
        return None
    pairs = [line.split() for line in worker['accounting']['memory.events'].splitlines()]
    if any(len(pair) != 2 for pair in pairs):
        raise ValueError('worker memory event accounting is malformed')
    events = {key: int(value) for key, value in pairs}
    if (len(events) != len(pairs) or any(value < 0 for value in events.values()) or
            not {'high', 'max', 'oom', 'oom_kill', 'oom_group_kill'}.issubset(events)):
        raise ValueError('worker memory counters are incomplete or inconsistent')
    recorded = worker['memory_failure']
    if recorded is None:
        if any(events.values()):
            raise ValueError('worker memory events were not classified as a failure')
        return None
    if (not isinstance(recorded, dict) or not any(events.values()) or
            recorded.get('memory_events') != events or
            any(type(value) is not int for value in recorded.get('memory_events', {}).values()) or
            recorded.get('oom_killed') is not (events['oom_kill'] > 0 or events['oom_group_kill'] > 0) or
            not 0 < int(worker['accounting']['memory.peak']) <= worker['budget']['host']['worker_bytes']):
        raise ValueError('worker memory failure differs from retained accounting')
    return dict(gpu_uuid=worker['gpu_uuid'], worker_pid=worker['termination']['worker_pid'],
                memory_events=events, oom_killed=recorded['oom_killed'])


def worker_failover(run, data, controller):
    execution = data.get("execution_result", {})
    failed = [worker for worker in execution.get("workers", []) if worker.get("worker_failed")]
    if not failed:
        if data.get("failed_workers", 0) or execution.get("failed_workers", 0):
            raise ValueError("worker failure count has no retained termination records")
        return
    if (data.get("allow_worker_failover") is not True
            or execution.get("allow_worker_failover") is not True
            or data.get("failed_workers") != len(failed)
            or execution.get("failed_workers") != len(failed)
            or len(execution.get("workers", [])) <= len(failed)
            or run["verification"].get("native_applied") is not True):
        raise ValueError("worker failover requires an applied native root and surviving worker")
    memory_failures = []
    for worker in failed:
        if (any(worker.get(key) is not True for key in (
                "forced_stop_confirmed", "launch_revoked", "workspace_released",
                "process_and_cgroup_quiescent", "gpu_teardown_confirmed"))
                or worker.get("teardown_method") != "process_and_cgroup_exit"
                or worker.get("exit_code") is not None
                or type(worker.get("reconciled_ms")) is not int
                or worker["reconciled_ms"] < 0):
            raise ValueError("worker failover lacks confirmed teardown and release")
        for key in ("failed_job", "lease_key"):
            value = worker.get(key)
            if (not isinstance(value, str) or len(value) != 64
                    or any(c not in "0123456789abcdef" for c in value)):
                raise ValueError("worker failover lacks exact job and lease identities")
        outer = [row for row in controller.get("workers", [])
                 if row.get("gpu_uuid") == worker.get("gpu_uuid")
                 and row.get("termination", {}).get("worker_pid") == worker.get("worker_pid")]
        if (len(outer) != 1 or outer[0].get("worker_failed") is not True
                or outer[0].get("termination") != worker):
            raise ValueError("worker failover termination differs from controller accounting")
        memory = worker_memory_failure(outer[0])
        if memory is not None:
            memory_failures.append(memory)
    if memory_failures:
        expected = dict.fromkeys(memory_failures[0]['memory_events'], 0)
        for failure in memory_failures:
            if set(failure['memory_events']) != set(expected):
                raise ValueError('failed workers have different memory event counters')
            for key, value in failure['memory_events'].items():
                expected[key] += value
        if controller.get('parent_memory_event_deltas') != expected:
            raise ValueError('fleet memory events differ from drained failed worker accounting')
    run["configuration"]["worker_failover"] = {
        "failed_workers": len(failed), "terminations": failed, "memory_failures": memory_failures,
        "coordinator_recovery_qualified": False, "worker_replacement_qualified": False,
        "scope": "An active worker failed; the same coordinator completed the native candidate using surviving original assignments."}
    run["measurement_scope"] = "typed_native_candidate_application_with_worker_failover"
    run["stages"].append({"name": "Active worker failover", "status": "passed", "wall_seconds": None})
    run["limitations"] = [item for item in run["limitations"] if not item.startswith(
        "One local native candidate was applied and its published state was independently replayed.")]
    run["limitations"].append(
        "Active collection failure recovered on a surviving GPU. Coordinator restart, worker replacement, startup/dispatch failures, OOM recovery and sustained transaction throughput remain unqualified. Failure and retry time are included; no matched speedup is claimed.")


    if memory_failures:
        run['stages'].append({'name': 'Worker memory failure and survivor retry', 'status': 'passed', 'wall_seconds': None})
        run['limitations'][-1] = ('A drained worker memory failure was recovered on the surviving GPU. '
            'The fleet event deltas exactly match the failed-worker counters. Failure and retry time are included. '
            'Automatic worker replacement, broader resource exhaustion, active reorg, and complete cold/post-seal throughput remain unqualified.')


def resource_exhaustion(run, directory, root):
    """Retain a qualified physical resource fault with its pinned observations."""
    path = directory / 'fault-qualification.json'
    if not path.is_file():
        return
    fault = read(path)
    recovery = run['configuration'].get('worker_failover', {})
    kind = fault.get('failure', {}).get('kind')
    if (fault.get('status') != 'passed'
            or kind not in ('private_spill_capacity_exhaustion', 'gpu_vram_exhaustion')
            or fault.get('native_blocks_applied') != 1
            or fault.get('intake_application_events') != 1
            or fault.get('duplicate_applications') != 0
            or type(fault.get('accepted_proofs_preserved')) is not int
            or fault['accepted_proofs_preserved'] < 1
            or fault.get('target_gpu_uuid') not in {
                row.get('gpu_uuid') for row in recovery.get('terminations', [])}
            or run['verification'].get('cpu_audited') is not True
            or run['verification'].get('native_applied') is not True
            or not fault.get('sources')):
        raise ValueError('resource exhaustion lacks qualified survivor recovery')
    failure = fault['failure']
    if kind == 'private_spill_capacity_exhaustion':
        if (failure.get('kernel_signal') != 'SIGBUS'
                or failure.get('filesystem', {}).get('exhausted', {}).get('free_bytes') != 0):
            raise ValueError('spill exhaustion lacks physical capacity failure')
    else:
        pressure = failure.get('pressure', {})
        if (failure.get('opencl_error') not in ('CL_MEM_OBJECT_ALLOCATION_FAILURE', 'CL_OUT_OF_RESOURCES')
                or pressure.get('status') != 'succeeded'
                or pressure.get('selected_uuid') != fault['target_gpu_uuid']
                or not 0 < pressure.get('allocated_bytes', 0) <= 14 * 1024**3
                or pressure.get('free_status') != 0 or pressure.get('destroy_status') != 0):
            raise ValueError('VRAM exhaustion lacks released device-memory pressure')
    for pin in fault['sources']:
        if reference(root / pin['path'], root) != pin:
            raise ValueError('resource fault source changed')
    run['sources'].extend([reference(path, root), *fault['sources']])
    run['configuration']['resource_exhaustion'] = fault
    run['stages'].append({'name': 'Physical resource exhaustion and survivor retry',
                          'status': 'passed', 'wall_seconds': None})
    run['limitations'] = [item for item in run['limitations'] if not item.startswith(
        'Active collection failure recovered on a surviving GPU.')]
    run['limitations'].append('Physical resource exhaustion recovered on the surviving GPU with accepted proofs preserved. '
        'Failure and retry time are included. Automatic supervision and worker replacement, complete cold/post-seal '
        'timing, and sustained transaction throughput remain unqualified.')


def pipeline_seal_timing(record):
    """Validate exact monotonic boundaries; keep nanoseconds lossless in browsers."""
    fields = ('pipeline_interval', 'seal_interval', 'seal_start_to_controller_exit_seconds',
              'seal_end_to_controller_exit_seconds')
    present = [name in record for name in fields]
    if not any(present):
        return False
    if not all(present):
        raise ValueError('native pipeline has incomplete seal timing')

    def stamp(value):
        if not isinstance(value, dict):
            raise ValueError('native pipeline timestamp is not an object')
        normalized = dict(value)
        for name in ('monotonic_ns', 'wall_time_ns'):
            ns = value.get(name)
            if type(ns) is str and ns.isascii() and ns.isdigit() and len(ns) <= 20:
                ns = int(ns)
                if str(ns) != value[name]:
                    raise ValueError('native pipeline timestamp is not canonical')
            if type(ns) is not int or not 0 <= ns < 2**64:
                raise ValueError('native pipeline timestamp is not unsigned nanoseconds')
            normalized[name] = str(ns)
        try:
            utc = datetime.fromisoformat(value['utc'])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError('native pipeline timestamp lacks a UTC instant') from error
        if utc.tzinfo is None or utc.utcoffset() != timezone.utc.utcoffset(utc):
            raise ValueError('native pipeline timestamp is not UTC')
        return normalized

    intervals = {}
    for name in fields[:2]:
        value = record[name]
        if not isinstance(value, dict):
            raise ValueError('native pipeline seal interval is not an object')
        intervals[name] = dict(value, started_at=stamp(value.get('started_at')),
                              finished_at=stamp(value.get('finished_at')))
    pipeline, seal = (intervals[name] for name in fields[:2])
    start, end = (int(pipeline[key]['monotonic_ns']) for key in ('started_at', 'finished_at'))
    seal_start, seal_end = (int(seal[key]['monotonic_ns']) for key in ('started_at', 'finished_at'))
    if not start <= seal_start < seal_end <= end:
        raise ValueError('native pipeline seal timestamps are out of order')
    measured = [(record['pipeline_seconds'], end-start), (seal.get('seconds'), seal_end-seal_start),
                (record[fields[2]], end-seal_start), (record[fields[3]], end-seal_end)]
    if any(type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0
           or not math.isclose(seconds, ns / 1e9, rel_tol=1e-12, abs_tol=1e-9)
           for seconds, ns in measured):
        raise ValueError('native pipeline seal durations differ from timestamps')
    if record[fields[3]] < record['sealed_application_seconds']:
        raise ValueError('native pipeline final invocation predates completed sealing')
    record.update(intervals)
    return True


def opening_cache_trial(run, record):
    """Keep resource qualification distinct from a matched cache comparison."""
    names = ('qualification_mode', 'context_phase', 'opening_denominator_cache',
             'performance_comparison')
    if not any(name in record for name in names):
        return False
    if not all(name in record for name in names):
        raise ValueError('opening cache trial metadata is incomplete')
    mode, phase = record['qualification_mode'], record['context_phase']
    comparison = record['performance_comparison']
    if (mode not in ('baseline', 'cache')
            or type(comparison) is not bool
            or record['opening_denominator_cache'] is not (mode == 'cache')
            or phase not in ('bootstrap', 'reduced-single', 'shared', 'matched')
            or comparison != (phase == 'matched')
            or record.get('case') == 'staged'
            or (phase == 'shared' and record.get('case') != 'shared')
            or (phase in ('bootstrap', 'reduced-single') and record.get('case') == 'shared')):
        raise ValueError('opening cache trial mode or context phase is inconsistent')
    cycle = record.get('comparison_cycle')
    if comparison:
        if type(cycle) is not int or not 1 <= cycle < 10000:
            raise ValueError('matched opening cache trial lacks a valid comparison cycle')
    elif 'comparison_cycle' in record:
        raise ValueError('resource qualification cannot claim a comparison cycle')
    workers = run['configuration'].get('shared_fleet', {}).get('workers', [])
    expected_workers = 2 if record.get('case') == 'shared' else 1
    if len(workers) != expected_workers or any(
            worker.get('budget', {}).get('opening_denominator_cache') is not (mode == 'cache')
            or worker.get('budget', {}).get('gpu', {}).get('bootstrap') is not (phase == 'bootstrap')
            for worker in workers):
        raise ValueError('opening cache trial differs from retained worker assignments')
    return not comparison


def native_pipeline(run, directory, root):
    """Retain a native qualification's complete preparation/application interval."""
    path = directory / 'pipeline-qualification.json'
    if not path.is_file():
        return
    record = read(path)
    case = record.get('case')
    resource_qualification = opening_cache_trial(run, record)
    if (record.get('status') != 'passed'
            or case not in ('single-laptop', 'single-desktop', 'shared', 'staged')
            or record.get('count') != 8
            or record.get('native_blocks_applied') != 1
            or record.get('duplicate_applications') != 0
            or record.get('matched_repetitions_completed') != (0 if resource_qualification else 1)
            or any(run['verification'].get(key) is not True for key in (
                'cpu_audited', 'native_applied', 'durable_intake_applied'))
            or record.get('summary') != reference(directory/'summary.json', root)
            or not record.get('sources')):
        raise ValueError('native pipeline lacks complete qualified application')
    for pin in record['sources']:
        if reference(root/pin['path'], root) != pin:
            raise ValueError('native pipeline source changed')
    if record['summary'] not in record['sources']:
        raise ValueError('native pipeline summary is not pinned')
    names = ('proving_seconds', 'owner_seconds', 'controller_invocation_seconds',
             'sealed_application_seconds', 'pipeline_seconds')
    intervals = [record.get(key) for key in names]
    if (any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0 for value in intervals)
            or intervals != sorted(intervals)
            or record['owner_seconds'] != run['timing']['elapsed_seconds']
            or record['proving_seconds'] != run['timing']['recursive_seconds']):
        raise ValueError('native pipeline timing boundaries are inconsistent')
    staged = case == 'staged'
    fresh, reused = (5, 3) if staged else (8, 0)
    if (record.get('fresh_recursive_proofs') != fresh
            or record.get('reused_recursive_proofs') != reused
            or run['configuration'].get('recorded_fresh_proofs') != fresh
            or (staged and run['configuration'].get('preseal_reuse', {}).get('count') != reused)
            or type(record.get('prefix_invocation_seconds')) not in (int, float)
            or not math.isfinite(record['prefix_invocation_seconds'])
            or not 0 <= record['prefix_invocation_seconds'] < record['pipeline_seconds']
            or (record['prefix_invocation_seconds'] > 0) != staged):
        raise ValueError('native pipeline fresh/reused work is inconsistent')
    exact_seal = pipeline_seal_timing(record)
    repetition = record.get('repetition')
    if repetition is not None and (type(repetition) is not int or not 1 <= repetition <= 10000):
        raise ValueError('native pipeline repetition is invalid')
    if repetition is not None and not exact_seal:
        raise ValueError('repeated native pipeline requires exact seal timestamps')
    if resource_qualification and not exact_seal:
        raise ValueError('opening cache qualification requires exact seal timestamps')
    run['configuration']['native_pipeline'] = record
    run['timing']['elapsed_seconds'] = record['pipeline_seconds']
    run['measurement_scope'] = 'typed_native_fixed_allocation_pipeline'
    run['sources'].extend([reference(path, root), *record['sources']])
    run['stages'].append(dict(name='Candidate preparation through native application',
                              status='succeeded', wall_seconds=record['pipeline_seconds']))
    scope = (f'One arm of repetition {repetition}, with fixed per-GPU limits and retained wallet/public inputs. '
             if repetition is not None else
             'One fixed-allocation qualification cycle, using identical retained wallet/public inputs. ')
    if record.get('performance_comparison') is True:
        scope = (f"One arm of comparison cycle {record['comparison_cycle']}, with fixed per-GPU limits "
                 'and retained wallet/public inputs. ')
    if resource_qualification:
        scope = ('One full-root resource qualification arm for the '
                 f"{record['qualification_mode']} mode, {record['context_phase']} context phase. "
                 'This arm does not establish a matched performance comparison or solving-time improvement. ')
    boundary = ('Exact seal start/end timestamps and intervals to controller exit are retained. '
                'Controller exit is an upper bound on host-ready time. This record does not establish '
                'sustained chain throughput.' if exact_seal else
                'The final invocation starts after preparation and seal checks; it does not measure '
                'the complete seal-to-ready boundary. Repeated timing trials remain pending.')
    run['limitations'].append(scope +
        'Elapsed time and per-run rate include pending-candidate preparation, prefix work when staged, '
        'final proving, CPU root audit and native application. Arrival submission, wallet proof creation '
        'and separate replay checks are excluded. ' + boundary)


def supervision(run, directory, root):
    """Use the full supervised invocation for elapsed time and transaction rate."""
    path = directory / 'supervision-qualification.json'
    if not path.is_file():
        return
    record = read(path)
    case = record.get('case')
    if (record.get('status') != 'passed'
            or case not in ('all-workers', 'supervisor-crash')
            or any(run['verification'].get(key) is not True for key in (
                'cpu_audited', 'native_applied', 'durable_intake_applied'))
            or record.get('native_blocks_applied') != 1
            or record.get('intake_application_events') != 1
            or record.get('duplicate_applications') != 0
            or type(record.get('accepted_proofs_preserved')) is not int
            or record['accepted_proofs_preserved'] < 1
            or not record.get('sources')):
        raise ValueError('supervision lacks qualified native recovery')
    for pin in record['sources']:
        if reference(root / pin['path'], root) != pin:
            raise ValueError('supervision source changed')
    for key in ('supervisor_result', 'invocation_exit'):
        if record.get(key) not in record['sources']:
            raise ValueError('supervision lacks pinned result or full invocation')
    result = read(root / record['supervisor_result']['path'])
    invocation = read(root / record['invocation_exit']['path'])
    attempts = result.get('attempts', [])
    seconds = invocation.get('seconds')
    owner_seconds = run['timing']['elapsed_seconds']
    proving_seconds = run['timing']['recursive_seconds']
    if (result.get('status') != 'succeeded'
            or result.get('record_type') != 'typed_native_supervision'
            or not attempts
            or [item.get('number') for item in attempts] != list(range(1, len(attempts)+1))
            or any(item.get('action') != 'recover' for item in attempts[:-1])
            or attempts[-1].get('action') != 'succeeded'
            or (root / attempts[-1]['directory']).resolve() != directory.resolve()
            or record.get('controller_attempts') != len(attempts)
            or record.get('controller_retries') != len(attempts)-1
            or result.get('retries') != len(attempts)-1
            or invocation.get('returncode') != 0
            or type(seconds) not in (float, int) or not math.isfinite(seconds)
            or type(owner_seconds) not in (float, int)
            or type(proving_seconds) not in (float, int)
            or not 0 < proving_seconds <= owner_seconds <= seconds
            or record.get('invocation_seconds') != seconds
            or record.get('owner_seconds') != owner_seconds
            or record.get('proving_seconds') != proving_seconds):
        raise ValueError('supervision timing or attempt identity is inconsistent')
    recovery = run['configuration'].get('coordinator_recovery', {})
    expected = (2, 1) if case == 'all-workers' else (1, 2)
    if ((len(attempts), record.get('supervisor_invocations')) != expected
            or record.get('automatic_recovery') is not (case == 'all-workers')
            or record.get('live_controller_adopted') is not (case == 'supervisor-crash')
            or (case == 'all-workers' and recovery.get('reused_proofs') != record['accepted_proofs_preserved'])):
        raise ValueError('supervision recovery case is inconsistent')
    run['configuration']['supervision'] = record
    run['timing']['elapsed_seconds'] = seconds
    run['measurement_scope'] = 'typed_native_supervised_candidate_application'
    run['sources'].extend([reference(path, root), *record['sources']])
    run['stages'].append(dict(name='Full supervised invocation including interruptions',
                              status='succeeded', wall_seconds=seconds))
    run['limitations'].append(
        'Elapsed time and transaction rate include the full supervised invocation, including interruption, '
        'restart and recovery. Owner and proving intervals cover only the final controller attempt. '
        'Wallet proving, preparation and separate exact-once replays are excluded. '
        'This is one fault trial, not sustained transaction throughput.')


def stale_candidate(run, data, controller, directory, root):
    change = controller.get('native_head_change')
    if change is None:
        return
    binding = controller.get('fleet_plan', {}).get('native_host', {})
    selection = controller.get('stale_selection')
    try:
        expected, observed = change['expected_head_token'], change['observed_head_token']
        valid = (controller['status'] == 'failed' and data.get('status', 'failed') == 'failed'
            and data.get('durable_host_applied') is not True
            and type(data.get('native_blocks_applied', 0)) is int
            and data.get('native_blocks_applied', 0) == 0
            and data.get('native_application_status') != 'indeterminate'
            and change['observation_is_native_validation'] is False
            and all(isinstance(token, str) and len(token) == 64 and bytes.fromhex(token).hex() == token
                    for token in (expected, observed)) and expected != observed
            and bytes(binding['head_token']).hex() == expected
            and type(change['expected_generation']) is int
            and change['expected_generation'] == binding['generation'])
        cancelled = selection is not None
        if cancelled:
            valid = valid and (change.get('owner_and_workers_quiescent') is True
                and type(change['quiescent_monotonic_ns']) is int
                and type(change['observed_monotonic_ns']) is int
                and change['quiescent_monotonic_ns'] >= change['observed_monotonic_ns'] > 0
                and selection['status'] == 'cancelled' and selection['application'] is None
                and selection['selection_id'] == controller['arrival_selection']
                and selection['native_host_binding'] == binding
                and read(directory / 'stale-selection.json') == selection
                and 'cleanup_failure' not in controller)
        observation = read(directory / 'stale-head.json')
        valid = valid and all(change.get(key) == value for key, value in observation.items())
    except (KeyError, ValueError, TypeError, AttributeError, OSError):
        valid = False
    if not valid:
        raise ValueError('stale-head cancellation evidence is inconsistent')
    run.update(status='failed', measurement_scope='typed_native_stale_candidate_cancellation',
               label='Stale native candidate cancelled' if cancelled else 'Stale native candidate / cleanup failed')
    run['configuration']['native_head_change'] = dict(change, intake_cancelled=cancelled,
        cancellation_qualified=cancelled, cleanup_failure=controller.get('cleanup_failure'))
    run['sources'].append(reference(directory / 'stale-head.json', root))
    if cancelled:
        run['sources'].append(reference(directory / 'stale-selection.json', root))
    run['stages'].append(dict(name='Stale candidate cancellation', status='passed' if cancelled else 'failed',
        wall_seconds=(change['quiescent_monotonic_ns']-change['observed_monotonic_ns'])/1e9 if cancelled else None))
    run['limitations'].append('The native head changed. Accepted proof bytes are retained; this failed candidate contributes no delivered transactions. '
        + ('The owner and workers drained before intake claims were released.' if cancelled else 'Cleanup did not complete; intake cancellation is not qualified.'))


def shared_metadata(run, controller):
    assignments = (controller.get('fleet_plan') or {}).get('workers', [])
    workloads = {worker.get('assignment', {}).get('workload_kind') for worker in assignments}
    if len(workloads) == 1 and next(iter(workloads)) in (
            'typed-paired-depth-six-bootstrap-v1', 'typed-paired-compact-depth-six-bootstrap-v1'):
        run['configuration'].update(construction='paired', registry_keys=12,
                                    execution_backend='typed-shared-process-dag')
    run['configuration']['shared_fleet'] = {key: controller.get(key) for key in (
        'fleet_plan', 'workers', 'owner_accounting', 'parent_memory_event_deltas',
        'execution_elapsed_seconds', 'shared_dag_owner')}


def enrich(run, data, path, root):
    if run.get('adapter') == 'typed-controller':
        shared_metadata(run, data)
        stale_candidate(run, {}, data, path.parent, root)
        for source in sorted(path.parent.glob('**/accounting.json')):
            run['sources'].append(reference(source, root))
        return
    if data.get("schema") == SHARED_SCHEMA and run.get("adapter") == "typed-worker":
        summary = path.parent.parent / "summary.json"
        if summary.is_file():
            controller = read(summary)
            if controller.get("schema") != SHARED_SCHEMA or (
                    controller.get("status") == "succeeded" and controller.get("result") != data):
                raise ValueError("shared GPU summary differs from its owner result")
            run["sources"].append(reference(summary, root))
            # A failed owner may exit before writing construction metadata. Its
            # retained fleet assignments still identify how to parse accepted
            # node events, without granting a root audit or native application.
            if data.get('status') != 'succeeded' and 'construction' not in data:
                assignments = (controller.get('fleet_plan') or {}).get('workers', [])
                workloads = {worker.get('assignment', {}).get('workload_kind')
                             for worker in assignments}
                if len(workloads) == 1 and next(iter(workloads)) in (
                        'typed-paired-depth-six-bootstrap-v1',
                        'typed-paired-compact-depth-six-bootstrap-v1'):
                    run['configuration'].update(construction='paired', registry_keys=12,
                                               execution_backend='typed-shared-process-dag')
                    run['label'] = 'Failed shared GPU DAG'
                if controller.get('cached_native_continuation') is True:
                    run.update(track='linux-cpu', platform={'os': 'linux', 'backend': 'cpu'},
                        label='Rejected cached root continuation', measurement_scope='typed_native_cached_recovery_rejection')
            run["configuration"]["shared_fleet"] = {
                key: controller.get(key) for key in (
                    "fleet_plan", "workers", "owner_accounting", "parent_memory_event_deltas",
                    "cpu_audited_roots", "execution_elapsed_seconds", "shared_dag_owner")}
            run['configuration']['shared_fleet']['cached_native_continuation'] = controller.get('cached_native_continuation', False)
            native_application(run, data, controller)
            pending_preparation(run, data, root)
            preseal_evidence(run, data, controller, path, root)
            worker_failover(run, data, controller)
            resource_exhaustion(run, summary.parent, root)
            coordinator_recovery(run, data, path, root)
            stale_candidate(run, data, controller, summary.parent, root)
            supervision(run, summary.parent, root)
            native_pipeline(run, summary.parent, root)
            for filename in ("native-application.json", "arrival-application.json"):
                application = path.parent / filename
                if application.is_file():
                    run["sources"].append(reference(application, root))
            for worker in sorted((summary.parent / "workers").glob("gpu-*")):
                for name in ("budget.json", "accounting.json"):
                    source = worker / name
                    if source.is_file():
                        run["sources"].append(reference(source, root))
            for source in sorted((path.parent / "proofs/execution").glob("worker-*.json")):
                run["sources"].append(reference(source, root))
    if run.get("adapter") == "typed-worker":
        summary = path.parent.parent / "summary.json"
        if summary.is_file():
            controller = read(summary)
            interruption = controller.get("controller_interruption")
            if controller.get("schema") == GPU_SCHEMA and interruption:
                run["configuration"]["benchmark_monitor_interruption"] = interruption
                run["sources"].append(reference(summary, root))
                run["limitations"].append("The benchmark monitor was interrupted, leaving a telemetry gap. Worker proof/audit duration and cgroup peak/event counters are retained separately; this run does not establish continuous monitoring or coordinator recovery.")
    if run.get("adapter") == "typed-attempt":
        summary = path.parent.parent / "summary.json"
        if summary.is_file():
            controller = read(summary)
            if controller.get("schema") == GPU_SCHEMA:
                run["status"] = controller.get("status", "unknown")
                run["sources"].append(reference(summary, root))
                if controller.get("failure"):
                    run["limitations"].append(controller["failure"])
        return
    if run.get("adapter") != "typed-worker":
        return
    if data.get('preseal_only') is True:
        return
    if data.get("cpu_audited") is not True:
        run["limitations"].append("Independent CPU audit is absent; transaction mix is not qualified.")
        return
    body_path = path.parent / "root-only/body.json"
    expected_sha = data.get("artifacts", {}).get("body.json")
    count = data.get("count")
    if type(count) is not int or not 1 <= count <= 64 or not expected_sha:
        run["limitations"].append("Audited transaction count/body reference is missing; transaction mix is unknown.")
        return
    # Retain the declared pin even when the source is unavailable or changed.
    # A later report check must not hide that loss of evidence.
    run["sources"].append({"path": relative(body_path, root), "sha256": expected_sha,
                           "bytes": body_path.stat().st_size if body_path.is_file() else 0})
    if not body_path.is_file() or digest(body_path) != expected_sha:
        run["limitations"].append("Audited public body is unavailable or has a different digest; transaction mix is unknown.")
        return
    body = read(body_path)
    transactions = body.get("transactions", [])
    kinds = [item.get("kind") for item in transactions[:count]]
    allowed = {"joinsplit", "htlc_redeem", "htlc_refund", "issuance"}
    if len(kinds) != count or any(kind not in allowed for kind in kinds):
        run["limitations"].append("Public transaction kinds are incomplete or unsupported; transaction mix is unknown.")
        return
    issuance = kinds.count("issuance")
    run["workload"].update(user_transactions=count - issuance, issuance_transactions=issuance,
        count_evidence=f"CPU-audited ordered prefix of {count} transactions; body SHA-256 {expected_sha}",
        description="Mixed depth-six root: " + ", ".join(f"{kind}={kinds.count(kind)}" for kind in sorted(allowed)))
    construction = run["configuration"]["construction"]
    cached_only = run['configuration'].get('coordinator_recovery', {}).get('cached_native_continuation') is True
    run["label"] = (f"Cached root continuation: {count} transactions" if cached_only else
        f"Mixed depth-six GPU root: {count} transactions" + (f" {construction}" if construction != "reference" else ""))
    if run['configuration'].get('native_application_recovered'):
        run['label'] = f'Cached receipt recovery: {count} transactions'
    elif cached_only and run['configuration']['coordinator_recovery'].get('recovered_unexported_proofs'):
        run['label'] = f'Cached export recovery: {count} transactions'
    if run["configuration"]["execution_backend"] == "typed-dag":
        run["label"] += " / typed DAG"
    elif run["configuration"]["execution_backend"] == "typed-process-dag":
        run["label"] += " / persistent GPU child"
    elif run["configuration"]["execution_backend"] == "typed-shared-process-dag" and not cached_only:
        run["label"] += " / shared GPU DAG"
        if run["configuration"].get("worker_failover"):
            run["label"] += (" / worker OOM failover" if any(item['oom_killed'] for item in
                run['configuration']['worker_failover'].get('memory_failures', [])) else " / worker failover")
        if run["configuration"].get("coordinator_recovery"):
            run["label"] += " / coordinator restart"
        if run["verification"].get("native_applied"):
            run["label"] += " / native height " + str(run["configuration"]["native_application"]["state"]["height"])
    if run["configuration"].get("query_readback_layout") == "gather":
        run["label"] += " / gathered queries"
    if run['configuration'].get('native_head_change'):
        run['label'] += ' / stale head rejected'
    if run['configuration'].get('native_pipeline'):
        pipeline = run['configuration']['native_pipeline']
        arm = {'single-laptop': 'one laptop GPU', 'single-desktop': 'one desktop GPU',
               'shared': 'two GPUs', 'staged': 'two GPUs, staged reuse'}[
                   pipeline['case']]
        run['label'] += ' / ' + arm + ' / fixed limits'
        if 'qualification_mode' in pipeline:
            run['label'] += (' / opening cache' if pipeline['opening_denominator_cache'] else ' / uncached openings')
            if pipeline['performance_comparison'] is False:
                run['label'] += ' / resource qualification'
    if run['configuration'].get('supervision'):
        run['label'] += (' / automatic fleet recovery'
                         if run['configuration']['supervision']['automatic_recovery']
                         else ' / supervisor restart')
