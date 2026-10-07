#!/usr/bin/env python3
"""Qualify one typed candidate DAG across independently bounded GPU services.

This reuses public wallet proofs. Optional native mode applies a prepared batch
and can consume a durable sealed intake selection. Unsealed native prefixes can
produce complete subtrees for reuse after fresh CPU verification. Active worker
recovery and complete cold/post-seal transaction boundaries remain open.
"""
import argparse
import copy
from fractions import Fraction
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time

M = importlib.import_module("block-v2-typed-multi-gpu-run")
T, G, R = M.T, M.G, M.R
Bootstrap = importlib.import_module('block_v2_coordinator_bootstrap')
Controller = importlib.import_module('block_v2_controller_bootstrap')
HeadGuard = importlib.import_module('block_v2_native_head_guard')
Calibration = importlib.import_module('block_v2_shared_calibration')


def read(path):
    return json.loads(Path(path).read_text())


def quiescent_fleet(owner_unit, attempts):
    """Confirm exact owner and worker services have no remaining processes."""
    Bootstrap.quiescent(Bootstrap.observation(owner_unit), owner_unit, None)
    for attempt in attempts:
        unit = attempt['unit']
        if not re.fullmatch(r'lattica-v2-multi-persistent-[0-9a-f]{64}\.service', unit):
            raise ValueError('invalid shared GPU worker service')
        output = G.systemctl('show', unit,
            '--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID,ControlGroup')
        state = dict(line.split('=', 1) for line in output.splitlines())
        for key in ('MainPID', 'ControlPID'):
            state[key] = int(state[key])
        Bootstrap.quiescent(state, unit, None)


def owner_succeeded(directory, state, *, prefix=False):
    if not prefix:
        return G.attempt_succeeded(directory, state)
    path = Path(directory) / 'result.json'
    if not path.is_file() or state.get('Result') != 'success' or state.get('ExecMainStatus') != '0':
        return False
    result = read(path)
    return (result.get('status') == 'succeeded' and result.get('preseal_only') is True
            and result.get('cpu_prefix_audited') is True and result.get('cpu_audited') is False)



def accounting_property(directory):
    # systemd parses argv here; paths are independently quoted, not shell code.
    def quote(value):
        return '"' + str(value).replace('%', '%%').replace('\\', '\\\\').replace('"', '\\"') + '"'
    return "--property=ExecStopPost=:" + " ".join(quote(value) for value in
        [sys.executable, Path(G.__file__).resolve(), "--accounting", directory])


def properties(unit, memory, quota, cpus, directory, runtime_seconds=7200):
    return ["systemd-run", "--user", "--quiet", "--expand-environment=no",
            "--service-type=exec", "--unit=" + unit, "--slice=" + G.SLICE,
            "--property=MemoryAccounting=yes", "--property=CPUAccounting=yes",
            "--property=MemoryMax=" + str(memory), "--property=MemorySwapMax=0",
            "--property=CPUQuota=" + quota, "--property=AllowedCPUs=" + ",".join(map(str, cpus)),
            "--property=KillMode=control-group", "--property=OOMPolicy=kill",
            "--property=TimeoutStopSec=30", f"--property=RuntimeMaxSec={runtime_seconds}",
            "--property=LimitCORE=0", "--property=UMask=0077", accounting_property(directory)]


def launch_worker(path):
    config = read(path)
    T.check_pins(config["pins"])
    budget, directory = config["budget"], Path(config["directory"])
    if read(directory / "budget.json") != budget:
        raise ValueError("shared worker budget changed")
    command = properties(budget["unit"], budget["host"]["worker_bytes"],
                         budget["cpu"]["quota_percent"], budget["cpu"]["allowed_cpus"], directory, config.get("runtime_seconds", 7200))
    command += ["--pipe", "--wait", "--property=BindsTo=" + config["owner_unit"],
                "--property=After=" + config["owner_unit"]]
    command += [f"--setenv={key}={value}" for key, value in G.environment(budget, directory).items()]
    command += config["command"]
    # stdin is the duplex Unix socket, inherited unchanged by the GPU process.
    result = subprocess.run(command)
    raise SystemExit(result.returncode)


def validate_execution(result, count, expected_workers, native_binding=None, *, preseal_only=False,
                       allow_worker_failover=False, recovery_source=None, recover_cached_only=False):
    if (result.get('cached_native_continuation', False) is not recover_cached_only
            or (recover_cached_only and (recovery_source is None or preseal_only or native_binding is None))):
        raise ValueError('cached-only continuation requires explicit native recovery')
    recovery = result.get('coordinator_recovery')
    if recovery_source is None:
        if recovery is not None:
            raise ValueError('unexpected coordinator recovery receipt')
    else:
        if (native_binding is None or preseal_only or not isinstance(recovery, dict)
                or recovery.get('source') != str(recovery_source)
                or any(recovery.get(key) is not True for key in (
                    'old_coordinator_quiescent', 'old_workers_quiescent', 'old_launches_revoked',
                    'old_workspace_reservations_released', 'original_resource_assignments_preserved'))
                or type(recovery.get('previous_epoch')) is not int or recovery['previous_epoch'] < 1
                or recovery.get('recovery_epoch') != recovery['previous_epoch'] + 1
                or result.get('recovery_epoch') != recovery['recovery_epoch']
                or recovery.get('coordinator_pid') != result.get('coordinator_pid')
                or type(recovery.get('previous_coordinator_pid')) is not int
                or recovery['previous_coordinator_pid'] <= 0
                or recovery['previous_coordinator_pid'] == result.get('coordinator_pid')):
            raise ValueError('coordinator recovery lacks exact prior-owner reconciliation')
        if any(node.get('recovered_from_journal') is not True for node in result.get('reused_nodes', [])):
            raise ValueError('recovered nodes must come from the reverified durable journal')
    if allow_worker_failover and native_binding is None:
        raise ValueError('worker failover requires a native snapshot binding')
    reused = result.get('reused_proofs', 0)
    reused_nodes = result.get('reused_nodes', [])
    if (result.get('preseal_only', False) is not preseal_only or type(reused) is not int or reused < 0
            or not isinstance(reused_nodes, list) or len(reused_nodes) != reused
            or any(not isinstance(n, dict) or n.get('cpu_reverified') is not True for n in reused_nodes)):
        raise ValueError('shared pre-seal scope or reuse accounting differs')
    if (result.get('status') != ('preseal_verified' if preseal_only else 'proved_cpu_audit_pending')
            or result.get('root_file') != (None if preseal_only else 'node.6.0')):
        raise ValueError('shared proof status or root scope differs')
    if (result.get("native_host_bound", False) is not (native_binding is not None)
            or result.get("native_host") != native_binding):
        raise ValueError("shared owner native snapshot binding differs")
    if (result.get("execution_backend") != "typed_shared_process_dag_v1"
            or result.get("shared_dag_owner") is not True
            or type(result.get("count")) is not int
            or result.get("count") != count or result.get("construction") != "typed-paired-v1"
            or type(result.get("fresh_proofs")) is not int
            or result["fresh_proofs"] < (0 if recover_cached_only else 1)
            or result.get("cpu_verified_nodes") != result.get("fresh_proofs")
            or result.get("worker_processes_exited") is not True
            or result.get("workspace_released_after_gpu_teardown") is not True
            or result.get("arrival_backend_integrated") is not False
            or result.get("durable_host_applied") is not False or result.get("production_ready") is not False):
        raise ValueError("shared typed owner result scope or teardown differs")
    workers = result.get("workers", [])
    if recover_cached_only:
        if (workers != [] or result.get('fresh_proofs') != 0 or reused == 0
                or type(result.get('gpu_workers_started')) is not int or result['gpu_workers_started'] != 0
                or type(result.get('maximum_active_jobs')) is not int or result['maximum_active_jobs'] != 0
                or result.get('backend') != 'cpu'
                or type(result.get('coordinator_pid')) is not int or result['coordinator_pid'] <= 0
                or result.get('allow_worker_failover', False) is not allow_worker_failover
                or type(result.get('failed_workers', 0)) is not int or result.get('failed_workers', 0) != 0):
            raise ValueError('cached-only continuation started work or lacks a reverified root')
        return
    expected = {(w["budget"]["gpu"]["uuid"], w["budget"]["unit"]) for w in expected_workers}
    actual = {(w.get("gpu_uuid"), w.get("unit")) for w in workers}
    pids = [w.get("worker_pid") for w in workers]
    if (actual != expected or len(workers) != len(expected) or len(set(pids)) != len(pids)
            or any(type(pid) is not int or pid <= 0 for pid in pids)
            or result.get("coordinator_pid") in pids or type(result.get("coordinator_pid")) is not int
            or result["coordinator_pid"] <= 0
            or type(result.get("maximum_active_jobs")) is not int
            or not 1 <= result["maximum_active_jobs"] <= len(workers)):
        raise ValueError("shared typed worker/coordinator identity differs")
    failed = [w for w in workers if w.get('worker_failed') is True]
    if (result.get('allow_worker_failover', False) is not allow_worker_failover
            or type(result.get('failed_workers', 0)) is not int
            or result.get('failed_workers', 0) != len(failed)
            or (failed and (not allow_worker_failover or len(failed) >= len(workers)))):
        raise ValueError('worker failure was not admitted or has no surviving worker')
    for worker in workers:
        if worker.get('worker_failed') is True:
            stopped = (worker.get('exit_code') is None and worker.get('forced_stop_confirmed') is True
                       and worker.get('launch_revoked') is True
                       and worker.get('teardown_method') == 'process_and_cgroup_exit'
                       and all(isinstance(worker.get(k), str) and len(worker[k]) == 64
                               and all(c in '0123456789abcdef' for c in worker[k])
                               for k in ['failed_job', 'lease_key']))
        else:
            stopped = (worker.get('worker_failed', False) is False
                       and type(worker.get('exit_code')) is int and worker.get('exit_code') == 0)
        if (worker.get('coordinator_pid') != result['coordinator_pid'] or not stopped
                or worker.get('gpu_teardown_confirmed') is not True or worker.get('workspace_released') is not True
                or worker.get('process_and_cgroup_quiescent') is not True):
            raise ValueError('shared typed worker did not exit quiescently')
        if any(type(worker.get(key)) is not int or worker[key] < 0 for key in ['cache_setups', 'cache_hits']):
            raise ValueError('shared typed cache counters invalid')
    if sum(w["cache_setups"] + w["cache_hits"] for w in workers) != result["fresh_proofs"]:
        raise ValueError("shared typed cache counters differ from proved jobs")


def validate_worker_accounting(accounting, budget, worker, allow_worker_failover):
    """Retain memory failures only for an admitted, fully drained failed worker."""
    pairs = [line.split() for line in accounting['memory.events'].splitlines()]
    if any(len(pair) != 2 for pair in pairs):
        raise ValueError('invalid worker memory event accounting')
    events = {key: int(value) for key, value in pairs}
    if (len(events) != len(pairs) or
            not {'high', 'max', 'oom', 'oom_kill', 'oom_group_kill'}.issubset(events) or
            any(value < 0 for value in events.values())):
        raise ValueError('invalid worker memory event accounting')
    if not 0 < int(accounting['memory.peak']) <= budget['host']['worker_bytes']:
        raise ValueError('typed worker exceeded assigned memory')
    if not any(events.values()):
        return None
    if (allow_worker_failover is not True or worker.get('worker_failed') is not True or
            worker.get('exit_code') is not None or
            worker.get('teardown_method') != 'process_and_cgroup_exit' or
            not all(worker.get(key) is True for key in (
                'forced_stop_confirmed', 'launch_revoked', 'workspace_released',
                'process_and_cgroup_quiescent', 'gpu_teardown_confirmed'))):
        raise ValueError('worker memory failure lacks admitted failover and confirmed teardown')
    return dict(memory_events=events, oom_killed=events['oom_kill'] > 0 or events['oom_group_kill'] > 0,
                scope='Failed worker only; original assignment and observed memory counters are retained.')


def fleet_event_deltas(before, after, workers, allow_worker_failover):
    if (set(before) != set(after) or
            any(type(value) is not int or value < 0 for counters in (before, after) for value in counters.values()) or
            any(after[key] < before[key] for key in before)):
        raise ValueError('fleet memory accounting changed or counters reset during execution')
    delta = {key: after[key] - before[key] for key in before}
    explained = dict.fromkeys(delta, 0)
    for worker in workers:
        failure = validate_worker_accounting(worker['accounting'], worker['budget'],
                                             worker['termination'], allow_worker_failover)
        if failure != worker.get('memory_failure'):
            raise ValueError('worker memory failure differs from retained accounting')
        if failure is not None:
            if set(failure['memory_events']) != set(delta):
                raise ValueError('worker and fleet memory event counters differ')
            for key, value in failure['memory_events'].items():
                explained[key] += value
    if delta != explained:
        raise ValueError(f'fleet memory events are not attributable to drained failed workers: {delta}')
    return delta


def check_recovery_profile(profile, recovery):
    if (recovery is not None and recovery.get('workload_profile') is not None
            and recovery['workload_profile'] != profile):
        raise ValueError('recovery workload profile differs from original inputs')


def admit_recovery(host, devices, profile, recovery, directory, timeout, *, assignment=None, calibrations=None):
    check_recovery_profile(profile, recovery)
    if recovery is None:
        return host, devices, M.plan_budgets(host, devices, profile, assignment=assignment, calibrations=calibrations)
    if assignment is not None and assignment != recovery['resource_assignment']:
        raise ValueError('fixed assignment differs from original recovery limits')
    original_calibrations = recovery.get('context_calibrations')
    if calibrations is not None and calibrations != original_calibrations:
        raise ValueError('context calibration differs from original recovery inputs')
    calibrations = original_calibrations
    if not 0 < timeout <= 300:
        raise ValueError('recovery admission wait must be between 0 and 300 seconds')
    deadline = time.monotonic() + timeout
    uuids = [device['uuid'] for device in devices]
    observations = []
    while True:
        try:
            budgets = M.plan_budgets(host, devices, profile, assignment=recovery['resource_assignment'], calibrations=calibrations)
            return host, devices, budgets
        except ValueError as error:
            if not str(error).startswith(('current host capacity cannot admit ', 'current free VRAM cannot admit ')):
                raise
            observations.append({'time_ns': time.time_ns(), 'failure': str(error),
                'host': host, 'devices': devices})
            G.durable(Path(directory) / 'recovery-admission-waits.json', observations)
            if time.monotonic() >= deadline:
                raise ValueError('recovery admission wait expired; original journal remains pending') from error
            time.sleep(2)
            host = G.detect_worker_host(host['scratch']['path'])
            inventory = {device['uuid']: device for device in R.detect_gpus(recovery['gpu_binary'])}
            devices = [inventory[uuid] for uuid in uuids]


def pin_recovery(directory, count, gpu, cpu, native_binding, _seen=None):
    """Pin the prior run and retain the journal of interrupted recoveries."""
    directory = Path(directory).resolve(strict=True)
    seen = set() if _seen is None else set(_seen)
    if directory in seen or len(seen) >= 64:
        raise ValueError('recovery lineage must be bounded and distinct')
    seen.add(directory)
    config_path = directory.parent / 'config.json'
    config = read(config_path)
    T.check_pins(config['pins'])
    has_workload = (config.get('workload_path') is not None or config.get('workload_profile') is not None
                    or any(Path(path).name == 'block-v2-multi-gpu-direct-readback-workload.json'
                           for path in config['pins']))
    original_profile = Calibration.source_profile(config, sys.modules[__name__]) if has_workload else None
    if (Path(config['owner_directory']).resolve() != directory or config['count'] != count
            or config.get('preseal_only') or config.get('reuse_preseal')
            or config.get('native_host') != native_binding or native_binding is None
            or config['pins'][config['gpu_binary']] != G.digest(gpu)
            or config['pins'][config['cpu_binary']] != G.digest(cpu)):
        raise ValueError('recovery requires the same native candidate and frozen binaries')
    proofs = directory / 'proofs'
    bootstrap = Bootstrap.reconcile(config_path)
    unfinished = bootstrap is not None and bootstrap['abandoned_incomplete_new_candidate']
    interrupted = bootstrap is not None and bootstrap.get('interrupted_existing_journal', False)
    plan = read(config['fleet_plan']) if unfinished or interrupted else read(proofs / 'fleet-plan.json')
    if plan != read(config['fleet_plan']):
        raise ValueError('retained coordinator plan differs from pinned controller plan')
    signatures = {}
    for worker in plan['workers']:
        assignment = copy.deepcopy(worker['assignment'])
        assignment['host'].pop('coordinator_job_bytes', None)
        uuid = assignment['gpu']['uuid']
        if uuid in signatures:
            raise ValueError('recovery GPU UUID is duplicated')
        signatures[uuid] = T.resource_signature(assignment)
    if interrupted and bootstrap['recovery_admission'] is None:
        # No mutation was allowed before the atomic recovery admission. Retain
        # partial metadata, then retry the exact previously admitted journal.
        prior = pin_recovery(Path(bootstrap['retry_source']).parent, count, gpu, cpu, native_binding, seen)
        if signatures != prior['resource_assignment']['limits_by_gpu']:
            raise ValueError('interrupted recovery changed original resource assignments')
        check_recovery_profile(original_profile, prior)
        gate = Path(bootstrap['guard'])
        files = [config_path, Path(config['fleet_plan'])]
        files += [p for base in (proofs, gate) for p in base.rglob('*') if p.is_file()]
        return dict(prior, pins=prior['pins'] | dict(T.pin(path) for path in files),
                    bootstrap_recovery={**bootstrap, 'source': str(proofs),
                                        'prior_bootstrap_recovery': prior.get('bootstrap_recovery')})
    if unfinished:
        if (not plan.get('startup_fenced')
                or plan.get('coordinator_bootstrap_guard') != bootstrap['guard']):
            raise ValueError('incomplete bootstrap lacks worker and coordinator admission fences')
        files = [config_path, Path(config['fleet_plan'])]
        files += [path for path in proofs.rglob('*') if path.is_file()]
        runtime = proofs / 'execution'
    else:
        files = [config_path, *[proofs / name for name in (
            'fleet-plan.json', 'coordinator.json', 'recovery-state.json', 'expected.json')]]
        for index in range(len(plan['workers'])):
            if plan.get('recover_cached_only', False):
                break
            start = proofs / f'execution/worker-{index}-start.json'
            if not plan.get('startup_fenced', False) or start.exists():
                files.append(start)
            if plan.get('startup_fenced', False):
                gate = proofs / f'execution/worker-{index}-startup'
                files += [gate / name for name in ('intent.json', 'authorization.json', 'started.json')
                          if (gate / name).exists()]
        state = read(proofs / 'recovery-state.json')
        if (proofs / 'recovery-admission.json').exists():
            files.append(proofs / 'recovery-admission.json')
        runtime = Path(state['durable_runtime'])
        if not runtime.is_absolute():
            raise ValueError('recovery journal origin must be absolute')
    if bootstrap is not None:
        gate = Path(bootstrap['guard'])
        files += [gate / name for name in ('intent.json', 'started.json', 'initialized.json', 'revoked.json')
                  if (gate / name).exists()]
    return {'source': str(proofs), 'gpu_binary': str(gpu), 'previous_plan': plan,
            'launch_directory': str(runtime / 'launches'),
            'pins': dict(T.pin(path) for path in files), 'gpu_uuids': list(signatures),
            'bootstrap_recovery': {**bootstrap, 'source': str(proofs)} if unfinished or interrupted else None,
            'context_calibrations': config.get('context_calibrations'),
            'workload_profile': original_profile,
            'resource_assignment': {'schema': 'lattica-typed-fleet-assignment-v1',
                                    'limits_by_gpu': signatures}}


def recovery_paths(owner_directory, recovery):
    """Worker launches must use the same journal selected for the coordinator."""
    if recovery is not None and not (recovery.get('bootstrap_recovery') or {}).get('abandoned_incomplete_new_candidate'):
        return recovery['source'], recovery['launch_directory']
    return None, str(Path(owner_directory) / 'proofs/execution/launches')


def configure_recovery(owner_directory, recovery, config, fleet, report):
    """Recovery provenance and the existing journal source can both be present."""
    source, launches = recovery_paths(owner_directory, recovery)
    if recovery and recovery.get('bootstrap_recovery') is not None:
        config['bootstrap_recovery'] = recovery['bootstrap_recovery']
        report['bootstrap_recovery'] = recovery['bootstrap_recovery']
    if source is not None:
        config['recover_from'] = source
        fleet['recover_from'] = source
        report['recovery_source'] = source
    return launches


def admit_cached_recovery(host, recovery):
    """Admit only the CPU coordinator; retained GPU budgets are identity metadata."""
    plan = recovery['previous_plan']
    ram, threads = plan['coordinator_ram_bytes'], plan['coordinator_threads']
    reserve = max(2 * R.GIB, (host['physical_bytes'] + 9) // 10)
    available = max(0, host['available_bytes'] - reserve)
    if host['cgroup_memory_headroom'] is not None:
        available = min(available, host['cgroup_memory_headroom'])
    if (type(ram) is not int or ram <= 0 or type(threads) is not int or threads <= 0
            or ram > available or Fraction(host['cpu_capacity']) < threads):
        raise ValueError('current host capacity cannot admit the cached recovery coordinator')
    budgets, devices = {}, []
    for worker in plan['workers']:
        budget = copy.deepcopy(worker['assignment'])
        budget['host'].pop('coordinator_job_bytes', None)
        if budget['host']['coordinator_bytes'] != ram:
            raise ValueError('retained coordinator memory assignment differs')
        budgets[budget['gpu']['uuid']] = budget
        devices.append(copy.deepcopy(budget['detected_gpu']))
    if list(budgets) != recovery['gpu_uuids']:
        raise ValueError('retained GPU order differs')
    return host, devices, budgets


def pin_preseal(directories):
    """Bound and pin every cache artifact before admitting GPU services."""
    if len(directories) > 64:
        raise ValueError('pre-seal cache directory limit exceeded')
    paths, pins = [], {}
    for value in directories:
        directory = Path(value).resolve(strict=True)
        if not directory.is_dir() or str(directory) in paths:
            raise ValueError('pre-seal cache directories must be distinct directories')
        manifest = directory / 'result.json'
        if manifest.stat().st_size > 1024 * 1024:
            raise ValueError('pre-seal cache manifest is too large')
        cache = read(manifest)
        nodes = cache.get('stable_nodes')
        if (cache.get('schema_version') != 1 or cache.get('status') != 'preseal_verified'
                or cache.get('preseal_only') is not True
                or not isinstance(nodes, list) or not 1 <= len(nodes) <= 62):
            raise ValueError('invalid pre-seal cache manifest')
        pins.update([T.pin(manifest)])
        names = set()
        for node in nodes:
            if not isinstance(node, dict):
                raise ValueError('invalid pre-seal node record')
            level, index, size = (node.get(k) for k in ('level', 'index', 'bytes'))
            if (type(level) is not int or not 0 < level < 6
                    or type(index) is not int or not 0 <= index < (64 >> level)
                    or type(size) is not int or not 0 < size <= 2 * 1024 * 1024):
                raise ValueError('invalid pre-seal node geometry or size')
            name = f'node.{level}.{index}'
            if name in names or (directory / name).stat().st_size != size:
                raise ValueError('duplicate pre-seal node or changed artifact size')
            names.add(name)
            pins.update([T.pin(directory / name)])
        paths.append(str(directory))
    return paths, pins


def open_intake(native, directory, selection_id, *, prefix=False):
    if prefix:
        if native is None or not directory or selection_id:
            raise ValueError('pre-seal dispatch needs native intake without a sealed selection')
        A = importlib.import_module('block_v2_native_arrivals')
        intake = A.Store(directory, native.store)
        intake.check_prefix(native)
        return intake
    if bool(directory) != bool(selection_id):
        raise ValueError("arrival store and selection must be supplied together")
    if not directory:
        return None
    if native is None:
        raise ValueError("arrival intake requires an independently verified native candidate")
    A = importlib.import_module("block_v2_native_arrivals")
    intake = A.Store(directory, native.store)
    intake.check_selection(selection_id, native)
    return intake


def application_recovery_inputs(directory):
    """Use the interrupted owner's audited root to recognize a lost native receipt."""
    directory = Path(directory).resolve(strict=True)
    previous = read(directory.parent / 'config.json')
    if Path(previous['owner_directory']).resolve() != directory:
        raise ValueError('application recovery owner identity differs')
    proof = directory / 'root-only/node.6.0'
    if not proof.is_file():
        return {}
    if previous.get('native_host') is None or previous.get('preseal_only'):
        raise ValueError('application recovery requires a sealed native owner')
    return dict(recover_proof=proof, recover_binding=previous['native_host'])


def owner(path):
    config = read(path)
    Bootstrap.enter(path)
    preseal = config.get('preseal_only', False)
    pool_mode = config.get("pool_requests") is not None
    T.check_pins(config["pins"])
    directory = Path(config["owner_directory"])
    started = time.monotonic()
    result = {"schema": "lattica-typed-shared-gpu-v1", "status": "running", "production_ready": False}
    if config.get('bootstrap_recovery') is not None:
        result['bootstrap_recovery'] = config['bootstrap_recovery']
    try:
        native = None
        if config.get("native_host") is not None:
            N = importlib.import_module("block_v2_native_shared")
            native = N.Candidate(config["host_config"], config["host_journal"],
                                 config["fixture"], config["count"], prefix=preseal,
                                 recover_proof=config.get('native_recovery_proof'),
                                 recover_binding=config['native_host'] if config.get('native_recovery_proof') else None)
            native.check(config["native_host"])
        intake = open_intake(native, config.get("arrival_store"), config.get("arrival_selection"), prefix=preseal)
        fixture = directory / "input"
        fixture.mkdir(mode=0o700)
        for source in T.fixture_files(Path(config["fixture"]), config["count"], "paired"):
            target = fixture / source.name
            shutil.copyfile(source, target)
            if G.digest(target) != config["pins"][str(source)]:
                raise ValueError("shared owner copied fixture differs")
        proving_started = time.monotonic()
        T.execute_logged([config["gpu_binary"], "prove-fleet-gpu", fixture, config["expected"],
                                    config["fleet_plan"], directory / "proofs"],
                                   directory / "prove.log", T.clean_environment() | {
                                       "RAYON_NUM_THREADS": str(config["coordinator_threads"])})
        proving = time.monotonic() - proving_started
        if pool_mode:
            stopped = read(directory / "proofs/pool-stopped.json")
            if stopped.get('workers_drained') is not True:
                raise ValueError('persistent pool did not drain workers')
            result.update(status='succeeded', pool_service=True, pool_result=stopped,
                          cpu_audited=False, durable_host_applied=False,
                          native_blocks_applied=0, elapsed_seconds=time.monotonic() - started)
            return
        execution = read(directory / "proofs/result.json")
        validate_execution(execution, config["count"], config["workers"], config.get("native_host"),
            preseal_only=preseal, allow_worker_failover=config.get('allow_worker_failover', False),
            recovery_source=config.get('recover_from'),
            recover_cached_only=config.get('recover_cached_only', False))
        result.update(allow_worker_failover=config.get('allow_worker_failover', False),
                      failed_workers=execution.get('failed_workers', 0),
            coordinator_recovery=execution.get('coordinator_recovery'),
            cached_native_continuation=execution.get('cached_native_continuation', False),
            gpu_workers_started=execution.get('gpu_workers_started', len(execution.get('workers', []))))
        nodes = T.public_events(directory / "prove.log", "fresh_typed_node")
        plan = read(config["proof_plan"])
        actual = [(f"node.{n['level']}.{n['index']}", n["mode"], n["count"]) for n in nodes]
        expected = [(task["file"], task["mode"], task["count"]) for task in plan["tasks"]]
        if preseal:
            expected = [task for task in expected if 0 < int(task[0].split('.')[1]) < 6
                        and task[2] == 1 << int(task[0].split('.')[1])]
        planned = {task[0]: task for task in expected}
        for cached in execution.get('reused_nodes', []):
            filename = f'node.{cached["level"]}.{cached["index"]}'
            if filename not in planned:
                raise ValueError('cached subtree is absent from the current proof plan')
            actual.append(planned[filename])
        if sorted(actual) != sorted(expected) or len(nodes) != execution["fresh_proofs"]:
            raise ValueError("shared owner did not produce exactly the planned nodes")
        if preseal:
            audit_started = time.monotonic()
            audit_path = directory / 'prefix-audit.json'
            T.execute_logged([config['cpu_binary'], 'audit-preseal', fixture, config['expected'],
                              directory / 'proofs', audit_path], directory / 'audit.log',
                             T.clean_environment() | {'RAYON_NUM_THREADS': '1'})
            audit = read(audit_path)
            if (audit.get('status') != 'passed' or audit.get('cpu_prefix_audited') is not True
                    or len(audit.get('nodes', [])) != execution['fresh_proofs'] + execution.get('reused_proofs', 0)):
                raise ValueError('independent CPU prefix audit differs from proved subtrees')
            native.check(config['native_host'])
            intake.check_prefix(native)
            result.update(status='succeeded', preseal_only=True, preseal_dispatch=True,
                execution_backend='typed-shared-process-dag', native_host_binding=config['native_host'],
                count=config['count'], construction='typed-paired-v1', execution_result=execution,
                fresh_proofs=execution['fresh_proofs'], reused_proofs=execution.get('reused_proofs', 0),
                proving_seconds=proving, cpu_audit_seconds=time.monotonic() - audit_started,
                cpu_audited=False, cpu_prefix_audited=True, prefix_audit=audit,
                elapsed_seconds=time.monotonic() - started, root_bytes=0, wallet_proofs_created=0,
                native_blocks_applied=0, durable_host_applied=False, durable_arrival_prefix=True,
                artifacts={f'node.{n["level"]}.{n["index"]}': G.digest(directory / 'proofs' / f'node.{n["level"]}.{n["index"]}')
                           for n in execution['stable_nodes']})
            return
        result.update(preseal_only=False, reused_proofs=execution.get('reused_proofs', 0),
                      preseal_dispatch=bool(config.get('reuse_preseal')))
        root_only = directory / "root-only"
        root_only.mkdir(mode=0o700)
        for name in T.public_names("paired"):
            shutil.copyfile(fixture / name, root_only / name)
        shutil.copyfile(config["expected"], root_only / "expected.json")
        shutil.copyfile(directory / "proofs/node.6.0", root_only / "node.6.0")
        audit_started = time.monotonic()
        T.execute_logged([config["cpu_binary"], "audit-root", root_only, root_only / "expected.json",
                                 root_only / "body.json", root_only / "node.6.0"],
                                directory / "audit.log", T.clean_environment() | {
                                    "RAYON_NUM_THREADS": str(config["coordinator_threads"])})
        audit = time.monotonic() - audit_started
        T.check_pins(config["pins"])
        result.update(status="succeeded", count=config["count"], construction="paired",
                      execution_backend="typed-shared-process-dag", execution_result=execution,
                      fresh_proofs=len(nodes), cpu_audited=True, proving_seconds=proving,
                      cpu_audit_seconds=audit, elapsed_seconds=time.monotonic() - started,
                      root_bytes=(root_only / "node.6.0").stat().st_size,
                      artifacts={p.name: G.digest(p) for p in root_only.iterdir()},
                      binary_sha256=config["pins"][config["gpu_binary"]],
                      arrival_backend_integrated=False, durable_host_applied=False,
                      wallet_proofs_created=0, native_blocks_applied=0)
        if native is not None:
            application_started = time.monotonic()
            HeadGuard.publish_handoff(native, directory)
            try:
                receipt = native.apply(root_only / "node.6.0", config["native_host"])
            except N.H.CommitIndeterminate:
                result.update(native_application_status="indeterminate", durable_host_applied=None,
                              native_blocks_applied=None)
                raise
            result.update(native_host_binding=config["native_host"], native_application=receipt,
                          native_application_status="applied", durable_host_applied=True,
                          native_blocks_applied=1,
                          native_application_recovered=native.recovered_application is not None,
                          fresh_native_blocks_applied=int(native.recovered_application is None),
                          native_application_seconds=time.monotonic() - application_started,
                          elapsed_seconds=time.monotonic() - started)
            G.durable(directory / "native-application.json", receipt, True)
            if intake is not None:
                intake_started = time.monotonic()
                result["arrival_publication_status"] = "pending"
                try:
                    applied = intake.record_application(config["arrival_selection"], native, receipt,
                                                        root_only / "node.6.0")
                except importlib.import_module("block_v2_native_arrivals").IntakeCommitIndeterminate:
                    result["arrival_publication_status"] = "indeterminate"
                    raise
                result.update(durable_arrival_intake=True, arrival_selection=config["arrival_selection"],
                              arrival_application=applied, arrival_publication_status="applied",
                              intake_publication_seconds=time.monotonic() - intake_started,
                              elapsed_seconds=time.monotonic() - started)
                G.durable(directory / "arrival-application.json", applied, True)
    except BaseException as error:
        result.update(status="failed", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        G.durable(directory / "result.json", result, True)


def run(args, control=None):
    preseal = getattr(args, 'preseal', False)
    pool_requests = getattr(args, 'pool_requests', None)
    pool_runtime = getattr(args, 'pool_runtime_seconds', 172800)
    if pool_requests is not None:
        pool_requests = pool_requests.resolve(strict=True)
        if (not pool_requests.is_dir() or pool_requests.stat().st_mode & 0o077
                or not args.host_config or preseal or args.recover_owner or args.reuse_preseal
                or args.arrival_store or getattr(args, 'allow_worker_failover', False)
                or not 7200 <= pool_runtime <= 604800):
            raise ValueError('pool requires private request directory, native host, fresh session, and bounded runtime')

    failover = getattr(args, 'allow_worker_failover', False)
    recover_owner = getattr(args, 'recover_owner', None)
    cached_only = getattr(args, 'recover_cached_only', False)
    if cached_only and not recover_owner:
        raise ValueError('cached-only continuation requires --recover-owner')
    if recover_owner and (not args.host_config or preseal or getattr(args, 'reuse_preseal', [])):
        raise ValueError('coordinator recovery requires a sealed native candidate without pre-seal import')
    if failover and (not args.host_config or len(set(args.gpu_uuid)) < 2):
        raise ValueError('worker failover requires a native candidate and at least two GPUs')
    reuse, cache_pins = pin_preseal(getattr(args, 'reuse_preseal', []))
    if (preseal or reuse) and not args.host_config:
        raise ValueError('pre-seal proving and reuse require a native candidate')
    gpu, cpu, source = (path.resolve(strict=True) for path in [args.gpu_binary, args.cpu_binary, args.fixture])
    inputs = T.fixture_files(source, args.count, "paired")
    scripts = [Path(__file__).resolve(), Path(M.__file__).resolve(), Path(T.__file__).resolve(),
               Path(M.C.__file__).resolve(), Path(G.__file__).resolve(), Path(R.__file__).resolve(),
               Path(Bootstrap.__file__).resolve()]
    scripts.append(Path(Controller.__file__).resolve())
    scripts.append(Path(Calibration.__file__).resolve())
    workload = getattr(args, "workload", None) or Path(__file__).with_name("block-v2-multi-gpu-direct-readback-workload.json")
    pins = dict(T.pin(path) for path in [gpu, cpu, *inputs, *scripts, workload])
    fixed_path = getattr(args, 'resource_assignment', None)
    fixed = None
    if fixed_path is not None:
        fixed_path = fixed_path.resolve(strict=True)
        fixed = read(fixed_path)
        pins.update(dict([T.pin(fixed_path)]))
    pins.update(cache_pins)
    if bool(args.host_config) != bool(args.host_journal):
        raise ValueError("native host config and journal must be supplied together")
    native = None
    native_recovery = application_recovery_inputs(recover_owner) if cached_only else {}
    if args.host_config:
        N = importlib.import_module("block_v2_native_shared")
        native = N.Candidate(args.host_config, args.host_journal, source, args.count,
                             prefix=preseal, **native_recovery)
        if native_recovery:
            pins.update(dict([T.pin(native_recovery['recover_proof'])]))
        pins.update({item["path"]: item["sha256"] for item in native.pins})
        pins.update(dict(T.pin(path) for path in [native.config_path, native.manifest_path,
            Path(N.__file__), Path(N.H.__file__), Path(N.D.__file__), Path(N.D._codec.__file__)]))
    intake = open_intake(native, args.arrival_store, args.arrival_selection, prefix=preseal)
    if intake is not None:
        A = importlib.import_module("block_v2_native_arrivals")
        pins.update(dict([T.pin(Path(A.__file__).resolve())]))
    recovery = pin_recovery(recover_owner, args.count, gpu, cpu, native.binding) if recover_owner else None
    if recovery:
        if args.gpu_uuid != recovery['gpu_uuids']:
            raise ValueError('coordinator recovery requires the original ordered GPU assignments')
        pins.update(recovery['pins'])
    out = args.evidence.resolve()
    locks = G.lock_fleet()
    report = {"schema": "lattica-typed-shared-gpu-v1", "status": "preparing", "count": args.count,
              "scope": "One candidate DAG across independently bounded persistent GPU services; fixture inputs only",
              "production_ready": False, "delivered_transactions_measured": False, "attempts": [],
              "preseal_only": preseal, "preseal_dispatch": preseal or bool(reuse), "reuse_preseal": reuse}
    if fixed_path is not None:
        report['resource_assignment'] = {'path': str(fixed_path), 'sha256': pins[str(fixed_path)]}
    created = launched = False
    if control is not None:
        report['controller_admission'] = control
        previous = Controller.read(Path(control['gate']) / 'intent.json').get('recovered_controller')
        if previous is not None:
            report['controller_recovery'] = {key: value for key, value in previous.items() if key != 'intent'}
    owner_unit = "lattica-v2-multi-owner-" + secrets.token_hex(32) + ".service"
    try:
        if json.loads(G.systemctl("list-units", "lattica-v2-multi-*.service", "--state=active,activating,deactivating", "--output=json", "--no-pager")):
            raise ValueError("another GPU qualification is active")
        if control is None:
            out.mkdir(mode=0o700, parents=True, exist_ok=False)
        elif Controller.guard(out) != Path(control['gate']):
            raise ValueError('controller output differs from its admitted directory')
        created = True
        expected, proof_plan = out / "expected.json", out / "proof-plan.json"
        if native is None:
            T.execute_logged([cpu, "expected", source, args.count, expected], out / "expected.log", T.clean_environment())
        else:
            native.check(native.binding)
            shutil.copyfile(source / "expected.json", expected)
            G.durable(out / "native-host.json", native.binding, True)
            pins.update(dict([T.pin(out / "native-host.json")]))
        T.execute_logged([cpu, "plan", source, expected], proof_plan, T.clean_environment())
        T.validate_plan(read(proof_plan), "paired")
        pins.update(dict(T.pin(p) for p in [expected, proof_plan]))
        profile = T.resource_profile(workload, "paired", "compact")
        check_recovery_profile(profile, recovery)
        calibrations = None
        if getattr(args, 'calibration_trial', []):
            calibrations, calibration_pins = Calibration.load(args.calibration_trial,
                shared=sys.modules[__name__], gpu_sha=pins[str(gpu)], cpu_sha=pins[str(cpu)],
                profile=profile, count=args.count, assignment=fixed, uuids=args.gpu_uuid,
                target_plan=read(proof_plan), preseal=preseal)
            pins.update(calibration_pins)
        elif recovery is not None:
            calibrations = recovery.get('context_calibrations')
        report['context_calibrations'] = calibrations
        host = G.detect_worker_host(str(args.scratch.resolve(strict=True)))
        if len(set(args.gpu_uuid)) != len(args.gpu_uuid) or not 1 <= len(args.gpu_uuid) <= 16:
            raise ValueError("shared typed worker GPU selection is empty or duplicated")
        if cached_only:
            host, devices, budgets = admit_cached_recovery(host, recovery)
        else:
            inventory = {device["uuid"]: device for device in R.detect_gpus(str(gpu))}
            devices = [inventory[uuid] for uuid in args.gpu_uuid]
            host, devices, budgets = admit_recovery(host, devices, profile, recovery, out,
                getattr(args, 'recovery_admission_timeout', 120), assignment=fixed, calibrations=calibrations)
        first = next(iter(budgets.values()))
        coordinator_bytes = first["host"]["coordinator_bytes"]
        coordinator_threads = int(first["cpu"]["coordinator_capacity"])
        if coordinator_threads < 1 or str(coordinator_threads) != first["cpu"]["coordinator_capacity"]:
            raise ValueError("shared coordinator requires an integral admitted CPU capacity")
        owner_dir = out / "owner"
        owner_dir.mkdir(mode=0o700)
        config = {"gpu_binary": str(gpu), "cpu_binary": str(cpu), "fixture": str(source), "count": args.count,
                  "pins": pins, "expected": str(expected), "proof_plan": str(proof_plan),
                  "owner_directory": str(owner_dir), "owner_unit": owner_unit,
                  "coordinator_threads": coordinator_threads, "fleet_plan": str(out / "fleet-plan.json"), "workers": [],
                  "preseal_only": preseal, "reuse_preseal": reuse, "allow_worker_failover": failover}
        config['context_calibrations'] = calibrations
        fleet = {"schema_version": 1, "recover_from": None, "coordinator_unit": owner_unit, "coordinator_ram_bytes": coordinator_bytes,
                 "coordinator_threads": coordinator_threads, "fleet_bytes": first["host"]["fleet_bytes"], "workers": [],
                 "preseal_only": preseal, "reuse_preseal": reuse, "allow_worker_failover": failover}
        guard = str(owner_dir / 'coordinator-startup')
        config['workload_path'] = str(workload.resolve(strict=True))
        config['workload_profile'] = profile
        config['coordinator_bootstrap_guard'] = guard
        if control is not None:
            config['controller_admission'] = control
        fleet['coordinator_bootstrap_guard'] = guard
        launch_directory = configure_recovery(owner_dir, recovery, config, fleet, report)
        config['recover_cached_only'] = cached_only
        fleet['recover_cached_only'] = cached_only
        fleet['startup_fenced'] = True
        report['cached_native_continuation'] = cached_only
        if native is not None:
            config.update(host_config=str(native.config_path), host_journal=str(native.journal),
                          native_host=native.binding)
            if native_recovery:
                config['native_recovery_proof'] = str(native_recovery['recover_proof'])
            fleet["native_host"] = native.binding
            report.update(native_host_binding=native.binding,
                          scope="One native candidate bound to a verified journal head; shared GPU proving and fenced native application")
        if intake is not None:
            config.update(arrival_store=str(intake.directory), arrival_selection=args.arrival_selection)
            report.update(durable_arrival_intake=not preseal, durable_arrival_prefix=preseal,
                          arrival_selection=args.arrival_selection)
        if preseal:
            report['scope'] = 'Unsealed native prefix; complete subtrees only; no claims or native application'
        if pool_requests:
            config['pool_requests'] = fleet['pool_requests'] = str(pool_requests)
            report['pool_service'] = True
        packet_share, remainder = divmod(coordinator_bytes, len(devices))
        for index, device in enumerate(devices):
            uuid = device["uuid"]
            budget = budgets[uuid]
            if native is not None:
                budget["native_host"] = native.binding
            budget["host"]["coordinator_job_bytes"] = packet_share + (index < remainder)
            budget["unit"] = "lattica-v2-multi-persistent-" + secrets.token_hex(32) + ".service"
            budget['startup_guard'] = str(owner_dir / f'proofs/execution/worker-{index}-startup')
            directory = out / "workers" / f"gpu-{index + 1:02d}"
            directory.mkdir(mode=0o700, parents=True)
            if not cached_only:
                scratch = args.scratch.resolve() / budget["unit"].removesuffix(".service")
                scratch.mkdir(mode=0o700)
                (directory / "scratch").symlink_to(scratch, target_is_directory=True)
            if pool_requests:
                budget['pool_job_limit'] = 16384
            G.durable(directory / "budget.json", budget, True)
            arguments = ["serve-shared-process-gpu", str(owner_dir / "input"), str(expected),
                launch_directory, str(budget["host"]["worker_bytes"])]
            if cached_only:
                # Preserve assignment identity without creating a launchable GPU request.
                config['workers'].append({'budget': budget, 'directory': str(directory)})
                pins.update(dict([T.pin(directory / 'budget.json')]))
                fleet['workers'].append({'assignment': budget, 'arguments': arguments,
                    'launcher': ['/usr/bin/false'], 'log': str(directory / 'prove.log')})
                continue
            worker_config = {"schema_version": 1, "budget": budget, "directory": str(directory),
                             "owner_unit": owner_unit, "runtime_seconds": pool_runtime if pool_requests else 7200, "command": [str(gpu), *arguments], "pins": copy.deepcopy(pins)}
            worker_config["pins"].update(dict([T.pin(directory / "budget.json")]))
            for path in inputs:
                worker_config["pins"][str(owner_dir / "input" / path.name)] = pins[str(path)]
            launch_file = directory / "launch.json"
            G.durable(launch_file, worker_config, True)
            config["workers"].append(worker_config)
            pins.update(dict(T.pin(p) for p in [directory / "budget.json", launch_file]))
            fleet["workers"].append({"assignment": budget, "arguments": arguments,
                "launcher": [sys.executable, str(Path(__file__).resolve()), "--launch-worker", str(launch_file)],
                "log": str(directory / "prove.log")})
            report["attempts"].append({"unit": budget["unit"], "uuid": uuid, "directory": str(directory)})
        G.durable(out / "fleet-plan.json", fleet, True)
        pins.update(dict([T.pin(out / "fleet-plan.json")]))
        G.durable(out / "config.json", config, True)
        Bootstrap.create(out / 'config.json', Path(__file__).resolve())
        G.durable(out / "admission.json", {"host": host, "devices": devices, "budgets": budgets,
            "cached_only": cached_only, "gpu_inventory_observed": not cached_only,
            "runtime_scope": "CPU coordinator only; retained GPU budgets are identity metadata" if cached_only else "GPU fleet"}, True)
        if control is not None:
            Controller.authorize(control, out / 'config.json')
        G.systemctl("set-property", "--runtime", G.SLICE, f"MemoryMax={fleet['fleet_bytes']}", "MemorySwapMax=0", "MemoryAccounting=yes")
        before = M.event_counters(Path("/sys/fs/cgroup") / G.unit_state(G.SLICE)["ControlGroup"].lstrip('/') / "memory.events")
        command = properties(owner_unit, coordinator_bytes, f"{coordinator_threads * 100}%", host["effective_cpus"], owner_dir, pool_runtime if pool_requests else 7200)
        if control is not None:
            command += ['--property=BindsTo=' + control['unit'], '--property=After=' + control['unit']]
        command += ["--property=StandardOutput=append:" + str(owner_dir / "worker.log"), "--property=StandardError=inherit",
                    f"--setenv=RAYON_NUM_THREADS={coordinator_threads}", sys.executable, str(Path(__file__).resolve()),
                    "--owner", str(out / "config.json")]
        report.update(status="running", input_pins=pins, fleet_plan=fleet, parent_memory_events_before=before,
                      owner_unit=owner_unit, timing_boundary="owner fixture copy, shared DAG proving and independent CPU root audit")
        G.durable(out / "summary.json", report, True)
        launched = True
        execution_started = time.monotonic()
        subprocess.run(command, check=True, timeout=30)
        observed = set()
        while True:
            head_change = None if pool_requests else HeadGuard.observe(native, owner_dir)
            if head_change is not None:
                report['native_head_change'] = head_change
                Controller.publish(out / 'stale-head.json', head_change)
                raise N.H.StaleHead('native head changed during active proving')
            for attempt in report["attempts"]:
                sample = G.telemetry(attempt, budgets[attempt["uuid"]])
                observed.update(sample.get("pids", []))
                with (Path(attempt["directory"]) / "telemetry.jsonl").open("a") as stream:
                    stream.write(json.dumps(sample) + "\n")
            state = G.unit_state(owner_unit)
            with (owner_dir / "telemetry.jsonl").open("a") as stream:
                stream.write(json.dumps({"time_ns": time.time_ns(), "unit": state}) + "\n")
            if G.terminated(state):
                if not (pool_requests and state.get("Result") == "success" and state.get("ExecMainStatus") == "0" and read(owner_dir / "result.json").get("pool_service") is True) and not owner_succeeded(owner_dir, state, prefix=preseal):
                    late_change = HeadGuard.failed_application(native, owner_dir)
                    if late_change is not None:
                        report['native_head_change'] = late_change
                        Controller.publish(out / 'stale-head.json', late_change)
                    raise ValueError("shared DAG owner failed; no automatic retry")
                break
            time.sleep(0.5)
        result = read(owner_dir / "result.json")
        if pool_requests:
            if result.get('status') != 'succeeded' or result.get('pool_service') is not True:
                raise ValueError('persistent pool owner failed')
            for worker in config['workers']:
                accounting = read(Path(worker['directory']) / 'accounting.json')
                validate_worker_accounting(accounting, worker['budget'], {}, False)
            after = M.event_counters(Path('/sys/fs/cgroup') / G.unit_state(G.SLICE)['ControlGroup'].lstrip('/') / 'memory.events')
            deltas = fleet_event_deltas(before, after, [], False)
            report.update(parent_memory_event_deltas=deltas)
            report.update(status='succeeded', pool_service=True, pool_result=result['pool_result'],
                          cpu_audited_roots=0, native_blocks_applied=0,
                          scope='Persistent aggregation service; per-candidate audit and native receipts are separate evidence')
            return

        validate_execution(result["execution_result"], args.count, config["workers"],
            config.get("native_host"), preseal_only=preseal, allow_worker_failover=failover,
            recovery_source=config.get('recover_from'), recover_cached_only=cached_only)
        if preseal:
            audit = read(owner_dir / 'prefix-audit.json')
            if (result.get('status') != 'succeeded' or result.get('preseal_only') is not True
                    or result.get('cpu_prefix_audited') is not True or result.get('cpu_audited') is not False
                    or result.get('native_blocks_applied') != 0 or result.get('durable_host_applied') is not False
                    or result.get('native_host_binding') != native.binding
                    or result.get('prefix_audit') != audit or audit.get('status') != 'passed'
                    or audit.get('cpu_audited_roots') != 0
                    or len(audit.get('nodes', [])) != result['fresh_proofs'] + result['reused_proofs']
                    or (owner_dir / 'proofs/node.6.0').exists()):
                raise ValueError('shared prefix audit or native isolation differs')
            native.check(native.binding)
            intake.check_prefix(native)
            report['prefix_independently_confirmed'] = True
        elif native is not None:
            if (result.get("status") != "succeeded" or result.get("durable_host_applied") is not True
                    or type(result.get("native_blocks_applied")) is not int
                    or result["native_blocks_applied"] != 1
                    or result.get("native_host_binding") != native.binding):
                raise ValueError("shared native owner did not confirm one bound application")
            native.verify_application(result["native_application"], owner_dir / "root-only/node.6.0", native.binding)
            if intake is not None:
                applied = intake.verify_recorded_application(args.arrival_selection, native,
                    result["native_application"], owner_dir / "root-only/node.6.0")
                if (result.get("arrival_publication_status") != "applied"
                        or result.get("arrival_application") != applied
                        or result.get("arrival_selection") != args.arrival_selection):
                    raise ValueError("shared owner did not confirm the sealed arrivals' application")
                report["arrival_application_independently_confirmed"] = True
        worker_results = []
        nodes = T.public_events(owner_dir / "prove.log", "fresh_typed_node")
        for attempt in report["attempts"]:
            directory, uuid = Path(attempt["directory"]), attempt["uuid"]
            if not G.terminated(G.unit_state(attempt["unit"])):
                raise ValueError("shared GPU service remains active")
            accounting = read(directory / "accounting.json")
            own_nodes = [node for node in nodes if node["gpu_uuid"] == uuid]
            completed = T.public_events(directory / "prove.log", "typed_gpu_work_complete")
            execution_worker = next(w for w in result['execution_result']['workers'] if w['gpu_uuid'] == uuid)
            memory_failure = validate_worker_accounting(accounting, budgets[uuid], execution_worker, failover)
            failed = execution_worker.get('worker_failed') is True
            if failed:
                if completed or execution_worker['cache_hits'] + execution_worker['cache_setups'] != len(own_nodes):
                    raise ValueError('failed worker completed-response accounting differs')
            elif len(completed) != 1 or completed[0]["recursive_proofs"] != len(own_nodes):
                raise ValueError("shared GPU work counters differ from accepted nodes")
            context = T.measured_context(directory / "prove.log", uuid) if own_nodes else None
            worker_results.append({"gpu_uuid": uuid, "budget": budgets[uuid], "accounting": accounting,
                                   "context_measurement": context, "fresh_proofs": len(own_nodes),
                                   "worker_failed": failed, "termination": execution_worker,
                                   "memory_failure": memory_failure})
        if any(pid in observed for pid, _, _ in G.gpu_processes()):
            raise ValueError("shared worker GPU context remains after exit")
        owner_accounting = read(owner_dir / "accounting.json")
        T.validate_accounting(owner_accounting, {"host": {"worker_bytes": coordinator_bytes}})
        after = M.event_counters(Path("/sys/fs/cgroup") / G.unit_state(G.SLICE)["ControlGroup"].lstrip('/') / "memory.events")
        deltas = fleet_event_deltas(before, after, worker_results, failover)
        T.check_pins(pins)
        report.update(status="succeeded", result=result, workers=worker_results, owner_accounting=owner_accounting,
                      parent_memory_events_after=after, parent_memory_event_deltas=deltas,
                      execution_elapsed_seconds=time.monotonic() - execution_started,
                      cpu_audited_roots=0 if preseal else 1,
                      cpu_audited_prefix_nodes=len(result['prefix_audit']['nodes']) if preseal else 0,
                      reused_recursive_proofs=result.get('reused_proofs', 0),
                      fresh_recursive_proofs=result["fresh_proofs"], shared_dag_owner=True)
    except BaseException as error:
        report.update(status="failed", failure=f"{type(error).__name__}: {error}")
        raise
    finally:
        try:
            if launched and not G.terminated(G.unit_state(owner_unit)):
                G.systemctl("stop", owner_unit)
            if launched and not G.terminated(G.unit_state(owner_unit)):
                raise ValueError('shared owner service cleanup incomplete')
            for attempt in report["attempts"]:
                if not G.terminated(G.unit_state(attempt["unit"])):
                    G.systemctl("stop", attempt["unit"])
                if not G.terminated(G.unit_state(attempt["unit"])):
                    raise ValueError("shared GPU service cleanup incomplete")
                scratch = Path(attempt["directory"]) / "scratch"
                if report["status"] == "succeeded" and scratch.is_symlink():
                    target = scratch.resolve()
                    expected = args.scratch.resolve() / attempt["unit"].removesuffix(".service")
                    if target == expected and target.is_dir():
                        shutil.rmtree(target)
            if report.get('native_head_change') is not None:
                quiescent_fleet(owner_unit, report['attempts'])
                report['native_head_change']['owner_and_workers_quiescent'] = True
                report['native_head_change']['quiescent_monotonic_ns'] = time.monotonic_ns()
                if intake is not None and not preseal and native.recovered_application is None:
                    cancelled = intake.cancel(args.arrival_selection, 'stale_head')
                    Controller.publish(out / 'stale-selection.json', cancelled)
                    report['stale_selection'] = cancelled
        except BaseException as error:
            report.update(status="failed", cleanup_failure=f"{type(error).__name__}: {error}")
            raise
        finally:
            if created:
                G.durable(out / "summary.json", report)
            for lock in locks:
                os.close(lock)
    print(json.dumps({"status": report["status"], "cpu_audited_roots": report.get("cpu_audited_roots", 0)}))


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller-request', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--supervisor-request', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--supervisor-accounting', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--supervise', action='store_true', help='supervise a sealed native candidate with bounded durable retries')
    parser.add_argument('--supervisor-max-restarts', type=int, default=2, help='maximum controller recovery attempts (0..8)')
    parser.add_argument('--supervisor-restart-delay', type=int, default=2, help='seconds between terminated attempts (0..60)')
    parser.add_argument('--recover-controller', type=Path,
                        help='resume an interrupted controller in a fresh evidence directory')
    parser.add_argument('--pool-requests', type=Path, help='private local inbox for persistent native candidates')
    parser.add_argument('--pool-runtime-seconds', type=int, default=172800, help='bounded persistent service lifetime, 7200 to 604800 seconds')
    parser.add_argument("--owner", type=Path)
    parser.add_argument("--launch-worker", type=Path)
    parser.add_argument("--gpu-binary", type=Path)
    parser.add_argument("--cpu-binary", type=Path)
    parser.add_argument("--workload", type=Path, help="explicit workload and pool allocation policy")
    parser.add_argument("--fixture", type=Path)
    parser.add_argument('--resource-assignment', type=Path,
                        help='retain fixed per-GPU CPU/RAM/spill/VRAM limits when current capacity admits them')
    parser.add_argument("--host-config", type=Path)
    parser.add_argument("--host-journal", type=Path)
    parser.add_argument("--arrival-store", type=Path)
    parser.add_argument("--arrival-selection")
    parser.add_argument("--allow-worker-failover", action="store_true",
                        help="drain failed supervised workers and retry their jobs on surviving GPUs")
    parser.add_argument("--recover-owner", type=Path,
        help="restart an interrupted native owner after exact service reconciliation")
    parser.add_argument("--recovery-admission-timeout", type=float, default=120,
        help="maximum seconds to wait for the original recovery limits to fit (up to 300)")
    parser.add_argument("--preseal", action="store_true", help="prove complete unsealed native prefix subtrees")
    parser.add_argument("--reuse-preseal", type=Path, action="append", default=[],
                        help="reuse a previous prefix owner's proofs directory after CPU verification")
    parser.add_argument('--calibration-trial', type=Path, action='append', default=[],
                        help='complete pinned single-GPU shared-owner trial for context calibration')
    parser.add_argument("--gpu-uuid", action="append", default=[])
    parser.add_argument("--count", type=int, choices=T.COUNTS, default=8)
    parser.add_argument("--scratch", type=Path, default=Path("/tmp"))
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--recover-cached-only", action="store_true",
                        help="reverify a complete recovered root and apply it without starting GPU workers")
    return parser


def main():
    parser = argument_parser()
    args = parser.parse_args()
    if args.supervisor_request or args.supervisor_accounting:
        supervisor = importlib.import_module('block_v2_supervisor')
        if args.supervisor_accounting:
            return supervisor.capture_accounting(args.supervisor_accounting, Path(__file__).resolve())
        return supervisor.run_request(args.supervisor_request, Path(__file__).resolve(), parser, sys.modules[__name__])
    if args.controller_request:
        args, control = Controller.enter(args.controller_request, parser, Path(__file__).resolve())
        return run(args, control)
    if args.owner:
        return owner(args.owner)
    if args.launch_worker:
        return launch_worker(args.launch_worker)
    recovered = None
    if args.recover_controller:
        if args.evidence is None:
            parser.error('controller recovery requires a fresh --evidence directory')
        options = {arg.split('=', 1)[0] for arg in sys.argv[1:] if arg.startswith('--')}
        if options - {'--recover-controller', '--evidence', '--recover-cached-only'}:
            parser.error('controller recovery reuses its pinned options; specify --recover-controller, --evidence and optional --recover-cached-only')
        args, recovered = Controller.recover(args, parser)
    if any(getattr(args, name) is None for name in ["gpu_binary", "cpu_binary", "fixture", "evidence"]):
        parser.error("GPU/CPU binaries, fixture and fresh evidence directory are required")
    scripts = set(Path(__file__).resolve().parent.glob('*.py')) | {Path(__file__).resolve()}
    paths = [args.gpu_binary.resolve(strict=True), args.cpu_binary.resolve(strict=True),
             *T.fixture_files(args.fixture.resolve(strict=True), args.count, 'paired'), *scripts,
             Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json')]
    if args.host_config:
        paths.append(args.host_config.resolve(strict=True))
    if args.resource_assignment:
        paths.append(args.resource_assignment.resolve(strict=True))
    if args.workload:
        paths.append(args.workload.resolve(strict=True))
    pins = dict(T.pin(path) for path in paths)
    if args.calibration_trial:
        pins.update(Calibration.source_pins(args.calibration_trial, sys.modules[__name__]))
    if args.supervise:
        if recovered is not None:
            raise ValueError('supervision starts from a fresh native candidate')
        supervisor = importlib.import_module('block_v2_supervisor')
        return supervisor.launch(args, Path(__file__).resolve(), pins)
    Controller.launch(args, Path(__file__).resolve(), pins, accounting_property, recovered)


if __name__ == "__main__":
    main()
