#!/usr/bin/env python3
"""Pinned grouped-eight research jobs, one process at a time per GPU UUID.

A new evidence directory is mandatory. Recovery reconciles existing attempts;
it never retries a proof or starts the remainder of an interrupted job.
"""
import argparse
from dataclasses import asdict
import fcntl
import hashlib
import itertools
from fractions import Fraction
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

import block_v2_resources as R

SLICE = 'lattica-v2-multi.slice'
INPUTS = tuple(f'wallet.{i}' for i in range(8)) + ('height', 'key.1', 'key.2', 'key.3')
ROOT = ('node.3.0', 'height', 'key.1', 'key.2', 'key.3')


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def durable(path, data, exclusive=False):
    path = Path(path)
    if exclusive and path.exists():
        raise ValueError(f'will not overwrite {path}')
    tmp = path.with_name(path.name + '.tmp')
    with open(tmp, 'x') as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_pins(config):
    if config.get('version') != 1 or not config.get('jobs'):
        raise ValueError('version 1 config with pinned jobs required')
    required = {config[k] for k in ('gpu_binary', 'cpu_binary', 'auditor')}
    if not 1 <= config['max_concurrency'] <= len(config['gpu_uuids']):
        raise ValueError('invalid requested concurrency')
    if len(set(config['gpu_uuids'])) != len(config['gpu_uuids']):
        raise ValueError('duplicate GPU UUID')
    ids = set()
    for job in config['jobs']:
        if not re.fullmatch('[a-z0-9_-]{1,48}', job['id']) or job['id'] in ids:
            raise ValueError('distinct simple job IDs required')
        ids.add(job['id'])
        if len(job['external']) != 3 or any(not re.fullmatch('[0-9a-fA-F]{64}', x) for x in job['external']):
            raise ValueError('external profile, chain and root must be pinned 32-byte hex strings')
        if job.get('gpu_uuid') and job['gpu_uuid'] not in config['gpu_uuids']:
            raise ValueError('job is pinned to an unselected GPU')
        height = (Path(job['source']) / 'height').read_bytes()
        if len(height) != 4 or int.from_bytes(height, 'little') != config['workload']['height']:
            raise ValueError('pinned input height differs from workload model')
        required.update(str(Path(job['source']) / name) for name in INPUTS)
    if not required <= config['pins'].keys():
        raise ValueError('missing binary or input pins')
    for path, expected in config['pins'].items():
        if digest(path) != expected:
            raise ValueError(f'pin changed: {path}')
    for uuid, cal in config.get('calibrations', {}).items():
        if cal['binary_sha256'] != config['pins'][config['gpu_binary']] or cal['profile_sha256'] != profile_digest(config):
            raise ValueError(f'stale calibration on {uuid}')


def profile_digest(config):
    # Context calibration is bound to the binary and proof geometry. Changing
    # host headroom estimates does not change the polynomial/kernel workload.
    workload = config['workload']
    identity = {k: workload[k] for k in ('version', 'name', 'height', 'geometry')}
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def selected_devices(config):
    devices = {d['uuid']: d for d in R.detect_gpus(config['gpu_binary'])}
    if any(u not in devices for u in config['gpu_uuids']):
        raise ValueError('selected GPU unavailable')
    return [devices[u] for u in sorted(config['gpu_uuids'])]


def choose_plan(config, host, devices, failures=None):
    failures = [] if failures is None else failures
    # A qualification run can enforce the prospective concurrent-worker
    # budgets while only launching one job at a time.
    requested_slots = config.get('worker_slots', config['max_concurrency'])
    if not 1 <= requested_slots <= len(devices):
        raise ValueError('invalid intended worker slots')
    for slots in range(requested_slots, 0, -1):
        for selection in itertools.combinations(devices, slots):
            pinned = {j['gpu_uuid'] for j in config['jobs'] if j.get('gpu_uuid')}
            if not pinned <= {d['uuid'] for d in selection}:
                continue
            try:
                budgets = R.plan(host, list(selection), slots, config['workload'], config.get('calibrations'))
                if config.get('qualification_mode'):
                    if config['max_concurrency'] != 1 or not config.get('worker_slots'):
                        raise ValueError('qualification mode requires serial execution with intended worker slots')
                    budgets = {uuid: R.qualification_budget(b, config['workload']) for uuid, b in budgets.items()}
                return budgets
            except ValueError as e:
                failures.append({'worker_slots': slots, 'gpu_uuids': [d['uuid'] for d in selection],
                                 'reason': str(e)})
        if config.get('worker_slots'):
            break
    raise ValueError('no resource plan fits: ' + '; '.join(f['reason'] for f in failures))


def qualification_gate(config, budgets):
    if min(config['max_concurrency'], len(budgets)) < 2:
        return
    for uuid, budget in budgets.items():
        if budget['gpu']['bootstrap']:
            raise ValueError('concurrent jobs require per-device context calibration')
        q = config.get('qualifications', {}).get(uuid, {})
        if not q.get('cpu_audited') or q.get('binary_sha256') != config['pins'][config['gpu_binary']] or q.get('profile_sha256') != profile_digest(config):
            raise ValueError(f'{uuid} needs a full-size CPU-audited qualification with this binary/profile')
        # Qualification at a larger allowance cannot authorize smaller workers.
        for section, keys in {'host': ['worker_bytes', 'spill_bytes'], 'gpu': ['managed_bytes', 'context_bytes'], 'cpu': ['rayon_threads']}.items():
            if any(q['budget'][section][key] > budget[section][key] for key in keys):
                raise ValueError(f'{uuid} has not qualified these smaller worker budgets')
        evidence = Path(q['evidence'])
        result = json.loads(evidence.read_text())
        if digest(evidence) != q['evidence_sha256'] or result.get('status') != 'succeeded' or not result.get('cpu_audited') or result.get('budget') != q['budget'] or result.get('binary_sha256') != q['binary_sha256'] or result.get('profile_sha256') != q['profile_sha256']:
            raise ValueError('qualification evidence missing or changed')


def systemctl(*args):
    return subprocess.check_output(['systemctl', '--user', *args], text=True, timeout=15)


def worker_cgroup():
    manager = systemctl('show', '--property=ControlGroup', '--value', '--', '-.slice').strip()
    root = Path('/sys/fs/cgroup')
    manager_path = (root / manager.lstrip('/')).resolve()
    if not manager.startswith('/') or not manager_path.is_relative_to(root) or not manager_path.is_dir():
        raise ValueError('cannot resolve the worker user-manager cgroup')
    # systemd expands slice name components into nested parent slices.
    parts = SLICE.removesuffix('.slice').split('-')
    return manager_path.joinpath(*('-'.join(parts[:i]) + '.slice' for i in range(1, len(parts) + 1)))


def detect_worker_host(scratch):
    return R.detect_host(scratch, worker_cgroup=worker_cgroup())


def unit_state(unit):
    out = systemctl('show', unit, '--property=ActiveState,SubState,ControlGroup,Result,ExecMainStatus')
    return dict(line.split('=', 1) for line in out.splitlines() if '=' in line)


def terminated(state):
    if state.get('ActiveState') not in ('inactive', 'failed', ''):
        return False
    group = state.get('ControlGroup')
    if group:
        events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
        if events.exists() and 'populated 1' in events.read_text():
            return False
    return True


def attempt_succeeded(directory, state):
    result = Path(directory) / 'result.json'
    if not result.exists() or state.get('Result') != 'success' or state.get('ExecMainStatus') != '0':
        return False
    value = json.loads(result.read_text())
    return value.get('status') == 'succeeded' and value.get('cpu_audited') is True


def reconcile(ledger, lookup=None):
    lookup = lookup or unit_state
    for attempt in ledger['attempts']:
        if attempt['status'] != 'running':
            continue
        state = lookup(attempt['unit'])
        attempt['last_unit_state'] = state
        if terminated(state):
            attempt['status'] = 'succeeded' if attempt_succeeded(attempt['directory'], state) else 'interrupted'
            attempt['reservation_released'] = True
    return ledger


def environment(budget, directory):
    gpu, cpu, host = (budget[k] for k in ('gpu', 'cpu', 'host'))
    layout = budget.get('readback_layout', 'banded')
    if layout not in ('banded', 'direct'):
        raise ValueError('unsupported assigned readback layout')
    query_layout = budget.get('query_readback_layout', 'rows')
    if query_layout not in ('rows', 'gather'):
        raise ValueError('unsupported assigned query readback layout')
    denominator_cache = budget.get('opening_denominator_cache', False)
    fri_fold = budget.get('gpu_fri_fold', False)
    if type(fri_fold) is not bool:
        raise ValueError('assigned GPU FRI folding selection must be boolean')
    if type(denominator_cache) is not bool:
        raise ValueError('assigned opening denominator cache selection must be boolean')
    return {
        'RAYON_NUM_THREADS': str(cpu['rayon_threads']), 'LATTICA_GPU_DEVICE_UUID': gpu['uuid'],
        'LATTICA_V2_ACCOUNTING_UNIT': budget['unit'], 'LATTICA_V2_WORKER_BUDGET': str(directory / 'budget.json'),
        'LATTICA_V2_GPU_MANAGED_BYTES': str(gpu['managed_bytes']),
            'LATTICA_V2_GPU_LDE_WORKSPACE_BYTES': str(budget.get('lde_workspace_bytes', 0)), 'LATTICA_V2_GPU_CONTEXT_BYTES': str(gpu['context_bytes']),
            'LATTICA_V2_GPU_FRI_FOLD': '1' if fri_fold else '0',
        'LATTICA_V2_HOST_OUTPUT_BYTES': str(host['worker_bytes']), 'LATTICA_SPILL_MAX_BYTES': str(host['spill_bytes']), 'LATTICA_SPILL_DIR': str(directory / 'scratch'),
        'LATTICA_V2_GPU_HASH': '1', 'LATTICA_V2_GPU_RETAIN_TREES': '1', 'LATTICA_V2_GPU_PIPELINE': '0',
        'LATTICA_V2_GPU_RESIDENT_LDE': '1', 'LATTICA_V2_GPU_OPENINGS': '1', 'LATTICA_V2_GPU_OPENING_COMPACT': '1',
        'LATTICA_V2_GPU_OPENING_PINNED': '0', 'LATTICA_V2_QUOTIENT_FUSION': '1', 'LATTICA_V2_GPU_QUOTIENT_LDE': '1',
        'LATTICA_V2_GPU_PARALLEL_READBACK': '1', 'LATTICA_V2_GPU_COMPACT_PROVER_DATA': '1',
        'LATTICA_V2_GPU_DIRECT_READBACK': '1' if layout == 'direct' else '0',
        'LATTICA_V2_GPU_QUERY_GATHER': '1' if query_layout == 'gather' else '0',
        'LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE': '1' if denominator_cache else '0',
        'LATTICA_FFT_TRACE': '1', 'LATTICA_PROFILE': '1', 'LATTICA_PROFILE_TIMELINE': '0',
    }


def launch(config, job, budget, directory, worker_script=None):
    worker_script = Path(worker_script or __file__).resolve()
    if worker_script != Path(__file__).resolve() and config['pins'].get(str(worker_script)) != digest(worker_script):
        raise ValueError('alternate worker controller must be pinned before launch')
    directory.mkdir(mode=0o700)
    scratch = Path(budget['host']['scratch_path']) / budget['unit'].removesuffix('.service')
    if len(os.fsencode(str(directory / 'scratch'))) > 255:
        raise ValueError('scratch path exceeds allocator path bound')
    scratch.mkdir(mode=0o700)
    (directory / 'scratch').symlink_to(scratch, target_is_directory=True)
    durable(directory / 'budget.json', budget, True)
    durable(directory / 'attempt.json', {'config': config, 'job': job, 'budget': budget}, True)
    command = ['systemd-run', '--user', '--no-block', '--expand-environment=no', '--unit=' + budget['unit'], '--slice=' + SLICE,
               '--property=MemoryAccounting=yes', '--property=MemoryMax=' + str(budget['host']['worker_bytes']),
               '--property=MemorySwapMax=0', '--property=CPUQuota=' + budget['cpu']['quota_percent'],
               '--property=AllowedCPUs=' + ','.join(map(str, budget['cpu']['allowed_cpus'])),
               '--property=RuntimeMaxSec=7200', '--property=KillMode=control-group', '--property=LimitCORE=0', '--property=UMask=0077',
               '--property=ExecStopPost=' + ' '.join([sys.executable, str(Path(__file__).resolve()), '--accounting', str(directory)]),
               '--property=StandardOutput=append:' + str(directory / 'worker.log'), '--property=StandardError=inherit']
    for name, value in environment(budget, directory).items():
        command.append(f'--setenv={name}={value}')
    command += [sys.executable, str(worker_script), '--worker', str(directory / 'attempt.json')]
    subprocess.run(command, check=True, timeout=30)


def gpu_processes():
    text = subprocess.check_output(['nvidia-smi', '--query-compute-apps=pid,gpu_uuid,used_memory', '--format=csv,noheader,nounits'], text=True, timeout=10)
    result = []
    for row in text.splitlines():
        pid, uuid, mib = [s.strip() for s in row.split(',')]
        result.append((int(pid), uuid, int(mib) * R.MIB))
    return result


def telemetry(attempt, budget):
    state = unit_state(attempt['unit'])
    sample = {'time_ns': time.time_ns(), 'unit': state, 'gpu_processes': []}
    group = state.get('ControlGroup')
    if group:
        root = Path('/sys/fs/cgroup') / group.lstrip('/')
        for name in ('memory.current', 'memory.peak', 'memory.events', 'cpu.stat', 'cpu.max', 'cpuset.cpus.effective'):
            try:
                sample[name] = (root / name).read_text().strip()
            except FileNotFoundError:
                pass  # The cgroup can disappear after unit_state observes exit.
        pids = set()
        if root.exists():
            for f in root.rglob('cgroup.procs'):
                try:
                    pids.update(map(int, f.read_text().split()))
                except FileNotFoundError:
                    pass
        sample['pids'] = sorted(pids)
        # Count allocated scratch blocks already reflected in filesystem free
        # space. ftruncate length also includes still-unfaulted pages, which
        # must remain reserved. Deduplicate inherited descriptors by inode.
        mappings = {}
        scratch = (Path(attempt['directory']) / 'scratch').resolve()
        for pid in pids:
            try:
                for fd in (Path('/proc') / str(pid) / 'fd').iterdir():
                    try:
                        link = os.readlink(fd)
                        if link.startswith(str(scratch) + '/lat-spill-'):
                            st = fd.stat()
                            mappings[(st.st_dev, st.st_ino)] = st.st_blocks * 512
                    except (FileNotFoundError, PermissionError):
                        pass
            except (FileNotFoundError, PermissionError):
                pass
        sample['scratch_allocated_bytes'] = sum(mappings.values())
        total = 0
        for pid, uuid, size in gpu_processes():
            if pid in pids:
                sample['gpu_processes'].append({'pid': pid, 'uuid': uuid, 'bytes': size})
                if uuid != budget['gpu']['uuid']:
                    raise ValueError('worker created a context on an unassigned GPU')
                total += size
        if total > budget['gpu']['total_bytes']:
            raise ValueError('observed worker VRAM exceeds assigned total limit')
    return sample


def worker(attempt_file):
    path = Path(attempt_file).resolve()
    record = json.loads(path.read_text())
    config, job, budget = (record[k] for k in ('config', 'job', 'budget'))
    directory = path.parent
    verify_pins(config)
    work = directory / 'job'
    work.mkdir(mode=0o700)
    for name in INPUTS:
        shutil.copyfile(Path(job['source']) / name, work / name)
        if digest(work / name) != config['pins'][str(Path(job['source']) / name)]:
            raise ValueError('copied input pin mismatch')
    cpu_env = {k: v for k, v in os.environ.items() if not k.startswith('LATTICA_V2_GPU') and k != 'LATTICA_GPU_DEVICE_UUID'}
    stages = [('check', config['cpu_binary'], ['check-registered', str(work), *job['external']], cpu_env),
              ('pairs', config['gpu_binary'], ['wrap-all', str(work), *job['external']], os.environ),
              ('merges', config['gpu_binary'], ['merge-all', str(work), *job['external']], os.environ),
              ('check-all', config['cpu_binary'], ['check-registered', str(work), *job['external']], cpu_env)]
    started = time.monotonic()
    for stage, binary, args, env in stages:
        durable(directory / (stage + '-started.json'), {'started_ns': time.time_ns()}, True)
        with open(directory / (stage + '.log'), 'x') as log:
            subprocess.run([binary, *args], stdout=log, stderr=subprocess.STDOUT, env=env, check=True, timeout=7100)
        durable(directory / (stage + '-finished.json'), {'finished_ns': time.time_ns()}, True)
    exported = directory / 'root-only'
    exported.mkdir(mode=0o700)
    for name in ROOT:
        source = work / name
        if name == 'node.3.0' and source.stat().st_size >= 2 * R.MIB:
            raise ValueError('root proof exceeds 2 MiB cap')
        shutil.copyfile(source, exported / name)
    with open(directory / 'audit.log', 'x') as log:
        subprocess.run([config['auditor'], 'root-eight', str(exported), *job['external']], stdout=log, stderr=subprocess.STDOUT, env=cpu_env, check=True)
    result = {'status': 'succeeded', 'cpu_audited': True, 'elapsed_seconds': time.monotonic() - started,
              'budget': budget, 'binary_sha256': config['pins'][config['gpu_binary']], 'profile_sha256': profile_digest(config),
              'root_bytes': (exported / 'node.3.0').stat().st_size, 'artifacts': {n: digest(exported / n) for n in ROOT}}
    durable(directory / 'result.json', result, True)


def lock_fleet():
    path = Path('/tmp') / f'lattica-v2-gpu-lease-{os.getuid()}'
    path.mkdir(mode=0o700, exist_ok=True)
    stat = path.lstat()
    if not path.is_dir() or path.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError('unsafe GPU lease directory')
    handles = []
    for name, mode in [('scheduler.lock', fcntl.LOCK_EX), ('exclusive.lock', fcntl.LOCK_SH)]:
        fd = os.open(path / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        if os.fstat(fd).st_uid != os.getuid():
            os.close(fd)
            raise ValueError('unsafe lease owner')
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
        handles.append(fd)
    return handles


def run(config, evidence):
    locks = lock_fleet()
    try:
        verify_pins(config)
        running = json.loads(systemctl('list-units', 'lattica-v2-multi-*.service', '--state=active,activating,deactivating', '--output=json', '--no-pager'))
        if running:
            raise ValueError('existing multi-GPU workers require recovery before a new run')
        evidence.mkdir(mode=0o700)  # refuse every existing evidence directory
        durable(evidence / 'config.json', config, True)
        # Make actual worker parents visible before reading inherited limits.
        # Detection excludes only our own previous fleet MemoryMax.
        systemctl('start', SLICE)
        host = detect_worker_host(config['scratch'])
        devices = selected_devices(config)
        budgets = choose_plan(config, host, devices)
        qualification_gate(config, budgets)
        durable(evidence / 'admission.json', {'host': host, 'devices': devices, 'budgets': budgets}, True)
        fleet = next(iter(budgets.values()))['host']['fleet_bytes']
        systemctl('set-property', '--runtime', SLICE, f'MemoryMax={fleet}', 'MemorySwapMax=0', 'MemoryAccounting=yes')
        systemctl('start', SLICE)
        ledger = {'version': 1, 'attempts': [], 'queued': [j['id'] for j in config['jobs']], 'status': 'running'}
        durable(evidence / 'ledger.json', ledger, True)
        jobs = iter(config['jobs'])
        active = {}
        sequence = 0
        try:
            while ledger['queued'] or active:
                for uuid, (attempt, budget) in list(active.items()):
                    sample = telemetry(attempt, budget)
                    attempt['observed_pids'] = sorted(set(attempt.get('observed_pids', [])) | set(sample.get('pids', [])))
                    attempt['scratch_allocated_bytes'] = sample.get('scratch_allocated_bytes', 0)
                    with open(Path(attempt['directory']) / 'telemetry.jsonl', 'a') as f:
                        f.write(json.dumps(sample) + '\n')
                    gpu_alive = any(pid in attempt['observed_pids'] for pid, _, _ in gpu_processes())
                    if terminated(sample['unit']) and not gpu_alive:
                        attempt['status'] = 'succeeded' if attempt_succeeded(attempt['directory'], sample['unit']) else 'failed'
                        attempt['reservation_released'] = True
                        scratch = (Path(attempt['directory']) / 'scratch').resolve()
                        if scratch.exists():
                            scratch.rmdir()
                        del active[uuid]
                        durable(evidence / 'ledger.json', ledger)
                        if attempt['status'] != 'succeeded':
                            raise ValueError('proving attempt failed; no automatic retry')
                if ledger['queued'] and len(active) < min(config['max_concurrency'], len(budgets)):
                    # Recheck actual availability, deduct remaining reservations
                    # (the used portion is already reflected in host availability).
                    host = detect_worker_host(config['scratch'])
                    devices = {d['uuid']: d for d in selected_devices(config)}
                    for uuid in budgets:
                        if uuid in active:
                            continue
                        queued_job = next(j for j in config['jobs'] if j['id'] == ledger['queued'][0])
                        if queued_job.get('gpu_uuid', uuid) != uuid:
                            continue
                        budget = budgets[uuid]
                        if (Fraction(host['cpu_capacity']) < Fraction(budget['cpu']['effective_capacity'])
                                or not set(budget['cpu']['allowed_cpus']).issubset(host['effective_cpus'])):
                            if active:
                                ledger['admission_pause'] = 'CPU capacity fell; active pools stay fixed'
                                continue
                            budgets = choose_plan(config, host, list(devices.values()))
                            qualification_gate(config, budgets)
                            fleet = next(iter(budgets.values()))['host']['fleet_bytes']
                            systemctl('set-property', '--runtime', SLICE, f'MemoryMax={fleet}', 'MemorySwapMax=0')
                            break
                        ram_remaining = sum(max(0, b['host']['worker_bytes'] - int(telemetry(a, b).get('memory.current', '0'))) for a, b in active.values())
                        reserve = budget['host']['coordinator_bytes']
                        usable = max(0, host['available_bytes'] - budget['host']['os_headroom_bytes'])
                        if host['cgroup_memory_headroom'] is not None:
                            usable = min(usable, host['cgroup_memory_headroom'])
                        if budget['host']['worker_bytes'] + ram_remaining + reserve > usable:
                            ledger['admission_pause'] = 'RAM availability fell below outstanding reservations; admissions stopped'
                            if active:
                                continue
                            # Nothing is active: recalculate all slots using the
                            # current snapshot, preserving the FIFO queue.
                            budgets = choose_plan(config, host, list(devices.values()))
                            qualification_gate(config, budgets)
                            fleet = next(iter(budgets.values()))['host']['fleet_bytes']
                            systemctl('set-property', '--runtime', SLICE, f'MemoryMax={fleet}', 'MemorySwapMax=0')
                            break
                        if budget['gpu']['total_bytes'] + budget['gpu']['headroom_bytes'] > devices[uuid]['nvidia']['free_bytes']:
                            ledger['admission_pause'] = 'GPU availability fell since planning; admissions stopped'
                            if active:
                                continue
                            # Nothing is active: recalculate all slots using the
                            # current snapshot, preserving the FIFO queue.
                            budgets = choose_plan(config, host, list(devices.values()))
                            qualification_gate(config, budgets)
                            fleet = next(iter(budgets.values()))['host']['fleet_bytes']
                            systemctl('set-property', '--runtime', SLICE, f'MemoryMax={fleet}', 'MemorySwapMax=0')
                            break
                        # Reserve full spill allocations; tmpfs resident pages were
                        # already included in RAM. Live allocation accounting is
                        # conservative here and never spends active reservations.
                        spill_need = budget['host']['spill_bytes'] + sum(max(0, b['host']['spill_bytes'] - a.get('scratch_allocated_bytes', 0)) for a, b in active.values())
                        if spill_need > host['scratch']['available_bytes'] - budget['host']['filesystem_headroom_bytes']:
                            ledger['admission_pause'] = 'scratch availability fell below reservations; admissions stopped'
                            if active:
                                continue
                            # Nothing is active: recalculate all slots using the
                            # current snapshot, preserving the FIFO queue.
                            budgets = choose_plan(config, host, list(devices.values()))
                            qualification_gate(config, budgets)
                            fleet = next(iter(budgets.values()))['host']['fleet_bytes']
                            systemctl('set-property', '--runtime', SLICE, f'MemoryMax={fleet}', 'MemorySwapMax=0')
                            break
                        job = next(jobs)
                        sequence += 1
                        unit = f'lattica-v2-multi-{os.getpid()}-{sequence}.service'
                        directory = evidence / f'{sequence:03d}-{job["id"]}'
                        budget = {**budget, 'unit': unit, 'slice': SLICE,
                                  'admission_recheck': {'host': host, 'gpu': devices[uuid]}}
                        attempt = {'job': job['id'], 'uuid': uuid, 'unit': unit, 'directory': str(directory), 'status': 'running', 'reservation_released': False}
                        ledger['attempts'].append(attempt)
                        ledger['queued'].pop(0)
                        durable(evidence / 'ledger.json', ledger)  # reservation BEFORE spawn
                        active[uuid] = (attempt, budget)
                        launch(config, job, budget, directory)
                        break
                time.sleep(0.5)
            ledger['status'] = 'succeeded'
        except BaseException:
            ledger['status'] = 'failed'
            for attempt, _ in active.values():
                try:
                    subprocess.run(['systemctl', '--user', 'stop', attempt['unit']], check=False, timeout=20)
                except subprocess.TimeoutExpired:
                    ledger.setdefault('cleanup_errors', []).append('stop timed out: ' + attempt['unit'])
            try:
                reconcile(ledger)
            except Exception as error:
                # Keep reservations when termination cannot be established.
                ledger.setdefault('cleanup_errors', []).append(str(error))
            raise
        finally:
            durable(evidence / 'ledger.json', ledger)
    finally:
        for fd in locks:
            os.close(fd)


def summarize(evidence):
    config = json.loads((evidence / 'config.json').read_text())
    admission = json.loads((evidence / 'admission.json').read_text())
    devices = {d['uuid']: d for d in admission['devices']}
    ledger = json.loads((evidence / 'ledger.json').read_text())
    results, calibrations, qualifications = [], {}, {}
    for attempt in ledger['attempts']:
        directory = Path(attempt['directory'])
        if attempt['status'] != 'succeeded':
            continue
        result_path = directory / 'result.json'
        result = json.loads(result_path.read_text())
        result['accounting'] = json.loads((directory / 'accounting.json').read_text())
        result['gpu_process_peak_bytes'] = 0
        for line in (directory / 'telemetry.jsonl').read_text().splitlines():
            sample = json.loads(line)
            result['gpu_process_peak_bytes'] = max(result['gpu_process_peak_bytes'], sum(p['bytes'] for p in sample['gpu_processes']))
        contexts = []
        for path in (directory / 'pairs.log', directory / 'merges.log'):
            for line in path.read_text().splitlines():
                if line.startswith('bounded_gpu_context '):
                    contexts.append(json.loads(line.split(' ', 1)[1]))
        if not contexts or any(x['uuid'] != attempt['uuid'] for x in contexts):
            raise ValueError('missing or mismatched synchronized context measurements')
        uuid = attempt['uuid']
        device = devices[uuid]
        peak = max(c['context_bytes'] for c in contexts)
        if uuid in calibrations:
            peak = max(peak, calibrations[uuid]['peak_context_bytes'])
        calibrations[uuid] = {'uuid': uuid, 'driver': device['nvidia']['driver'], 'runtime': device['opencl']['driver'],
                              'peak_context_bytes': peak, 'samples': len(contexts),
                              'binary_sha256': config['pins'][config['gpu_binary']], 'profile_sha256': profile_digest(config)}
        qualifications[uuid] = {k: result[k] for k in ('cpu_audited', 'budget', 'binary_sha256', 'profile_sha256')}
        qualifications[uuid].update(evidence=str(result_path), evidence_sha256=digest(result_path))
        results.append(result)
    return {'version': 1, 'status': ledger['status'], 'results': results,
            'calibrations': calibrations, 'qualifications': qualifications, 'production_ready': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--recover', type=Path)
    parser.add_argument('--summarize', type=Path)
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--accounting', type=Path)
    args = parser.parse_args()
    if args.accounting:
        root = R.cgroup_path()
        data = {name: (root / name).read_text().strip() for name in ('memory.current', 'memory.peak', 'memory.events', 'cpu.stat', 'cpu.max', 'cpuset.cpus.effective')}
        durable(args.accounting / 'accounting.json', data, True)
    elif args.worker:
        worker(args.worker)
    elif args.summarize:
        print(json.dumps(summarize(args.summarize), indent=2))
    elif args.recover:
        locks = lock_fleet()
        try:
            path = args.recover / 'ledger.json'
            ledger = reconcile(json.loads(path.read_text()))
            durable(path, ledger)
            print(json.dumps(ledger, indent=2))
        finally:
            for fd in locks:
                os.close(fd)
    else:
        if not args.config:
            parser.error('--config is required')
        config = json.loads(args.config.read_text())
        verify_pins(config)
        if args.plan:
            host = detect_worker_host(config['scratch'])
            devices = selected_devices(config)
            failures = []
            budgets = choose_plan(config, host, devices, failures)
            print(json.dumps({'plan_version': 1, 'captured_ns': str(time.time_ns()),
                              'requested_workers': config.get('worker_slots', config['max_concurrency']),
                              'admitted_workers': len(budgets), 'admission_failures': failures,
                              'config_sha256': digest(args.config),
                              'binary_sha256': config['pins'][config['gpu_binary']],
                              'profile_sha256': profile_digest(config),
                              'workload_id': config['workload'].get('name', config['workload'].get('id')),
                              'host': host, 'devices': devices, 'budgets': budgets}, indent=2))
        else:
            if not args.evidence:
                parser.error('a fresh --evidence directory is required')
            try:
                run(config, args.evidence.resolve())
            finally:
                # run() has completed its worker cleanup; no measured work remains.
                from block_v2_report_export import export_after_run
                export_after_run(args.evidence.resolve())


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'FAILED: {error}', file=sys.stderr)
        sys.exit(1)
