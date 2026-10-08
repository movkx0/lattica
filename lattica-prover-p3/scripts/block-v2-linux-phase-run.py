#!/usr/bin/env python3
"""Bounded Linux shared-memory screen: repeated GPU UUIDs are independent jobs.

One complete eight-input, CPU-audited job on each GPU with this exact binary
must qualify driver contexts before two slots on that device can be admitted.
Public cache and proof artifacts are per invocation. Private spill stays tmpfs.
"""
import argparse
from collections import Counter
from fractions import Fraction
import copy
import csv
import importlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

T = importlib.import_module('block-v2-typed-gpu-run')
G, R = T.G, T.R
M = importlib.import_module('block-v2-typed-multi-gpu-run')
P = importlib.import_module('block_v2_phase_memory')


def read(path):
    return json.loads(Path(path).read_text())


def contexts(log, budget):
    samples = [json.loads(line.split(' ', 1)[1]) for line in log.read_text().splitlines()
               if line.startswith('bounded_gpu_context ')]
    if not samples:
        raise ValueError('missing in-process GPU context measurements')
    for sample in samples:
        if (sample['uuid'] != budget['gpu']['uuid'] or sample['limit_bytes'] != budget['gpu']['total_bytes']
                or sample['managed_live_bytes'] > budget['gpu']['managed_bytes']
                or sample['context_bytes'] > budget['gpu']['context_bytes']):
            raise ValueError('context measurement exceeds its reservation')
    return dict(samples=len(samples), peak_context_bytes=max(s['context_bytes'] for s in samples),
                peak_process_bytes=max(s['process_bytes'] for s in samples))


def calibration(paths, binary, inventory, profile):
    result = {}
    for path in paths:
        doc = read(path / 'summary.json')
        if (doc.get('status') != 'succeeded' or doc.get('binary_sha256') != G.digest(binary)
                or doc.get('memory_model', {}).get('schema') != P.SCHEMA
                or doc.get('workload') != profile):
            raise ValueError('context qualification differs from binary, memory mode, or geometry')
        for worker in doc['workers']:
            expected_env = P.schedule(doc['memory_model'], Path('/tmp/qualification'), 1)['env']
            measured_env = worker['budget']['memory_schedule']['env']
            for key in P.ENV - {'PHASE_DIR', 'SHARED_PREPROCESSING_DIR', 'GPU_WORKERS'}:
                if measured_env[key] != expected_env[key]:
                    raise ValueError('context qualification memory/scratch policy changed')
            uuid = worker['uuid']
            device = inventory[uuid]
            if worker['drivers'] != dict(nvidia=device['nvidia']['driver'], opencl=device['opencl']['driver']):
                raise ValueError('context qualification driver changed')
            if not worker['result']['cpu_audited'] or worker['result']['fresh_proofs'] != 8:
                raise ValueError('context qualification needs a complete CPU-audited eight-input root')
            result[uuid] = max(result.get(uuid, 0), worker['context']['peak_context_bytes'])
    return result


def compute_processes():
    out = subprocess.run(['nvidia-smi', '--query-compute-apps=pid,gpu_uuid,process_name',
                          '--format=csv,noheader,nounits'], check=True, text=True, capture_output=True, timeout=15)
    return [(int(pid.strip()), uuid.strip(), name.strip()) for pid, uuid, name in csv.reader(out.stdout.splitlines())]


def idle(uuids):
    allowed = set()
    for pid, uuid, name in compute_processes():
        if uuid in uuids:
            if Path(name).name not in ('kwin_wayland', 'Xorg', 'gnome-shell'):
                raise ValueError(f'GPU busy with another compute process: {pid} {name}')
            allowed.add(pid)
    return allowed


def shared_mappings(pids, shared_dir):
    result = []
    for pid in pids:
        try:
            root = Path('/proc') / str(pid)
            maps = []
            for line in (root / 'maps').read_text().splitlines():
                fields = line.split(None, 5)
                if len(fields) == 6 and fields[5].startswith(str(shared_dir) + '/'):
                    maps.append(dict(inode=int(fields[4]), permissions=fields[1], path=fields[5]))
            if maps:
                memory = {}
                for line in (root / 'smaps_rollup').read_text().splitlines():
                    fields = line.split()
                    if fields[0].rstrip(':') in ('Rss', 'Pss', 'Private_Dirty', 'Shared_Dirty', 'Anonymous'):
                        memory[fields[0].rstrip(':') + '_bytes'] = int(fields[1]) * 1024
                result.append(dict(pid=pid, mappings=maps, memory=memory))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--gpu-binary', type=Path, required=True)
    ap.add_argument('--cpu-binary', type=Path, required=True)
    ap.add_argument('--fixture', type=Path, required=True)
    ap.add_argument('--gpu-uuid', action='append', required=True)
    ap.add_argument('--calibration', type=Path, action='append', default=[])
    ap.add_argument('--managed-gib', type=float, default=6.25)
    ap.add_argument('--evidence', type=Path, required=True)
    args = ap.parse_args()
    os.umask(0o077)
    out = args.evidence.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    gpu, cpu, fixture = (p.resolve(strict=True) for p in (args.gpu_binary, args.cpu_binary, args.fixture))
    profile = T.resource_profile(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json'), 'paired', 'compact')
    profile['geometry']['query_readback_layout'] = 'gather'
    plan = P.model(profile, len(args.gpu_uuid))
    managed = int(args.managed_gib * R.GIB)
    if managed != 6.25 * R.GIB:
        raise ValueError('initial phase qualification uses exactly 6.25 GiB managed VRAM per worker')
    report = dict(schema='lattica-linux-phase-screen-v1', status='preparing', binary_sha256=G.digest(gpu),
                  count_per_root=8, workers=[], memory_model=plan, workload=profile, gpu_only=False,
                  started_ns=time.time_ns(), production_ready=False)
    G.durable(out / 'summary.json', report, True)
    locks, live, prior, shared_dir = [], [], None, None
    try:
        locks = G.lock_fleet()
        allowed = idle(args.gpu_uuid)
        inventory = {d['uuid']: d for d in R.detect_gpus(str(gpu))}
        if any(u not in inventory for u in args.gpu_uuid):
            raise ValueError('selected GPU unavailable')
        host = G.detect_worker_host(Path('/tmp'))
        host_budget = P.admit_host(host, plan)
        calibrated = calibration(args.calibration, gpu, inventory, profile)
        counts = Counter(args.gpu_uuid)
        (out / 'phases').mkdir(mode=0o700)
        shared_dir = Path('/tmp') / f'lattica-v2-phase-public-{os.getuid()}-{os.getpid()}'
        shared_dir.mkdir(mode=0o700)
        if shared_dir.stat().st_dev != host['scratch']['device']:
            raise ValueError('shared cache and private spill must use the admitted tmpfs')
        report['shared_directory'] = str(shared_dir)
        # Pin controller sources as well as both binaries, public wallets and keys.
        sources = [gpu, cpu, *T.fixture_files(fixture, 8, 'paired'), *Path(__file__).parent.glob('*.py'),
                   Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json')]
        pins = dict(T.pin(p.resolve()) for p in sources)
        T.execute_logged([cpu, 'expected', fixture, 8, out / 'expected.json'], out / 'expected.log', T.clean_environment())
        T.execute_logged([cpu, 'plan', fixture, out / 'expected.json'], out / 'plan.json', T.clean_environment())
        pins.update(dict(T.pin(out / n) for n in ('expected.json', 'plan.json')))
        threads = min(6, int(Fraction(host['cpu_capacity']) - 1) // len(args.gpu_uuid))
        if threads < 1:
            raise ValueError('insufficient CPU capacity')
        for index, uuid in enumerate(args.gpu_uuid):
            device = inventory[uuid]
            automatic = R.gpu_budget(device)
            if uuid in calibrated:
                context = R.up(max(512 * R.MIB, (5 * calibrated[uuid] + 3) // 4))
            else:
                if counts[uuid] != 1:
                    raise ValueError('each shared GPU needs a successful new-binary context qualification')
                context = automatic.context_bytes
            total = managed + context
            # Include every slot, every context, one device headroom allowance,
            # and current non-worker allocations (e.g. the display compositor).
            available = automatic.available_bytes
            if counts[uuid] * total + automatic.headroom_bytes > min(available, automatic.usable_bytes):
                raise ValueError('summed physical-GPU reservations do not fit live VRAM')
            gb = vars(automatic).copy()
            gb.update(managed_bytes=managed, context_bytes=context, total_bytes=total, bootstrap=uuid not in calibrated)
            budget = dict(cpu=dict(version=R.VERSION, effective_capacity=host['cpu_capacity'], coordinator_capacity='1',
                                   rayon_threads=threads, quota_percent=str(threads * 100) + '%', allowed_cpus=host['affinity_cpus']),
                          host=copy.deepcopy(host_budget), gpu=gb,
                          drivers=dict(nvidia=device['nvidia']['driver'], opencl=device['opencl']['driver']),
                          detected_gpu=device, detected_host=host,
                          memory_schedule=P.schedule(plan, out, counts[uuid], shared_dir), readback_layout='direct',
                          query_readback_layout='gather', opening_denominator_cache=False, gpu_fri_fold=False,
                          lde_workspace_bytes=0, typed_ram_admission='compact', workload_kind=profile['name'],
                          qualification_capacity_test=True, slice=G.SLICE,
                          unit=f'lattica-v2-multi-{os.getpid()}-phase-{index}.service')
            # Independent compiled-geometry guard still receives a real cgroup cap.
            if budget['host']['worker_bytes'] < T.minimum_ram(profile):
                raise ValueError('worker cap below compiled compact retained-storage bound')
            root = out / f'worker-{index}'
            root.mkdir(mode=0o700)
            assignment = dict(schema='lattica-typed-resource-assignment-v1', limits=T.resource_signature(budget))
            G.durable(root / 'assignment.json', assignment, True)
            local_pins = {**pins, **dict([T.pin(root / 'assignment.json')])}
            config = dict(gpu_binary=str(gpu), cpu_binary=str(cpu), fixture=str(fixture), construction='paired',
                          execution_backend='typed-process-dag', ram_admission='compact', count=8, workload=profile,
                          pins=local_pins, expected=str(out / 'expected.json'), plan=str(out / 'plan.json'),
                          resource_assignment=str(root / 'assignment.json'),
                          resource_assignment_sha256=local_pins[str(root / 'assignment.json')])
            G.durable(root / 'config.json', config, True)
            worker = dict(index=index, uuid=uuid, drivers=budget['drivers'], unit=budget['unit'],
                          directory=str(root / '001-typed'), budget=budget, config=config, observed_pids=[])
            report['workers'].append(worker)
        G.durable(out / 'admission.json', dict(host=host, devices=inventory, plan=plan, host_budget=host_budget), True)
        prior = dict(line.split('=', 1) for line in G.systemctl('show', G.SLICE, '--property=MemoryMax,MemorySwapMax').splitlines())
        G.systemctl('set-property', '--runtime', G.SLICE, f"MemoryMax={host_budget['fleet_bytes']}", 'MemorySwapMax=0', 'MemoryAccounting=yes')
        group = G.systemctl('show', G.SLICE, '--property=ControlGroup', '--value').strip()
        fleet = Path('/sys/fs/cgroup') / group.lstrip('/')
        before = M.event_counters(fleet / 'memory.events')
        report.update(status='running', fleet_events_before=before)
        G.durable(out / 'summary.json', report)
        started = time.monotonic()
        for worker in report['workers']:
            T.check_pins(worker['config']['pins'])
            live.append(worker)
            G.launch(worker['config'], {'id': 'linux-phase-eight'}, worker['budget'], Path(worker['directory']), worker_script=Path(T.__file__))
        fleet_peak = 0
        while live:
            if time.monotonic() - started > 2400:
                raise TimeoutError('bounded screen exceeded forty minutes')
            pids = set(allowed)
            for worker in list(live):
                sample = G.telemetry(worker, worker['budget'])
                sample['shared_mappings'] = shared_mappings(sample.get('pids', []), shared_dir)
                worker['observed_pids'] = sorted(set(worker['observed_pids']) | set(sample.get('pids', [])))
                pids.update(worker['observed_pids'])
                directory = Path(worker['directory'])
                with (directory / 'telemetry.jsonl').open('a') as stream:
                    stream.write(json.dumps(sample) + '\n')
                state = sample['unit']
                if G.terminated(state):
                    if not G.attempt_succeeded(directory, state):
                        raise ValueError(f"worker {worker['index']} failed: {state}")
                    worker['result'] = read(directory / 'result.json')
                    worker['accounting'] = read(directory / 'accounting.json')
                    if worker['result']['fresh_proofs'] != 8 or not worker['result']['cpu_audited']:
                        raise ValueError('root lacks eight fresh proofs and independent CPU audit')
                    events = dict(line.split() for line in worker['accounting']['memory.events'].splitlines())
                    if any(int(v) for v in events.values()):
                        raise ValueError('worker memory pressure counters are nonzero')
                    worker['context'] = contexts(directory / 'prove.log', worker['budget'])
                    M.cleanup(worker, worker['budget'], set(worker['observed_pids']))
                    live.remove(worker)
                    G.durable(out / 'summary.json', report)
            processes = compute_processes()
            for pid, uuid, name in processes:
                if uuid in counts and pid not in pids:
                    # Include descendants which appeared since the cgroup sample.
                    belongs = any(str(pid) in (Path('/sys/fs/cgroup') / G.unit_state(w['unit'])['ControlGroup'].lstrip('/') / 'cgroup.procs').read_text().split()
                                  for w in live if G.unit_state(w['unit']).get('ControlGroup'))
                    if not belongs:
                        raise RuntimeError(f'another GPU worker started: {pid} {name}')
            current = int((fleet / 'memory.current').read_text())
            fleet_peak = max(fleet_peak, current)
            with (out / 'fleet.jsonl').open('a') as stream:
                stream.write(json.dumps(dict(time_ns=time.time_ns(), clock_ns=time.monotonic_ns(), memory_current=current,
                                             active_workers=len(live), gpu_processes=[dict(pid=pid, uuid=uuid, name=name)
                                                 for pid, uuid, name in processes if uuid in counts and pid in pids - allowed])) + '\n')
            fs = os.statvfs('/tmp')
            if fs.f_bavail * fs.f_frsize < host_budget['filesystem_headroom_bytes']:
                raise RuntimeError('tmpfs reserve consumed during screen')
            M.event_deltas(before, M.event_counters(fleet / 'memory.events'))
            time.sleep(1)
        shared = [dict(name=p.name, inode=p.stat().st_ino, bytes=p.stat().st_size, mode=oct(p.stat().st_mode & 0o777))
                  for p in shared_dir.glob('*.prefix')]
        report.update(status='succeeded', elapsed_seconds=time.monotonic()-started,
                      fleet_sampled_peak_bytes=fleet_peak, fleet_events_after=M.event_counters(fleet / 'memory.events'), shared_files=shared)
    except BaseException as error:
        report.update(status='failed', failure=f'{type(error).__name__}: {error}')
        raise
    finally:
        cleanup_errors = []
        for worker in live:
            try:
                M.cleanup(worker, worker['budget'], set(worker['observed_pids']))
            except BaseException as error:
                cleanup_errors.append(str(error))
        if prior is not None:
            G.systemctl('set-property', '--runtime', G.SLICE, *[f'{k}={v}' for k, v in prior.items()])
        if not cleanup_errors and shared_dir is not None and shared_dir.exists():
            # File pages may be charged to the first writer; keep them until every
            # worker and GPU context is gone, then remove the entire per-run pool.
            shutil.rmtree(shared_dir)
        report.update(finished_ns=time.time_ns(), cleanup_errors=cleanup_errors, fleet_limits_restored=prior)
        G.durable(out / 'summary.json', report)
        for fd in locks:
            os.close(fd)
    if cleanup_errors:
        raise RuntimeError('worker cleanup incomplete')


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise RuntimeError(f'screen interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    main()
