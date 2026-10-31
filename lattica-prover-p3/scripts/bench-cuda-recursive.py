#!/usr/bin/env python3
"""Pinned, serial recursive GPU comparison; independent CPU audits are untimed.

Build all arms with the same capacity and CPU target. Profiling is an explicit
single-run diagnostic mode and is never included in throughput comparisons.
"""
import argparse
import secrets
import pwd
import hashlib

import importlib

import json

import os

from pathlib import Path

import re

import shutil

import statistics

import subprocess

import sys

import tempfile

import threading

import time

def read(path):
    return json.loads(path.read_text())

def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def check(pins=None):
    for name, expected in read(OUT / 'binary-pins.json').items():
        assert sha(name) == expected, name
    for name, expected in read(OUT / 'source-pins.json').items():
        assert sha(ROOT / name) == expected, name
    for name, expected in (pins or {}).items():
        assert sha(name) == expected, name

def progress(**value):
    temporary = OUT / 'progress.tmp'
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(OUT / 'progress.json')
    print(json.dumps(value), flush=True)

def managed_gpu_peak(log, backend):
    if backend == 'cuda':
        peaks = []
        for line in log.splitlines():
            if line.startswith('typed_cuda_memory '):
                peaks.append(json.loads(line.split(' ', 1)[1])['peak_bytes'])
            elif line.startswith('{'):
                record = json.loads(line)
                if record.get('event') == 'typed_gpu_work_complete' and record.get('backend') == 'cuda':
                    peaks.append(record['cuda']['peak_bytes'])
    elif backend == 'opencl':
        peaks = [int(value) for value in re.findall(r'managed_peak_bytes=(\d+)', log)]
    else:
        raise ValueError('unsupported GPU memory report backend')
    if any(type(value) is not int or value < 0 for value in peaks):
        raise ValueError('invalid managed GPU memory peak')
    return max(peaks, default=None)


def properties(unit):
    fields = ['ActiveState', 'SubState', 'MainPID', 'ControlPID', 'Result',
              'ExecMainStatus', 'ControlGroup', 'MemoryPeak', 'CPUUsageNSec']
    command = ['systemctl', '--user', 'show', unit]
    for field in fields:
        command += ['-p', field]
    return dict(line.split('=', 1) for line in subprocess.check_output(command, text=True).splitlines())

def cpu_step(label, args):
    check()
    directory = OUT / f'cpu-{label}'
    directory.mkdir()
    unit = f'lattica-cuda-prof-{RUN_TOKEN}-{label}.service'
    command = ['systemd-run', '--user', '--quiet', f'--unit={unit}',
               '--property=MemoryMax=3G', '--property=MemorySwapMax=0',
               '--property=CPUQuota=400%', '--property=TasksMax=96',
               '--property=LimitCORE=0', '--property=LimitSTACK=8M',
               '--property=RuntimeMaxSec=180', '--property=TimeoutStopSec=10',
               '--property=RemainAfterExit=yes', '--property=KillMode=control-group',
               f'--property=StandardOutput=append:{directory}/output.log',
               '--property=StandardError=inherit', f'--working-directory={ROOT}',
               '/usr/bin/env', '-i', f'HOME={pwd.getpwuid(os.getuid()).pw_dir}', f'USER={pwd.getpwuid(os.getuid()).pw_name}',
               'PATH=/usr/bin:/bin', f'XDG_RUNTIME_DIR=/run/user/{os.getuid()}',
               'RAYON_NUM_THREADS=4', str(CPU), *map(str, args)]
    write(directory / 'command.json', command)
    subprocess.run(command, check=True)
    started = time.monotonic()
    state = {}
    try:
        while time.monotonic() - started < 195:
            state = properties(unit)
            if state['SubState'] in ('exited', 'dead', 'failed') or state['ActiveState'] == 'failed':
                break
            time.sleep(0.5)
        else:
            raise TimeoutError(unit)
        write(directory / 'result.json', dict(state=state, seconds=time.monotonic()-started,
                                              binary_sha256=sha(CPU)))
        assert state['Result'] == 'success' and state['ExecMainStatus'] == '0', (label, state)
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], check=True)
        retired = properties(unit)
        write(directory / 'retired.json', retired)
        assert retired['MainPID'] == '0' and retired['ControlPID'] == '0', retired

def prepare(count):
    directory = OUT / f'inputs-{count}'
    directory.mkdir()
    fixture = directory / 'fixture'
    fixture.mkdir()
    for name in ['height.json', *[f'key.{i}' for i in range(1, 13)],
                 *[f'wallet.{i}' for i in range(count)]]:
        shutil.copyfile(SOURCE / name, fixture / name)
    body = read(SOURCE / 'body.json')
    body['transactions'] = body['transactions'][:count]
    assert len(body['transactions']) == count
    write(fixture / 'body.json', body)
    expected, plan_path = fixture / 'expected.json', directory / 'plan.json'
    cpu_step(f'n{count}-expected', ['expected', fixture, count, expected])
    cpu_step(f'n{count}-plan', ['execution-plan', fixture, expected, plan_path])
    plan = read(plan_path)
    jobs = sorted(plan['jobs'], key=lambda job: (job['level'], job['start']))
    assert len(jobs) == count
    ready = set()
    for job in jobs:
        assert set(job['dependencies']) <= ready
        ready.add(job['id'])
    assert plan['root_job'] in ready
    request = directory / 'request.json'
    write(request, {'schema_version': 1, 'jobs': [job['id'] for job in jobs], 'seeds': []})
    pins = {str(path): sha(path) for path in [CPU, *BINARIES.values(), plan_path, request, *fixture.iterdir()]}
    write(directory / 'pins.json', pins)
    return fixture, plan, request, pins

def shared_limits():
    return subprocess.check_output(['systemctl', '--user', 'show', 'lattica-v2-multi.slice',
        'lattica-v2-multi-coordinator.slice', '-p', 'Id', '-p', 'MemoryMax',
        '-p', 'MemorySwapMax', '-p', 'CPUQuotaPerSecUSec'], text=True)

def telemetry(directory, stop):
    fields = ['timestamp', 'utilization.gpu', 'memory.used', 'memory.free',
              'power.draw', 'temperature.gpu', 'clocks.sm', 'clocks.mem', 'pstate']
    write(directory / 'gpu-telemetry-fields.json', fields)
    command = ['nvidia-smi', '-i', UUID,
        '--query-gpu=' + ','.join(fields),
        '--format=csv,noheader,nounits']
    with (directory / 'gpu-telemetry.jsonl').open('x') as stream:
        while not stop.is_set():
            result = subprocess.run(command, text=True, capture_output=True, timeout=5)
            stream.write(json.dumps(dict(monotonic=time.monotonic(), exit_code=result.returncode,
                output=result.stdout.strip(), error=result.stderr.strip())) + '\n')
            stream.flush()
            stop.wait(2)

def trial(count, phase, index, prepared):
    fixture, plan, request, pins = prepared
    check(pins)
    label = f'n{count}-{ARM}-{phase}-{index}'
    directory = OUT / label
    directory.mkdir()
    live = directory / 'recursive'
    scratch = Path(tempfile.mkdtemp(prefix=f'lattica-cuda-prof-{RUN_TOKEN}-{label}-', dir='/tmp'))
    command = ['/usr/bin/python3', str(CRATE / 'scripts/block-v2-typed-shared-gpu-run.py'),
        '--gpu-backend', GPU_BACKEND, '--owned-public-gpu',
        '--fleet-slice', f'lattica-v2-multi-cp{RUN_TOKEN}-{label}.slice',
        '--gpu-uuid', UUID, '--gpu-binary', str(GPU), '--cpu-binary', str(CPU),
        '--fixture', str(fixture), '--count', str(count), '--block-capacity', '128',
        '--pool-calibration', str(request), '--scratch', str(scratch), '--evidence', str(live)]
    if GPU_BACKEND == 'cuda':
        command += ['--cuda-library-path', str(CUDA_LIB)]
    if PROFILE is not None:
        command += ['--linux-profile', str(PROFILE)]
    write(directory / 'command.json', command)
    environment = {key: value for key, value in os.environ.items()
        if not key.startswith(('LATTICA_', 'RAYON_', 'CUDA_')) and key != 'LD_LIBRARY_PATH'}
    environment['RAYON_NUM_THREADS'] = '4'
    before = shared_limits()
    (directory / 'shared-limits-before.txt').write_text(before)
    stop = threading.Event()
    monitor = threading.Thread(target=telemetry, args=(directory, stop), daemon=True)
    monitor.start()
    started = time.monotonic()
    try:
        with (directory / 'launcher.log').open('x') as log:
            completed = subprocess.run(command, cwd=CRATE, env=environment,
                                       stdout=log, stderr=subprocess.STDOUT, timeout=900)
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        monitor.join(timeout=10)
        assert not monitor.is_alive(), 'telemetry did not stop'
    after = shared_limits()
    (directory / 'shared-limits-after.txt').write_text(after)
    assert completed.returncode == 0, (label, completed.returncode)
    assert before == after
    summary, config = read(live / 'summary.json'), read(live / 'config.json')
    assert summary['status'] == 'succeeded' and summary['pool_calibration']
    assert not summary['approved_for_pool_import'] and not summary['host_pool_timing_approved']
    assert all(value == 0 for value in summary['parent_memory_event_deltas'].values())
    shared.quiescent_fleet(config['owner_unit'], summary['attempts'])
    log = (live / 'workers/gpu-01/prove.log').read_text()
    reports = [json.loads(line.split(' ', 1)[1]) for line in log.splitlines()
               if line.startswith('proving_stage_report ')]
    entry_point = 'cuda_typed_registered_program' if GPU_BACKEND == 'cuda' else 'block_v2_registered_program'
    assert sum(r['entry_point'] == entry_point for r in reports) == count
    for report in reports:
        assert report['policy'] == 'gpu_required'
        assert report['succeeded'] and report['stage_coverage_complete']
        assert not report['completion_rejected'] and report['observation_errors'] == 0
        assert all(s['backend'] == ('cuda' if GPU_BACKEND == 'cuda' else 'open_cl') for s in report['capabilities']['stages'])
        assert all(s['backend'] == ('cuda' if GPU_BACKEND == 'cuda' else 'open_cl') and s['calls'] == s['completed_calls']
                   and s['device_calls'] > 0 for s in report['observations'])
    calibration = read(live / 'owner/proofs/calibration-result.json')
    observations = calibration['observations']
    assert len(observations) == count
    root = next(row for row in observations if bytes(row['job']).hex() == plan['root_job'])
    staged, audit_path = directory / 'staged-request.json', directory / 'cpu-inventory.json'
    write(staged, config['pool_calibration'])
    cpu_step(f'{label}-audit', ['audit-pool-calibration', fixture, fixture / 'expected.json',
                              staged, live / 'owner/proofs', audit_path])
    audit = read(audit_path)
    assert audit['requested_proofs'] == count and audit['complete_proof_bytes_verified']
    cpu_step(f'{label}-root', ['audit-root', fixture, fixture / 'expected.json',
                            fixture / 'body.json', live / 'owner/proofs' / root['file']])
    check(pins)
    peak = managed_gpu_peak(log, GPU_BACKEND)
    result = dict(status='passed', backend=GPU_BACKEND, arm=ARM, instrumented=PROFILE is not None, count=count, block_capacity=128,
        phase=phase, index=index, whole_launcher_seconds=elapsed,
        proof_observations_seconds=sum(row['elapsed_ms'] for row in observations)/1000,
        observations=observations, fresh_recursive_proofs=count, seed_proofs=0,
        complete_gpu_reports=len(reports), independent_cpu_audit=str(audit_path),
        cpu_root_audit_passed=True, workers_retired=True,
        managed_gpu_peak_bytes=peak,
        worker_accounting=summary['worker_accounting'], owner_accounting=summary['owner_accounting'],
        memory_event_deltas=summary['parent_memory_event_deltas'])
    write(directory / 'result.json', result)
    return result

def summarize(trials, arms, counts):
    workloads = []
    for count in counts:
        for arm in arms:
            rows = [r for r in trials if r['count'] == count and r['arm'] == arm
                    and r['phase'] == 'measured' and not r.get('instrumented', False)]
            if not rows:
                continue
            item = dict(count=count, arm=arm, user_transactions=count*3//4, issuance_entries=count//4)
            for metric in ('whole_launcher_seconds', 'proof_observations_seconds'):
                values = [r[metric] for r in rows]
                item[metric] = dict(samples=values, median=statistics.median(values), min=min(values), max=max(values))
            item['aggregation_equivalent_user_transactions_per_hour'] = item['user_transactions']*3600/item['whole_launcher_seconds']['median']
            peaks = [r['managed_gpu_peak_bytes'] for r in rows if r['managed_gpu_peak_bytes'] is not None]
            item['managed_gpu_peak_bytes'] = max(peaks, default=None)
            item['worker_host_peak_bytes'] = max(int(r['worker_accounting']['memory.peak']) for r in rows)
            workloads.append(item)
    return workloads


def main():
    global ROOT, OUT, CRATE, SOURCE, CPU, GPU, UUID, CUDA_LIB, BINARIES, PROFILE, RUN_TOKEN, shared, ARM, GPU_BACKEND
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--fixture', type=Path, required=True)
    ap.add_argument('--cpu-binary', type=Path, required=True)
    ap.add_argument('--arm', action='append', required=True, metavar='NAME:BACKEND:BINARY')
    ap.add_argument('--gpu-uuid', required=True)
    ap.add_argument('--cuda-library-path', type=Path)
    ap.add_argument('--count', type=int, choices=(4, 8), action='append')
    ap.add_argument('--repetitions', type=int, default=5)
    ap.add_argument('--warmups', type=int, default=1)
    ap.add_argument('--linux-profile', type=Path)
    args = ap.parse_args()
    if not 1 <= args.repetitions <= 10 or not 0 <= args.warmups <= 1:
        ap.error('repetitions must be 1..10 and warmups 0..1')
    ROOT, OUT = args.source_root.resolve(strict=True), args.output.resolve()
    CRATE, SOURCE = ROOT/'lattica-prover-p3', args.fixture.resolve(strict=True)
    CPU, UUID = args.cpu_binary.resolve(strict=True), args.gpu_uuid
    CUDA_LIB = args.cuda_library_path.resolve(strict=True) if args.cuda_library_path else None
    PROFILE = args.linux_profile.resolve(strict=True) if args.linux_profile else None
    RUN_TOKEN = secrets.token_hex(4)
    arms, BINARIES = {}, {}
    for value in args.arm:
        name, backend, path = value.split(':', 2)
        if not re.fullmatch('[a-z][a-z0-9-]{0,24}', name) or name in arms or backend not in ('cuda', 'opencl'):
            ap.error('invalid or duplicate arm')
        if backend == 'cuda' and CUDA_LIB is None:
            ap.error('CUDA arms require --cuda-library-path')
        arms[name], BINARIES[name] = backend, Path(path).resolve(strict=True)
    if PROFILE and (len(arms) != 1 or args.repetitions != 1 or args.warmups != 0):
        ap.error('profiling requires one arm, one repetition and no warmup')
    OUT.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(CRATE/'scripts'))
    shared = importlib.import_module('block-v2-typed-shared-gpu-run')
    paths = set(subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
                + subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], cwd=ROOT, text=True).splitlines())
    pins = {name: sha(ROOT/name) for name in sorted(paths)
            if name.startswith('lattica-prover-p3/') and (name.endswith(('.rs', '.cu', '.cuh', '.py', '.json', '.toml', '.lock')))}
    write(OUT/'source-pins.json', pins)
    write(OUT/'binary-pins.json', {str(p): sha(p) for p in [CPU, *BINARIES.values(), Path(__file__).resolve()]})
    (OUT/'source.patch').write_bytes(subprocess.check_output(['git', 'diff'], cwd=ROOT))
    counts = args.count or [4, 8]
    write(OUT/'identity.json', dict(source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        arms={k:dict(backend=arms[k],binary=str(p),sha256=sha(p)) for k,p in BINARIES.items()},
        gpu_uuid=UUID, cpu_binary_sha256=sha(CPU), hardware=subprocess.check_output(['nvidia-smi'],text=True),
        counts=counts, capacity=128, threads=4, warmups=args.warmups, repetitions=args.repetitions,
        instrumented=PROFILE is not None, profile=str(PROFILE) if PROFILE else None,
        limits='worker 3 GiB; coordinator 1 GiB; fleet 4 GiB; zero swap; existing GPU admission',
        scope='Fresh recursive aggregation only; wallet generation, native application and separate audits excluded'))
    trials=[]
    try:
        prepared = {count: prepare(count) for count in counts}
        for count in counts:
            for index in range(args.warmups):
                for ARM, GPU_BACKEND in arms.items():
                    GPU=BINARIES[ARM]
                    progress(status='running',count=count,arm=ARM,phase='warmup',completed_trials=len(trials))
                    trials.append(trial(count,'warmup',index+1,prepared[count]))
            for index in range(args.repetitions):
                order=list(arms.items())
                if index%2: order.reverse()
                for ARM, GPU_BACKEND in order:
                    GPU=BINARIES[ARM]
                    phase='profile' if PROFILE else 'measured'
                    progress(status='running',count=count,arm=ARM,phase=phase,index=index+1,completed_trials=len(trials))
                    trials.append(trial(count,phase,index+1,prepared[count]))
        write(OUT/'result.json',dict(status='passed',instrumented=PROFILE is not None,
            workloads=summarize(trials,arms,counts),trials=trials,
            independently_cpu_verified_proofs=sum(r['count'] for r in trials),
            independently_cpu_verified_roots=len(trials)))
        progress(status='passed',completed_trials=len(trials))
    except BaseException as error:
        progress(status='failed',completed_trials=len(trials),error_type=type(error).__name__,error=str(error))
        raise

if __name__=='__main__':
    main()
