#!/usr/bin/env python3
"""Offline matched VRAM experiment over pinned, previously audited binaries.

This does not change production admission or resume a capacity-256 experiment.
All arms keep the same proof geometry, inputs, host pipeline, CPU and RAM caps.
"""
import argparse
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

GIB = 1 << 30
SLICE = 'lattica-v2-multi.slice'
VARIANTS = {
    'baseline': (7 * GIB, GIB, 0),
    'wide': (9 * GIB, 2 * GIB, 0),
    'cached': (9 * GIB, 2 * GIB, 2 * GIB),
    'roomy': (9 * GIB, GIB, 0),
    'roomy-cached': (9 * GIB, GIB, 2 * GIB),
}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def modules(source):
    sys.path.insert(0, str(source / 'source/scripts'))
    runner = importlib.import_module('block-v2-multi-gpu-run')
    runner.SLICE = SLICE
    return runner, importlib.import_module('block_v2_owned_cli'), importlib.import_module('block-v2-typed-gpu-run')


def variant_budget(base, name, available_bytes):
    managed, allocation, workspace = VARIANTS[name]
    result = copy.deepcopy(base)
    gpu = result['gpu']
    total = managed + gpu['context_bytes']
    if total + gpu['headroom_bytes'] > min(available_bytes, gpu['usable_bytes']):
        raise ValueError('insufficient free VRAM for the selected budget and unchanged reserves')
    if allocation > result['detected_gpu']['opencl']['max_allocation_bytes']:
        raise ValueError('per-buffer budget exceeds hardware allowance')
    if workspace > managed // 4:
        raise ValueError('scratch cache exceeds its engine limit')
    gpu.update(managed_bytes=managed, max_allocation_bytes=allocation,
               total_bytes=total, available_bytes=available_bytes)
    result['lde_workspace_bytes'] = workspace
    return result


def gpu_sample(uuid):
    command = ['nvidia-smi', '--id=' + uuid]
    row = subprocess.check_output(command + [
        '--query-gpu=memory.used,memory.free,utilization.gpu,utilization.memory,power.draw,temperature.gpu',
        '--format=csv,noheader,nounits'], text=True, timeout=5)
    sample = dict(zip(['used_mib', 'free_mib', 'gpu_percent', 'memory_percent', 'power_w', 'temperature_c'],
                      (float(v.strip()) for v in row.strip().split(','))))
    rows = subprocess.check_output(command + [
        '--query-compute-apps=pid,used_memory', '--format=csv,noheader,nounits'], text=True, timeout=5)
    sample['compute_processes'] = [dict(pid=int(line.split(',')[0]), used_mib=int(line.split(',')[1]))
                                   for line in rows.splitlines() if line.strip()]
    return sample


def verify_sources(source, fixture):
    for name, digest in read(source / 'source-manifest.json').items():
        if sha(source / name) != digest:
            raise ValueError('pinned source changed: ' + name)
    for name, digest in read(source / 'binary-manifest.json').items():
        if sha(name) != digest:
            raise ValueError('pinned binary changed: ' + name)
    for name, digest in read(fixture / 'run-01/fixture-manifest.json').items():
        if sha(fixture / 'run-01/fixture' / name) != digest:
            raise ValueError('pinned fixture changed: ' + name)


def controller(out):
    config = read(out / 'config.json')
    source = Path(config['source_run'])
    G, _, _ = modules(source)
    base = read(out / 'budget-base.json')
    cpu = Path(config['cpu_binary'])
    auditor = Path(config['audit_binary'])
    adapter = Path(config['gpu_binary'])
    fixture = out / 'fixture'
    expected = out / 'expected.json'
    stages = []

    def interrupted(signum, frame):
        raise KeyboardInterrupt('benchmark controller interrupted')

    signal.signal(signal.SIGTERM, interrupted)

    def stage(name, args, *, variant=None, ram=GIB):
        directory = out / name
        directory.mkdir()
        unit = 'lattica-v2-multi-' + config['tag'] + '-' + name + '.service'
        environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'RAYON_NUM_THREADS': '4',
                       'LATTICA_PROVING_POLICY': 'cpu-required', 'LATTICA_PROVING_REPORT': '1'}
        environment.update({key: os.environ[key] for key in ['HOME', 'USER', 'LOGNAME', 'XDG_RUNTIME_DIR']
                            if key in os.environ})
        if variant is not None:
            preflight = gpu_sample(config['uuid'])
            save(directory / 'gpu-preflight.json', preflight)
            budget = variant_budget(base, variant, int(preflight['free_mib']) << 20)
            budget['unit'] = unit
            save(directory / 'budget.json', budget)
            environment.update(G.environment(budget, directory))
            environment.update(CUDA_CACHE_PATH=str(out / 'driver-cache'),
                               CUDA_CACHE_MAXSIZE=str(GIB), LATTICA_V2_HOST_PIPELINE='1')
        save(directory / 'environment.json', environment)
        command = ['systemd-run', '--user', '--quiet', '--wait', '--pipe', '--expand-environment=no',
                   '--service-type=exec', '--unit=' + unit, '--slice=' + SLICE,
                   '-p', 'MemoryMax=' + str(ram), '-p', 'MemorySwapMax=0',
                   '-p', 'CPUQuota=400%', '-p', 'AllowedCPUs=' + ','.join(map(str, base['cpu']['allowed_cpus'])),
                   '-p', 'RuntimeMaxSec=1200', '-p', 'LimitCORE=0', '-p', 'LimitSTACK=8M',
                   '-p', 'KillMode=control-group', '-p', 'OOMPolicy=kill', '-p', 'BindsTo=' + config['owner'],
                   '-p', 'ExecStopPost=:/usr/bin/python3 ' + str(out / 'control/account.py') + ' ' + str(directory / 'accounting.json'),
                   '/usr/bin/env', '-i']
        command += [key + '=' + str(value) for key, value in environment.items()]
        command += ['/usr/bin/python3', str(out / 'control/timer.py'), str(directory / 'process-timing.json')]
        command += list(map(str, args))
        save(directory / 'command.json', command)
        started = time.monotonic()
        interrupted_stage = False
        with (directory / 'output.log').open('x') as log, (directory / 'telemetry.jsonl').open('x') as telemetry:
            proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            try:
                group = G.worker_cgroup() / unit
                while proc.poll() is None:
                    sample = {'seconds': time.monotonic() - started}
                    for field in ['memory.current', 'memory.peak', 'memory.swap.current', 'memory.events', 'cpu.stat']:
                        try:
                            sample[field] = (group / field).read_text().strip()
                        except FileNotFoundError:
                            pass
                    try:
                        sample['fleet_memory_current'] = int((G.worker_cgroup() / 'memory.current').read_text())
                    except FileNotFoundError:
                        pass
                    if variant is not None:
                        sample['gpu'] = gpu_sample(config['uuid'])
                    telemetry.write(json.dumps(sample) + '\n')
                    telemetry.flush()
                    time.sleep(0.5)
            except BaseException:
                interrupted_stage = True
                subprocess.run(['systemctl', '--user', 'stop', unit], check=False, timeout=30)
                proc.wait(timeout=30)
                raise
            finally:
                result = dict(name=name, variant=variant, seconds=time.monotonic() - started,
                              exit_code=proc.returncode, interrupted=interrupted_stage,
                              output_sha256=sha(directory / 'output.log'))
                for file, key in [('accounting.json', 'accounting'), ('process-timing.json', 'process_timing')]:
                    if (directory / file).exists():
                        result[key] = read(directory / file)
                stages.append(result)
                save(out / 'stages.json', stages)
                print(json.dumps({key: result[key] for key in ['name', 'seconds', 'exit_code', 'interrupted']}), flush=True)
        if proc.returncode:
            raise RuntimeError('stage failed: ' + name)
        return result

    stage('expected', [cpu, 'expected', fixture, config['count'], expected])
    stage('plan', [cpu, 'plan', fixture, expected])
    plan = read(out / 'plan/output.log')
    save(out / 'proof-plan.json', plan)
    assert plan['count'] == config['count'] and plan['block_capacity'] == 128
    root_name = 'node.' + str(plan['depth']) + '.0'
    for trial in config['trials']:
        name = trial['name']
        proofs = out / ('proofs-' + name)
        stage('prove-' + name, [adapter, 'prove-cpu', fixture, expected, proofs, 3 * GIB],
              variant=trial['variant'], ram=3 * GIB)
        stage('audit-root-' + name, [cpu, 'audit-root', fixture, expected, fixture / 'body.json', proofs / root_name])
        stage('audit-all-' + name, [auditor, 'execution-audit', fixture, expected, proofs, '00' * 32, out / ('audit-' + name)])
    for name, digest in read(out / 'binary-manifest.json').items():
        assert sha(name) == digest, name
    save(out / 'completion.json', dict(status='completed', count=config['count'], block_capacity=128,
                                     trials=len(config['trials']), production_deadline_qualified=False))


def launch(args):
    source, fixture, out = (p.resolve() for p in [args.source_run, args.fixture_run, args.output])
    if not 1 <= args.count <= 128 or not 1 <= args.repetitions <= 5:
        raise ValueError('count must be 1..128 and repetitions must be 1..5')
    if len(set(args.variants)) != len(args.variants) or 'baseline' not in args.variants:
        raise ValueError('select distinct variants including baseline')
    verify_sources(source, fixture)
    G, Owned, T = modules(source)
    locks = G.lock_fleet()
    if json.loads(G.systemctl('list-units', 'lattica-v2-multi-*.service',
                             '--state=active,activating,deactivating', '--output=json', '--no-pager')):
        raise RuntimeError('another bounded fleet service is active')
    out.mkdir(mode=0o700)
    (out / 'control').mkdir()
    shutil.copy2(__file__, out / 'control/benchmark.py')
    for name in ['timer.py', 'account.py']:
        shutil.copy2(source / 'control' / name, out / 'control' / name)
    subprocess.run(['cp', '-a', '--reflink=auto', str(fixture / 'run-01/fixture'), str(out / 'fixture')], check=True)
    body = read(out / 'fixture/body.json')
    body['transactions'] = body['transactions'][:args.count]
    save(out / 'fixture/body.json', body)
    shutil.copytree(source / 'driver-cache', out / 'driver-cache')
    cpu = fixture / 'bin-cpu/block-v2-paired-probe'
    auditor = fixture / 'bin-cpu/capacity-128-audit'
    gpu = fixture / 'bin-gpu/block-v2-paired-probe'
    adapter = source / 'bin-gpu/capacity-128-benchmark'
    host = G.detect_worker_host('/tmp')
    devices = G.R.detect_gpus(str(gpu))
    uuid = read(source / 'budget-base.json')['gpu']['uuid']
    device = next(value for value in devices if value['uuid'] == uuid)
    profile = Owned.resource_profile(Owned.workload_path(128), 128)
    base = Owned.plan_budgets(host, [device], profile, resource_signature=T.resource_signature,
                             slice_name=SLICE)[uuid]
    base['proving_environment'] = {'LATTICA_PROVING_POLICY': 'gpu-required', 'LATTICA_PROVING_REPORT': '1'}
    for variant in args.variants:
        variant_budget(base, variant, device['nvidia']['free_bytes'])
    save(out / 'budget-base.json', base)
    save(out / 'hardware.json', dict(host=host, device=device, cpuinfo=Path('/proc/cpuinfo').read_text()))
    save(out / 'binary-manifest.json', {str(p): sha(p) for p in [cpu, auditor, gpu, adapter]})
    save(out / 'fixture-manifest.json', {p.name: sha(p) for p in sorted((out / 'fixture').iterdir()) if p.is_file()})
    save(out / 'source-pins.json', {str(source / name): sha(source / name) for name in ['source-manifest.json', 'binary-manifest.json']})
    tag = 'vram-' + hashlib.sha256(str(out).encode()).hexdigest()[:10]
    trials = [dict(name='warmup', variant='baseline', measured=False)]
    for repeat in range(args.repetitions):
        order = args.variants if repeat % 2 == 0 else list(reversed(args.variants))
        trials += [dict(name=f'{repeat + 1:02d}-{variant}', variant=variant, measured=True) for variant in order]
    config = dict(schema='lattica-vram-pilot-v1', source_run=str(source), fixture_run=str(fixture),
                  cpu_binary=str(cpu), audit_binary=str(auditor), gpu_binary=str(adapter), uuid=uuid,
                  count=args.count, repetitions=args.repetitions, trials=trials,
                  variants={k: dict(zip(['managed_bytes', 'max_allocation_bytes', 'workspace_bytes'], VARIANTS[k])) for k in args.variants},
                  tag=tag, owner='lattica-v2-multi-' + tag + '-controller.service',
                  scope='Standalone partial block in the 128 profile; reused wallets and keys; fresh recursive proofs; CPU audits outside proof timing.')
    save(out / 'config.json', config)
    G.systemctl('set-property', '--runtime', SLICE, 'MemoryMax=4G', 'MemorySwapMax=0', 'CPUQuota=400%', 'MemoryAccounting=yes')
    command = ['systemd-run', '--user', '--wait', '--pipe', '--unit=' + config['owner'], '--slice=' + SLICE,
               '-p', 'MemoryMax=1G', '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=400%',
               '-p', 'LimitCORE=0', '-p', 'RuntimeMaxSec=7200', '-p', 'KillMode=control-group',
               '/usr/bin/python3', str(out / 'control/benchmark.py'), '--controller', str(out)]
    save(out / 'controller-command.json', command)
    with (out / 'controller.log').open('x') as log:
        code = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
    completed = (out / 'completion.json').exists()
    save(out / 'controller-result.json', dict(exit_code=code, completion_receipt_exists=completed))
    if code or not completed:
        raise RuntimeError('VRAM experiment did not complete; retained output: ' + str(out))
    print(out)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-run', type=Path)
    parser.add_argument('--fixture-run', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--count', type=int, default=8)
    parser.add_argument('--repetitions', type=int, default=2)
    parser.add_argument('--variants', nargs='+', choices=VARIANTS, default=['baseline', 'wide', 'cached'])
    parser.add_argument('--controller', type=Path, help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.controller:
        controller(options.controller)
    elif all([options.source_run, options.fixture_run, options.output]):
        launch(options)
    else:
        parser.error('--source-run, --fixture-run and --output are required')
