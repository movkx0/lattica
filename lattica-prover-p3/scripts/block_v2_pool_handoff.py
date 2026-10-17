"""Authenticate a final native selection while one bounded prefix pool is idle.

The callback runs after independent prefix audit in the coordinator's existing
selected coordinator job allowance. Its output is independently rechecked before it can
become a pool request. No callback or receipt renews either original clock.
"""
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import block_v2_capacity as Capacity
import re
import subprocess
import sys

import block_v2_pool_timing as T
import block_v2_pool_seal as Seal
import block_v2_public_artifact_cache as PublicCache

JOB_BYTES = (1 << 30) - T.SHARED_BYTES

def job_bytes(config):
    return (1 << 30) - Capacity.coordinator_shared_bytes(Capacity.configured(config))
MIN_HANDOFF_MS = 30_000


def continuation_reserve_ms(value):
    if type(value) is not int or not 0 < value < T.DISPATCH_MS - MIN_HANDOFF_MS:
        raise ValueError('handoff requires a bounded positive continuation reserve')
    return value


def validate_callback(callback):
    """The trusted controller reserves final proving time before it may seal."""
    if (not isinstance(callback, dict)
            or set(callback) != {'command', 'pins', 'continuation_reserve_ms'}
            or not isinstance(callback['command'], list) or not callback['command']
            or not all(isinstance(arg, str) for arg in callback['command'])
            or not Path(callback['command'][0]).is_absolute()
            or not isinstance(callback['pins'], dict) or not callback['pins']):
        raise ValueError('handoff requires a pinned callback and a bounded continuation reserve')
    return continuation_reserve_ms(callback['continuation_reserve_ms'])


class HandoffWindowUnavailable(ValueError):
    """A live phase lacks the reserve before any handoff service has started."""

    def __init__(self, workflow, phase_deadline_ms, observed_ms, continuation_ms):
        reserve = continuation_reserve_ms(continuation_ms)
        super().__init__('prefix phase lacks the handoff and continuation window')
        self.window = {
            'pool_workflow': copy.deepcopy(workflow),
            'phase_deadline_monotonic_ms': phase_deadline_ms,
            'observed_monotonic_ms': observed_ms,
            'minimum_handoff_ms': MIN_HANDOFF_MS,
            'continuation_reserve_ms': reserve,
            'required_window_ms': MIN_HANDOFF_MS + reserve,
        }


def read(path):
    return json.loads(T.regular(Path(path).absolute(), 1 << 20), object_pairs_hook=T.unique_object)


def publish(path, value):
    # Import lazily: the phases module also imports this module.
    import block_v2_pool_phases as P
    P.publish(path, value)


def check_extension(prefix, final):
    if (prefix.get('scope') != 'prefix' or final.get('scope', 'candidate') != 'candidate'
            or any(prefix.get(k) != final.get(k) for k in
                   ['schema_version', 'head_token', 'generation', 'configuration_sha256'])):
        raise ValueError('handoff changed native scope or head')
    old, new = prefix['expected'], final['expected']
    if (any(old.get(k) != new.get(k) for k in ['schema_version', 'profile', 'chain', 'block_height'])
            or type(old.get('count')) is not int or type(new.get('count')) is not int
            or not 2 <= old['count'] <= new['count'] <= Capacity.MAX_TRANSACTIONS
            or any(old['authorized_issuance'].get(str(i), 0) != new['authorized_issuance'].get(str(i), 0)
                   for i in range(old['count']))):
        raise ValueError('handoff changed native prefix count or policy')


def transition(proofs, config):
    """Metadata detects a transition; native replay and journal replay authorize it."""
    proofs = Path(proofs)
    intent_path, committed_path = (proofs / name for name in
                                   ['prefix-transition-intent.json', 'prefix-transition.json'])
    if not intent_path.exists() and not committed_path.exists():
        return None
    intent, committed = read(intent_path), read(committed_path)
    request = intent.get('request', {})
    if (intent != committed or intent.get('schema_version') != 1
            or config.get('pool_prefix_handoff') is not True or config.get('preseal_only') is not True
            or intent.get('original') != config.get('native_host')
            or intent.get('workflow') != config.get('pool_workflow')
            or not T.nonzero_digest(intent.get('prefix_root')) or not T.nonzero_digest(intent.get('final_root'))
            or request.get('schema_version') != 1 or request.get('deadline_ms') != T.WORKFLOW_MS
            or not re.fullmatch('[0-9a-f]{64}', request.get('arrival_selection', ''))
            or not Path(request.get('fixture', '')).is_absolute()
            or not Path(request.get('expected', '')).is_absolute()):
        raise ValueError('handoff recovery requires one complete committed transition')
    check_extension(intent['original'], request['native_host'])
    Seal.check(request.get('pool_seal'), config['pool_workflow'])
    return request


def effective_config(config):
    request = transition(Path(config['owner_directory']) / 'proofs', config)
    if request is None:
        return config
    effective = copy.deepcopy(config)
    effective.update(native_host=request['native_host'], fixture=request['fixture'],
                     expected=request['expected'], count=request['native_host']['expected']['count'],
                     preseal_only=False, pool_prefix_handoff=False,
                     arrival_selection=request['arrival_selection'], pool_seal=request['pool_seal'])
    return effective


def verify_native(config, request):
    N = importlib.import_module('block_v2_native_shared')
    S = importlib.import_module('block-v2-typed-shared-gpu-run')
    check_extension(config['native_host'], request['native_host'])
    native = N.Candidate(config['host_config'], config['host_journal'], request['fixture'],
                         request['native_host']['expected']['count'])
    native.check(request['native_host'])
    intake = S.open_intake(native, config['arrival_store'], request['arrival_selection'], prefix=False)
    if intake is None or Seal.selection(intake, native, request['arrival_selection'], config['pool_workflow']) != request['pool_seal']:
        raise ValueError('handoff differs from the original durable native seal')
    return native, intake


def prefix_cache_pins(cache, receipt, block_capacity=64):
    """Pin the complete published outputs before the independent reader starts."""
    nodes = receipt.get('stable_nodes')
    if (receipt.get('status') != 'preseal_verified' or receipt.get('preseal_only') is not True
            or type(nodes) is not list or not 1 <= len(nodes) <= Capacity.validate(block_capacity) - 2):
        raise ValueError('cache retirement requires a completed bounded prefix')
    pins = {}
    for node in nodes:
        level, index, size = (node.get(key) for key in ['level', 'index', 'bytes'])
        if (type(level) is not int or not 1 <= level < Capacity.depth(block_capacity)
                or type(index) is not int or not 0 <= index < (block_capacity >> level)
                or type(size) is not int or not 0 < size <= 2 << 20
                or not T.nonzero_digest(node.get('job')) or not T.nonzero_digest(node.get('artifact_digest'))):
            raise ValueError('cache retirement prefix geometry or identity')
        name = f'node.{level}.{index}'
        if name in pins:
            raise ValueError('duplicate cache retirement prefix output')
        payload = T.regular(Path(cache) / name, 2 << 20)
        if len(payload) != size:
            raise ValueError('cache retirement prefix size changed')
        pins[name] = {'bytes': size, 'sha256': hashlib.sha256(payload).hexdigest()}
    manifest = T.regular(Path(cache) / 'result.json', 1 << 20)
    if json.loads(manifest, object_pairs_hook=T.unique_object) != receipt:
        raise ValueError('cache retirement prefix manifest changed')
    pins['result.json'] = {'bytes': len(manifest), 'sha256': hashlib.sha256(manifest).hexdigest()}
    return pins


def retire_audited_prefix(cache, receipt, audited, pins, deadline_ms):
    """The audit process has exited; the published prefix outputs are immutable.

    The pool stays idle waiting for its next request, which writes a different
    candidate directory. Its journal and retained in-memory proofs are untouched.
    """
    if (audited.get('status') != 'passed' or audited.get('cpu_prefix_audited') is not True
            or audited.get('cpu_audited_roots') != 0
            or audited.get('count') != receipt['native_host']['expected']['count']
            or audited.get('nodes') != receipt['stable_nodes']):
        raise ValueError('cache retirement requires the identical independently audited prefix')
    expected_names = {'result.json', *(f"node.{n['level']}.{n['index']}" for n in receipt['stable_nodes'])}
    if set(pins) != expected_names:
        raise ValueError('cache retirement pins differ from the audited output inventory')
    return PublicCache.release_pinned(Path(cache), pins, deadline_ms)


def child(input_path):
    value = read(input_path)
    directory = Path(value['directory'])
    config = read(value['config'])
    workflow = config['pool_workflow']
    boot, now = T.workflow_clock()
    T.validate_workflow(workflow, boot, now)
    reserve = continuation_reserve_ms(value.get('continuation_reserve_ms'))
    handoff_deadline = value.get('handoff_deadline_monotonic_ms')
    fleet = read(config['fleet_plan'])
    completion_deadline = min(fleet['pool_scheduling']['dispatch_deadline_monotonic_ms'],
                              workflow['deadline_monotonic_ms'])
    if (type(handoff_deadline) is not int
            or not now < handoff_deadline <= completion_deadline - reserve):
        raise ValueError('handoff changed or exhausted its reserved continuation window')
    for path, digest in value['pins'].items():
        if T.digest(path) != digest:
            raise ValueError('handoff input changed after admission')
    group = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip().removeprefix('0::').lstrip('/')
    if (group.parent.name != T.COORDINATOR_SLICE or (group / 'memory.max').read_text().strip() != str(job_bytes(config))
            or (group / 'memory.swap.max').read_text().strip() != '0'
            or (group.parent / 'memory.max').read_text().strip() != str(1 << 30)):
        raise ValueError('handoff escaped the original coordinator job allowance')
    def state():
        fields = {k: (group / k).read_text().strip() for k in
                  ['memory.max', 'memory.peak', 'memory.swap.max', 'memory.swap.peak', 'memory.events', 'cpu.max']}
        events = dict(row.split() for row in fields['memory.events'].splitlines())
        quota, period = map(int, fields['cpu.max'].split())
        if (quota != 4 * period or fields['memory.swap.peak'] != '0'
                or int(fields['memory.peak']) > job_bytes(config)
                or any(events.get(k, '0') != '0' for k in ['max', 'oom', 'oom_kill', 'oom_group_kill'])):
            raise ValueError('handoff exceeded its original resource allowance')
        return {'path': str(group), 'files': fields}
    publish(directory / 'cgroup-before.json', state())
    S = importlib.import_module('block-v2-typed-shared-gpu-run')
    N = importlib.import_module('block_v2_native_shared')
    cache = Path(value['prefix_cache'])
    if read(cache / 'result.json')['native_host'] != config['native_host']:
        raise ValueError('handoff prefix receipt changed native binding')
    prefix = N.Candidate(config['host_config'], config['host_journal'], config['fixture'], config['count'], prefix=True)
    prefix.check(config['native_host'])
    S.open_intake(prefix, config['arrival_store'], None, prefix=True)
    del prefix
    audit = directory / 'prefix-audit.json'
    prefix_receipt = read(cache / 'result.json')
    prefix_pins = prefix_cache_pins(cache, prefix_receipt, Capacity.configured(config))
    argv = [config['cpu_binary'], 'audit-preseal', config['fixture'], config['expected'], str(cache), str(audit)]
    publish(directory / 'audit-command.json', argv)
    with (directory / 'prefix-audit.log').open('xb') as log:
        subprocess.run(argv, check=True, stdout=log, stderr=subprocess.STDOUT)
    audited = read(audit)
    receipt = read(cache / 'result.json')
    if receipt != prefix_receipt:
        raise ValueError('handoff prefix changed during independent audit')
    if (audited.get('status') != 'passed' or audited.get('cpu_prefix_audited') is not True
            or audited.get('cpu_audited_roots') != 0 or audited.get('count') != config['count']
            or len(audited.get('nodes', [])) != len(receipt['stable_nodes'])):
        raise ValueError('handoff prefix lacks complete independent CPU audit')
    retirement = retire_audited_prefix(cache, receipt, audited, prefix_pins, workflow['deadline_monotonic_ms'])
    publish(directory / 'audited-prefix-cache-retirement.json', retirement)
    boot, now = T.workflow_clock()
    T.validate_workflow(workflow, boot, now)
    if now >= handoff_deadline:
        raise ValueError('handoff preparation exhausted its window before sealing')
    response = directory / 'native-selection.json'
    with (directory / 'callback.log').open('xb') as log:
        subprocess.run([*value['command'], str(input_path), str(response)], check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    selected = read(response)
    if set(selected) != {'fixture', 'arrival_selection'} or not Path(selected['fixture']).is_absolute():
        raise ValueError('handoff callback must return one durable native selection')
    final = N.Candidate(config['host_config'], config['host_journal'], selected['fixture'],
                        read(Path(selected['fixture']) / 'expected.json')['count'])
    check_extension(config['native_host'], final.binding)
    intake = S.open_intake(final, config['arrival_store'], selected['arrival_selection'], prefix=False)
    seal = Seal.selection(intake, final, selected['arrival_selection'], workflow)
    for i in range(config['count']):
        for name in [f'wallet.{i}', f'complete-body.{i}']:
            if T.digest(Path(config['fixture']) / name) != T.digest(final.fixture / name):
                raise ValueError('handoff changed an ordered prefix input')
    request = {'schema_version': 1, 'fixture': str(final.fixture), 'expected': str(final.fixture / 'expected.json'),
               'native_host': final.binding, 'deadline_ms': T.WORKFLOW_MS,
               'arrival_selection': selected['arrival_selection'], 'pool_seal': seal}
    pins = {item['path']: item['sha256'] for item in final.pins}
    pins.update(dict(S.T.pin(path) for path in S.T.fixture_files(final.fixture, final.count, 'paired')))
    pins[str(final.fixture / 'expected.json')] = T.digest(final.fixture / 'expected.json')
    Seal.check(seal, workflow)
    boot, now = T.workflow_clock()
    T.validate_workflow(workflow, boot, now)
    if now >= handoff_deadline:
        raise ValueError('handoff callback exhausted the reserved continuation window')
    publish(directory / 'request.json', request)
    publish(directory / 'receipt.json', {'schema_version': 1, 'native_authenticated': True,
            'prefix_cpu_audited': True, 'pool_workflow': workflow, 'pins': pins,
            'request_sha256': T.digest(directory / 'request.json')})
    publish(directory / 'cgroup-after.json', state())


def run(phase, prefix_cache, callback):
    reserve = validate_callback(callback)
    phase = Path(phase)
    config = read(phase / 'config.json')
    if config.get('pool_prefix_handoff') is not True or not config.get('arrival_store'):
        raise ValueError('handoff requires a pinned native callback and admitted prefix service')
    boot, now = T.workflow_clock()
    T.validate_workflow(config['pool_workflow'], boot, now)
    fleet = read(config['fleet_plan'])
    directory = phase / 'handoff'
    if directory.exists() or directory.is_symlink():
        raise ValueError('handoff has already started; no automatic retry')
    phase_deadline = fleet['pool_scheduling']['dispatch_deadline_monotonic_ms']
    workflow_remaining = config['pool_workflow']['deadline_monotonic_ms'] - now
    required = MIN_HANDOFF_MS + reserve
    if workflow_remaining < required:
        raise ValueError('original workflow lacks the handoff and continuation window')
    remaining = min(phase_deadline - now, workflow_remaining)
    if remaining <= 0:
        raise ValueError('prefix service handoff window expired')
    if remaining < required:
        raise HandoffWindowUnavailable(config['pool_workflow'], phase_deadline, now, reserve)
    remaining -= reserve
    directory.mkdir(mode=0o700)
    pins = dict(callback['pins'])
    pins[str(phase / 'config.json')] = T.digest(phase / 'config.json')
    pins[config['fleet_plan']] = T.digest(Path(config['fleet_plan']))
    pins[str(Path(prefix_cache) / 'result.json')] = T.digest(Path(prefix_cache) / 'result.json')
    pins[str(Path(__file__).resolve())] = T.digest(__file__)
    value = {'schema_version': 1, 'directory': str(directory), 'config': str(phase / 'config.json'),
             'prefix_cache': str(prefix_cache), 'command': callback['command'], 'pins': pins,
             'continuation_reserve_ms': reserve, 'handoff_deadline_monotonic_ms': now + remaining}
    publish(directory / 'input.json', value)
    unit = 'lattica-v2-handoff-' + T.digest(directory / 'input.json') + '.service'
    command = ['systemd-run', '--user', '--wait', '--pipe', '--collect', '--service-type=exec',
               '--unit=' + unit, '--slice=' + T.COORDINATOR_SLICE,
               '--property=MemoryMax=' + str(job_bytes(config)), '--property=MemorySwapMax=0',
               '--property=CPUQuota=400%', '--property=KillMode=control-group', '--property=LimitCORE=0',
               '--property=RuntimeMaxSec=' + str(remaining // 1000),
               '--property=BindsTo=' + config['owner_unit'], '--property=After=' + config['owner_unit'],
               '--setenv=RAYON_NUM_THREADS=4', '--setenv=PYTHONDONTWRITEBYTECODE=1',
               sys.executable, str(Path(__file__).resolve()), '--child', str(directory / 'input.json')]
    publish(directory / 'command.json', command)
    S = importlib.import_module('block-v2-typed-shared-gpu-run')
    try:
        with (directory / 'output.log').open('xb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=remaining / 1000 + 5, env=S.T.clean_environment())
        publish(directory / 'service-result.json', {'exit': result.returncode})
        if result.returncode:
            raise ValueError('bounded native handoff failed; no automatic retry')
    finally:
        if S.G.systemctl('show', unit, '--property=LoadState', '--value').strip() != 'not-found':
            subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=30)
        if S.G.systemctl('show', unit, '--property=LoadState', '--value').strip() != 'not-found':
            raise ValueError('handoff service lifetime was not reconciled')
    receipt = read(directory / 'receipt.json')
    if (receipt.get('native_authenticated') is not True or receipt.get('prefix_cpu_audited') is not True
            or receipt.get('pool_workflow') != config['pool_workflow']
            or receipt.get('request_sha256') != T.digest(directory / 'request.json')):
        raise ValueError('handoff lacks authenticated native selection receipt')
    for path, digest in receipt['pins'].items():
        if T.digest(path) != digest:
            raise ValueError('final native input changed after bounded preparation')
    request = read(directory / 'request.json')
    check_extension(config['native_host'], request['native_host'])
    Seal.check(request['pool_seal'], config['pool_workflow'])
    boot, now = T.workflow_clock()
    T.validate_workflow(config['pool_workflow'], boot, now)
    if min(phase_deadline, config['pool_workflow']['deadline_monotonic_ms']) - now < reserve:
        raise ValueError('handoff consumed the reserved continuation window')
    return request


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != '--child':
        raise SystemExit('usage: block_v2_pool_handoff.py --child INPUT')
    child(Path(sys.argv[2]).resolve(strict=True))
