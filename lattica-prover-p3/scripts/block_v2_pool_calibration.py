"""Bounded live-sample requests for the maintained CLI; never timing approval."""
import hashlib
import json
from pathlib import Path
import re

import block_v2_capacity as Capacity
import block_v2_pool_timing as T

MAX_JOBS = 16
MAX_SEEDS = 127


def check_mode(args):
    path = getattr(args, 'pool_calibration', None)
    if path is None:
        return False
    incompatible = ['pool_requests', 'pool_timing_approval', 'preseal', 'reuse_preseal',
                    'recover_owner', 'recover_cached_only', 'allow_worker_failover',
                    'arrival_store', 'arrival_selection', 'supervise', 'recover_controller']
    if (any(getattr(args, name, None) for name in incompatible)
            or len(getattr(args, 'gpu_uuid', [])) != 1
            or getattr(args, 'pool_runtime_seconds', None) not in (None, T.SERVICE_SECONDS)):
        raise ValueError('calibration requires one bounded worker without pooling, retry, recovery, failover or arrival application')
    return True


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('calibration job identity must be 32 lowercase hex bytes')
    return list(bytes.fromhex(value))


def load(path):
    path = Path(path).absolute()
    raw = T.regular(path, T.MAX_JSON_BYTES)
    value = json.loads(raw, object_pairs_hook=T.unique_object)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'jobs', 'seeds'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or not isinstance(value['jobs'], list) or not 1 <= len(value['jobs']) <= MAX_JOBS
            or not isinstance(value['seeds'], list) or len(value['seeds']) > MAX_SEEDS):
        raise ValueError('calibration request version or inventory bounds')
    jobs = [identifier(job) for job in value['jobs']]
    if len({tuple(job) for job in jobs}) != len(jobs):
        raise ValueError('duplicate calibration job')
    pins = {str(path): hashlib.sha256(raw).hexdigest()}
    seeds, seen = [], set(value['jobs'])
    for seed in value['seeds']:
        if not isinstance(seed, dict) or set(seed) != {'job', 'path', 'sha256'}:
            raise ValueError('calibration seed fields')
        job = identifier(seed['job'])
        if seed['job'] in seen:
            raise ValueError('calibration seed is duplicate or replaces a fresh job')
        seen.add(seed['job'])
        if (not isinstance(seed['path'], str) or not Path(seed['path']).is_absolute()
                or len(seed['path'].encode()) > 4096):
            raise ValueError('calibration seed path bound')
        proof = T.regular(seed['path'], 2 << 20)
        digest = hashlib.sha256(proof).hexdigest()
        if digest != seed['sha256']:
            raise ValueError('calibration seed bytes changed')
        pins[seed['path']] = digest
        seeds.append({'job': job, 'path': seed['path']})
    return {'schema_version': 1, 'jobs': jobs, 'seeds': seeds}, pins


def stage(path, binary, device, budget, profile, environment):
    request, pins = load(path)
    binding = T.binding(binary, device, budget, profile, environment)
    request['identity'] = T.fingerprints(binding)
    return request, {'binding': binding, 'identity': request['identity'], 'source_pins': pins,
                     'approved_for_pool_import': False}, pins


def validate_result(value, request, workflow, window, native, uuid, directory, *, block_capacity=Capacity.DEFAULT_CAPACITY):
    """Check collection receipts; a separate complete audit must approve timings."""
    if (value.get('schema_version') != 1 or value.get('status') != 'calibrated_cpu_audit_pending'
            or value.get('approved_for_pool_import') is not False
            or value.get('scheduled_throughput_admitted') is not False
            or value.get('native_applied') is not False
            or value.get('workers_drained') is not True or value.get('workspace_released') is not True
            or value.get('independent_complete_audit_pending') is not True
            or value.get('bootstrap_ms') != 180000 or value.get('pool_workflow') != workflow
            or value.get('native_host') != native or value.get('gpu_uuid') != uuid
            or value.get('identity') != request['identity'] or not T.nonzero_digest(value.get('executable'))
            or type(value.get('fresh_proofs')) is not int or value['fresh_proofs'] != len(request['jobs'])
            or type(value.get('seed_proofs')) is not int or value['seed_proofs'] != len(request['seeds'])
            or value.get('fresh_recursive_dag') is not False
            or value.get('existing_recursive_proofs_imported') is not bool(request['seeds'])):
        raise ValueError('calibration completion, binding or diagnostic scope changed')
    fields = ['started_ms', 'completed_ms', 'stopped_ms', 'dispatch_deadline_ms']
    if any(type(value.get(key)) is not int for key in fields):
        raise ValueError('calibration clock receipt type')
    start, complete, stop, deadline = (value[key] for key in fields)
    maximum = window['dispatch_deadline_monotonic_ms'] - workflow['started_monotonic_ms']
    # Rust's conservative workflow clock rounds upward by at most one ms.
    if not (0 <= start <= complete < deadline <= maximum + 1
            and complete <= stop < min(T.WORKFLOW_MS, deadline + 30000)):
        raise ValueError('calibration exceeded its original work or shutdown window')
    observations = value.get('observations')
    if not isinstance(observations, list) or len(observations) != len(request['jobs']):
        raise ValueError('calibration observation count')
    previous, resident_mode = start, None
    for observation, job in zip(observations, request['jobs']):
        if (not isinstance(observation, dict) or observation.get('job') != job
                or type(observation.get('mode')) is not int
                or observation.get('warm') is not (resident_mode == observation['mode'])
                or any(type(observation.get(k)) is not int for k in ['issued_ms', 'accepted_ms', 'elapsed_ms', 'estimate_ms', 'proof_bytes'])
                or not previous <= observation['issued_ms'] <= observation['accepted_ms'] <= complete
                or not 0 < observation['elapsed_ms'] <= 150000
                or observation['estimate_ms'] <= 0
                or observation.get('estimate_source') not in ['Bootstrap', 'Live', 'ColdLive']
                or observation['estimate_source'] == 'Bootstrap' and observation['estimate_ms'] != 180000
                or not Capacity.valid_node_file(observation.get('file'), block_capacity)):
            raise ValueError('calibration observation is not ordered live evidence')
        proof = T.regular(Path(directory) / observation['file'], 2 << 20)
        if len(proof) != observation['proof_bytes']:
            raise ValueError('calibration proof length changed')
        previous = observation['accepted_ms']
        resident_mode = observation['mode']
    records = value.get('records')
    if not isinstance(records, list) or not 1 <= len(records) <= len(request['jobs']):
        raise ValueError('calibration record inventory')
    for index, record in enumerate(records):
        path = Path(directory) / f'timing-{index:03}.bin'
        if (not isinstance(record, dict) or set(record) != {'path', 'content_identity'}
                or record['path'] != str(path) or not T.nonzero_digest(record['content_identity'])):
            raise ValueError('calibration record path or identity changed')
        T.regular(path, 4096)
