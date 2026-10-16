"""Pin independently approved timing records for the maintained local pool.

Only the trusted host supplies these approvals. Timing files from workers or
their result packets are not accepted here, and timing never admits a proof.
"""
import copy
import hashlib
import json
from pathlib import Path
import stat
import time

MAX_JSON_BYTES = 128 << 10
MAX_RECORDS = 64
SERVICE_SECONDS = 180
DISPATCH_MS = 150000
SHARED_BYTES = 576 << 20
PHASE_JOB_LIMIT = 256
WORKFLOW_MS = 600000
COORDINATOR_SLICE = 'lattica-v2-multi-coordinator.slice'


def validate_workflow(value, boot, now):
    keys = {'schema_version', 'boot_id', 'started_monotonic_ms', 'deadline_monotonic_ms'}
    if (not isinstance(value, dict) or set(value) != keys
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or not isinstance(value['boot_id'], str) or len(value['boot_id']) != 36
            or value['boot_id'] != boot
            or any(type(value[k]) is not int or not 0 <= value[k] < 1 << 64
                   for k in ['started_monotonic_ms', 'deadline_monotonic_ms'])
            or value['deadline_monotonic_ms'] - value['started_monotonic_ms'] != WORKFLOW_MS
            or not value['started_monotonic_ms'] <= now < value['deadline_monotonic_ms']):
        raise ValueError('pool workflow clock changed or original deadline expired')
    return copy.deepcopy(value)


def workflow_clock():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip(), time.monotonic_ns() // 1_000_000


def workflow(path=None, previous=None):
    """Retain an exact existing workflow, or start before this runner's preparation.

    A complete fresh-wallet controller supplies a receipt whose origin precedes
    wallet generation. Restarts can never substitute a fresh receipt.
    """
    boot, now = workflow_clock()
    supplied = None
    pins = {}
    if path is not None:
        path = Path(path).absolute()
        raw = regular(path, MAX_JSON_BYTES)
        supplied = json.loads(raw, object_pairs_hook=unique_object)
        pins[str(path)] = hashlib.sha256(raw).hexdigest()
    if previous is not None:
        original = previous.get('pool_workflow')
        if (not previous.get('pool_scheduling') or not previous.get('pool_requests')
                or original is None or supplied is not None and supplied != original):
            raise ValueError('pool recovery requires its original bounded workflow')
        value = original
    else:
        value = supplied if supplied is not None else {
            'schema_version': 1, 'boot_id': boot, 'started_monotonic_ms': now,
            'deadline_monotonic_ms': now + WORKFLOW_MS}
    return validate_workflow(value, boot, now), pins


def service_window(workflow):
    boot, now = workflow_clock()
    validate_workflow(workflow, boot, now)
    return {'schema_version': 1, 'boot_id': boot, 'issued_monotonic_ms': now,
            'dispatch_deadline_monotonic_ms': now + DISPATCH_MS}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def regular(path, limit):
    path = Path(path)
    metadata = path.lstat()
    if not path.is_absolute() or not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
        raise ValueError('pool timing input must be a bounded absolute regular file')
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise ValueError('pool timing input changed size')
    return data


def fingerprints(binding):
    values = [
        'lattica/nvidia/opencl/gpu-required/native-pool/v1',
        {'embedded_kernels_executable_sha256': binding['executable_sha256']},
        binding['device'], binding['drivers'], binding['settings'],
    ]
    return [list(hashlib.sha256(canonical(value)).digest()) for value in values]


def binding(binary, device, budget, profile, environment):
    stable_budget = copy.deepcopy(budget)
    # Inventory snapshots contain free memory, cgroup occupancy and observation
    # paths. They are admission evidence, not effective worker settings. Stable
    # device/driver identity and every enforced limit remain bound below.
    for name in ['unit', 'startup_guard', 'native_host', 'detected_host', 'detected_gpu']:
        stable_budget.pop(name, None)
    stable_budget['host'].pop('scratch_path', None)
    stable_budget['gpu'].pop('available_bytes', None)
    stable_environment = {k: v for k, v in environment.items() if k not in (
        'LATTICA_V2_ACCOUNTING_UNIT', 'LATTICA_V2_WORKER_BUDGET', 'LATTICA_SPILL_DIR')}
    if (stable_environment.get('LATTICA_PROVING_POLICY') != 'gpu-required'
            or stable_environment.get('LATTICA_PROVING_REPORT') != '1'):
        raise ValueError('qualified pool requires GPU arithmetic and stage reports')
    nv, cl = device['nvidia'], device['opencl']
    if budget['gpu']['uuid'] != device['uuid'] or nv['uuid'] != device['uuid']:
        raise ValueError('pool timing device differs from the worker assignment')
    return {
        'executable_sha256': digest(binary),
        'device': {key: nv[key] for key in ['uuid', 'name', 'total_bytes', 'pci']},
        'drivers': {'nvidia': nv['driver'], 'opencl': cl['driver']},
        'settings': {'budget': stable_budget, 'profile': profile, 'environment': stable_environment},
    }


def approvals(values, uuids):
    result = {}
    for value in values:
        uuid, separator, path = value.partition('=')
        if not separator or uuid not in uuids or uuid in result:
            raise ValueError('pool timing approvals require a unique assigned UUID=PATH')
        target = Path(path).absolute()
        regular(target, MAX_JSON_BYTES)
        result[uuid] = target
    if result and set(result) != set(uuids):
        raise ValueError('every qualified pool worker needs its own timing approval')
    return result


def nonzero_digest(value):
    return (isinstance(value, list) and len(value) == 32
            and all(type(n) is int and 0 <= n <= 255 for n in value) and any(value))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate pool timing manifest field')
        result[key] = value
    return result


def stage(path, output, binary, device, budget, profile, environment):
    """Validate observed host settings, pin source records, emit bounded Rust input.

    Rust rechecks every record's content identity and binds the actual worker
    image, immutable descriptor, profile and resources before starting it.
    """
    raw = regular(path, MAX_JSON_BYTES)
    approval = json.loads(raw, object_pairs_hook=unique_object)
    required = {'schema_version', 'approved_for_pool_import', 'binding', 'identity', 'executable', 'records'}
    if (not isinstance(approval, dict) or set(approval) != required
            or type(approval['schema_version']) is not int or approval['schema_version'] != 1
            or approval['approved_for_pool_import'] is not True):
        raise ValueError('pool timing input is not an approved versioned host manifest')
    expected = binding(binary, device, budget, profile, environment)
    if approval['binding'] != expected or approval['identity'] != fingerprints(expected):
        raise ValueError('pool timing executable, device, driver or settings changed')
    if not nonzero_digest(approval['executable']):
        raise ValueError('pool timing process image fingerprint missing')
    records = approval['records']
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError('pool timing record count')
    pins = {str(Path(path)): hashlib.sha256(raw).hexdigest()}
    staged, seen = [], set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {'path', 'sha256', 'content_identity', 'evidence'}:
            raise ValueError('pool timing record fields')
        data = regular(record['path'], 4096)
        actual = hashlib.sha256(data).hexdigest()
        if (actual != record['sha256'] or actual in seen
                or not nonzero_digest(record['content_identity']) or not nonzero_digest(record['evidence'])):
            raise ValueError('pool timing record content or evidence changed/duplicated')
        seen.add(actual)
        pins[record['path']] = actual
        staged.append({k: record[k] for k in ['path', 'content_identity', 'evidence']})
    value = {'schema_version': 1, 'gpu_uuid': device['uuid'], 'executable': approval['executable'],
             'identity': approval['identity'], 'records': staged}
    encoded = canonical(value)
    if len(encoded) > MAX_JSON_BYTES:
        raise ValueError('staged pool timing approval exceeds bounded decoder')
    with Path(output).open('xb') as target:
        target.write(encoded)
    pins[str(output)] = hashlib.sha256(encoded).hexdigest()
    return pins
