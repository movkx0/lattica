"""CUDA admission for the maintained pool; no imported OpenCL reservations.

The fixed envelope is independently enforced by the worker. Native preparation
admits actual public programs and complete device schedules inside these caps.
This model is not a timing approval or a measured context-memory estimate.
"""
import copy
from dataclasses import asdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import stat

import block_v2_capacity as Capacity
import block_v2_resources as R

WORKLOAD = Path(__file__).with_name('block-v2-typed-cuda-owned-workload.json')


def same(a, b):
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def workload_path(block_capacity=64):
    Capacity.validate(block_capacity)
    return WORKLOAD if block_capacity == 64 else WORKLOAD.with_name('block-v2-typed-cuda-owned-workload-128.json')


def resource_profile(path, block_capacity=64):
    supported = json.loads(workload_path(block_capacity).read_text())
    if not same(json.loads(Path(path).read_text()), supported):
        raise ValueError('unsupported CUDA owned CLI qualification profile')
    profile = copy.deepcopy(supported)
    profile['typed_ram_admission'] = 'owned'
    profile['geometry'].update(registry_programs=12, tree_depth=Capacity.depth(block_capacity))
    return profile


def runtime(directory):
    directory = Path(directory).resolve(strict=True)
    if (not directory.is_dir() or len(str(directory).encode()) > 4096
            or any(c in str(directory) for c in ':\n\r\0')):
        raise ValueError('CUDA runtime requires one absolute library directory')
    libraries = {}
    for name, alias in [('nvrtc', 'libnvrtc.so'), ('builtins', 'libnvrtc-builtins.so.12.9')]:
        path = directory / alias
        target = path.resolve(strict=True)
        metadata = target.stat()
        if (target.parent != directory or not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= 256 << 20):
            raise ValueError('CUDA runtime library must be a bounded regular file in its directory')
        with target.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        libraries[name] = {'path': str(path), 'target': str(target), 'sha256': digest}
    return {'schema_version': 1, 'library_directory': str(directory), 'libraries': libraries}


def runtime_pins(value):
    if (not isinstance(value, dict) or not isinstance(value.get('library_directory'), str)
            or not same(value, runtime(value['library_directory']))):
        raise ValueError('CUDA runtime libraries or selection changed')
    return {library[field]: library['sha256']
            for library in value['libraries'].values() for field in ('path', 'target')}


def plan_budgets(host, devices, profile, assignment=None, calibrations=None, *, resource_signature, slice_name):
    capacity = Capacity.configured(profile)
    if not same(profile, resource_profile(workload_path(capacity), capacity)):
        raise ValueError('CUDA planner requires its supported complete profile')
    if len(devices) != 1 or calibrations is not None:
        raise ValueError('CUDA owned qualification requires one worker and no imported context calibration')
    device = devices[0]
    R.cuda_identity(device)
    if Fraction(host['cpu_capacity']) < 4 or len(host['effective_cpus']) < 4:
        raise ValueError('CUDA owned worker requires four host threads')
    fs = host['scratch']
    if not fs['tmpfs'] or fs['quota_bytes'] is not None or fs['page_bytes'] != profile['page_bytes']:
        raise ValueError('CUDA owned qualification requires supported tmpfs scratch accounting')
    uuid = device['uuid']
    budget = R.shared_budgets(host, [uuid])[uuid]
    ram, cpu = budget['host'], budget['cpu']
    if ram['fleet_bytes'] < 4 * R.GIB or ram['spill_bytes'] < R.GIB:
        raise ValueError('host or scratch cannot admit CUDA owned qualification')
    ram.update(worker_bytes=3 * R.GIB, coordinator_bytes=R.GIB, fleet_bytes=4 * R.GIB, spill_bytes=R.GIB)
    cpu.update(effective_capacity='4', coordinator_capacity='4', rayon_threads=4,
               quota_percent='400%', allowed_cpus=host['effective_cpus'][:4])
    gpu = asdict(R.gpu_budget(device))
    headroom = max(R.GIB, gpu['headroom_bytes'])
    required = 11 * R.GIB + headroom
    if (gpu['usable_bytes'] < required or gpu['available_bytes'] < required
            or gpu['max_allocation_bytes'] < R.GIB):
        raise ValueError('CUDA owned qualification requires managed/context capacity plus full GPU headroom')
    gpu.update(managed_bytes=7 * R.GIB, context_bytes=4 * R.GIB, headroom_bytes=headroom,
               total_bytes=11 * R.GIB, max_allocation_bytes=R.GIB,
               host_output_bytes=ram['worker_bytes'], bootstrap=True)
    budget.update(backend='cuda', cuda=copy.deepcopy(profile['cuda']), gpu=gpu,
                  workload_kind=profile['name'], typed_ram_admission='owned',
                  qualification_capacity_test=True, detected_host=host, detected_gpu=device, slice=slice_name)
    if assignment is not None:
        expected = {'schema': 'lattica-typed-fleet-assignment-v1', 'limits_by_gpu': {uuid: resource_signature(budget)}}
        if not same(assignment, expected):
            raise ValueError('CUDA fixed resource limits, construction or hardware changed')
    return {uuid: budget}


def environment(budget, directory):
    if budget.get('backend') != 'cuda' or budget.get('typed_ram_admission') != 'owned':
        raise ValueError('CUDA environment requires owned CUDA admission')
    # Construction is separately validated by the Rust worker. No OpenCL
    # witness/randomness/transcript reservation or switch is substituted here.
    runtime_pins(budget.get('cuda_runtime'))
    if not same(budget.get('proving_environment'),
                {'LATTICA_PROVING_POLICY': 'gpu-required', 'LATTICA_PROVING_REPORT': '1'}):
        raise ValueError('CUDA worker requires GPU arithmetic and stage reports')
    gpu, host, cpu = (budget[k] for k in ('gpu', 'host', 'cpu'))
    if gpu.get('host_output_bytes') != host['worker_bytes']:
        raise ValueError('CUDA output allowance differs from the assigned worker')
    return {**budget['proving_environment'], 'RAYON_NUM_THREADS': str(cpu['rayon_threads']),
        'LATTICA_GPU_DEVICE_UUID': gpu['uuid'], 'LATTICA_V2_ACCOUNTING_UNIT': budget['unit'],
        'LATTICA_V2_WORKER_BUDGET': str(directory / 'budget.json'),
        'LATTICA_V2_GPU_MANAGED_BYTES': str(gpu['managed_bytes']),
        'LATTICA_V2_GPU_CONTEXT_BYTES': str(gpu['context_bytes']),
        'LATTICA_V2_HOST_OUTPUT_BYTES': str(host['worker_bytes']),
        'LATTICA_SPILL_MAX_BYTES': str(host['spill_bytes']), 'LATTICA_SPILL_DIR': host['scratch_path'],
        'LD_LIBRARY_PATH': budget['cuda_runtime']['library_directory']}


def validate_completion(event, budget, expected=None):
    """Retirement telemetry is required in addition to independent proof checks."""
    count = event.get('recursive_proofs')
    stats = event.get('cuda')
    if (event.get('backend') != 'cuda' or event.get('cpu_only') is not False
            or event.get('owned_public_worker') is not True or event.get('production_ready') is not False
            or type(count) is not int or not 0 <= count <= budget['pool_job_limit']
            or expected is not None and count != expected or not isinstance(stats, dict)):
        raise ValueError('CUDA worker completion differs from its assigned backend/work')
    for key in ['live_bytes','allocations','modules','pending_commands','public_program_bytes','public_programs']:
        if type(stats.get(key)) is not int or stats[key] != 0:
            raise ValueError('CUDA worker retained a device owner at shutdown')
    for key in ['peak_bytes','completed_commands','uploaded_bytes','downloaded_bytes']:
        if type(stats.get(key)) is not int or stats[key] < (1 if count else 0):
            raise ValueError('CUDA worker completion lacks bounded work telemetry')
    if stats['peak_bytes'] > budget['gpu']['managed_bytes']:
        raise ValueError('CUDA worker exceeded its managed allocation budget')
