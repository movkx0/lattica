"""Explicit bounded owned-worker experiment, separate from legacy admission.

These are enforced qualification limits, not measured CLI context approval or a
complete RSS/lifetime claim. The witness reservation already includes its full
heap/spill request backing; tmpfs spill is charged to the same worker cgroup.
"""
import copy
from dataclasses import asdict
from fractions import Fraction
import json
from pathlib import Path

import block_v2_resources as R
import block_v2_capacity as Capacity

WORKLOAD = Path(__file__).with_name('block-v2-typed-owned-gpu-workload.json')


def workload_path(block_capacity=64, backend='opencl'):
    if backend == 'cuda':
        import block_v2_cuda_cli as Cuda
        return Cuda.workload_path(block_capacity)
    if backend != 'opencl':
        raise ValueError('unsupported owned GPU backend')
    Capacity.validate(block_capacity)
    return WORKLOAD if block_capacity == 64 else WORKLOAD.with_name('block-v2-typed-owned-gpu-workload-128.json')


def resource_profile(path, block_capacity=64, backend='opencl'):
    if backend == 'cuda':
        import block_v2_cuda_cli as Cuda
        return Cuda.resource_profile(path, block_capacity)
    if backend != 'opencl':
        raise ValueError('unsupported owned GPU backend')
    supported = json.loads(workload_path(block_capacity).read_text())
    supplied = json.loads(Path(path).read_text())
    # A different lifecycle/geometry needs a separately reviewed model. JSON
    # encoding distinguishes booleans from integers (Python equality does not).
    if json.dumps(supplied, sort_keys=True) != json.dumps(supported, sort_keys=True):
        raise ValueError('unsupported owned CLI qualification profile')
    profile = copy.deepcopy(supported)
    profile['typed_ram_admission'] = 'owned'
    profile['geometry'].update(registry_programs=12, tree_depth=Capacity.depth(block_capacity))
    return profile


def check_mode(args):
    enabled = getattr(args, 'owned_public_gpu', False)
    backend = getattr(args, 'gpu_backend', 'opencl')
    if backend not in ('cuda', 'opencl'):
        raise ValueError('unsupported GPU backend')
    if backend == 'cuda' and (not enabled or not getattr(args, 'cuda_library_path', None)
                              or getattr(args, 'calibration_trial', [])):
        raise ValueError('CUDA requires owned admission, an explicit library directory and no OpenCL context calibration')
    if backend != 'cuda' and getattr(args, 'cuda_library_path', None):
        raise ValueError('CUDA library selection requires the CUDA backend')
    if enabled and (len(args.gpu_uuid) != 1 or not (
            getattr(args, 'pool_calibration', None) or getattr(args, 'pool_timing_approval', []))):
        raise ValueError('owned CLI qualification requires one bounded calibration or approved pool worker')
    return enabled


def plan_budgets(host, devices, profile, assignment=None, calibrations=None, *, resource_signature, slice_name):
    if profile.get('backend') == 'cuda':
        import block_v2_cuda_cli as Cuda
        return Cuda.plan_budgets(host, devices, profile, assignment, calibrations,
                                 resource_signature=resource_signature, slice_name=slice_name)
    if any(R.device_backend(device) != 'opencl' for device in devices):
        raise ValueError('owned workload and selected GPU backend differ')
    if json.dumps(profile, sort_keys=True) != json.dumps(resource_profile(workload_path(Capacity.configured(profile)), Capacity.configured(profile)), sort_keys=True):
        raise ValueError('owned CLI planner requires its supported complete profile')
    if len(devices) != 1 or calibrations is not None:
        raise ValueError('owned CLI experiment requires one device and no imported context calibration')
    device = devices[0]
    uuid = device['uuid']
    if (uuid != device['nvidia']['uuid'] or uuid.lower() != device['opencl']['uuid'].lower()
            or Fraction(host['cpu_capacity']) < 4 or len(host['effective_cpus']) < 4):
        raise ValueError('owned CLI device identity or four-thread host capacity differs')
    fs = host['scratch']
    if not fs['tmpfs'] or fs['quota_bytes'] is not None or fs['page_bytes'] != profile['page_bytes']:
        raise ValueError('owned CLI requires supported tmpfs scratch accounting')
    # Use the existing OS/filesystem margins and actual worker ancestry. Fixed
    # experimental caps must fit beneath them; no margin is relaxed.
    capacity = R.shared_budgets(host, [uuid])[uuid]
    ram = capacity['host']
    if ram['fleet_bytes'] < 4 * R.GIB or ram['spill_bytes'] < R.GIB:
        raise ValueError('host or scratch cannot admit the owned CLI experiment')
    ram.update(worker_bytes=3 * R.GIB, coordinator_bytes=R.GIB,
               fleet_bytes=4 * R.GIB, spill_bytes=R.GIB)
    cpu = capacity['cpu']
    cpu.update(effective_capacity='4', coordinator_capacity='4', rayon_threads=4,
               quota_percent='400%', allowed_cpus=host['effective_cpus'][:4])
    gpu = asdict(R.gpu_budget(device))
    # This fixed bootstrap envelope was used for native research. It confers
    # no timing/context approval on the CLI, whose startup must be qualified.
    if (gpu['available_bytes'] < 12 * R.GIB or gpu['usable_bytes'] < 12 * R.GIB
            or gpu['headroom_bytes'] > R.GIB or gpu['max_allocation_bytes'] < R.GIB):
        raise ValueError('owned CLI requires 12 GiB free GPU capacity and 1 GiB allocations')
    gpu.update(managed_bytes=7 * R.GIB, context_bytes=4 * R.GIB,
               headroom_bytes=R.GIB, total_bytes=11 * R.GIB,
               max_allocation_bytes=R.GIB, bootstrap=True)
    budget = dict(cpu=cpu, host=ram, gpu=gpu, detected_host=host, detected_gpu=device,
                  workload_kind=profile['name'], typed_ram_admission='owned',
                  qualification_capacity_test=True, slice=slice_name,
                  readback_layout=R.readback_layout(profile),
                  query_readback_layout=R.query_readback_layout(profile),
                  opening_denominator_cache=False, gpu_fri_fold=False, lde_workspace_bytes=0,
                  witness_bounds=copy.deepcopy(profile['witness_bounds']))
    for field in ('gpu_quotient_eval', 'gpu_quotient_resident', 'gpu_lookup', 'gpu_opening_eval',
                  'gpu_fri_resident', 'gpu_pcs_device_only', 'gpu_witness', 'gpu_randomness',
                  'gpu_transcript', 'owned_quotient_reservation', 'witness_reservation',
                  'randomness_bounds', 'randomness_reservation', 'transcript_bounds',
                  'transcript_reservation'):
        budget[field] = getattr(R, field)(profile)
    failures = R.workload_failures(budget, profile)
    if failures:
        raise ValueError('owned CLI known reservation model does not fit: ' + '; '.join(failures))
    R.validate_transcript_assignment(budget, True)
    if assignment is not None:
        expected = {'schema': 'lattica-typed-fleet-assignment-v1',
                    'limits_by_gpu': {uuid: resource_signature(budget)}}
        if json.dumps(assignment, sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError('owned CLI fixed resource limits or hardware changed')
    return {uuid: budget}
