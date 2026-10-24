"""Versioned immutable resource plans for the research multi-GPU runner.

No system changes here. Detection is separate from pure admission arithmetic so
heterogeneous hardware, containers and low-resource cases are reproducible.
"""
import copy
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
import json
import math
import os
import subprocess

MIB = 1 << 20
GIB = 1 << 30
WORKER_PROTOCOL_HOST_BYTES = 8 * MIB
# Decoded children survive the prover call. This shared decoder allowance stays
# outside cached session budgets, including on Empty jobs before reuse.
WORKER_INPUT_HOST_BYTES = 64 * MIB
# Warm workers may keep this much System backing after a drained job. Reserve
# it beside fresh proving allocations; explicit extra caches are charged below.
# This is the reuse baseline, not a complete allocator/driver lifetime bound.
RETAINED_SYSTEM_HOST_BYTES = 512 * MIB
RAYON_STACK_BYTES = 2 * MIB
RAYON_STACK_AUX_BYTES = 64 * 1024
RAYON_THREAD_HOST_BYTES = RAYON_STACK_BYTES + 3 * RAYON_STACK_AUX_BYTES
CALLER_STACK_BYTES = 8 * MIB
CALLER_STACK_HOST_BYTES = CALLER_STACK_BYTES + 3 * RAYON_STACK_AUX_BYTES


def worker_stack_reserve(budget):
    """Stacks/guards/signal stacks; allocator, main and driver owners are separate."""
    threads = budget['cpu']['rayon_threads']
    if type(threads) is not int or not 1 <= threads <= (1 << 32) - 1:
        raise ValueError('Rayon stack reservation requires a positive u32 thread count')
    return threads * RAYON_THREAD_HOST_BYTES

# Per active typed job: packets/publication + bounded decode + CPU verifier.
# The verifier conservatively counts the decoded proof a second time. Global
# coordinator/DAG/allocator/OS storage still needs its enclosing lifetime plan.
COORDINATOR_JOB_HOST_BYTES = (16 + 64 + 257) * MIB
# Known shared owners; Rust checks this floor against its compiled layouts.
# Remaining lifetime accounting is required before ordinary admission opens.
COORDINATOR_SHARED_HOST_BYTES = 512 * MIB


def coordinator_job_budgets(total, workers, shared=COORDINATOR_SHARED_HOST_BYTES):
    """Reserve shared owners, then split the remainder of the unchanged cap."""
    if (type(total) is not int or type(workers) is not int
            or not 1 <= workers <= 16 or not 0 < total <= (1 << 63) - 1):
        raise ValueError('invalid coordinator job reservation')
    if type(shared) is not int or shared < COORDINATOR_SHARED_HOST_BYTES:
        raise ValueError('invalid coordinator shared reservation')
    available = total - shared
    if available < workers * COORDINATOR_JOB_HOST_BYTES:
        raise ValueError('coordinator RAM cannot admit shared state and packet, decode and CPU verifier storage per job')
    share, remainder = divmod(available, workers)
    return [share + (index < remainder) for index in range(workers)]


QUANTUM = 256 * MIB
VERSION = 1
# Fixed hiding profile in block_v2/profile.rs, not an adjustable workload knob.
HIDING_COLUMNS = 4


def up(n, unit=QUANTUM):
    return ((n + unit - 1) // unit) * unit


def down(n, unit=QUANTUM):
    return max(0, n // unit * unit)


def cpulist(text):
    out = set()
    for part in text.strip().split(','):
        if not part:
            continue
        limits = list(map(int, part.split('-')))
        lo, hi = (limits[0], limits[0]) if len(limits) == 1 else limits
        if lo < 0 or hi < lo:
            raise ValueError('invalid CPU list')
        out.update(range(lo, hi + 1))
    return out


def ancestors(path, root=Path('/sys/fs/cgroup')):
    path = path.resolve()
    if not path.is_relative_to(root):
        raise ValueError('cgroup outside cgroup v2 mount')
    while True:
        yield path
        if path == root:
            return
        path = path.parent


def cgroup_path():
    lines = [s[3:] for s in Path('/proc/self/cgroup').read_text().splitlines() if s.startswith('0::')]
    if len(lines) != 1:
        raise ValueError('cgroup v2 required')
    return Path('/sys/fs/cgroup') / lines[0].lstrip('/')


def command_json(argv):
    return json.loads(subprocess.check_output(argv, text=True, timeout=30))


def cgroup_limits(paths, cpu_set, ignored_memory_paths=(), root=Path('/sys/fs/cgroup')):
    """Intersect the supplied cgroup ancestries; count shared ancestors once."""
    cpu_set = set(cpu_set)
    ignored_memory_paths = {Path(p).resolve() for p in ignored_memory_paths}
    quotas, groups, memory_heads = [], [], []
    paths = sorted({p for leaf in paths for p in ancestors(Path(leaf), root)})
    for path in paths:
        row = {'path': str(path)}
        if not path.is_dir():
            # Read-only plans can include an inactive systemd slice. The run
            # starts the empty hierarchy before taking its admission snapshot.
            row['present'] = False
            groups.append(row)
            continue
        if (path / 'cpuset.cpus.effective').exists():
            row['cpuset'] = (path / 'cpuset.cpus.effective').read_text().strip()
            if row['cpuset']:
                cpu_set &= cpulist(row['cpuset'])
        if (path / 'cpu.max').exists():
            row['cpu_max'] = (path / 'cpu.max').read_text().strip()
            quota, period = row['cpu_max'].split()
            if quota != 'max':
                quotas.append(Fraction(int(quota), int(period)))
        if (path / 'memory.max').exists():
            row['memory_max'] = (path / 'memory.max').read_text().strip()
            row['memory_current'] = int((path / 'memory.current').read_text())
            if path in ignored_memory_paths:
                row['memory_limit_owned_by_controller'] = True
            elif row['memory_max'] != 'max':
                memory_heads.append(max(0, int(row['memory_max']) - row['memory_current']))
        groups.append(row)
    capacity = min([Fraction(len(cpu_set)), *quotas])
    return {'effective_cpus': sorted(cpu_set), 'cpu_capacity': str(capacity),
            'cgroup_memory_headroom': min(memory_heads) if memory_heads else None,
            'ancestors': groups}


def detect_host(scratch, worker_cgroup=None):
    mem = {k: int(v.split()[0]) * 1024 for k, v in
           (line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())}
    online = cpulist(Path('/sys/devices/system/cpu/online').read_text())
    affinity = set(os.sched_getaffinity(0))
    # A systemd worker is launched into its assigned slice, not the observer's
    # service. Observer-only limits must not cap sibling workers. The assigned
    # slice's complete ancestry still enforces shared manager/system limits.
    paths = [Path(worker_cgroup)] if worker_cgroup is not None else [cgroup_path()]
    # The fleet's previous MemoryMax is ours to recalculate, unlike parent
    # limits. Including it would shrink each successive plan toward zero.
    limits = cgroup_limits(paths, online & affinity,
                           [worker_cgroup] if worker_cgroup is not None else [])
    scratch = Path(scratch).resolve(strict=True)
    fs = command_json(['findmnt', '-J', '-T', str(scratch), '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS'])['filesystems'][0]
    stat = os.statvfs(scratch)
    # A filesystem's free blocks need not reflect user/project/subvolume quotas.
    # tmpfs has no separate quota allowance. Other filesystems require explicit
    # support before admission; never silently substitute NVMe storage.
    if any(option in fs['options'].split(',') for option in ('quota', 'usrquota', 'grpquota', 'prjquota')):
        raise ValueError('scratch filesystem quota accounting is not qualified')
    if fs['fstype'] != 'tmpfs':
        raise ValueError('compact concurrent research currently requires an explicitly selected tmpfs scratch filesystem; disk quotas are not yet qualified')
    return {
        'version': VERSION, 'physical_bytes': mem['MemTotal'], 'available_bytes': mem['MemAvailable'],
        'resource_cgroup_scope': 'assigned_workers' if worker_cgroup is not None else 'current_process',
        'online_cpus': sorted(online), 'affinity_cpus': sorted(affinity), **limits,
        'scratch': {'path': str(scratch), 'filesystem': fs, 'device': scratch.stat().st_dev,
                    'capacity_bytes': stat.f_blocks * stat.f_frsize,
                    'available_bytes': stat.f_bavail * stat.f_frsize, 'quota_bytes': None,
                    'tmpfs': True, 'page_bytes': os.sysconf('SC_PAGE_SIZE')},
    }


def detect_gpus(binary):
    opencl = command_json([str(binary), '--gpu-inventory'])
    fields = 'uuid,name,memory.total,memory.free,driver_version,pci.bus_id'
    text = subprocess.check_output(['nvidia-smi', '--query-gpu=' + fields, '--format=csv,noheader,nounits'], text=True, timeout=10)
    nvidia = {}
    for row in text.splitlines():
        uuid, name, total, free, driver, pci = [s.strip() for s in row.split(',')]
        nvidia[uuid.lower()] = {'uuid': uuid, 'name': name, 'total_bytes': int(total) * MIB,
                                'free_bytes': int(free) * MIB, 'driver': driver, 'pci': pci}
    devices = []
    for cl in opencl:
        if not cl['uuid'] or cl['uuid'].lower() not in nvidia:
            continue
        nv = nvidia[cl['uuid'].lower()]
        devices.append({'uuid': nv['uuid'], 'opencl': cl, 'nvidia': nv})
    if len({d['uuid'] for d in devices}) != len(devices):
        raise ValueError('duplicate OpenCL UUID; selection is ambiguous')
    return devices


@dataclass(frozen=True)
class GpuBudget:
    version: int
    uuid: str
    usable_bytes: int
    available_bytes: int
    headroom_bytes: int
    context_bytes: int
    managed_bytes: int
    total_bytes: int
    max_allocation_bytes: int
    bootstrap: bool


@dataclass(frozen=True)
class CpuBudget:
    version: int
    effective_capacity: str
    coordinator_capacity: str
    rayon_threads: int
    quota_percent: str
    allowed_cpus: tuple


@dataclass(frozen=True)
class HostBudget:
    version: int
    fleet_bytes: int
    coordinator_bytes: int
    worker_bytes: int
    spill_bytes: int
    scratch_device: int
    scratch_path: str
    tmpfs: bool
    os_headroom_bytes: int
    filesystem_headroom_bytes: int
    swap_bytes: int = 0


def gpu_budget(device, calibration=None):
    cl, nv = device['opencl'], device['nvidia']
    usable = min(cl['global_bytes'], nv['total_bytes'])
    available = min(cl['global_bytes'], nv['free_bytes'])
    headroom = up(max(512 * MIB, (usable + 19) // 20))
    if calibration is not None:
        if calibration['uuid'] != device['uuid'] or calibration['driver'] != nv['driver'] or calibration['runtime'] != cl['driver']:
            raise ValueError('GPU calibration identity or driver/runtime mismatch')
        context = up(max(512 * MIB, (5 * calibration['peak_context_bytes'] + 3) // 4))
    else:
        # Measured calibration follows a bounded bootstrap run. Half the free
        # capacity after headroom limits managed allocations during bootstrap.
        context = up(max(512 * MIB, (available - headroom + 1) // 2))
    managed = down(available - headroom - context)
    if managed <= 0 or cl['max_allocation_bytes'] < 8:
        raise ValueError('GPU has no admitted managed capacity')
    return GpuBudget(VERSION, device['uuid'], usable, available, headroom, context, managed,
                     managed + context, cl['max_allocation_bytes'], calibration is None)


def shared_budgets(host, uuids, allocation=None):
    if allocation is not None:
        return pool_budgets(host, uuids, allocation)
    uuids = sorted(uuids)
    if not uuids or len(set(uuids)) != len(uuids):
        raise ValueError('one worker slot per distinct GPU UUID required')
    capacity = Fraction(host['cpu_capacity'])
    reserve = Fraction(1 if capacity >= 2 else 0)
    usable = capacity - reserve
    integer = math.floor(usable)
    if integer < len(uuids):
        raise ValueError('CPU capacity cannot give each worker one Rayon thread')
    base, remainder = divmod(integer, len(uuids))
    os_headroom = max(2 * GIB, math.ceil(host['physical_bytes'] / 10))
    fleet = max(0, host['available_bytes'] - os_headroom)
    if host['cgroup_memory_headroom'] is not None:
        fleet = min(fleet, host['cgroup_memory_headroom'])
    fleet = down(fleet)
    coordinator = up(max(512 * MIB, math.ceil(fleet / 50), len(uuids) * COORDINATOR_JOB_HOST_BYTES))
    worker = down((fleet - coordinator) // len(uuids))
    fs = host['scratch']
    fs_headroom = max(GIB, math.ceil(fs['capacity_bytes'] / 20))
    spill_available = max(0, fs['available_bytes'] - fs_headroom)
    if fs['quota_bytes'] is not None:
        spill_available = min(spill_available, fs['quota_bytes'])
    spill = down(spill_available // len(uuids))
    if fs['tmpfs']:
        spill = min(spill, worker)
    if worker <= 0 or spill <= 0:
        raise ValueError('host or scratch capacity cannot admit workers')
    result = {}
    for i, uuid in enumerate(uuids):
        threads = base + int(i < remainder)
        quota = Fraction(threads) + (usable - integer) / len(uuids)
        # systemd accepts at most two decimal places in percentages; round down.
        quota_percent = f'{math.floor(quota * 10000) / 100:.2f}'.rstrip('0').rstrip('.') + '%'
        cpu = CpuBudget(VERSION, str(capacity), str(reserve), threads, quota_percent, tuple(host['effective_cpus']))
        ram = HostBudget(VERSION, fleet, coordinator, worker, spill, fs['device'], fs['path'], fs['tmpfs'], os_headroom, fs_headroom)
        result[uuid] = {'cpu': asdict(cpu), 'host': asdict(ram)}
    return result


def pool_budgets(host, uuids, policy):
    """Reserve wallet/auditor capacity before weighted GPU-worker allocation.

    Weights are declared tuning inputs, never hardware speed claims. The normal
    per-geometry admission checks still apply to every resulting assignment.
    """
    uuids = sorted(uuids)
    if not uuids or len(set(uuids)) != len(uuids):
        raise ValueError('pool requires distinct GPU UUIDs')
    required = {'wallet_threads', 'wallet_bytes', 'coordinator_threads', 'coordinator_bytes', 'weights'}
    if not isinstance(policy, dict) or set(policy) != required:
        raise ValueError('pool allocation fields differ')
    for key in required - {'weights'}:
        if type(policy[key]) is not int or policy[key] <= 0:
            raise ValueError('pool allocation must use positive integer reservations')
    if set(policy['weights']) != set(uuids):
        raise ValueError('pool weights must name every admitted GPU UUID')
    weights = {u: Fraction(str(policy['weights'][u])) for u in uuids}
    if any(w <= 0 or w > 1000 for w in weights.values()):
        raise ValueError('pool allocation weights out of bounds')
    # Reuse detection, filesystem and OS margins. No margin is reduced.
    ordinary = shared_budgets(host, uuids)
    first = ordinary[uuids[0]]
    # The existing controller runs outside the GPU slice with a 4 GiB/one-core
    # cap. Keep its allowance within explicit OS/controller headroom.
    headroom = max(first['host']['os_headroom_bytes'], 6 * GIB)
    fleet = down(first['host']['fleet_bytes'] - (headroom - first['host']['os_headroom_bytes']))
    coordinator = up(policy['coordinator_bytes'])
    coordinator_job_budgets(coordinator, len(uuids))
    wallet = up(policy['wallet_bytes'])
    available = down(fleet - coordinator - wallet)
    capacity = Fraction(host['cpu_capacity'])
    threads = math.floor(capacity) - policy['coordinator_threads'] - policy['wallet_threads'] - 1
    if threads < len(uuids) or available < len(uuids) * QUANTUM:
        raise ValueError('pool wallet/coordinator reservations exhaust host capacity')
    total = sum(weights.values())
    # Allocate a minimum thread first; distribute remaining integer cores by
    # largest remainder. RAM rounds down and leaves rounding slack unassigned.
    spare = threads - len(uuids)
    cores = {u: 1 + math.floor(spare * weights[u] / total) for u in uuids}
    remainder = threads - sum(cores.values())
    order = sorted(uuids, key=lambda u: (-(spare * weights[u] / total % 1), u))
    for u in order[:remainder]:
        cores[u] += 1
    for u in uuids:
        budget = ordinary[u]
        budget['host'].update(coordinator_bytes=coordinator, fleet_bytes=fleet, os_headroom_bytes=headroom,
                              worker_bytes=down(available * weights[u] // total))
        if budget['host']['tmpfs']:
            budget['host']['spill_bytes'] = min(budget['host']['spill_bytes'], budget['host']['worker_bytes'])
        budget['cpu'].update(coordinator_capacity=str(policy['coordinator_threads']),
                             rayon_threads=cores[u], quota_percent=f'{cores[u] * 100}%')
        budget['wallet'] = {'threads': policy['wallet_threads'], 'ram_bytes': wallet}
        budget['controller'] = {'threads': 1, 'ram_bytes': 4 * GIB, 'charged_to_os_headroom': True}
        budget['allocation_policy'] = policy
    return ordinary


def readback_layout(profile):
    layout = profile.get('geometry', {}).get('host_readback_layout', 'banded')
    if layout not in ('banded', 'direct'):
        raise ValueError('unsupported workload host readback layout')
    return layout


def query_readback_layout(profile):
    layout = profile.get('geometry', {}).get('query_readback_layout', 'rows')
    if layout not in ('rows', 'gather'):
        raise ValueError('unsupported workload query readback layout')
    return layout


def opening_denominator_cache(profile):
    enabled = profile.get('geometry', {}).get('opening_denominator_cache', False)
    if type(enabled) is not bool:
        raise ValueError('opening denominator cache selection must be boolean')
    return enabled


def extra_host_reserve(profile):
    fri = profile.get('geometry', {}).get('gpu_fri_fold', False)
    if type(fri) is not bool:
        raise ValueError('GPU FRI folding requires an explicit boolean')
    cache = profile.get('preprocessing_cache')
    if cache is not None and (not isinstance(cache, dict)
            or set(cache) != {'entries', 'reserve_bytes'} or type(cache['entries']) is not int
            or not 1 <= cache['entries'] <= 12 or type(cache['reserve_bytes']) is not int
            or cache['reserve_bytes'] < 0 or (cache['entries'] == 1) != (cache['reserve_bytes'] == 0)):
        raise ValueError('invalid preprocessing cache reservation')
    # FRI input/output vectors are already in the phase model. The two
    # additional bounded transfer arrays together fit within this MiB.
    # The quotient candidate additionally stages rows and compiles a bounded
    # expression program. This reserve must accompany workload qualification;
    # it is not permission to exceed the worker's existing cgroup limit.
    return ((cache['reserve_bytes'] if cache else 0) + (MIB if fri else 0)
            + (256 * MIB if gpu_quotient_eval(profile) else 0)
            + lookup_random_host_reserve(profile) + opening_host_reserve(profile)
            + fri_resident_host_reserve(profile) + WORKER_PROTOCOL_HOST_BYTES
            + WORKER_INPUT_HOST_BYTES
            + RETAINED_SYSTEM_HOST_BYTES
            + witness_reservation(profile)['host_bytes']
            + randomness_reservation(profile)['host_bytes'] + transcript_reservation(profile)['host_bytes'])


def gpu_quotient_eval(profile):
    enabled = profile.get('geometry', {}).get('gpu_quotient_eval', False)
    if type(enabled) is not bool:
        raise ValueError('GPU quotient evaluation requires an explicit boolean')
    return enabled


def gpu_quotient_resident(profile):
    enabled = profile.get('geometry', {}).get('gpu_quotient_resident', False)
    if type(enabled) is not bool:
        raise ValueError('GPU quotient residency requires an explicit boolean')
    if enabled and not gpu_quotient_eval(profile):
        raise ValueError('GPU quotient residency requires GPU quotient evaluation')
    return enabled


def gpu_lookup(profile):
    enabled = profile.get('geometry', {}).get('gpu_lookup', False)
    if type(enabled) is not bool or (enabled and not gpu_quotient_resident(profile)):
        raise ValueError('GPU lookup requires an explicit boolean and owned GPU quotient evaluation')
    return enabled


def gpu_opening_eval(profile):
    enabled = profile.get('geometry', {}).get('gpu_opening_eval', False)
    if type(enabled) is not bool or (enabled and not gpu_quotient_resident(profile)):
        raise ValueError('GPU opening evaluation requires a boolean and owned GPU quotient inputs')
    return enabled


def gpu_fri_resident(profile):
    enabled = profile.get('geometry', {}).get('gpu_fri_resident', False)
    if type(enabled) is not bool or (enabled and not gpu_opening_eval(profile)):
        raise ValueError('resident GPU FRI requires a boolean and owned opening evaluation')
    return enabled


def gpu_pcs_device_only(profile):
    enabled = profile.get('geometry', {}).get('gpu_pcs_device_only', False)
    if type(enabled) is not bool or (enabled and
            (not gpu_fri_resident(profile) or not gpu_lookup(profile))):
        raise ValueError('device-only GPU PCS requires a boolean, resident FRI and GPU lookup')
    return enabled


def gpu_witness(profile):
    enabled = profile.get('geometry', {}).get('gpu_witness', False)
    if type(enabled) is not bool or (enabled and not gpu_pcs_device_only(profile)):
        raise ValueError('GPU witness construction requires an explicit boolean and device-only PCS')
    return enabled


def gpu_randomness(profile):
    enabled = profile.get('geometry', {}).get('gpu_randomness', False)
    if type(enabled) is not bool or enabled and not gpu_witness(profile):
        raise ValueError('GPU randomness requires a boolean and owned GPU witnesses')
    return enabled


def gpu_transcript(profile):
    enabled = profile.get('geometry', {}).get('gpu_transcript', False)
    if type(enabled) is not bool or enabled and not gpu_randomness(profile):
        raise ValueError('GPU transcript requires a boolean and registered GPU randomness')
    return enabled


def transcript_bounds(profile):
    if not gpu_transcript(profile):
        return None
    return dict(live_states=2, batch_words=4096, scalar_outputs=4096,
                partition_cosets=256, grind_batch=65536, grind_bits=20,
                grind_candidates=1 << 26)


def transcript_reservation(profile):
    bounds = transcript_bounds(profile)
    if bounds is None:
        return dict(managed_bytes=0, max_allocation_bytes=0, host_bytes=0)
    states = bounds['live_states'] * 18 * 8
    io = 2 * bounds['batch_words'] * 8
    scalars = (3 + 4 * bounds['scalar_outputs']) * 8
    grinding = (bounds['grind_batch'] + (bounds['grind_batch'] + 255) // 256 + 2) * 8
    return dict(managed_bytes=states + io + scalars + grinding,
                max_allocation_bytes=bounds['grind_batch'] * 8, host_bytes=MIB)


def validate_transcript_assignment(budget, selected):
    assigned = budget.get('gpu_transcript', False)
    if type(assigned) is not bool or type(selected) is not bool or assigned != selected:
        raise ValueError('GPU transcript selection differs from worker assignment')
    if not selected:
        return
    if budget.get('gpu_randomness') is not True:
        raise ValueError('GPU transcript requires registered GPU randomness')
    validate_randomness_assignment(budget, True)
    # This fixed profile covers every admitted primitive call; it is not a
    # caller-controlled estimate that could omit a live buffer or snapshot.
    profile = {'geometry': {key: True for key in ('gpu_transcript', 'gpu_randomness',
        'gpu_witness', 'gpu_pcs_device_only', 'gpu_fri_resident', 'gpu_lookup',
        'gpu_opening_eval', 'gpu_quotient_resident', 'gpu_quotient_eval')}}
    expected = transcript_reservation(profile)
    if (budget.get('transcript_bounds') != transcript_bounds(profile)
            or budget.get('transcript_reservation') != expected
            or any(type(v) is not int for v in budget['transcript_bounds'].values())
            or any(type(v) is not int for v in budget['transcript_reservation'].values())):
        raise ValueError('GPU transcript bounds or reservation differ from supported profile')
    def number(parent, key):
        fields = budget.get(parent)
        value = fields.get(key) if isinstance(fields, dict) else None
        if type(value) is not int or not 0 <= value <= (1 << 64) - 1:
            raise ValueError('missing or invalid worker ' + parent + '.' + key)
        return value
    managed = expected['managed_bytes'] + sum(number(parent, 'managed_bytes') for parent in
        ('owned_quotient_reservation', 'witness_reservation', 'randomness_reservation'))
    host = expected['host_bytes'] + sum(number(parent, 'host_bytes') for parent in
        ('witness_reservation', 'randomness_reservation'))
    if max(managed, host) > (1 << 64) - 1:
        raise ValueError('GPU transcript aggregate reservation overflow')
    if (managed > number('gpu', 'managed_bytes')
            or expected['max_allocation_bytes'] > number('gpu', 'max_allocation_bytes')
            or host > number('host', 'worker_bytes')):
        raise ValueError('simultaneous GPU transcript reservations exceed worker allowance')


def randomness_bounds(profile):
    if not gpu_randomness(profile):
        return None
    prefix, quotient, chunks, _, _, _ = opening_geometry(profile)
    columns = trace_columns(profile)
    # Witness bounds can exceed the actual raw trace geometry. Keep that
    # conservative allowance in the RNG assignment without treating it as
    # the width of a committed matrix.
    witness_reservation(profile)
    witness = profile['witness_bounds']
    bounds = dict(rows=prefix // 2, main_columns=columns[0],
                  preprocessing_columns=columns[1], lookup_columns=columns[2],
                  quotient_rows=quotient, quotient_chunks=chunks)
    for key in ('main_columns', 'preprocessing_columns'):
        bounds[key] = max(bounds[key], witness[key])
    for key in ('rows', 'main_columns', 'preprocessing_columns'):
        if type(witness.get(key)) is not int or bounds[key] < witness[key]:
            raise ValueError('GPU randomness bounds do not cover assigned witness bounds')
    return bounds


def randomness_reservation_for_bounds(bounds, cached_programs=1):
    keys = {'rows', 'main_columns', 'preprocessing_columns', 'lookup_columns',
            'quotient_rows', 'quotient_chunks'}
    if (not isinstance(bounds, dict) or set(bounds) != keys
            or any(type(n) is not int or n < 0 for n in bounds.values())
            or type(cached_programs) is not int or not 1 <= cached_programs <= 12):
        raise ValueError('invalid GPU randomness bounds')
    rows, quotient, chunks = (bounds[k] for k in ('rows', 'quotient_rows', 'quotient_chunks'))
    columns = [bounds[k] for k in ('main_columns', 'preprocessing_columns', 'lookup_columns')]
    if (not 1 <= rows <= 1 << 20 or rows & (rows - 1) or not columns[0]
            or max(columns) > 4096 or not rows * 2 <= quotient <= rows * 512
            or quotient & (quotient - 1) or not 2 <= chunks <= 16
            or chunks & (chunks - 1) or quotient < chunks * 2):
        raise ValueError('GPU randomness bounds exceed supported proof geometry')
    prefix, chunk_rows = rows * 2, quotient // chunks
    height = max(prefix, chunk_rows * 2) * 16
    if height > 1 << 25:
        raise ValueError('GPU randomness salt height exceeds 2^25')
    samples = [rows * (columns[0] + 8), rows * (columns[2] + 8), quotient * 4,
               chunk_rows * (chunks - 1) * 7, prefix * 7, height * 4]
    largest_sample = max(samples)
    if largest_sample > 1 << 28:
        raise ValueError('GPU randomness request exceeds 2^28 words')
    # Public preprocessing stays resident. Private salts, including FRI, keep replay
    # records; only one output plus sampler scratch is live during execution.
    salt_rows = prefix * 16 * cached_programs + height
    sample_outputs = max(samples[0], samples[1], samples[2] + samples[3], samples[4]) * 8
    batch = min(largest_sample, 1 << 20)
    raw_bytes = ((batch * 2 + 30) // 16) * 64
    scratch = raw_bytes + ((batch + 255) // 256) * 16 + 8
    return dict(managed_bytes=salt_rows * 32 + sample_outputs + scratch + 160,
                max_allocation_bytes=max(largest_sample * 8, raw_bytes), host_bytes=MIB)


def randomness_reservation(profile):
    if not gpu_randomness(profile):
        return dict(managed_bytes=0, max_allocation_bytes=0, host_bytes=0)
    return randomness_reservation_for_bounds(randomness_bounds(profile),
        profile.get('preprocessing_cache', {}).get('entries', 1))


def validate_randomness_assignment(budget, selected):
    assigned = budget.get('gpu_randomness', False)
    if type(assigned) is not bool or type(selected) is not bool or assigned != selected:
        raise ValueError('GPU randomness selection differs from worker assignment')
    if not selected:
        return
    required = ('gpu_witness', 'gpu_pcs_device_only', 'gpu_quotient_eval',
                'gpu_quotient_resident', 'gpu_lookup', 'gpu_opening_eval', 'gpu_fri_resident')
    if any(budget.get(key) is not True for key in required):
        raise ValueError('GPU randomness requires all owned witness and PCS consumers')
    bounds = budget.get('randomness_bounds')
    expected = randomness_reservation_for_bounds(bounds,
        budget.get('preprocessing_cache', {}).get('entries', 1))
    if budget.get('randomness_reservation') != expected:
        raise ValueError('GPU randomness reservation differs from its bounds')
    def number(parent, key):
        value = budget.get(parent, {}).get(key)
        if type(value) is not int or value < 0:
            raise ValueError('missing or invalid worker ' + parent + '.' + key)
        return value
    for key in ('rows', 'main_columns', 'preprocessing_columns'):
        if bounds[key] < number('witness_bounds', key):
            raise ValueError('GPU randomness bounds do not cover assigned witness bounds')
    managed = (expected['managed_bytes'] + number('owned_quotient_reservation', 'managed_bytes')
               + number('witness_reservation', 'managed_bytes'))
    host = expected['host_bytes'] + number('witness_reservation', 'host_bytes')
    if (managed > number('gpu', 'managed_bytes')
            or expected['max_allocation_bytes'] > number('gpu', 'max_allocation_bytes')
            or host > number('host', 'worker_bytes')):
        raise ValueError('simultaneous GPU randomness reservations exceed worker allowance')


def witness_reservation_for_bounds(bounds, cached_programs=1):
    """Match machine/gpu_backend/resources.rs; upper bounds, not measurements."""
    keys = {'rows', 'main_columns', 'preprocessing_columns', 'metadata_bytes',
            'compiler_host_bytes', 'program_host_bytes', 'wires', 'input_values'}
    optional = {'program_retained_host_bytes', 'compiler_retained_host_bytes', 'pcs_retained_host_bytes'}
    if (not isinstance(bounds, dict) or not keys <= set(bounds) <= keys | optional
            or any(type(n) is not int or not 0 <= n <= (1 << 64) - 1 for n in bounds.values())
            or type(cached_programs) is not int or not 1 <= cached_programs <= 12):
        raise ValueError('invalid GPU witness resource bounds')
    rows, main, pre = (bounds[k] for k in ('rows', 'main_columns', 'preprocessing_columns'))
    meta, compiler, source = (bounds[k] for k in ('metadata_bytes', 'compiler_host_bytes', 'program_host_bytes'))
    # Historical assignments conservatively retain their complete source peak.
    # A precise retained bound is checked against the actual program by workers.
    retained = bounds.get('program_retained_host_bytes', 0) or source
    retained_compiler = bounds.get('compiler_retained_host_bytes', 0) or (compiler - meta)
    if (not 8 <= rows <= 1 << 24 or rows & (rows - 1)
            or not 1 <= main <= 4096 or not 1 <= pre <= 4096
            or meta < 192 or meta % 8 or compiler < meta or not source or retained > source
            or retained_compiler > compiler - meta
            or bounds['wires'] > 1 << 26 or bounds['input_values'] > bounds['wires']):
        raise ValueError('invalid GPU witness resource bounds')
    # Pinned hiding preprocessing doubles the trace, applies blowup 16 and
    # retains four eight-byte salt fields per LDE row in compatible host mode.
    conservative_pcs = MIB + rows * 2 * 16 * 4 * 8
    retained_pcs = bounds.get('pcs_retained_host_bytes', 0) or conservative_pcs
    if not MIB <= retained_pcs <= conservative_pcs:
        raise ValueError('invalid retained PCS metadata allowance')
    trace, preprocessing = rows * main * 8, rows * pre * 8
    wires, inputs = max(1, bounds['wires']) * 8, max(1, bounds['input_values']) * 8
    samples = rows * (main + 8) * 8
    work = max(trace + wires + inputs + 8, preprocessing + 8, trace + samples + 8)
    # The uploaded metadata is device-owned. A compact schedule remains per
    # cached program; historical bounds retain conservative compiler slack.
    # Only retained source is charged per cache entry. Construction history,
    # setup compiler/manifest + staging and incoming source + inputs are
    # separate lifetimes. The latter can overlap a full preprocessing cache.
    # One independent verifier overlaps the proving cache. Its source-derived
    # 257 MiB lifecycle reservation is per serial worker, not per cache entry.
    # Packed lookup arrays, names and expression Arcs are capped at 64 MiB
    # per AIR. Cached outputs overlap incoming construction and the single
    # 192 MiB symbolic workspace, so reserve both independently.
    retained_lookups = 64 * MIB
    # An additional 1 MiB holds the fixed typed session, including all unused
    # cache slots and its single registry; this does not scale with live keys.
    # The retained OpenCL engine adds at most 64 MiB of mapped staging and
    # 8 MiB of Rust metadata, including timing-log growth overlap. Driver and
    # initialization/job scratch remain separate phase-accounting work.
    input_staging = inputs * 3 + 8
    staging = max(input_staging, samples, trace * 2)
    transient = max(compiler + staging, source + input_staging)
    # Sequential public hashing / periodic inverse NTT compiler workspace.
    # Mirrors device::compiler_constants; no change to the whole-worker cap.
    compiler_periodic_words = 65536 + 65536 // 2 + 2
    compiler_scratch = max((4096 + 4) * 8, compiler_periodic_words * 8)
    result = {'managed_bytes': meta * cached_programs + work + compiler_scratch,
              'max_allocation_bytes': max(meta, trace, preprocessing, wires, inputs, samples, 65536 * 8),
              'host_bytes': (retained + retained_compiler + retained_lookups + retained_pcs) * cached_programs + transient
                   + (2 + 72) * MIB + 65536 + 192 * MIB + 257 * MIB}
    if any(n > (1 << 64) - 1 for n in result.values()):
        raise ValueError('GPU witness resource overflow')
    return result


def witness_reservation(profile):
    if not gpu_witness(profile):
        return {'managed_bytes': 0, 'max_allocation_bytes': 0, 'host_bytes': 0}
    bounds = profile.get('witness_bounds')
    reserve = witness_reservation_for_bounds(bounds, profile.get('preprocessing_cache', {}).get('entries', 1))
    geometry = profile['geometry']
    columns = trace_columns(profile)
    if (bounds['rows'] < profile['height'] or bounds['rows'] * 2 < geometry['degree_prefix_rows']
            or bounds['main_columns'] < columns[0]
            or bounds['preprocessing_columns'] < columns[1]):
        raise ValueError('GPU witness bounds do not cover workload geometry')
    return reserve


def fri_resident_host_reserve(profile):
    if not gpu_fri_resident(profile):
        return 0
    degree = opening_geometry(profile)[3]
    # Host RNG: the first layer has N/2 rows and four fields; raw fields
    # and the canonical upload vector can coexist. Device RNG consumes and
    # replays salts on GPU. Both paths retain bounded query proof material.
    staging = 0 if gpu_randomness(profile) else degree * 16 * 32
    if staging > GIB:
        raise ValueError('resident FRI salt staging exceeds host allowance')
    return staging + MIB + pcs_query_host_reserve(profile)


def pcs_query_host_reserve(profile):
    """Final query payload, one matrix's readback/gather tile, and assembly."""
    if not gpu_fri_resident(profile):
        return 0
    _, _, chunks, degree, columns, _ = opening_geometry(profile)
    matrices = chunks + 4
    # The fixed profile uses 128 queries; reserve the device API's full 256.
    # Committed widths already include hiding columns. Retain eight fields
    # of conservative slack, salts, and a separate path for every matrix (an
    # overestimate for matrices batched into one commitment). Match Rust's
    # additional 1 MiB metadata allowance per batch conservatively per matrix.
    fields = sum(columns) + 8 + chunks * 7 + 7 + matrices * 4
    paths = matrices * (degree * 16).bit_length() * 32
    reserve = 2 * 256 * (fields * 8 + paths) + matrices * MIB
    if reserve > GIB:
        raise ValueError('resident PCS queries exceed host allowance')
    return reserve


def trace_columns(profile):
    """Raw base-field widths, before hiding; None for legacy PCS profiles.

    Witness and RNG bounds describe raw traces. Existing main_columns and
    permutation_columns_upper_bound describe committed matrices. Require
    both explicit raw widths for GPU witnesses; never infer geometry from
    a witness allocation bound. Lookup widths are flattened base fields,
    including the accumulator, rather than a count of cubic columns.
    """
    geometry = profile['geometry']
    keys = ('main_trace_columns', 'permutation_trace_columns_upper_bound')
    if geometry.get('gpu_witness') is not True and not any(k in geometry for k in keys):
        return None
    main, permutation = (geometry.get(k) for k in keys)
    pre = geometry.get('preprocessing_columns')
    if (any(type(n) is not int or not 0 <= n <= 4096 for n in (main, pre, permutation))
            or main == 0):
        raise ValueError('explicit bounded raw trace column geometry is required')
    for raw, key in ((main, 'main_columns'), (permutation, 'permutation_columns_upper_bound')):
        committed = geometry.get(key)
        expected = raw + HIDING_COLUMNS if raw else 0
        if type(committed) is not int or committed != expected or committed > 4096:
            raise ValueError('committed column geometry must include four hiding columns per nonempty raw trace')
    return [main, pre, permutation]


def opening_geometry(profile):
    geometry = profile['geometry']
    prefix = geometry.get('degree_prefix_rows')
    quotient = geometry.get('retained_quotient_rows')
    chunks = geometry.get('quotient_matrices')
    if (any(type(n) is not int or n < 1 or n & (n - 1) for n in (prefix, quotient, chunks))
            or not 2 <= chunks <= 16 or quotient < 2 * chunks):
        raise ValueError('GPU opening evaluation requires bounded degree geometry')
    degree = max(prefix, 2 * quotient // chunks)
    if degree * 16 > 1 << 25:
        raise ValueError('GPU opening FRI vector exceeds its supported height')
    columns = [geometry.get(k) for k in ('main_columns', 'preprocessing_columns',
                                        'permutation_columns_upper_bound')]
    if any(type(n) is not int or not 0 <= n <= 4096 for n in columns) or not columns[0]:
        raise ValueError('GPU opening evaluation requires bounded column geometry')
    trace_columns(profile)
    # At most two distinct heights, 32 points/matrix, fixed seven-column
    # quotient and random-codeword commitments, and one instance per worker.
    claims = 32 * (sum(columns) + chunks * 7 + 7) * 24
    return prefix, quotient, chunks, degree, columns, claims


def opening_host_reserve(profile):
    if not gpu_opening_eval(profile):
        return 0
    prefix, quotient, chunks, degree, columns, claims = opening_geometry(profile)
    heights = {prefix * 16, 2 * quotient // chunks * 16}
    # Match opening_pcs/owned.rs: resident FRI consumes the device vectors
    # directly. Claims still cross the host boundary in either mode, with
    # both raw readback and converted values briefly live.
    fri_bytes = 0 if gpu_fri_resident(profile) else sum(heights) * 24
    reserve = 2 * (fri_bytes + claims) + MIB
    if reserve > 4 * GIB:
        raise ValueError('GPU opening host boundary exceeds its allowance')
    return reserve


def lookup_random_sample_bytes(profile):
    """Sample geometry, independent of which backend generates the samples."""
    if not gpu_lookup(profile):
        return 0
    geometry = profile['geometry']
    prefix = geometry.get('degree_prefix_rows')
    columns = trace_columns(profile)
    # Legacy profiles lack raw geometry: retain their conservative committed
    # width allowance. Explicit profiles use the same raw width as Rust RNG.
    width = columns[2] if columns is not None else geometry.get('permutation_columns_upper_bound')
    if (type(prefix) is not int or not 2 <= prefix <= 1 << 31 or prefix & (prefix - 1)
            or type(width) is not int or not (0 if columns is not None else 1) <= width <= 65536):
        raise ValueError('GPU lookup requires bounded doubled trace and permutation geometry')
    return (prefix // 2) * (width + 8) * 8


def lookup_random_host_reserve(profile):
    samples = lookup_random_sample_bytes(profile)
    # Host samples are uploaded one trace at a time. Device RNG produces the
    # same-sized GPU allocation without a host sample matrix.
    return 0 if gpu_randomness(profile) else samples


def owned_quotient_reservation(profile):
    """Reserve captured/projected prefixes and one quotient coset at a time.

    Three prefix sets cover captures, projections and evaluated inputs, plus
    the widest transform's second buffer. Only the cubic output spans the full
    quotient domain; no full-width quotient input expansion is reserved.
    """
    gpu_pcs_device_only(profile)
    fri_resident = gpu_fri_resident(profile)
    if not gpu_quotient_resident(profile):
        return {'managed_bytes': 0, 'max_allocation_bytes': 0}
    geometry = profile['geometry']
    prefix = geometry.get('degree_prefix_rows')
    quotient = geometry.get('retained_quotient_rows')
    if any(type(n) is not int or n < 1 or n > 1 << 31 or n & (n - 1)
           for n in (prefix, quotient)) or quotient < prefix:
        raise ValueError('owned quotient requires bounded power-of-two domain geometry')
    if quotient > prefix * 256:
        raise ValueError('owned quotient exceeds 256 cosets')
    chunks = geometry.get('quotient_matrices')
    if (type(chunks) is not int or not 2 <= chunks <= 16 or chunks & (chunks - 1)
            or quotient < chunks * 2):
        raise ValueError('owned quotient hiding requires 2..16 equal chunks of at least two rows')
    columns = [geometry.get(k) for k in ('main_columns', 'preprocessing_columns',
                                       'permutation_columns_upper_bound')]
    if any(type(n) is not int or not 0 <= n <= 65536 for n in columns) or columns[0] == 0:
        raise ValueError('owned quotient requires bounded column geometry')
    trace_columns(profile)
    count, widest = sum(columns), max(columns)
    cache_entries = profile.get('preprocessing_cache', {}).get('entries', 1)
    if type(cache_entries) is not int or not 1 <= cache_entries <= 12:
        raise ValueError('invalid owned preprocessing cache count')
    prefixes = prefix * (3 * count + widest + (cache_entries - 1) * columns[1]) * 8
    output = (quotient + prefix) * 3 * 8
    # Fixed profile: three cubic coefficients plus four random columns.
    random_bytes = quotient * 4 * 8
    mask_bytes = (quotient // chunks) * (chunks - 1) * 7 * 8
    commit_live = (cache_entries * prefix * columns[1] * 8 + quotient * 3 * 8
                   + random_bytes + mask_bytes + chunks * 3 * 8)
    managed = max(prefixes + output, commit_live) + 64 * MIB
    largest = max(prefix * max(widest, 3) * 8, quotient * 3 * 8,
                  random_bytes, mask_bytes, 64 * MIB)
    if gpu_lookup(profile):
        random_samples = lookup_random_sample_bytes(profile)
        rows = prefix // 2
        # Captures, cached public preprocessing, projection plus two transform
        # buffers, original main/pre traces, output, scan hierarchy and samples.
        lookup_live = prefix * (columns[0] + cache_entries * columns[1]
                                + 3 * max(columns[:2]) + columns[2]) * 8
        lookup_live += rows * (sum(columns) + 6) * 8 + random_samples
        # Bounded expression tile <=64 MiB, immutable code and parameters.
        managed = max(managed, lookup_live + 128 * MIB)
        largest = max(largest, random_samples)
    if gpu_opening_eval(profile):
        prefix, quotient, chunks, degree, columns, claims = opening_geometry(profile)
        private = prefix * (columns[0] + columns[2]) * 8
        quotient_captures = quotient * 2 * 7 * 8
        random_capture = degree * 7 * 8
        retained = (private + cache_entries * prefix * columns[1] * 8
                    + quotient_captures + random_capture)
        # Accumulator, expanded vector and transform scratch coexist. Prefix
        # compression and all claimed values/point parameters remain live.
        opening_live = (retained + degree * 16 * 24 * 3 + degree * 24 + claims
                        + 32 * (chunks + 4) * 24 + 128 * MIB)
        managed = max(managed, commit_live + private + quotient_captures + 64 * MIB,
                      opening_live)
        largest = max(largest, 2 * quotient // chunks * 7 * 8,
                      random_capture, degree * 16 * 24, claims)
        if fri_resident:
            height = degree * 16
            # All reduced inputs may coexist with opening scratch. FRI layer
            # vectors, salts and trees form decreasing geometric series; add
            # a full input vector, fold/mix outputs and commitment sponge.
            # Query reconstruction uses two transform tiles plus indices,
            # roots and gathered rows. Prefer 64 MiB, or one column for a
            # taller domain. All retained FRI layers may still be live.
            query_scratch = max(64 * MIB, height * 16 + 8192)
            managed = max(managed, opening_live + height * 48,
                          retained + height * 216 + 128 * MIB + query_scratch)
            largest = max(largest, height * 32)
    return {'managed_bytes': managed, 'max_allocation_bytes': largest}


def workload_failures(budget, profile):
    """Check simultaneous allocations by phase; tmpfs pages belong to RAM.

    `heap` includes caches, pinned buffers, retained salts, and driver host
    memory. `spill_payloads` are the live allocations in that phase, not
    independently measured peaks. Every mapping includes header/alignment.
    Profiles are pinned alongside binaries and must pass per-GPU qualification.
    """
    if profile.get('version') != VERSION or not profile.get('phases'):
        raise ValueError('a versioned workload lifetime plan is required')
    readback_layout(profile)
    query_readback_layout(profile)
    cache_metadata_bytes = 64 * 1024 if opening_denominator_cache(profile) else 0
    extra_reserve = extra_host_reserve(profile) + worker_stack_reserve(budget) + CALLER_STACK_HOST_BYTES
    owned = owned_quotient_reservation(profile)
    witness = witness_reservation(profile)
    randomness = randomness_reservation(profile)
    transcript = transcript_reservation(profile)
    host, gpu = budget['host'], budget['gpu']
    page = profile.get('page_bytes', 0)
    if page < 1 or page & (page - 1):
        raise ValueError('spill page size must be a positive power of two')
    failures = []
    for phase in profile['phases']:
        values = [phase[k] for k in ('heap_bytes', 'pinned_bytes', 'driver_host_bytes', 'resident_spill_bytes', 'managed_gpu_bytes', 'max_gpu_allocation_bytes')]
        values += phase['spill_payloads']
        if any(type(n) is not int or n < 0 for n in values):
            raise ValueError('workload allocations must be nonnegative byte counts')
        spill = sum(up(n, page) + page for n in phase['spill_payloads'])
        ram = phase['heap_bytes'] + phase['pinned_bytes'] + phase['driver_host_bytes'] + cache_metadata_bytes + extra_reserve
        ram += spill if host['tmpfs'] else phase['resident_spill_bytes']
        for resource, needed, available in (
                ('host RAM', ram, host['worker_bytes']),
                ('spill', spill, host['spill_bytes']),
                ('managed VRAM', phase['managed_gpu_bytes'] + owned['managed_bytes'] + witness['managed_bytes'] + randomness['managed_bytes'] + transcript['managed_bytes'], gpu['managed_bytes']),
                ('GPU allocation', max(phase['max_gpu_allocation_bytes'], owned['max_allocation_bytes'], witness['max_allocation_bytes'], randomness['max_allocation_bytes'], transcript['max_allocation_bytes']), gpu['max_allocation_bytes'])):
            if needed > available:
                failures.append(f"{phase.get('name', 'unnamed phase')}: {resource} requires {needed} bytes; budget {available} bytes")
    return failures


def workload_fits(budget, profile):
    return not workload_failures(budget, profile)


def plan(host, devices, slots, profile, calibrations=None):
    calibrations = calibrations or {}
    shared = shared_budgets(host, [d['uuid'] for d in devices[:slots]], profile.get('pool_allocation'))
    budgets = {}
    for device in devices[:slots]:
        uuid = device['uuid']
        budget = {**shared[uuid], 'gpu': asdict(gpu_budget(device, calibrations.get(uuid))),
                  'readback_layout': readback_layout(profile),
                  'query_readback_layout': query_readback_layout(profile),
                  'opening_denominator_cache': opening_denominator_cache(profile),
                  'gpu_quotient_eval': gpu_quotient_eval(profile),
                  'gpu_quotient_resident': gpu_quotient_resident(profile),
                 'gpu_lookup': gpu_lookup(profile),
                 'gpu_opening_eval': gpu_opening_eval(profile),
                 'gpu_fri_resident': gpu_fri_resident(profile),
                 'gpu_pcs_device_only': gpu_pcs_device_only(profile),
                  'gpu_witness': gpu_witness(profile),
                  'gpu_randomness': gpu_randomness(profile),
                  'gpu_transcript': gpu_transcript(profile),
                  'transcript_bounds': transcript_bounds(profile),
                  'transcript_reservation': transcript_reservation(profile),
                  'randomness_bounds': randomness_bounds(profile),
                  'randomness_reservation': randomness_reservation(profile),
                 'witness_bounds': profile.get('witness_bounds') if gpu_witness(profile) else None,
                 'witness_reservation': witness_reservation(profile),
                  'owned_quotient_reservation': owned_quotient_reservation(profile),
                  'detected_host': host, 'detected_gpu': device}
        workspace = profile.get('geometry', {}).get('lde_workspace_bytes', 0)
        if type(workspace) is not int or not 0 <= workspace <= budget['gpu']['managed_bytes'] // 4:
            raise ValueError('LDE workspace cache exceeds explicit GPU reservation')
        budget['lde_workspace_bytes'] = workspace
        fri_fold = profile.get('geometry', {}).get('gpu_fri_fold', False)
        if type(fri_fold) is not bool:
            raise ValueError('GPU FRI folding requires an explicit boolean')
        budget['gpu_fri_fold'] = fri_fold
        cache = profile.get('preprocessing_cache')
        if cache is not None:
            if (set(cache) != {'entries', 'reserve_bytes'} or type(cache['entries']) is not int
                    or not 1 <= cache['entries'] <= 12 or type(cache['reserve_bytes']) is not int
                    or cache['reserve_bytes'] < 0 or (cache['entries'] == 1) != (cache['reserve_bytes'] == 0)
                    or cache['reserve_bytes'] >= budget['host']['worker_bytes']):
                raise ValueError('invalid preprocessing cache reservation')
            budget['preprocessing_cache'] = dict(cache)
        failures = workload_failures(budget, profile)
        if failures:
            raise ValueError(f'workload does not fit assigned resources on {uuid}: ' + '; '.join(failures))
        budgets[uuid] = budget
    return budgets


def qualification_budget(budget, profile):
    """Exercise stricter limits than an otherwise admitted fleet plan.

    Derive RAM from simultaneous workload allocations plus one 256 MiB quantum,
    and cap managed VRAM at half of detected available memory after headroom.
    This gives later admissions room to absorb ordinary availability changes
    while the full-size proof was tested under stricter actual cgroups.
    """
    import copy
    budget = copy.deepcopy(budget)
    page = profile['page_bytes']
    peak = max(phase['heap_bytes'] + phase['pinned_bytes'] + phase['driver_host_bytes'] +
               (sum(up(n, page) + page for n in phase['spill_payloads']) if budget['host']['tmpfs'] else phase['resident_spill_bytes'])
               for phase in profile['phases'])
    peak += extra_host_reserve(profile)
    budget['host']['worker_bytes'] = min(budget['host']['worker_bytes'], up(peak) + QUANTUM)
    budget['host']['spill_bytes'] = min(budget['host']['spill_bytes'], budget['host']['worker_bytes'])
    gpu = budget['gpu']
    gpu['managed_bytes'] = min(gpu['managed_bytes'], down((gpu['available_bytes'] - gpu['headroom_bytes']) // 2))
    gpu['total_bytes'] = gpu['managed_bytes'] + gpu['context_bytes']
    budget['qualification_capacity_test'] = True
    if not workload_fits(budget, profile):
        raise ValueError('stricter qualification budget does not fit the workload')
    return budget
