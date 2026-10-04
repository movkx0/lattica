"""Versioned immutable resource plans for the research multi-GPU runner.

No system changes here. Detection is separate from pure admission arithmetic so
heterogeneous hardware, containers and low-resource cases are reproducible.
"""
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
import json
import math
import os
import subprocess

MIB = 1 << 20
GIB = 1 << 30
QUANTUM = 256 * MIB
VERSION = 1


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
    """Intersect caller and worker ancestry; count shared ancestors only once."""
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
    paths = [cgroup_path()]
    if worker_cgroup is not None:
        paths.append(worker_cgroup)
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


def shared_budgets(host, uuids):
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
    coordinator = up(max(512 * MIB, math.ceil(fleet / 50)))
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


def workload_fits(budget, profile):
    """Check simultaneous allocations by phase; tmpfs pages belong to RAM.

    `heap` includes caches, pinned buffers, retained salts, and driver host
    memory. `spill_payloads` are the live allocations in that phase, not
    independently measured peaks. Every mapping includes header/alignment.
    Profiles are pinned alongside binaries and must pass per-GPU qualification.
    """
    if profile.get('version') != VERSION or not profile.get('phases'):
        raise ValueError('a versioned workload lifetime plan is required')
    host, gpu = budget['host'], budget['gpu']
    page = profile.get('page_bytes', 0)
    if page < 1 or page & (page - 1):
        raise ValueError('spill page size must be a positive power of two')
    for phase in profile['phases']:
        values = [phase[k] for k in ('heap_bytes', 'pinned_bytes', 'driver_host_bytes', 'resident_spill_bytes', 'managed_gpu_bytes', 'max_gpu_allocation_bytes')]
        values += phase['spill_payloads']
        if any(type(n) is not int or n < 0 for n in values):
            raise ValueError('workload allocations must be nonnegative byte counts')
        spill = sum(up(n, page) + page for n in phase['spill_payloads'])
        ram = phase['heap_bytes'] + phase['pinned_bytes'] + phase['driver_host_bytes']
        ram += spill if host['tmpfs'] else phase['resident_spill_bytes']
        if ram > host['worker_bytes'] or spill > host['spill_bytes']:
            return False
        if phase['managed_gpu_bytes'] > gpu['managed_bytes'] or phase['max_gpu_allocation_bytes'] > gpu['max_allocation_bytes']:
            return False
    return True


def plan(host, devices, slots, profile, calibrations=None):
    calibrations = calibrations or {}
    shared = shared_budgets(host, [d['uuid'] for d in devices[:slots]])
    budgets = {}
    for device in devices[:slots]:
        uuid = device['uuid']
        budget = {**shared[uuid], 'gpu': asdict(gpu_budget(device, calibrations.get(uuid))),
                  'detected_host': host, 'detected_gpu': device}
        if not workload_fits(budget, profile):
            raise ValueError(f'workload does not fit assigned resources on {uuid}')
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
    budget['host']['worker_bytes'] = min(budget['host']['worker_bytes'], up(peak) + QUANTUM)
    budget['host']['spill_bytes'] = min(budget['host']['spill_bytes'], budget['host']['worker_bytes'])
    gpu = budget['gpu']
    gpu['managed_bytes'] = min(gpu['managed_bytes'], down((gpu['available_bytes'] - gpu['headroom_bytes']) // 2))
    gpu['total_bytes'] = gpu['managed_bytes'] + gpu['context_bytes']
    budget['qualification_capacity_test'] = True
    if not workload_fits(budget, profile):
        raise ValueError('stricter qualification budget does not fit the workload')
    return budget
