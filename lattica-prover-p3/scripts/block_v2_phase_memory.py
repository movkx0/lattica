"""Opt-in Linux phase/shared-page admission for the paired eight-input screen.

This is a conservative lifetime model, not a sum of per-process RSS: Linux
charges each shared page to one cgroup. Worker caps allow that ownership skew;
the parent fleet cap enforces the sum of unique pages plus private live data.
"""
import copy
import itertools
from pathlib import Path
import block_v2_resources as R

SCHEMA = 'lattica-linux-phase-memory-v1'
ENV = {'PHASE_DIR', 'PHASE_SLOTS', 'LATE_PHASE_SLOTS', 'QUERY_PHASE_SLOTS',
       'SHARED_PREPROCESSING_DIR', 'SHARED_PREPROCESSING_MAX_BYTES', 'MEMORY_RECLAIM',
       'COMPACT_SALTS', 'LDE_SCRATCH_BYTES', 'QUERY_SCRATCH_BYTES', 'GPU_WORKERS'}


def model(profile, workers, heavy=1, late=1, query=1):
    if type(workers) is not int or not 1 <= workers <= 3:
        raise ValueError('phase model supports one to three workers')
    if (heavy, late, query) != (1, 1, 1):
        raise ValueError('initial Linux phase qualification requires one slot in each pool')
    if profile.get('typed_ram_admission') != 'compact' or R.readback_layout(profile) != 'direct':
        raise ValueError('phase sharing requires compact direct readback')
    geometry = profile['geometry']
    public = geometry['logical_lde_rows'] // 2 * geometry['preprocessing_columns'] * 8
    if public != 6710886400 or geometry.get('registry_programs') != 12:
        raise ValueError('phase model requires paired height-262144 geometry')
    # Exactly two public program prefixes fit the finite mmap cache. Runtime
    # reservation counts incomplete files too; a third cannot be published.
    shared = 2 * public
    phases = []
    for phase in profile['phases']:
        payloads = list(phase['spill_payloads'])
        if payloads.count(public) != 1:
            raise ValueError('phase must contain exactly one shareable public prefix')
        payloads.remove(public)
        spill = sum(R.up(n, profile['page_bytes']) + profile['page_bytes'] for n in payloads)
        private = sum(phase[k] for k in ('heap_bytes', 'pinned_bytes', 'driver_host_bytes')) + spill
        private += R.extra_host_reserve(profile)
        phases.append(dict(name=phase['name'], spill_bytes=spill, private_bytes=private,
                           pool='late' if phase['name'] in ('quotient_commit', 'openings') else 'heavy'))
    if {p['pool'] for p in phases} != {'heavy', 'late'}:
        raise ValueError('unknown phase names')
    # Outside permits there are no trace, quotient, or query scratch allocations.
    # Keep the full heap/pinned/driver allowances plus 512 MiB for private
    # preprocessing salt checkpoints and retained metadata. No salt saving is
    # deducted from either active-phase bound.
    idle = max(sum(p[k] for k in ('heap_bytes', 'pinned_bytes', 'driver_host_bytes'))
               for p in profile['phases']) + 512 * R.MIB + R.extra_host_reserve(profile)
    bounds = {'idle': idle, **{pool: max(p['private_bytes'] for p in phases if p['pool'] == pool)
                              for pool in ('heavy', 'late')}}
    states = [state for state in itertools.product(bounds, repeat=workers)
              if state.count('heavy') <= heavy and state.count('late') <= late]
    worst = max(states, key=lambda state: sum(bounds[k] for k in state))
    private = sum(bounds[k] for k in worst)
    spill_bounds = {'idle': 512 * R.MIB, **{pool: max(p['spill_bytes'] for p in phases if p['pool'] == pool)
                                           for pool in ('heavy', 'late')}}
    fleet_spill = shared + max(sum(spill_bounds[k] for k in state) for state in states)
    return dict(schema=SCHEMA, workers=workers, heavy_slots=heavy, late_slots=late, query_slots=query,
                shared_capacity_bytes=shared, shared_prefix_bytes=public, idle_private_bytes=idle,
                phases=phases, private_bounds=bounds, worst_state=worst,
                fleet_payload_bytes=shared + private, fleet_spill_bytes=R.up(fleet_spill),
                private_spill_bounds=spill_bounds,
                worker_cap_bytes=R.up(shared + max(bounds.values())),
                worker_spill_bytes=R.up(max(p['spill_bytes'] for p in phases)))


def environment(schedule):
    if schedule.get('schema') != SCHEMA or set(schedule.get('env', {})) != ENV:
        raise ValueError('invalid Linux memory schedule environment')
    env = schedule['env']
    for key in ('PHASE_DIR', 'SHARED_PREPROCESSING_DIR'):
        if not Path(env[key]).is_absolute():
            raise ValueError('memory pool paths must be absolute')
    for key in ENV - {'PHASE_DIR', 'SHARED_PREPROCESSING_DIR'}:
        if not isinstance(env[key], str) or not env[key].isdigit() or int(env[key]) <= 0:
            raise ValueError('memory schedule values must be positive decimal integers')
    if any(env[k] != '1' for k in ('PHASE_SLOTS', 'LATE_PHASE_SLOTS', 'QUERY_PHASE_SLOTS', 'MEMORY_RECLAIM', 'COMPACT_SALTS')):
        raise ValueError('unqualified Linux memory schedule')
    return {'LATTICA_V2_' + k: v for k, v in env.items()}


def schedule(plan, out, gpu_workers, shared_dir=None):
    env = dict(PHASE_DIR=str(out / 'phases'), PHASE_SLOTS=str(plan['heavy_slots']),
               LATE_PHASE_SLOTS=str(plan['late_slots']), QUERY_PHASE_SLOTS=str(plan['query_slots']),
               SHARED_PREPROCESSING_DIR=str(shared_dir if shared_dir is not None else out / 'shared-public'),
               SHARED_PREPROCESSING_MAX_BYTES=str(plan['shared_capacity_bytes']),
               MEMORY_RECLAIM='1', COMPACT_SALTS='1', LDE_SCRATCH_BYTES=str(2 * R.GIB),
               QUERY_SCRATCH_BYTES=str(2 * R.GIB), GPU_WORKERS=str(gpu_workers))
    result = dict(schema=SCHEMA, env=env)
    environment(result)
    return result


def admit_host(host, plan):
    coordinator = R.up(max(512 * R.MIB, (host['physical_bytes'] + 49) // 50))
    os_reserve = max(2 * R.GIB, (host['physical_bytes'] + 9) // 10)
    available = host['available_bytes'] - os_reserve
    if host['cgroup_memory_headroom'] is not None:
        available = min(available, host['cgroup_memory_headroom'])
    required = R.up(plan['fleet_payload_bytes'] + coordinator)
    if required > available:
        raise ValueError(f'phase fleet needs {required} bytes; {available} available after OS reserve')
    fs = host['scratch']
    fs_reserve = max(R.GIB, (fs['capacity_bytes'] + 19) // 20)
    if not fs['tmpfs'] or plan['fleet_spill_bytes'] > fs['available_bytes'] - fs_reserve:
        raise ValueError('phase-limited private spill and shared public tmpfs reservations do not fit')
    # Both public shared pages and private spills stay in tmpfs. Phase permits
    # bound their concurrent total, while each individual allocator retains its
    # own cap. No host RAM saving relies on disk writeback or page eviction.
    return dict(version=R.VERSION, fleet_bytes=required, coordinator_bytes=coordinator,
                worker_bytes=plan['worker_cap_bytes'], spill_bytes=plan['worker_spill_bytes'],
                scratch_device=fs['device'], scratch_path=fs['path'], tmpfs=True,
                os_headroom_bytes=os_reserve, filesystem_headroom_bytes=fs_reserve, swap_bytes=0)
