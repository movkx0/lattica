"""Exact CPU-only metadata selectors and Linux perf counter reconciliation."""
import json
import math
from pathlib import Path

EVENTS = ('cycles:u', 'instructions:u', 'cache-references:u', 'cache-misses:u',
          'task-clock:u')
PREFIXES = {
    'registered': 'block_v2::machine::verifier::batch::shape::metadata_planning::tests::scaling::',
    'native': 'component_tree::native_shape::profiling::tests::scaling::',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def selection(kind, workers, argv):
    require(kind in PREFIXES and workers in (4, 8, 12, 16), 'invalid CPU scaling selection')
    selector = PREFIXES[kind] + f'{kind}_cpu_scaling_{workers}'
    require(len(argv) == 6 and argv[1] == selector
            and set(argv[2:]) == {'--exact', '--ignored', '--test-threads=1', '--nocapture'},
            'CPU scaling requires the exact metadata-only test')
    name = 'lattica_prover_p3-' if kind == 'registered' else 'lattica_pq_ringct_research-'
    require(Path(argv[0]).name.startswith(name), 'wrong CPU scaling test executable')
    return {'kind': kind, 'workers': workers, 'events': list(EVENTS),
            'transactions_or_proofs': False, 'gpu_used': False}


def command(argv):
    return ['/usr/bin/perf', 'stat', '--no-big-num', '-x', ';',
            '-e', ','.join(EVENTS), '--', *argv]


def validate(content, selected, *, counters_required=True):
    rows = [json.loads(line.split('CPU_SCALING_RESULT ', 1)[1])
            for line in content.splitlines() if line.startswith('CPU_SCALING_RESULT ')]
    require(len(rows) == 1, 'CPU scaling must emit one result')
    row = rows[0]
    require(row.get('kind') == selected['kind'] and row.get('workers') == selected['workers']
            and row.get('counts_equal') is True and row.get('gpu_used') is False,
            'CPU scaling scope or mathematical parity differs')
    require(row.get('cases') == (72 if selected['kind'] == 'registered' else 159),
            'CPU scaling catalogue is incomplete')
    require(type(row.get('elapsed_ns')) is int and row['elapsed_ns'] > 0,
            'missing CPU scaling duration')
    if selected['kind'] == 'native':
        require(type(row.get('original_host_bytes')) is int and row['original_host_bytes'] > 0,
                'invalid original native allowance')
        require(row.get('ledger_all_claims_released') is True, 'native phase claims did not retire')
        require(type(row.get('phase_host_bytes_peak')) is int
                and row['phase_host_bytes_peak'] >= row['original_host_bytes'], 'invalid native phase allowance')
        require(row['cache']['admitted_host_bytes_peak'] <= row['phase_host_bytes_peak'] <= max(row['original_host_bytes'], 3 << 30), 'native phase exceeded its bounded ledger allowance')
        require(row['phase_host_bytes_peak'] <= row['original_host_bytes'] + (1 << 30), 'native phase supplement exceeded one GiB')
    counters = {}
    for line in content.splitlines():
        fields = line.strip().split(';')
        if len(fields) < 5 or fields[2] not in EVENTS:
            continue
        require(fields[2] not in counters, 'duplicate perf event')
        value, running, percent = float(fields[0]), float(fields[3]), float(fields[4])
        require(all(math.isfinite(v) for v in (value, running, percent))
                and value >= 0 and running > 0 and 0 < percent <= 100.01, 'invalid perf counter')
        counters[fields[2]] = {'value': value, 'unit': fields[1],
                              'running_ns': running, 'running_percent': percent}
    require(set(counters) == (set(EVENTS) if counters_required else set()),
            'missing, unexpected or unsupported perf counters')
    threads = [json.loads(line.split('CPU_SCALING_THREAD ', 1)[1])
               for line in content.splitlines() if line.startswith('CPU_SCALING_THREAD ')]
    jobs = [json.loads(line.split('CPU_SCALING_JOB ', 1)[1])
            for line in content.splitlines() if line.startswith('CPU_SCALING_JOB ')]
    stats = row['planning'] if selected['kind'] == 'registered' else row['cache']
    require(len(threads) == stats['threads_spawned'] and len(jobs) == stats['jobs_started'] + stats.get('maintenance_jobs', 0),
            'incomplete per-worker or per-job scheduling samples')
    if selected.get('placement') in ('packed', 'spread'):
        require(stats.get('pinned_workers') == stats['threads_spawned'] and stats.get('affinity_failures') == 0,
                'requested CPU placement was not applied to every worker')
    totals = {}
    for key in ('voluntary_switches', 'involuntary_switches', 'migrations', 'user_ns', 'system_ns'):
        require(all(type(t.get(key)) is int and t[key] >= 0 for t in threads),
                'unavailable or invalid OS worker counter: ' + key)
        totals[key] = sum(t[key] for t in threads)
    require(all(type(j.get('elapsed_ns')) is int and j['elapsed_ns'] > 0 for j in jobs),
            'invalid per-job duration')
    return {'result': row, 'counters': counters, 'worker_scheduling': totals,
            'threads': threads, 'jobs': jobs,
            'scheduling_scope': 'worker lifetimes via getrusage(RUSAGE_THREAD) and /proc/thread-self/sched',
            'counter_scope': 'whole metadata-only test process including startup and teardown'}
