"""Numerical metadata parity and timing receipts; never full-workflow evidence."""
import json

from opencl_private_spend_validate import require


def natural(value):
    require(type(value) is int and 0 <= value < (1 << 128), 'invalid metadata counter')
    return value


def validate(content):
    def records(prefix):
        return [json.loads(line[len(prefix):]) for line in content.splitlines() if line.startswith(prefix)]
    counts = records('METADATA_COUNTING_QUALIFICATION ')
    rows = records('METADATA_CPU_QUALIFICATION ')
    require(len(counts) == 1 and len(rows) == 5, 'incomplete metadata qualification')
    counts = counts[0]
    require(counts.get('shapes') == 72 and counts.get('all_counts_equal') is True
            and counts.get('gpu_used') is False, 'metadata counting parity missing')
    for key in ('materialized_ns', 'counted_ns', 'materialized_peak_bytes', 'counted_peak_bytes'):
        require(natural(counts.get(key)) > 0, 'missing metadata counting measurement')
    require(counts['counted_peak_bytes'] < counts['materialized_peak_bytes'], 'counting storage did not decrease')
    for width, row in zip((1, 2, 4, 8, 16), rows):
        require(type(row.get('workers')) is int and row['workers'] == width
                and row.get('shapes') == 72 and row.get('counts_equal') is True
                and row.get('gpu_used') is False, 'metadata worker parity missing')
        for key in ('cold_ns', 'warm_ns', 'original_host_bytes'):
            require(natural(row.get(key)) > 0, 'missing metadata measurement')
        stats, cache = row.get('planning'), row.get('cache')
        require(type(stats) is dict and type(cache) is dict, 'missing metadata statistics')
        for key in ('worker_ceiling', 'peak_active_workers', 'largest_cohort', 'envelopes',
                    'heights_completed', 'jobs_started', 'cohorts', 'budget_reductions',
                    'failed_envelopes', 'admitted_host_bytes_peak', 'wall_ns', 'worker_elapsed_ns',
                    'symbolic_preparations', 'shared_symbolic_bytes_peak', 'worker_auxiliary_bytes_peak'):
            natural(stats.get(key))
        require(stats['worker_ceiling'] == width
                and 1 <= stats['peak_active_workers'] <= stats['largest_cohort'] <= width
                and (width == 1 or stats['peak_active_workers'] > 1)
                and stats['envelopes'] == stats['symbolic_preparations'] == 4 and stats['heights_completed'] == 72
                and stats['shared_symbolic_bytes_peak'] > 0 and stats['worker_auxiliary_bytes_peak'] > 0
                and stats['jobs_started'] >= 72 and stats['failed_envelopes'] == 0
                and 0 < stats['admitted_host_bytes_peak'] <= row['original_host_bytes']
                and 0 < stats['wall_ns'] <= row['cold_ns']
                and stats['worker_elapsed_ns'] > 0, 'invalid metadata concurrency or admission')
        for key in ('hits', 'misses', 'evictions', 'failed_computations', 'planning_ns', 'entries', 'reserved_host_bytes'):
            natural(cache.get(key))
        require(cache['hits'] == cache['misses'] == cache['entries'] == 4
                and cache['evictions'] == cache['failed_computations'] == 0
                and cache['reserved_host_bytes'] == 1 << 20, 'invalid metadata cache evidence')
    tables = table_records(content)
    return dict(tables=tables, scope='CPU numerical metadata only; no RingCT transaction or aggregate proof',
                counting=counts, measurements=rows, complete_workflow_speedup_claimed=False)


def table_records(content):
    def records(prefix):
        result = []
        for line in content.splitlines():
            # libtest may leave its test-name prefix on the first stderr line.
            if line.startswith('test ') and ' ... ' in line:
                line = line.split(' ... ', 1)[1]
            if line.startswith(prefix): result.append(json.loads(line[len(prefix):]))
        return result
    identities, rows = records('METADATA_TABLE_IDENTITY '), records('METADATA_TABLE_ROW ')
    require(len(identities) == 1 and len(rows) == 72, 'incomplete qualified table data')
    identity = identities[0]
    for key in ('source_digest', 'profile_id'):
        value = identity.get(key)
        require(type(value) is list and len(value) == 32 and any(value)
                and all(type(n) is int and 0 <= n < 256 for n in value), 'invalid table identity')
    require(type(identity.get('signature')) is list and len(identity['signature']) == 12
            and all(type(n) is int and n >= 0 for n in identity['signature']), 'invalid table signature')
    require(type(identity.get('available')) is bool, 'invalid table availability')
    for index, row in enumerate(rows):
        require(type(row.get('public_values')) is int and type(row.get('log_height')) is int
                and row['public_values'] == (25, 28, 38, 46)[index // 18]
                and row['log_height'] == 3 + index % 18, 'invalid table row domain')
        values = row.get('values')
        require(type(values) is list and len(values) == 9
                and all(type(n) is int and 0 <= n < (1 << 64) for n in values), 'invalid table row values')
    results = records('METADATA_TABLE_QUALIFICATION ')
    require(len(results) == int(identity['available']), 'missing or unexpected table parity')
    if results:
        result = results[0]
        require(result.get('envelopes') == 4 and result.get('shapes') == 72
                and result.get('counts_equal') is True and result.get('gpu_used') is False
                and natural(result.get('elapsed_ns')) > 0, 'invalid table parity result')
        stats, cache = result.get('planning', {}), result.get('cache', {})
        require(stats.get('jobs_started') == stats.get('symbolic_preparations') == 0
                and cache.get('table_hits') == cache.get('misses') == cache.get('entries') == 4,
                'table fast path compiled or omitted shapes')
    return dict(identity=identity, rows=rows, qualification=results[0] if results else None)
