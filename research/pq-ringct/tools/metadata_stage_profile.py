"""Accept a process-isolated complete metadata measurement, never a proof receipt."""
import json

SELECTOR = 'spend_pipeline::full_workflow::driver::metadata_profile::tests::complete_n3_metadata_stage'
def selector(transactions):
    require(transactions in (3, 4), 'unsupported metadata transaction count')
    return SELECTOR.replace('complete_n3_', f'complete_n{transactions}_')

PREFIX = 'RINGCT_METADATA_STAGE_PROFILE '
FAMILIES = ('aes', 'shake', 'transcript', 'sparse', 'uniform', 'statement', 'private',
            'affine', 'ntt', 'mul', 'g_bound', 'permutation', 'linear_map')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(value):
    require(type(value) is int and 0 <= value < 1 << 128, 'invalid metadata counter')
    return value


def cache_rates(c):
    for key in ('hits', 'misses', 'table_hits', 'failed_computations', 'evictions'):
        natural(c[key])
    require(c['table_hits'] <= c['misses'] and c['failed_computations'] == 0,
            'invalid or failed metadata cache computations')
    requests = c['hits'] + c['misses']
    require(requests > 0, 'empty metadata cache measurement')
    cold = c['misses'] - c['table_hits']
    return dict(requests=requests, memory_hits=c['hits'], table_hits=c['table_hits'],
                cold_misses=cold, memory_miss_rate=c['misses'] / requests,
                cold_miss_rate=cold / requests, evictions=c['evictions'])


def preparation_detail(content, timing, required, variant='reference', transactions=3):
    def records(prefix):
        return [json.loads(line[len(prefix):]) for line in content.splitlines()
                if line.startswith(prefix)]
    operations = records('RINGCT_PREPARATION_OPERATIONS ')
    graphs = records('RINGCT_GRAPH_PREPARATION_PROFILE ')
    if not required and not operations and not graphs:
        return None
    # One graph and source scope per member, plus seven constructor scopes
    # per member when endpoint commitments are not reused.
    require(len(operations) == transactions * (2 if variant in ('all', 'endpoints') else 9) and len(graphs) == transactions,
            'incomplete raw preparation detail')
    families = ['node_commitment', 'field_commitment', 'arithmetic', 'other']
    metrics = ['allocation', 'kernel_setup', 'upload_enqueue', 'readback_wait',
               'cleanup', 'device_wait']
    for record in operations:
        require(record['schema'] in ('ringct-preparation-operations-v1', 'ringct-preparation-operations-v2', 'ringct-preparation-operations-v3')
                and record['complete'] is True and record['families'] == families
                and record['metrics'] == metrics and len(record['counters']) == 4,
                'invalid raw preparation detail')
        if 'field_kernels' in record:
            require(len(record['field_kernels']) == (3 if record['schema'] == 'ringct-preparation-operations-v3' else 2) and
                    sum(natural(n) for n in record['field_kernels']) == record['counters'][1]['device_calls'],
                    'incomplete field kernel counters')
        if record['schema'] == 'ringct-preparation-operations-v3':
            sizes = record.get('field_stream_sizes')
            require(type(sizes) is list and len(sizes) == 5 and
                    sum(natural(n) for n in sizes) == record['counters'][1]['logical_hashes'],
                    'incomplete field stream size counters')
        if 'arithmetic_shapes' in record:
            require(len(record['arithmetic_shapes']) == 32 and record['arithmetic_overflow'] == 0,
                    'incomplete arithmetic shape counters')
            require(sum(natural(row['calls']) for row in record['arithmetic_shapes']) == record['counters'][2]['calls'],
                    'arithmetic shape counters disagree')
            for row in record['arithmetic_shapes']:
                natural(row['opcode']); natural(row['output_words'])
                require(row['calls'] == 0 or (1 <= row['opcode'] <= (12 if record['schema'] == 'ringct-preparation-operations-v3' else 10) and row['output_words'] > 0),
                        'invalid arithmetic shape')
        for counter in record['counters']:
            if record['schema'] in ('ringct-preparation-operations-v2', 'ringct-preparation-operations-v3'):
                natural(counter['logical_hashes'])
            for key in ('calls', 'wall_ns', 'device_calls', 'device_ns', 'allocations',
                        'allocated_words', 'uploaded_bytes', 'downloaded_bytes'):
                natural(counter[key])
            require(len(counter['metric_ns']) == len(metrics), 'incomplete operation metrics')
            for value in counter['metric_ns']:
                natural(value)
    if any(record['schema'] in ('ringct-preparation-operations-v2', 'ringct-preparation-operations-v3') for record in operations):
        require(all(record['schema'] in ('ringct-preparation-operations-v2', 'ringct-preparation-operations-v3') for record in operations),
                'mixed preparation counter versions')
        totals = [sum(record['counters'][i]['logical_hashes'] for record in operations) for i in range(4)]
        require(totals == [1778 * transactions, transactions * (56 if variant in ('all', 'endpoints') else 63), 0, 0],
                'incomplete logical commitment coverage')
        for record in operations:
            for counter in record['counters'][:2]:
                require(counter['calls'] <= counter['logical_hashes'] <= 64 * counter['calls'],
                        'invalid commitment batch size')
    sources = records('RINGCT_SOURCE_PREPARATION_PROFILE ')
    require(len(sources) == transactions, 'incomplete source preparation detail')
    for rows, steps, boundary in (
        (graphs, ['input_validation', 'scope_startup', 'imports', 'relation', 'finalize'], 'graph_sources_ns'),
        (sources, ['registration', 'algebra', 'tree', 'statement', 'manifest', 'native',
                   'crypto', 'auxiliary', 'producer'], 'source_preparation_ns')):
        total = 0
        for row in rows:
            require(row['steps'] == steps and row['completed'] == len(steps)
                    and len(row['wall_ns']) == len(steps), 'incomplete preparation timeline')
            total += sum(natural(value) for value in row['wall_ns'])
        require(total <= timing[boundary], 'preparation timeline exceeds phase boundary')
    return dict(operations=operations, graphs=graphs, sources=sources,
                metrics_overlap=True)


def parallel_detail(content, workers, variant, concurrency=None, readiness=None):
    """Per-wave elapsed times overlap GPU publication; worker_ns is not CPU time."""
    require(variant in ('all', 'serial', 'registration', 'crypto', 'native'), 'invalid parallel variant')
    prefix = 'RINGCT_METADATA_PARALLEL '
    result = {}
    for line in content.splitlines():
        if not line.startswith(prefix):
            continue
        row = json.loads(line[len(prefix):])
        family, stats = row['family'], row['statistics']
        require(family in ('registration_encode', 'registration_hash', 'crypto_hash', 'crypto', 'native', 'native_data', 'crypto_leaves', 'case_pipeline', 'case_readiness')
                and family not in result, 'unknown or duplicate parallel phase')
        require(variant in ('all', family.split('_')[0]) and workers > 1, 'disabled parallel phase')
        if family in ('native_data', 'crypto_leaves', 'case_pipeline', 'case_readiness'):
            enabled = {'native_data': ('all', 'native'), 'crypto_leaves': ('all', 'crypto'), 'case_pipeline': ('all', 'overlap'), 'case_readiness': ('all', 'overlap')}
            require(concurrency in enabled[family], 'disabled concurrency phase')
        fields = ('jobs', 'width', 'peak_active', 'threads', 'budget_reductions',
                  'admitted_host_bytes', 'worker_ns', 'wait_ns', 'publication_ns', 'wall_ns')
        if concurrency is not None:
            fields += ('queued_peak', 'queue_ns', 'idle_ns', 'max_job_ns', 'gpu_ns', 'overlap_worker_ns')
        require(set(stats) == set(fields), 'incomplete parallel statistics')
        for value in stats.values():
            natural(value)
        if family == 'case_readiness':
            require(readiness in ('all', 'cpu'), 'disabled readiness phase')
        maximum_jobs = 524 if family in ('case_pipeline', 'case_readiness') else 512 if family == 'native_data' else 64
        # An early pool can decline speculative work when the later exact
        # source census arrives. Its already admitted lanes remain bounded.
        early = family == 'case_readiness'
        maximum_width = workers if early else min(workers, stats['jobs'])
        require((0 if early else 2) <= stats['jobs'] <= maximum_jobs and 2 <= stats['width'] <= maximum_width
                and (0 if stats['jobs'] == 0 else 1) <= stats['peak_active'] <= stats['width']
                and stats['threads'] == stats['width'] - 1, 'parallel worker ceiling exceeded')
        require(stats['budget_reductions'] == int(stats['width'] < maximum_width)
                and 0 < stats['admitted_host_bytes'] <= 32 << 30, 'invalid parallel admission')
        require(stats['wall_ns'] > 0 and (stats['worker_ns'] > 0 or early and stats['jobs'] == 0)
                and stats['wait_ns'] + stats['publication_ns'] <= stats['wall_ns'], 'invalid parallel timing')
        if concurrency is not None:
            require(stats['queued_peak'] <= min(64, stats['jobs']), 'queue admission exceeded')
            require(stats['max_job_ns'] <= stats['worker_ns'] and stats['gpu_ns'] <= stats['publication_ns']
                    and stats['overlap_worker_ns'] <= stats['worker_ns'], 'invalid overlap timing')
            require(stats['gpu_ns'] == 0 or family in ('case_pipeline', 'case_readiness'), 'GPU publication outside case pool')
        result[family] = stats
    require(('registration_encode' in result) == ('registration_hash' in result), 'incomplete registration waves')
    return result


def readiness_detail(content, transactions, parallel, timing, required):
    rows = [json.loads(line.split(' ', 1)[1]) for line in content.splitlines()
            if line.startswith('RINGCT_METADATA_READINESS_DETAIL ')]
    if not rows:
        require(not required or 'case_readiness' not in parallel, 'missing readiness timeline')
        return None
    require(len(rows) == 1 and 'case_readiness' in parallel, 'unexpected readiness timeline')
    row = rows[0]
    require(set(row) == {'graph_ready_ns', 'source_ready_ns', 'registration_ready_ns',
        'request_ready_ns', 'joined_ns', 'early_crypto'}, 'incomplete readiness timeline')
    require(type(row['early_crypto']) is bool, 'invalid early crypto flag')
    joined = natural(row['joined_ns'])
    require(joined <= timing['graph_sources_ns'] + timing['source_preparation_ns'], 'readiness time exceeds source phases')
    for name in ('graph_ready_ns', 'source_ready_ns', 'registration_ready_ns'):
        require(len(row[name]) == transactions, 'wrong readiness member count')
        for value in row[name]:
            require(natural(value) <= joined, 'invalid readiness member time')
    require(all(row['graph_ready_ns']), 'incomplete graph readiness')
    fallback = not any(row['source_ready_ns'])
    require(row['graph_ready_ns'] == sorted(row['graph_ready_ns']) and row['source_ready_ns'] == sorted(row['source_ready_ns']), 'source publication reordered')
    if fallback:
        require(not row['early_crypto'] and not any(row['request_ready_ns']), 'work survived source admission fallback')
        for graph, registration in zip(row['graph_ready_ns'], row['registration_ready_ns']):
            require(registration == 0 or graph <= registration, 'registration preceded graph')
    else:
        require(row['source_ready_ns'][0] >= row['graph_ready_ns'][-1], 'source preceded graph layer')
        for graph, registration, source in zip(row['graph_ready_ns'], row['registration_ready_ns'], row['source_ready_ns']):
            require(graph <= registration <= source, 'registration dependency violated')
    require(len(row['request_ready_ns']) == 7 * transactions, 'wrong request completion count')
    for index, value in enumerate(row['request_ready_ns']):
        value = natural(value)
        require(value <= joined and (value == 0 or value >= row['source_ready_ns'][index // 7]), 'request preceded its source')
        require(not row['early_crypto'] or value != 0, 'early crypto lost a request')
    if row['early_crypto']:
        require(not any(name in parallel for name in ('crypto', 'crypto_hash', 'crypto_leaves')), 'early crypto recomputed by a second pool')
    return row

def validate(content, require_preparation_detail=False, expected_transactions=3, expected_host_profile='standard'):
    require(expected_transactions in (3, 4), "unsupported metadata transaction count")
    require(expected_host_profile in ("standard", "expanded-36", "expanded-40") and
            (expected_host_profile == "standard" or expected_transactions == 4), "invalid metadata host profile")
    records = [json.loads(line[len(PREFIX):]) for line in content.splitlines() if line.startswith(PREFIX)]
    require(len(records) == 1, 'expected exactly one complete metadata report')
    r = records[0]
    require(r['schema'] == 'ringct-complete-metadata-profile-v1'
            and r['transactions'] == expected_transactions and r['layout'] == 'paired-v1'
            and r['setup_seed'] == [17] * 32 and r['context'] == [34] * 32
            and r['host_profile'] == expected_host_profile and r['metadata_workers'] in (1, 2, 4, 8, 16),
            'unexpected fixed N3/N4 profile')
    require(r['input_randomness'] in ('fixed-public-parameters-fresh-private-entropy', 'replayed-verified-public-fixture'),
            'incorrect fixture reproducibility claim')
    require(r['complete_metadata'] is True and r['complete_workflow'] is False
            and r['recursive_proofs_generated'] == 0
            and r['retirement'] == 'process-teardown-incomplete-case-owners-retained',
            'not an isolated metadata boundary measurement')
    require('RINGCT_FULL_WORKFLOW_CASE ' not in content, 'unexpected complete workflow receipt')
    variant = r.get('hash_variant', 'reference')
    require(variant in ('reference', 'nodes', 'endpoints', 'fields', 'all'), 'invalid hash variant')
    require(r.get('endpoint_adoptions', 0) == (7 * expected_transactions if variant in ('all', 'endpoints') else 0), 'incomplete endpoint reuse')
    reuse_variant = r.get('reuse_variant', 'baseline')
    require(reuse_variant in ('baseline', 'structure', 'verifier', 'arithmetic', 'all'), 'invalid reuse variant')
    reuse = r.get('reuse_counters')
    if reuse is not None:
        require(len(reuse) == 8, 'incomplete reuse counters')
        for value in reuse: natural(value)
        require(reuse[3] == (expected_transactions if reuse_variant in ('all', 'structure') else 0), 'incomplete structural reuse')
        require(reuse[7] == (4 * expected_transactions if reuse_variant in ('all', 'arithmetic') else 0), 'incomplete vector recipes')
        require(reuse[6] == 0, 'numeric verifier cache overflow')
        require((reuse[4] > 0) == (reuse_variant in ('all', 'verifier')), 'incorrect verifier reuse')
    pipeline_variant = r.get('pipeline_variant', 'baseline')
    parallel_variant = r.get('parallel_variant', 'serial')
    checks = r.get('native_reference_checks', [0] * 6)
    require(type(checks) is list and len(checks) == 6, 'invalid native reference coverage')
    for value in checks: natural(value)
    concurrency_variant = r.get('concurrency_variant')
    require(concurrency_variant in (None, 'baseline', 'native', 'crypto', 'overlap', 'all'), 'invalid concurrency variant')
    readiness = r.get('readiness_variant', 'baseline')
    require(readiness in ('baseline', 'cpu', 'gpu', 'all'), 'invalid readiness variant')
    kernel = r.get('tiled_kernel', 'paired')
    require(kernel in ('paired', 'fused'), 'invalid tiled field kernel')
    parallel = parallel_detail(content, r['metadata_workers'], parallel_variant, concurrency_variant, readiness)
    require(pipeline_variant in ('baseline', 'field_hash', 'registration', 'arithmetic', 'all'), 'invalid pipeline variant')
    pipeline_counts = r.get('pipeline_counters')
    if 'pipeline_variant' in r:
        require(type(pipeline_counts) is list and len(pipeline_counts) == 4, 'incomplete pipeline counters')
        for value in pipeline_counts: natural(value)
        require(pipeline_counts[2] == (expected_transactions if pipeline_variant in ('registration', 'all') and reuse_variant in ('all', 'structure') and r['metadata_workers'] >= 2 else 0), 'incorrect parallel registration count')
        require((pipeline_counts[3] > 0) == (pipeline_variant in ('arithmetic', 'all')), 'incorrect fused arithmetic count')
    next_variant = r.get('next_variant', 'baseline')
    require(next_variant in ('baseline', 'field_hash', 'encoding', 'case_cache', 'all'), 'invalid next variant')
    next_counts = r.get('next_counters')
    if 'next_variant' in r:
        require(type(next_counts) is list and len(next_counts) == 4, 'incomplete next counters')
        for value in next_counts: natural(value)
        require(reuse is not None, 'next counters require reuse counters')
        require((next_counts[0] == 0) == (next_variant in ('encoding', 'all')), 'incorrect expression allocations')
        require(next_counts[1] > 0, 'missing shape allocation counts')
        if next_variant in ('case_cache', 'all'):
            require(next_counts[2:] == reuse[4:6], 'incomplete case cache counters')
        else:
            require(next_counts[2:] == [0, 0], 'unexpected case cache use')
    timing = r['timing']
    for value in timing.values():
        natural(value)
    require(timing['total_ns'] > 0 and timing['total_ns'] == sum(timing[k] for k in (
        'setup_ns', 'graph_sources_ns', 'source_preparation_ns', 'inventory_ns',
        'reservation_ns', 'constructors_ns')), 'metadata phases overlap or are incomplete')
    require(timing['constructors_ns'] == sum(timing[k] for k in (
        'native_constructors_ns', 'crypto_constructors_ns', 'graph_constructors_ns',
        'final_aggregation_ns')), 'constructor phases overlap or are incomplete')
    clocks = [json.loads(line.split(' ', 1)[1]) for line in content.splitlines()
              if line.startswith('RINGCT_METADATA_TIMING ')]
    require(clocks == [timing], 'missing or mismatched metadata boundary clock')
    input_ns = natural(r['native_input_generation_ns']) + natural(r.get('fixture_load_verify_ns', 0))
    require(natural(r['generation_and_startup_ns']) >= input_ns > 0, 'invalid input preparation timing')
    require((r['native_input_generation_ns'] == 0) == (r['input_randomness'] == 'replayed-verified-public-fixture'), 'incorrect input provenance')
    registered = cache_rates(r['registered_cache'])
    native = cache_rates(r['native_cache'])
    families = r['native_families']
    require(len(families) == len(FAMILIES), 'incomplete native family inventory')
    for f in families:
        for value in f.values():
            natural(value)
        require(f['requests'] == f['cache_hits'] + f['table_hits'] + f['cold_misses'],
                'native family requests do not balance')
    for key, family_key in [('requests', 'requests'), ('memory_hits', 'cache_hits'),
                            ('table_hits', 'table_hits'), ('cold_misses', 'cold_misses')]:
        require(native[key] == sum(f[family_key] for f in families), 'native family counters disagree')
    combined = {key: registered[key] + native[key] for key in ('requests', 'memory_hits', 'table_hits', 'cold_misses')}
    combined['cold_miss_rate'] = combined['cold_misses'] / combined['requests']
    constructors = r.get('constructor_families', [])
    constructor_ns = r.get('constructor_ns', [])
    require(len(constructors) == len(constructor_ns) and len(constructors) <= 128 and
            len(set(constructors)) == len(constructors), 'incomplete constructor timings')
    for value in constructor_ns: natural(value)
    metadata_startup_ns = r['generation_and_startup_ns'] - input_ns
    return dict(transactions=r['transactions'], host_profile=r['host_profile'], readiness_detail=readiness_detail(content, r['transactions'], parallel, timing, require_preparation_detail), readiness_variant=readiness, tiled_kernel=kernel, native_reference_checks=checks, concurrency_variant=concurrency_variant or 'baseline', parallel_variant=parallel_variant, parallel=parallel, constructor_ns=dict(zip(constructors, constructor_ns)), pipeline_variant=pipeline_variant, pipeline_counters=pipeline_counts, next_variant=next_variant, next_counters=next_counts, reuse_variant=reuse_variant, reuse_counters=reuse, hash_variant=variant, endpoint_adoptions=r.get('endpoint_adoptions', 0), metadata_workers=r['metadata_workers'], fixture_load_verify_ns=r.get('fixture_load_verify_ns', 0), complete_metadata=True, complete_workflow=False, recursive_proofs_generated=0,
                timing=timing, native_input_generation_ns=r['native_input_generation_ns'],
                generation_and_startup_ns=r['generation_and_startup_ns'],
                metadata_startup_ns=metadata_startup_ns,
                complete_metadata_ns=metadata_startup_ns + timing['total_ns'],
                registered=registered, native=native, combined=combined,
                families=dict(zip(FAMILIES, families)),
                expensive_misses=[m for m in r['expensive_misses'] if m is not None],
        planner=r['planner'], native_cache=r['native_cache'], retirement=r['retirement'],
        preparation_detail=preparation_detail(content, timing, require_preparation_detail, variant, expected_transactions))
