"""Accept a process-isolated complete metadata measurement, never a proof receipt."""
import json

SELECTOR = 'spend_pipeline::full_workflow::driver::metadata_profile::tests::complete_n3_metadata_stage'
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


def preparation_detail(content, timing, required, variant='reference'):
    def records(prefix):
        return [json.loads(line[len(prefix):]) for line in content.splitlines()
                if line.startswith(prefix)]
    operations = records('RINGCT_PREPARATION_OPERATIONS ')
    graphs = records('RINGCT_GRAPH_PREPARATION_PROFILE ')
    if not required and not operations and not graphs:
        return None
    # Three graphs, three source preparations, and 21 constructor scopes that
    # hash two field commitments each. All belong to the complete N3 boundary.
    require(len(operations) == (6 if variant in ('all', 'endpoints') else 27) and len(graphs) == 3,
            'incomplete raw preparation detail')
    families = ['node_commitment', 'field_commitment', 'arithmetic', 'other']
    metrics = ['allocation', 'kernel_setup', 'upload_enqueue', 'readback_wait',
               'cleanup', 'device_wait']
    for record in operations:
        require(record['schema'] in ('ringct-preparation-operations-v1', 'ringct-preparation-operations-v2')
                and record['complete'] is True and record['families'] == families
                and record['metrics'] == metrics and len(record['counters']) == 4,
                'invalid raw preparation detail')
        if 'arithmetic_shapes' in record:
            require(len(record['arithmetic_shapes']) == 32 and record['arithmetic_overflow'] == 0,
                    'incomplete arithmetic shape counters')
            require(sum(natural(row['calls']) for row in record['arithmetic_shapes']) == record['counters'][2]['calls'],
                    'arithmetic shape counters disagree')
            for row in record['arithmetic_shapes']:
                natural(row['opcode']); natural(row['output_words'])
                require(row['calls'] == 0 or (1 <= row['opcode'] <= 10 and row['output_words'] > 0),
                        'invalid arithmetic shape')
        for counter in record['counters']:
            if record['schema'] == 'ringct-preparation-operations-v2':
                natural(counter['logical_hashes'])
            for key in ('calls', 'wall_ns', 'device_calls', 'device_ns', 'allocations',
                        'allocated_words', 'uploaded_bytes', 'downloaded_bytes'):
                natural(counter[key])
            require(len(counter['metric_ns']) == len(metrics), 'incomplete operation metrics')
            for value in counter['metric_ns']:
                natural(value)
    if any(record['schema'] == 'ringct-preparation-operations-v2' for record in operations):
        require(all(record['schema'] == 'ringct-preparation-operations-v2' for record in operations),
                'mixed preparation counter versions')
        totals = [sum(record['counters'][i]['logical_hashes'] for record in operations) for i in range(4)]
        require(totals == [5334, 168 if variant in ('all', 'endpoints') else 189, 0, 0],
                'incomplete logical commitment coverage')
        for record in operations:
            for counter in record['counters'][:2]:
                require(counter['calls'] <= counter['logical_hashes'] <= 64 * counter['calls'],
                        'invalid commitment batch size')
    sources = records('RINGCT_SOURCE_PREPARATION_PROFILE ')
    require(len(sources) == 3, 'incomplete source preparation detail')
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


def validate(content, require_preparation_detail=False):
    records = [json.loads(line[len(PREFIX):]) for line in content.splitlines() if line.startswith(PREFIX)]
    require(len(records) == 1, 'expected exactly one complete metadata report')
    r = records[0]
    require(r['schema'] == 'ringct-complete-metadata-profile-v1'
            and r['transactions'] == 3 and r['layout'] == 'paired-v1'
            and r['setup_seed'] == [17] * 32 and r['context'] == [34] * 32
            and r['host_profile'] == 'standard' and r['metadata_workers'] in (1, 8, 16),
            'unexpected fixed N3 profile')
    require(r['input_randomness'] in ('fixed-public-parameters-fresh-private-entropy', 'replayed-verified-public-fixture'),
            'incorrect fixture reproducibility claim')
    require(r['complete_metadata'] is True and r['complete_workflow'] is False
            and r['recursive_proofs_generated'] == 0
            and r['retirement'] == 'process-teardown-incomplete-case-owners-retained',
            'not an isolated metadata boundary measurement')
    require('RINGCT_FULL_WORKFLOW_CASE ' not in content, 'unexpected complete workflow receipt')
    variant = r.get('hash_variant', 'reference')
    require(variant in ('reference', 'nodes', 'endpoints', 'fields', 'all'), 'invalid hash variant')
    require(r.get('endpoint_adoptions', 0) == (21 if variant in ('all', 'endpoints') else 0), 'incomplete endpoint reuse')
    reuse_variant = r.get('reuse_variant', 'baseline')
    require(reuse_variant in ('baseline', 'structure', 'verifier', 'arithmetic', 'all'), 'invalid reuse variant')
    reuse = r.get('reuse_counters')
    if reuse is not None:
        require(len(reuse) == 8, 'incomplete reuse counters')
        for value in reuse: natural(value)
        require(reuse[3] == (3 if reuse_variant in ('all', 'structure') else 0), 'incomplete structural reuse')
        require(reuse[7] == (12 if reuse_variant in ('all', 'arithmetic') else 0), 'incomplete vector recipes')
        require(reuse[6] == 0, 'numeric verifier cache overflow')
        require((reuse[4] > 0) == (reuse_variant in ('all', 'verifier')), 'incorrect verifier reuse')
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
    metadata_startup_ns = r['generation_and_startup_ns'] - input_ns
    return dict(reuse_variant=reuse_variant, reuse_counters=reuse, hash_variant=variant, endpoint_adoptions=r.get('endpoint_adoptions', 0), metadata_workers=r['metadata_workers'], fixture_load_verify_ns=r.get('fixture_load_verify_ns', 0), complete_metadata=True, complete_workflow=False, recursive_proofs_generated=0,
                timing=timing, native_input_generation_ns=r['native_input_generation_ns'],
                generation_and_startup_ns=r['generation_and_startup_ns'],
                metadata_startup_ns=metadata_startup_ns,
                complete_metadata_ns=metadata_startup_ns + timing['total_ns'],
                registered=registered, native=native, combined=combined,
                families=dict(zip(FAMILIES, families)),
                expensive_misses=[m for m in r['expensive_misses'] if m is not None],
        planner=r['planner'], native_cache=r['native_cache'], retirement=r['retirement'],
        preparation_detail=preparation_detail(content, timing, require_preparation_detail, variant))
