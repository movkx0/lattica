"""Native CPU metadata profiling receipts; no complete workflow claims."""
import json
from opencl_private_spend_validate import require

def natural(n):
    require(type(n) is int and 0 <= n < (1 << 128), 'invalid native metadata counter')
    return n

def validate(content):
    def records(prefix):
        return [json.loads(line[len(prefix):]) for line in content.splitlines() if line.startswith(prefix)]
    rows, summaries = records('NATIVE_METADATA_PROFILE_ROW '), records('NATIVE_METADATA_PROFILE ')
    require(len(rows) in (39,159) and len(summaries) == 1, 'incomplete native metadata profile')
    summary=summaries[0]
    require(summary.get('cases') == len(rows) and summary.get('gpu_used') is False, 'wrong profile scope')
    keys=set(); names=set(); families=set()
    for row in rows:
        require(row.get('counts_equal') is True and row.get('warm_calls') == 8, 'missing native cache parity')
        require(row.get('name') not in names and type(row.get('name')) is str, 'duplicate native profile name')
        names.add(row['name'])
        require(type(row.get('family')) is str, 'missing native family')
        families.add(row['family'])
        key=row.get('key')
        require(type(key) is list and len(key) == 32 and all(type(v) is int and 0 <= v < 256 for v in key), 'bad native profile key')
        require(tuple(key) not in keys, 'duplicate native descriptor key'); keys.add(tuple(key))
        for field, length in [('values',8),('geometry',5)]:
            require(type(row.get(field)) is list and len(row[field]) == length, 'bad native profile shape')
            for value in row[field]: natural(value)
        for phase, wall in [('cold_phases','cold_ns'),('warm_phases','warm_total_ns')]:
            require(natural(row.get(wall)) > 0 and type(row.get(phase)) is dict, 'missing native phase timing')
            timings=row[phase]
            require(set(timings)=={'preflight_ns','key_ns','lookup_ns','periodic_ns','symbolic_ns','lowering_ns','finalization_ns'}, 'missing native compiler phases')
            require(sum(natural(t) for t in timings.values()) <= row[wall], 'overlapping native metadata timings')
        require(all(row['warm_phases'][p] == 0 for p in ['periodic_ns','symbolic_ns','lowering_ns','finalization_ns']), 'warm native hit compiled')
        if 'lowering_phases' in row:
            detail = row['lowering_phases']
            phases = {'setup_ns','pcs_ns','selectors_ns','periodic_ns','quotient_ns','constraints_ns'}
            pcs = {'pcs_setup_ns','pcs_query_ns','pcs_opening_ns','pcs_reduction_ns','pcs_folding_ns'}
            periodic = {'periodic_specialization_ns','periodic_interpolation_ns','periodic_emission_ns'}
            require(type(detail) is dict and set(detail) in (phases, phases | pcs, phases | pcs | periodic), 'incomplete lowering phases')
            require(sum(natural(detail[n]) for n in phases) <= row['cold_phases']['lowering_ns'], 'overlapping native lowering phases')
            if pcs <= detail.keys():
                require(sum(natural(detail[n]) for n in pcs) <= detail['pcs_ns'], 'overlapping PCS sub-stages')
            if periodic <= detail.keys():
                require(sum(natural(detail[n]) for n in periodic) <= detail['periodic_ns'], 'overlapping periodic sub-stages')
        natural(row['original_host_bytes'])
        require(row['values'][-1] <= 2 << 30, 'native compiler exceeded original cap')
    require(families == {'aes','shake','transcript','sparse','uniform','statement','private','affine','ntt','mul','g_bound','permutation','linear_map'}, 'incomplete native family coverage')
    require(summary.get('cold_ns') == sum(r['cold_ns'] for r in rows)
            and summary.get('warm_total_ns') == sum(r['warm_total_ns'] for r in rows), 'native profile total mismatch')
    for field in ['fingerprint_cold_ns','fingerprint_warm_ns','catalogue_ns','original_host_bytes_peak']: natural(summary.get(field))
    cache=summary.get('cache',{})
    require(cache.get('misses')==cache.get('entries')==len(rows) and cache.get('hits')==len(rows)*8
            and cache.get('evictions')==cache.get('failed_computations')==0
            and cache.get('reserved_host_bytes')==1 << 20, 'invalid native profile cache accounting')
    cohorts = records('NATIVE_METADATA_COHORT ')
    identities = records('NATIVE_METADATA_TABLE_IDENTITY ')
    tables = records('NATIVE_METADATA_TABLE_QUALIFICATION ')
    identity = None
    def digest(value):
        require(type(value) is list and len(value) == 32 and all(type(v) is int and 0 <= v < 256 for v in value), 'invalid native table digest')
    if cohorts or identities or tables:
        require(len(cohorts) == 5 and len(identities) == 1, 'incomplete native worker qualification')
        require([c.get('workers') for c in cohorts] == [1,2,4,8,16], 'wrong native worker ceilings')
        for c in cohorts:
            require(c.get('counts_equal') is True and c.get('gpu_used') is False and natural(c.get('elapsed_ns')) > 0, 'native cohort parity or scope')
            stats = c.get('cache', {})
            require(stats.get('entries') == stats.get('misses') == 39 and stats.get('table_hits') == 0
                    and stats.get('evictions') == stats.get('failed_computations') == 0, 'native cohort cache accounting')
            require(1 <= stats.get('peak_workers',0) <= c['workers'] and stats.get('jobs_started',0) >= 39
                    and stats.get('periodic_preparations') == 1, 'native cohort execution accounting')
            require(natural(stats.get('admitted_host_bytes_peak')) <= c.get('original_host_bytes_peak') == summary['original_host_bytes_peak'], 'native cohort enlarged original memory budget')
        identity = identities[0]
        for field in ['source','profile']: digest(identity.get(field))
        require(type(identity.get('available')) is bool, 'missing native table availability')
        descriptor_keys = set()
        for row in rows:
            digest(row.get('descriptor_key'))
            descriptor_keys.add(tuple(row['descriptor_key']))
            require(all(n < 1 << 64 for n in row['geometry'] + row['values']), 'native row exceeds pinned integer layout')
        require(len(descriptor_keys) == len(rows), 'duplicate canonical native descriptor key')
        require(len(tables) == int(identity['available']), 'missing native table parity')
        if tables:
            table = tables[0]
            require(table.get('cases') == len(rows) and table.get('counts_equal') is True and table.get('gpu_used') is False, 'native table scope or parity')
            require(natural(table.get('elapsed_ns')) > 0 and table.get('cache',{}).get('table_hits') == len(rows), 'native tables were not used')
            require(all(table.get('phases',{}).get(p) == 0 for p in ['periodic_ns','symbolic_ns','lowering_ns','finalization_ns']), 'native table lookup compiled')
    return dict(scope='native metadata descriptor catalogue only; no transactions or proofs', rows=rows, summary=summary,
                cohorts=cohorts, identity=identity, tables=tables)
