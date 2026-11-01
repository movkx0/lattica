"""Qualification for actual recursive metadata, separately from whole workflows."""
import json
from cpu_identity_receipts import stage


def validate(content):
    from opencl_private_spend_validate import require
    prefix = 'CPU_IDENTITY_QUALIFICATION '
    rows = [json.loads(line[len(prefix):]) for line in content.splitlines() if line.startswith(prefix)]
    require(len(rows) == 5, 'CPU identity qualification needs all five worker widths')
    baseline, fields = None, None
    for row, width in zip(rows, (1, 2, 4, 8, 16)):
        require(row.get('schema') == 'ringct-cpu-identity-qualification-v1' and row.get('workers') == width
                and row.get('programs') == 17 and row.get('gpu_reference_programs') == 1 and type(row.get('component_ns')) is int and row['component_ns'] > 0,
                'CPU qualification geometry or elapsed time')
        require(row.get('independent_cpu_verified_proofs') == (2 if width == 16 else 0), 'CPU qualification proof coverage')
        identities = row.get('identities')
        require(type(identities) is list and len(identities) == 17 and all(type(d) is list and len(d) == 4
                and all(type(v) is int and 0 <= v < 0xffffffff00000001 for v in d) for d in identities),
                'CPU qualification identity encoding')
        baseline = identities if baseline is None else baseline
        require(identities == baseline, 'CPU worker scheduling changed identities')
        reports = row.get('reports'); counts = [width] * (17 // width) + ([17 % width] if 17 % width else [])
        require(type(reports) is list and len(reports) == len(counts), 'CPU qualification cohort coverage')
        next_job = 0; total_fields = 0
        for report, count in zip(reports, counts):
            require(report.get('schema') == 'identity-cpu-prefix-v1' and report.get('streams') == count
                    and report.get('requested_workers') == width and report.get('effective_workers') == count
                    and report.get('peak_active_workers') == count, 'CPU qualification did not execute actual concurrent width')
            stage(report['analysis'], 'block_v2_identity_source_analysis', 'open_cl', 'gpu_required')
            stage(report['cpu'], 'block_v2_cpu_identity_prefixes', 'cpu', 'cpu_required')
            require(all(type(report.get(k)) is int and report[k] > 0 for k in ('fields', 'worker_elapsed_ns', 'hash_wall_ns', 'analysis_ns')),
                    'CPU qualification noncanonical component counters')
            workers = report['workers']
            require(type(workers) is list and all(type(w) is dict and all(type(w.get(k)) is int and w[k] >= 0 for k in ('job', 'fields', 'elapsed_ns')) for w in workers), 'CPU qualification worker counters')
            require(len(workers) == count and [w['job'] for w in workers] == list(range(next_job, next_job + count)),
                    'CPU qualification job order')
            require(sum(w['elapsed_ns'] for w in workers) == report['worker_elapsed_ns']
                    and sum(w['fields'] for w in workers) == report['fields']
                    and 0 < report['hash_wall_ns'] <= report['cpu']['elapsed_ns'], 'CPU qualification component timing')
            next_job += count; total_fields += report['fields']
        fields = total_fields if fields is None else fields
        require(total_fields == fields and next_job == 17, 'CPU qualification metadata inventory changed')
    return dict(schema='ringct-cpu-identity-qualification-audit-v1', workers=[1, 2, 4, 8, 16],
                programs=17, fields=fields, independent_cpu_verified_proofs=2,
                actual_sixteen_worker_concurrency=True, complete_workflow_qualified=False,
                measurements=rows)
