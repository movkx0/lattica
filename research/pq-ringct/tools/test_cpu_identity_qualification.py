"""Full and tail measurements must reconcile with the worker receipts."""
import copy
import json
import unittest
from cpu_identity_qualification import validate
from test_cpu_identity_receipts import operation


def fixture():
    rows = []
    for width in (1, 2, 4, 8, 16):
        reports = []
        for first in range(0, 17, width):
            count = min(width, 17 - first)
            reports.append(dict(schema='identity-cpu-prefix-v1', streams=count,
                requested_workers=width, effective_workers=count, peak_active_workers=count,
                fields=count * 40, worker_elapsed_ns=count * 8, hash_wall_ns=9, analysis_ns=100,
                analysis=operation('block_v2_identity_source_analysis', False, 101),
                cpu=operation('block_v2_cpu_identity_prefixes'),
                workers=[dict(job=j, fields=40, elapsed_ns=8) for j in range(first, first + count)]))
        rows.append(dict(schema='ringct-cpu-identity-qualification-v2', workers=width,
            programs=17, gpu_reference_programs=1, component_ns=1000,
            independent_cpu_verified_proofs=2 if width == 16 else 0,
            identities=[[i, 0, 0, 0] for i in range(17)], reports=reports,
            full_programs=16, tail_programs=1, full_batches_hash_ns=9 * (16 // width),
            tail_hash_ns=9, total_hash_ns=9 * len(reports)))
    return rows


def render(rows):
    return '\n'.join('CPU_IDENTITY_QUALIFICATION ' + json.dumps(row) for row in rows)


class QualificationTests(unittest.TestCase):
    def test_full_and_tail_hash_times_exclude_proof_time(self):
        result = validate(render(fixture()))
        self.assertFalse(result['complete_workflow_qualified'])
        self.assertEqual(result['independent_cpu_verified_proofs'], 2)

    def test_missing_or_misattributed_measurements_are_rejected(self):
        for key, value in [('full_programs', 17), ('tail_programs', 0),
                           ('full_batches_hash_ns', 1000), ('tail_hash_ns', 0),
                           ('total_hash_ns', 1000), ('total_hash_ns', True),
                           ('independent_cpu_verified_proofs', 0)]:
            rows = copy.deepcopy(fixture()); rows[-1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(render(rows))
        rows = fixture(); del rows[-1]['full_batches_hash_ns']
        with self.assertRaises(ValueError): validate(render(rows))
        with self.assertRaises(ValueError): validate(render(fixture()[:-1]))
