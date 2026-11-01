"""Pure guard/receipt checks; synthetic records are not performance evidence."""
import copy
import json
import unittest
from unittest.mock import patch

import opencl_private_spend_validate as runner
from test_opencl_private_spend_validate import arguments
from metadata_cpu_qualification import validate


class MetadataQualificationTests(unittest.TestCase):
    def test_exact_cpu_only_test_preserves_memory_and_rayon_settings(self):
        command = ['/tmp/metadata-test',
            'block_v2::machine::verifier::batch::shape::metadata_planning::tests::metadata_cpu_worker_qualification',
            '--exact', '--ignored', '--test-threads=1', '--nocapture']
        with patch.object(runner, 'identity_physical_cpus', return_value=list(range(16))):
            args = arguments(profile='research-compile-large', expect_tests=True,
                             metadata_cpu_qualification=True, command=command, build_label='build')
            plan = runner.build_plan(args)
            self.assertEqual(plan['cpu_quota'], '1600%')
            self.assertEqual(plan['memory_max_bytes'], 32 << 30)
            self.assertEqual(plan['environment']['RAYON_NUM_THREADS'], '2')
            self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'], 'cpu-required')
            self.assertNotIn('LATTICA_V2_GPU_MANAGED_BYTES', plan['environment'])
            args.command = command[:1] + ['another-test'] + command[2:]
            with self.assertRaises(ValueError): runner.build_plan(args)
            args.command = command
            args.profile = 'full'
            with self.assertRaises(ValueError): runner.build_plan(args)
        with patch.object(runner, 'identity_physical_cpus', return_value=list(range(8))):
            args.profile = 'research-compile-large'
            with self.assertRaises(ValueError): runner.build_plan(args)

    def fixture(self):
        count = dict(shapes=72, all_counts_equal=True, materialized_ns=100,
            counted_ns=90, materialized_peak_bytes=100, counted_peak_bytes=40, gpu_used=False)
        rows = []
        for width in (1, 2, 4, 8, 16):
            effective = min(width, 4)
            rows.append(dict(workers=width, shapes=72, counts_equal=True, gpu_used=False,
                cold_ns=100, warm_ns=1, original_host_bytes=1000,
                planning=dict(worker_ceiling=width, peak_active_workers=effective, largest_cohort=effective,
                    envelopes=4, heights_completed=72, jobs_started=72, cohorts=72 // effective,
                    budget_reductions=0, failed_envelopes=0, admitted_host_bytes_peak=1000,
                    wall_ns=90, worker_elapsed_ns=200, symbolic_preparations=4,
                    shared_symbolic_bytes_peak=128, worker_auxiliary_bytes_peak=16),
                cache=dict(hits=4, misses=4, entries=4, evictions=0, failed_computations=0,
                           planning_ns=100, reserved_host_bytes=1 << 20)))
        return count, rows

    @staticmethod
    def content(count, rows):
        tables = '\nMETADATA_TABLE_IDENTITY ' + json.dumps(dict(source_digest=[1]*32, profile_id=[2]*32, signature=[1]*12, available=False))
        tables += ''.join('\nMETADATA_TABLE_ROW ' + json.dumps(dict(public_values=p, log_height=h, values=[1]*9))
                          for p in (25, 28, 38, 46) for h in range(3, 21))
        return tables + '\nMETADATA_COUNTING_QUALIFICATION ' + json.dumps(count) + '\n' + '\n'.join(
            'METADATA_CPU_QUALIFICATION ' + json.dumps(row) for row in rows)

    def test_rejects_missing_parity_gpu_work_unadmitted_memory_and_forged_concurrency(self):
        count, rows = self.fixture()
        self.assertFalse(validate(self.content(count, rows))['complete_workflow_speedup_claimed'])
        for key, value in [('peak_active_workers', 17), ('heights_completed', 71),
                           ('failed_envelopes', 1), ('admitted_host_bytes_peak', 1001),
                           ('worker_ceiling', True)]:
            bad = copy.deepcopy(rows); bad[-1]['planning'][key] = value
            with self.assertRaises(ValueError): validate(self.content(count, bad))
        for key, value in [('counts_equal', False), ('gpu_used', True), ('workers', True)]:
            bad = copy.deepcopy(rows); bad[-1][key] = value
            with self.assertRaises(ValueError): validate(self.content(count, bad))
        with self.assertRaises(ValueError): validate(self.content(count, rows[:-1]))
        count['all_counts_equal'] = False
        with self.assertRaises(ValueError): validate(self.content(count, rows))

    def test_first_table_record_may_follow_the_libtest_prefix(self):
        count, rows = self.fixture()
        content = self.content(count, rows).replace('METADATA_TABLE_IDENTITY ',
            'test qualification ... METADATA_TABLE_IDENTITY ')
        self.assertEqual(len(validate(content)['tables']['rows']), 72)
