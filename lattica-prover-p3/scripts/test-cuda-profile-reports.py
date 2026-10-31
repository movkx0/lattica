#!/usr/bin/env python3
import copy
import importlib
import unittest

A = importlib.import_module('analyze-cuda-profile')
B = importlib.import_module('bench-cuda-recursive')
C = importlib.import_module('report-cuda-comparison')


class ProfileReportTests(unittest.TestCase):
    def report(self):
        rows=[]
        for count in (4,8):
            for index in range(1,6):
                for arm, seconds in [('base',100),('candidate',95)]:
                    rows.append(dict(status='passed', instrumented=False, phase='measured', arm=arm,
                        count=count,index=index,cpu_root_audit_passed=True,workers_retired=True,
                        fresh_recursive_proofs=count,seed_proofs=0,block_capacity=128,memory_event_deltas={'max':0},
                        whole_launcher_seconds=seconds+5,proof_observations_seconds=seconds))
        return dict(status='passed',instrumented=False,trials=rows)

    def test_overlap_is_counted_once_for_gpu_activity(self):
        self.assertEqual(A.union_ns([(1,5),(2,3),(4,7),(7,8),(11,13)]),9)
        self.assertEqual(A.union_ns([]),0)

    def test_memory_peaks_use_the_selected_backend(self):
        log = ('typed_cuda_memory {"peak_bytes":72}\n'
               '{"event":"typed_gpu_work_complete","backend":"cuda","cuda":{"peak_bytes":80}}\n'
               'managed_peak_bytes=99\n')
        self.assertEqual(B.managed_gpu_peak(log, 'cuda'), 80)
        self.assertEqual(B.managed_gpu_peak(log, 'opencl'), 99)

    def test_missing_memory_peaks_are_unknown_not_zero(self):
        self.assertIsNone(B.managed_gpu_peak('unrelated log\n', 'cuda'))
        rows = self.report()['trials']
        for row in rows:
            row.update(managed_gpu_peak_bytes=None, worker_accounting={'memory.peak':'1'})
        self.assertTrue(all(r['managed_gpu_peak_bytes'] is None
                            for r in B.summarize(rows, ['base','candidate'], [4,8])))

    def test_invalid_cuda_memory_peak_is_rejected(self):
        for peak in ('-1', 'true', '"80"'):
            with self.subTest(peak=peak), self.assertRaises(ValueError):
                B.managed_gpu_peak('typed_cuda_memory {"peak_bytes":'+peak+'}\n', 'cuda')

    def test_correct_improvement_qualifies_and_issuance_is_excluded(self):
        result=C.compare(self.report(),'base','candidate')
        self.assertTrue(result['qualified'])
        self.assertEqual(result['workloads'][0]['candidate_aggregation_equivalent_user_transactions_per_hour'],108)

    def test_regression_on_either_size_rejects_candidate(self):
        report=self.report()
        for row in report['trials']:
            if row['count']==8 and row['arm']=='candidate': row['whole_launcher_seconds']=109
        self.assertFalse(C.compare(report,'base','candidate')['qualified'])

    def test_bad_or_instrumented_sample_cannot_qualify(self):
        for change in ({'instrumented':True},{'cpu_root_audit_passed':False},{'workers_retired':False},
                       {'memory_event_deltas':{'max':1}},{'proof_observations_seconds':float('nan')}):
            report=self.report()
            report['trials'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                C.compare(report,'base','candidate')

    def test_incomplete_or_duplicate_pairs_rejected(self):
        for duplicate in (False,True):
            report=self.report()
            if duplicate: report['trials'].append(copy.deepcopy(report['trials'][0]))
            else: report['trials'].pop()
            with self.assertRaises(ValueError): C.compare(report,'base','candidate')


if __name__=='__main__': unittest.main()
