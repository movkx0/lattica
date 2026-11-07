import copy
import unittest
from cpu_commitment_campaign import proof_gates, screen_score


class CommitmentQualification(unittest.TestCase):
    def test_screen_requires_every_shape_and_rejects_local_regression(self):
        rows = [dict(commitment_path=p, height=1 << h, threads=t, width=w, matrices=n,
            commit_ns=100 if p == 'existing' else 90)
            for p in ('existing','packed') for h in (18,21) for t in (4,16)
            for w,n in ((94,1),(200,1),(51,1),(3,16))]
        self.assertTrue(screen_score(rows, 'packed')['eligible'])
        with self.assertRaises(RuntimeError): screen_score(rows[:-1], 'packed')
        rows[-1]['commit_ns'] = 104
        self.assertFalse(screen_score(rows, 'packed')['eligible'])

    def test_proof_gate_includes_preparation_every_family_and_batch_throughput(self):
        def record(jobs, wall):
            return dict(cpu_proof_acceptance=dict(records=[dict(jobs=jobs,wall_ns=wall)]))
        target = record([dict(comparisons=[dict(candidate=True,observation=dict(service_ns=59e9))])], 140e9)
        reference = record([dict(id=i,cold_input_service_upper_ns=40e9) for i in range(36)], 220e9)
        candidate = copy.deepcopy(reference)
        self.assertTrue(all(proof_gates([target],[reference],[candidate]).values()))
        target['cpu_proof_acceptance']['records'][0]['jobs'][0]['comparisons'][0]['observation']['service_ns']=60e9
        self.assertFalse(proof_gates([target],[reference],[candidate])['cold_recursive_under_60s'])
        candidate['cpu_proof_acceptance']['records'][0]['wall_ns']=221e9
        self.assertFalse(proof_gates([target],[reference],[candidate])['throughput_preserved'])
        for j in candidate['cpu_proof_acceptance']['records'][0]['jobs']:
            if j['id'] % 9 == 0: j['cold_input_service_upper_ns']=42e9
        self.assertFalse(proof_gates([target],[reference],[candidate])['no_family_regression_over_3pct'])


if __name__ == '__main__':
    unittest.main()
