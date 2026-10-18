import copy
import unittest
from coverage import require_gpu_stages


def report(cached=False):
    return dict(policy='gpu_required', succeeded=True, stage_coverage_complete=True,
                completion_rejected=False, observation_errors=0, entry_point='wrap',
                observations=[dict(stage=s, backend='open_cl', device_calls=1)
                              for s in ['witness', 'preprocessing']],
                components=[dict(scope=s, started=True, cached=cached, succeeded=True,
                                 stage_coverage_complete=True)
                            for s in ['registry_compilation', 'preprocessing']])


class CoverageTests(unittest.TestCase):
    def test_only_completed_public_reuse_with_a_prior_gpu_proof_is_accepted(self):
        stages = {'witness', 'preprocessing'}
        self.assertEqual(require_gpu_stages([report(), report(True)], stages)
                         ['proofs_with_public_compilation_cache_hits'], 1)
        with self.assertRaises(ValueError):
            require_gpu_stages([report(True)], stages)
        for mutate in [lambda r: r.update(entry_point='merge'),
                       lambda r: r['observations'].clear(),
                       lambda r: r['observations'].pop(),
                       lambda r: r.update(policy='cpu')]:
            bad = copy.deepcopy(report(True)); mutate(bad)
            with self.assertRaises(ValueError):
                require_gpu_stages([report(), bad], stages)


if __name__ == '__main__':
    unittest.main()
