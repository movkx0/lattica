"""Resource selection tests; no service or GPU launched."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_opencl_private_spend_validate import arguments
import opencl_private_spend_validate as runner

class CpuGuardTests(unittest.TestCase):
    def test_smt_siblings_do_not_increase_worker_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for cpu in range(32):
                topology = root / f'cpu{cpu}' / 'topology'; topology.mkdir(parents=True)
                (topology / 'physical_package_id').write_text('0')
                (topology / 'core_id').write_text(str(cpu % 16))
            self.assertEqual(runner.identity_physical_cpus(range(32), root), list(range(16)))
            self.assertEqual(runner.identity_physical_cpus([1, 17, 18], root), [1, 18])
    def test_dedicated_identity_budget_preserves_gpu_host_threads_and_memory(self):
        command = ['/tmp/identity-test', 'identity_preprocessing_screen::cpu_recursive_identity_worker_qualification',
                   '--exact', '--ignored', '--test-threads=1', '--nocapture']
        with patch.object(runner, 'identity_physical_cpus', return_value=list(range(16))):
            plan = runner.build_plan(arguments(profile='full', expect_tests=True, identity_cpu_qualification=True,
                                               command=command, build_label='build'))
        self.assertEqual(plan['cpu_quota'], '1600%')
        self.assertEqual(plan['environment']['RAYON_NUM_THREADS'], '8')
        self.assertEqual(plan['memory_max_bytes'], 47 << 30)
        self.assertEqual(plan['identity_physical_cpus'], list(range(16)))
        ordinary = runner.build_plan(arguments(profile='full'))
        self.assertEqual(ordinary['cpu_quota'], '800%')
        self.assertIsNone(ordinary['identity_physical_cpus'])
        with patch.object(runner, 'identity_physical_cpus', return_value=list(range(8))), self.assertRaises(ValueError):
            runner.build_plan(arguments(profile='full', expect_tests=True, identity_cpu_qualification=True,
                                        command=command, build_label='build'))
