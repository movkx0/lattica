import unittest
from unittest.mock import patch

import cpu_build_target as target
import opencl_private_spend_validate as guard
from test_opencl_private_spend_validate import arguments


class CpuBuildTargetTests(unittest.TestCase):
    def test_requires_the_complete_isa_on_each_processor(self):
        supported = 'flags : ' + ' '.join(sorted(target.REQUIRED | {'abm'})) + '\n'
        target.check(target.TARGET, machine='x86_64', cpuinfo=supported * 16)
        target.check(target.TARGET, machine='x86_64', cpuinfo=supported.replace('abm', 'lzcnt'))
        for machine, content in [('aarch64', supported), ('x86_64', ''),
                                 ('x86_64', supported + supported.replace('avx2', '')),
                                 ('x86_64', supported.replace('abm', ''))]:
            with self.assertRaises(ValueError):
                target.check(target.TARGET, machine=machine, cpuinfo=content)
        with self.assertRaises(ValueError):
            target.check('native', machine='x86_64', cpuinfo=supported)

    @patch.object(target, 'check')
    def test_target_is_a_recorded_build_control_and_default_is_unchanged(self, check):
        defaults = guard.build_plan(arguments(profile='build', command=['/tmp/cargo', 'build', '--release']))
        self.assertNotIn('RUSTFLAGS', defaults['environment'])
        self.assertIsNone(defaults['build_cpu_target'])
        for command in (['/tmp/cargo', 'build', '--release'], ['/tmp/cargo', 'test', '--release', '--no-run']):
            plan = guard.build_plan(arguments(profile='build', command=command, build_cpu_target=target.TARGET))
            self.assertEqual(plan['environment']['RUSTFLAGS'], '-C target-cpu=x86-64-v3')
            self.assertEqual(plan['build_cpu_target'], target.TARGET)
        check.assert_called_with(target.TARGET)

    @patch.object(target, 'check')
    def test_runtime_jobs_and_unrecorded_test_execution_cannot_select_a_build_target(self, _):
        for profile, command in [('full', ['/tmp/test']), ('build', ['/tmp/test']),
                                 ('build', ['cargo', 'test', '--release'])]:
            with self.assertRaises(ValueError):
                target.configure(target.TARGET, profile, command, {})


if __name__ == '__main__':
    unittest.main()
