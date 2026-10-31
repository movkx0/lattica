"""Pure policy tests; no process, project, OpenCL or proving entry is imported."""
import argparse
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'native_hashx_scratch_guard', Path(__file__).with_name('native_hashx_scratch_guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

ROOT = '/tmp/hashx-policy-source'
UUID = 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'
EXE = ROOT + '/target/release/deps/lattica_pq_ringct_research-recorded'


def args(mode='sequence', **changes):
    values = dict(profile='full', expect_tests=True, build_label='hashx-recorded-build',
                  expect_result=False, expect_direct_result=False, benchmark=False,
                  correctness_label=None, record_artifact=[], device_uuid=UUID,
                  owned_native_hashx_test=mode)
    values.update(changes)
    return argparse.Namespace(**values)


def command(mode='sequence'):
    return [EXE, guard.SELECTORS[mode], '--exact', '--ignored', '--test-threads=1', '--nocapture']


def environment(options=None, argv=None, base=None, tree='host', kernel='baseline'):
    options = options or args()
    return guard.build_environment(options, argv or command(options.owned_native_hashx_test),
                                   tree, kernel, base if base is not None else guard.expected_base(ROOT, UUID), ROOT)


def identities(mode='sequence'):
    env, receipt = environment(args(mode))
    plan = dict(profile='full', command=command(mode), expect_tests=True, expect_result=False,
                expect_direct_result=False, build_label='hashx-recorded-build', benchmark=False,
                memory_max_bytes=47 * guard.GIB, memory_high_bytes=45 * guard.GIB,
                fresh_memavailable_required_bytes=49 * guard.GIB, cpu_quota='800%',
                public_hash_kernel='baseline', environment=env, owned_native_hashx_environment=receipt)
    sources = {path: 'a' * 64 for path in guard.REQUIRED_SOURCES}
    executable = dict(path=EXE, resolved_path=EXE, sha256='b' * 64,
                      build_record=ROOT + '/.tools/pq-opencl-opt/runs/hashx-recorded-build.json',
                      build_record_sha256='c' * 64)
    plan['owned_native_hashx_binding'] = guard.bind_execution(plan, sources, executable, ROOT)
    return plan, sources, executable


def output(mode='sequence'):
    lines = ['running 1 test', 'test ' + guard.SELECTORS[mode] + ' ... ']
    if mode == 'sequence':
        for case in range(2):
            lines.append('hashx_original_scratch_component case=' + str(case)
                         + ' native=10 cpu_verified=20 original_pcs_host=1000000'
                         + ' peak_retained_children=10 retained_children=0 original_snapshots_equal=true whole_workflow=false')
            lines.append('hashx_original_scratch_terminal case=' + str(case)
                         + ' current_host=0 current_device=0 categories_zero=8')
    else:
        lines.append('hashx_original_scratch_rejection native=1 cpu_verified=1 rejected_next=2 '
                     'original_snapshots_equal=true whole_workflow=false')
        lines.append('hashx_original_scratch_terminal case=0 current_host=0 current_device=0 categories_zero=8')
    lines.extend(['ok', '', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 1.00s'])
    # libtest may place the first diagnostic immediately after its test prefix.
    return '\n'.join(lines).replace(' ... \n', ' ... ', 1) + '\n'


class EnvironmentPolicyTests(unittest.TestCase):
    def test_exact_modes_keep_original_profile_and_bounded_environment(self):
        for mode in guard.SELECTORS:
            env, receipt = environment(args(mode))
            self.assertEqual(env[guard.FLAG], '1')
            self.assertEqual(env['LATTICA_PROVING_POLICY'], 'gpu-required')
            self.assertEqual(env['LATTICA_GPU_DEVICE_UUID'], UUID)
            self.assertEqual(env['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'], 'host')
            self.assertEqual(env['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8 * guard.GIB))
            self.assertEqual(env['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * guard.GIB))
            self.assertEqual(env['RAYON_NUM_THREADS'], '8')
            self.assertEqual(receipt, guard.environment_receipt(env, mode))
            self.assertLessEqual(receipt['entry_count'], 64)
            self.assertLessEqual(receipt['serialized_bytes'], 8192)
            for field in ('dispatch_authority', 'physical_identity_verified', 'performance_qualified',
                          'prepared_artifact_reuse', 'complete_faithful_ringct_workflow'):
                self.assertIs(receipt[field], False)

    def test_other_profiles_and_mixed_modes_refuse(self):
        changes = [dict(profile=value) for value in (
            'build', 'source-preflight', 'research-compile', 'research-compile-large', 'smoke', 'direct-full')]
        changes += [dict(build_label=None), dict(build_label='../escape'), dict(expect_tests=False),
                    dict(expect_result=True), dict(expect_direct_result=True), dict(benchmark=True),
                    dict(correctness_label='old'), dict(record_artifact=[EXE]),
                    dict(direct_ring_recursion_census_label='old')]
        changes += [{key: True} for key in guard.EXCLUSIVE_MODES]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                environment(args(**change))

    def test_changed_or_inherited_environment_never_passes(self):
        base = guard.expected_base(ROOT, UUID)
        for name in base:
            changed = dict(base)
            changed[name] += 'x'
            with self.subTest(name=name), self.assertRaises(ValueError):
                environment(base=changed)
        for base in [dict(base, LD_PRELOAD='/tmp/foreign.so'), {}, dict(base, HOME='/other')]:
            with self.assertRaises(ValueError):
                environment(base=base)
        for uuid in [None, '', '0', 'GPU-invalid', UUID + '\0']:
            with self.subTest(uuid=uuid), self.assertRaises(ValueError):
                environment(args(device_uuid=uuid))
        for changes in [dict(tree='device'), dict(kernel='sbox-pair-v1')]:
            with self.assertRaises(ValueError):
                environment(**changes)

    def test_command_requires_exact_test_and_no_extra_flags(self):
        original = command()
        changes = [original + ['extra'], [EXE.replace('lattica_pq_ringct_research', 'lattica_prover_p3'), *original[1:]],
                   ['relative', *original[1:]], [EXE, guard.SELECTORS['reordered'], *original[2:]],
                   [EXE, 'other', *original[2:]]]
        for flag in original[2:]:
            changes.append([value for value in original if value != flag])
        changes.append([value.replace('--test-threads=1', '--test-threads=2') for value in original])
        for changed in changes:
            with self.subTest(command=changed), self.assertRaises(ValueError):
                environment(argv=changed)


class ExecutionBindingTests(unittest.TestCase):
    def test_manifest_and_recorded_executable_are_bound_without_authority(self):
        plan, sources, executable = identities()
        binding = guard.bind_execution(plan, sources, executable, ROOT)
        self.assertEqual(binding['source_count'], len(sources))
        self.assertEqual(binding['executable_sha256'], executable['sha256'])
        self.assertEqual(binding['selected_physical_device_uuid'], UUID)
        self.assertFalse(binding['dispatch_authority'])
        for key in guard.REQUIRED_SOURCES:
            changed = dict(sources)
            del changed[key]
            with self.subTest(source=key), self.assertRaises(ValueError):
                guard.bind_execution(plan, changed, executable, ROOT)
        altered = dict(sources)
        altered[next(iter(altered))] = 'd' * 64
        self.assertNotEqual(binding['source_manifest_sha256'],
                            guard.bind_execution(plan, altered, executable, ROOT)['source_manifest_sha256'])

    def test_changed_limits_environment_and_build_identity_refuse(self):
        plan, sources, executable = identities()
        for key in ('profile', 'memory_max_bytes', 'memory_high_bytes',
                    'fresh_memavailable_required_bytes', 'cpu_quota', 'build_label', 'public_hash_kernel'):
            changed = copy.deepcopy(plan)
            changed[key] = None
            with self.subTest(field=key), self.assertRaises(ValueError):
                guard.bind_execution(changed, sources, executable, ROOT)
        changed = copy.deepcopy(plan)
        changed['environment']['RAYON_NUM_THREADS'] = '9'
        with self.assertRaises(ValueError):
            guard.bind_execution(changed, sources, executable, ROOT)
        for key in executable:
            changed = dict(executable)
            del changed[key]
            with self.subTest(executable=key), self.assertRaises(ValueError):
                guard.bind_execution(plan, sources, changed, ROOT)
        for sources in [dict(sources, bad='no-hash'), {'../escape': 'a' * 64}]:
            with self.assertRaises(ValueError):
                guard.bind_execution(plan, sources, executable, ROOT)


class QualificationEvidenceTests(unittest.TestCase):
    def test_exact_sequence_and_reordered_evidence_have_separate_counts(self):
        for mode, native, verified in [('sequence', 20, 40), ('reordered', 1, 1)]:
            plan, _, _ = identities(mode)
            report = guard.validate_log(output(mode), plan)
            self.assertEqual(report['native_proofs'], native)
            self.assertEqual(report['independent_cpu_verifications'], verified)
            self.assertTrue(report['terminal_zero_claims'])
            self.assertFalse(report['complete_request_dispatch'])
            self.assertFalse(report['performance_qualified'])

    def test_missing_reordered_duplicate_and_overbudget_evidence_refuse(self):
        plan, _, _ = identities()
        original = output()
        variants = [original.replace('case=1', 'case=0'), original + original,
                    original.replace('current_host=0', 'current_host=1', 1),
                    original.replace('categories_zero=8', 'categories_zero=7', 1),
                    original.replace('native=10', 'native=9', 1),
                    original.replace('cpu_verified=20', 'cpu_verified=10', 1),
                    original.replace('peak_retained_children=10', 'peak_retained_children=9', 1),
                    original.replace('original_snapshots_equal=true', 'original_snapshots_equal=false', 1),
                    original.replace('whole_workflow=false', 'whole_workflow=true', 1),
                    original.replace('original_pcs_host=1000000', 'original_pcs_host=' + str(24 * guard.GIB + 1)),
                    original.replace('original_pcs_host=1000000', 'original_pcs_host=999999', 1),
                    original.replace('0 ignored', '1 ignored'),
                    original + 'hashx_original_scratch_unknown\n', original + 'panicked at fixture\n',
                    original + 'OPENCL_OPT_RESULT {}\n', output('reordered'),
                    original + 'test result: ok. 0 passed; 0 failed; 0 ignored;\n',
                    original + 'test result: ok. 2 passed; 0 failed; 0 ignored;\n',
                    'test result: ok. 1 passed; 0 failed;\n']
        lines = original.splitlines()
        variants.append('\n'.join(line for line in lines if 'terminal case=1' not in line))
        for changed in variants:
            with self.subTest(log=changed), self.assertRaises(ValueError):
                guard.validate_log(changed, plan)
        plan.pop('owned_native_hashx_binding')
        with self.assertRaises(ValueError):
            guard.validate_log(original, plan)


if __name__ == '__main__':
    unittest.main()
