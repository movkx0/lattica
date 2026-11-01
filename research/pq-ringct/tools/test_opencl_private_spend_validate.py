"""Correctness-runner policy tests; no compiler, prover or GPU is launched."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
import re
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('opt_validate', Path(__file__).with_name('opencl_private_spend_validate.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def arguments(**changes):
    values = dict(profile='build', label='policy-test', seconds=60,
                  command=['--', '/usr/bin/true'], expect_tests=False,
                  expect_result=False, execute=True, exclusive_window=True,
                  build_label=None, record_artifact=[])
    values.update(changes)
    return argparse.Namespace(**values)


class CorrectnessPolicyTests(unittest.TestCase):
    def test_callgraph_requires_exact_native_cpu_catalogue_and_reports_sampling_event(self):
        command = ['/tmp/lattica_pq_ringct_research-profile',
                   'component_tree::native_shape::profiling::tests::scaling::native_cpu_scaling_16',
                   '--exact', '--ignored', '--test-threads=1', '--nocapture']
        options = dict(profile='research-compile-large', expect_tests=True, build_label='native-build',
                       command=command, cpu_scaling_profile='native', cpu_scaling_workers=16,
                       cpu_scaling_callgraph=True)
        plan = runner.build_plan(arguments(**options))
        self.assertEqual(plan['cpu_scaling_profile']['events'], ['cycles:u'])
        self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'], 'cpu-required')
        for changed in [dict(cpu_scaling_profile=None), dict(cpu_scaling_profile='registered'),
                        dict(command=command[:1] + ['recursive_proof'] + command[2:])]:
            with self.assertRaises(ValueError):
                runner.build_plan(arguments(**{**options, **changed}))

    def test_cargo_test_artifacts_must_be_emitted_even_if_stale_file_exists(self):
        build = dict(command=['/tmp/cargo', 'test', '--release', '--lib', '--no-run'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current, stale = root / 'current-test', root / 'stale-test'
            current.write_bytes(b'new executable')
            stale.write_bytes(b'old executable')
            log = f'    Finished release profile in 0.01s\n  Executable unittests src/lib.rs ({current})\n'
            with patch.object(runner, 'ROOT', root):
                self.assertEqual(runner.require_cargo_test_artifacts(build, log, [current]),
                                 [str(current.resolve())])
                for content, requested in [(log, [stale]), (log, [current, stale]),
                                           ('Finished release profile\n', [current]),
                                           ('unrelated (' + str(current) + ')\n', [current])]:
                    with self.subTest(content=content, requested=requested), self.assertRaises(ValueError):
                        runner.require_cargo_test_artifacts(build, content, requested)
                for descriptor in ('unittests src/lib.rs', 'tests/verify_relation.rs',
                                   'benches/verify_relation.rs', 'unittests src/bin/prover.rs'):
                    emitted = f'  Executable {descriptor} ({current})\n'
                    with self.subTest(descriptor=descriptor):
                        self.assertEqual(runner.require_cargo_test_artifacts(build, emitted, [current]),
                                         [str(current.resolve())])
                relative = '  Executable unittests src/lib.rs (current-test)\n'
                self.assertEqual(runner.require_cargo_test_artifacts(build, relative, [current]),
                                 [str(current.resolve())])
                alias = root / 'alias'
                alias.symlink_to(current)
                self.assertEqual(runner.require_cargo_test_artifacts(build, relative, [alias]),
                                 [str(current.resolve())])

    def test_executable_provenance_rechecks_cargo_inventory_and_build_log_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'stale-test'
            binary.write_bytes(b'executable')
            binary.chmod(0o700)
            log = root / 'test-build.log'
            record_path = root / 'test-build.json'
            sources = {'source.rs': 'recorded source digest'}
            record = dict(status='passed', profile='build', source_inputs_unchanged=True,
                          all_subprocesses_terminal_and_reaped=True, input_sha256=sources,
                          built_artifact_sha256={str(binary): runner.sha(binary)},
                          raw_log=str(log), command=['/tmp/cargo', 'test', '--no-run'])
            plan = dict(command=[str(binary)], build_label='test-build')
            log.write_text(f'  Executable unittests src/lib.rs ({root / "new-test"})\n')
            record['raw_log_sha256'] = runner.sha(log)
            record_path.write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                runner.executable_provenance(plan, sources, root)
            log.write_text(f'  Executable unittests src/lib.rs ({binary})\n')
            with self.assertRaises(ValueError):
                runner.executable_provenance(plan, sources, root)
            record['raw_log_sha256'] = runner.sha(log)
            record_path.write_text(json.dumps(record))
            self.assertEqual(runner.executable_provenance(plan, sources, root)['sha256'],
                             runner.sha(binary))

    def request_source_arguments(self, mode, **changes):
        selector = runner.REQUEST_SOURCE_TESTS[mode][0]
        values = dict(profile='research-compile-large', expect_tests=True,
                      build_label='request-source-build', owned_request_source_test=mode,
                      command=['/tmp/lattica_pq_ringct_research-recorded', selector,
                               '--exact', '--ignored', '--test-threads=1', '--nocapture'])
        values.update(changes)
        return arguments(**values)

    def test_request_source_modes_keep_exact_cpu_environment_and_cannot_admit_requests(self):
        for mode, (selector, flag) in runner.REQUEST_SOURCE_TESTS.items():
            plan = runner.build_plan(self.request_source_arguments(mode))
            default = runner.build_plan(arguments(profile='research-compile-large'))
            self.assertEqual(plan['environment'], {**default['environment'], flag: '1'})
            for key in ('memory_max_bytes', 'memory_high_bytes',
                        'fresh_memavailable_required_bytes', 'cpu_quota'):
                self.assertEqual(plan[key], default[key])
            meta = plan['owned_request_source_environment']
            self.assertEqual(meta['selector'], selector)
            for key in ('gpu_dispatch', 'dispatch_authority', 'complete_request_admission',
                        'complete_faithful_ringct_workflow', 'performance_qualified'):
                self.assertFalse(meta[key])
            self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'], 'cpu-required')
            self.assertFalse(any('GPU' in key for key in plan['environment']))

    def test_request_source_modes_refuse_cross_selection_gpu_options_and_proving(self):
        for mode in runner.REQUEST_SOURCE_TESTS:
            original = self.request_source_arguments(mode).command
            changed = [dict(profile=p) for p in runner.PROFILES if p != 'research-compile-large']
            changed += [dict(build_label=None), dict(expect_tests=False), dict(expect_result=True),
                        dict(expect_direct_result=True), dict(retained_tree_storage='host'),
                        dict(public_hash_kernel='sbox-pair-v1'), dict(device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'),
                        dict(owned_source_shape_test=True), dict(active_hashx_preflight=True),
                        dict(owned_runtime_test='native-shake'), dict(note_workflow_cpu=True),
                        dict(direct_ring_screen=True), dict(direct_ring_identity_test='baseline'),
                        dict(command=original + ['extra']), dict(command=['/usr/bin/cargo', 'test']),
                        dict(command=[part for part in original if part != '--exact']),
                        dict(command=[part.replace('--test-threads=1', '--test-threads=2') for part in original])]
            for other, (selector, _) in runner.REQUEST_SOURCE_TESTS.items():
                if other != mode:
                    changed.append(dict(command=[original[0], selector, *original[2:]]))
            for changes in changed:
                with self.subTest(mode=mode, changes=changes), self.assertRaises(ValueError):
                    runner.build_plan(self.request_source_arguments(mode, **changes))

    def test_request_source_output_requires_exactly_one_test_and_no_proof_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.log'
            valid = 'test result: ok. 1 passed; 0 failed; 0 ignored; finished in 0.01s\n'
            for mode in runner.REQUEST_SOURCE_TESTS:
                path.write_text(valid)
                runner.validate_output(path, runner.build_plan(self.request_source_arguments(mode)))
                for bad in (valid.replace('1 passed', '2 passed'), valid + valid,
                            valid + 'PUBLIC_HASH_EXECUTION {}\n', valid + 'proving_stage_report {}\n',
                            valid + 'OPENCL_OPT_RESULT {}\n'):
                    path.write_text(bad)
                    with self.subTest(mode=mode, log=bad), self.assertRaises(ValueError):
                        runner.validate_output(path, runner.build_plan(self.request_source_arguments(mode)))

    def test_non_hashx_tests_still_require_public_hash_execution_evidence(self):
        def plan(kernel):
            return runner.build_plan(arguments(profile='full', expect_tests=True,
                                               build_label='hash-build', public_hash_kernel=kernel,
                                               command=['/tmp/recorded-hash-test']))
        evidence = dict(kernel='sbox-pair-v1', gpu_tuning_compiled=True, nvidia_supported=True)
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'test.log'
            passed = 'test result: ok. 1 passed; 0 failed;\n'
            log.write_text(passed)
            with self.assertRaises(ValueError):
                runner.validate_output(log, plan('sbox-pair-v1'))
            log.write_text(passed + 'PUBLIC_HASH_EXECUTION ' + json.dumps(evidence) + '\n')
            accepted = plan('sbox-pair-v1')
            runner.validate_output(log, accepted)
            self.assertEqual(accepted['public_hash_acceptance'], evidence)
            with self.assertRaises(ValueError):
                runner.validate_output(log, plan('baseline'))
            for field in ('gpu_tuning_compiled', 'nvidia_supported'):
                log.write_text(passed + 'PUBLIC_HASH_EXECUTION '
                               + json.dumps({**evidence, field: False}) + '\n')
                with self.subTest(field=field), self.assertRaises(ValueError):
                    runner.validate_output(log, plan('sbox-pair-v1'))

    def hashx_arguments(self, **changes):
        values = dict(profile='source-preflight', expect_tests=True, build_label='source-build',
                      device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c',
                      retained_tree_storage='host', active_hashx_preflight=True,
                      command=['/tmp/lattica_prover_p3-recorded', runner.ACTIVE_HASHX_PREFLIGHT_TEST,
                               '--exact', '--ignored', '--test-threads=1', '--nocapture'])
        values.update(changes)
        return arguments(**values)

    def test_hashx_preflight_preserves_modeled_limits_in_lower_source_only_envelope(self):
        plan = runner.build_plan(self.hashx_arguments())
        self.assertEqual((plan['memory_max_bytes'], plan['memory_high_bytes'],
                          plan['fresh_memavailable_required_bytes']),
                         (8 * runner.GIB, 6 * runner.GIB, 10 * runner.GIB))
        env = plan['environment']
        self.assertEqual(env['LATTICA_PROVING_POLICY'], 'gpu-required')
        for name, value in [('MANAGED', 8), ('CONTEXT', 4)]:
            self.assertEqual(env['LATTICA_V2_GPU_' + name + '_BYTES'], str(value * runner.GIB))
        self.assertEqual(env['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * runner.GIB))
        self.assertEqual(env['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8 * runner.GIB))
        self.assertEqual(env['LATTICA_OWNED_NATIVE_SHAKE_SHAPE_PREFLIGHT'], '1')
        self.assertNotIn('LATTICA_NATIVE_SPEND_QUALIFICATION', env)
        meta = plan['active_hashx_preflight_environment']
        self.assertFalse(meta['gpu_dispatch'])
        self.assertFalse(meta['dispatch_authority'])
        self.assertFalse(meta['complete_request_admission'])

    def test_hashx_preflight_refuses_other_commands_profiles_and_proving_modes(self):
        original = self.hashx_arguments().command
        changed = [dict(profile=p) for p in runner.PROFILES if p != 'source-preflight']
        changed += [dict(active_hashx_preflight=False), dict(build_label=None),
                    dict(device_uuid=None), dict(expect_tests=False), dict(expect_result=True),
                    dict(expect_direct_result=True), dict(retained_tree_storage='device'),
                    dict(public_hash_kernel='sbox-pair-v1'), dict(note_owned_proof=True),
                    dict(owned_runtime_test='native-shake'), dict(owned_source_shape_test=True),
                    dict(command=['/usr/bin/cargo', 'test']), dict(command=original + ['extra']),
                    dict(command=[original[0], 'other_test', *original[2:]]),
                    dict(command=[part for part in original if part != '--exact'])]
        for changes in changed:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.hashx_arguments(**changes))
        with self.assertRaises(ValueError):
            runner.build_plan(arguments(profile='source-preflight'))

    def hashx_log(self, refused=()):
        lines = ['active_hashx_source_preflight schema=1 scope=source_phase_only native_count=10 paired_group_count=5 input_bytes=16416 output_bytes=137 operation_host_bytes=25769803776 worker_host_bytes=34359738368 managed_device_bytes=8589934592 context_device_bytes=4294967296 native_host_ceiling_bytes=25769803776 max_rows=1048576 cryptographic_proof_started=false',
                 'active_hashx_source_preflight_startup Footprint { managed_device_bytes: 512 }']
        first = 0
        for i, count in enumerate((16,) * 7 + (8, 1, 1)):
            data = dict(rows=4096 * count, main_width=517 if count == 1 else 518,
                        maximum_quotient_chunks=32, maximum_matrices=34,
                        preopening_host_bytes=100, opening_workspace_host_bytes=100,
                        retained_metadata_host_bytes=100, opened_value_descriptors_host_bytes=100,
                        required_pcs_host_bytes=1000, operation_host_budget_bytes=24 * runner.GIB,
                        maintained_device_plan_complete='true', managed_phase_ceiling_bytes=8 * runner.GIB,
                        maintained_phase_peak_bytes=1 << 20, fresh_runtime_baseline_bytes=512,
                        source_allocation_ceiling_bytes=4 * runner.GIB, opening_device_peak_bytes=100,
                        fri_device_peak_bytes=100, query_device_peak_bytes=100,
                        minimum_opening_device_bytes=100, largest_opening_allocation_bytes=100,
                        retained_tree_storage_mode='HostBacking', selected_tree_host_quota_bytes=8 * runner.GIB,
                        required_tree_host_bytes=100, complete_native_dispatch_admission='false')
            footprint = 'NativeShakePcsFootprint { ' + ', '.join(f'{k}: {v}' for k, v in data.items()) + ' }'
            detail = (f'rows={4096 * count} width={517 if count == 1 else 518} admitted=false refusal=bounded source refusal'
                      if i in refused else 'admitted=true footprint=' + footprint)
            lines.append(f'active_hashx_source_preflight_shape index={i} first_permutation={first} permutations={count} {detail}')
            first += count
        category = 'CategoryCounters { current: Bytes { host: 0, device: 0 }, peak: Bytes { host: 1, device: 1 } }'
        terminal = ('Snapshot { allowance: WorkerAllowance { host: 34359738368, device: 8589934592 }, '
                    'current: Bytes { host: 0, device: 0 }, peak: Bytes { host: 34359738368, device: 8589934592 }, categories: ['
                    + ', '.join([category] * 8) + '] }')
        lines.append(f'active_hashx_source_preflight_terminal screened=10 admitted={10 - len(refused)} refused={len(refused)} phase_feasibility={str(not refused).lower()} complete_request_admission=false cryptographic_proof_started=false terminal={terminal}')
        lines.append('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 500 filtered out; finished in 0.01s')
        return '\n'.join(lines)

    def test_hashx_preflight_distinguishes_successful_screen_from_phase_feasibility(self):
        self.assertTrue(runner.validate_active_hashx_preflight(self.hashx_log())['phase_feasibility'])
        report = runner.validate_active_hashx_preflight(self.hashx_log((0, 1)))
        self.assertFalse(report['phase_feasibility'])
        self.assertEqual(report['refused'], 2)
        self.assertFalse(report['complete_request_admission'])

    def test_hashx_preflight_rejects_missing_reordered_inconsistent_or_live_claims(self):
        original = self.hashx_log()
        lines = original.splitlines()
        bad = ['\n'.join(lines[:3] + lines[4:]),
               '\n'.join(lines[:2] + [lines[3], lines[2]] + lines[4:]),
               '\n'.join(lines[:3] + [lines[-2]] + lines[3:-2] + [lines[-1]]),
               original + '\n' + lines[-2],
               original.replace('first_permutation=112', 'first_permutation=113'),
               original.replace('admitted=10 refused=0', 'admitted=9 refused=1'),
               original.replace('phase_feasibility=true', 'phase_feasibility=false'),
               original.replace('host: 0', 'host: 1'),
               original.replace('input_bytes=16416', 'input_bytes=16417'),
               original.replace('output_bytes=137', 'output_bytes=136'),
               original.replace('worker_host_bytes=34359738368', 'worker_host_bytes=34359738369'),
               original.replace('rows: 65536', 'rows: 32768'),
               original.replace('main_width: 518', 'main_width: 517'),
               original.replace('maximum_quotient_chunks: 32, ', ''),
               original.replace('maintained_device_plan_complete: true', 'maintained_device_plan_complete: false'),
               original.replace('complete_native_dispatch_admission: false', 'complete_native_dispatch_admission: true'),
               original.replace('maintained_phase_peak_bytes: 1048576', 'maintained_phase_peak_bytes: 8589934593'),
               original.replace('fresh_runtime_baseline_bytes: 512', 'fresh_runtime_baseline_bytes: 513'),
               original.replace('WorkerAllowance { host: 34359738368', 'WorkerAllowance { host: 34359738369'),
               original.replace('CategoryCounters {', 'MissingCategory {', 1),
               original.replace('cryptographic_proof_started=false', 'cryptographic_proof_started=true')]
        empty = re.sub(r'footprint=NativeShakePcsFootprint \{ [^}]+ \}',
                       'footprint=NativeShakePcsFootprint {}', original)
        bad.append(empty)
        for marker in ('PUBLIC_HASH_EXECUTION {}', 'proving_stage_report {}', 'OPENCL_OPT_RESULT {}'):
            bad.append(original + '\n' + marker)
        for log in bad:
            with self.subTest(log=log), self.assertRaises(ValueError):
                runner.validate_active_hashx_preflight(log)


    def note_arguments(self, **changes):
        values = dict(profile='full', expect_tests=True, build_label='owned-note-build',
                      device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c',
                      note_owned_proof=True,
                      command=['/tmp/lattica_prover_p3-recorded', runner.NOTE_OWNED_TEST,
                               '--exact', '--ignored', '--test-threads=1', '--nocapture'])
        values.update(changes)
        return arguments(**values)

    def test_owned_note_environment_is_exact_and_preserves_the_process_envelope(self):
        selected = runner.build_plan(self.note_arguments())
        default = runner.build_plan(arguments(profile='full'))
        for key in ['memory_max_bytes', 'memory_high_bytes', 'fresh_memavailable_required_bytes',
                    'cpu_quota', 'profile']:
            self.assertEqual(selected[key], default[key])
        environment = selected['environment']
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * runner.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_PIPELINE'], '0')
        self.assertEqual(environment['RAYON_NUM_THREADS'], '8')
        self.assertNotIn('LATTICA_NATIVE_SPEND_QUALIFICATION', environment)
        self.assertNotIn('LATTICA_V2_GPU_LDE_WORKSPACE_BYTES', environment)
        self.assertEqual(selected['note_startup_environment']['entry_count'], len(environment))
        self.assertFalse(selected['note_startup_environment']['dispatch_authority'])
        self.assertIsNone(default['note_startup_environment'])
        self.assertFalse(selected['performance_qualified'])
        direct = runner.build_plan(self.note_arguments(profile='direct-full'))
        self.assertEqual(direct['environment'], environment)
        self.assertEqual(direct['memory_max_bytes'], 45 * runner.GIB)
        self.assertEqual(direct['memory_high_bytes'], 43 * runner.GIB)
        self.assertEqual(direct['fresh_memavailable_required_bytes'], 47 * runner.GIB)
        self.assertEqual(direct['cpu_quota'], selected['cpu_quota'])

    def test_owned_note_environment_refuses_other_tests_profiles_and_selectors(self):
        original = self.note_arguments().command
        changes = [dict(profile=profile) for profile in ['build', 'smoke', 'research-compile-large']]
        changes += [dict(build_label=None), dict(device_uuid=None), dict(expect_tests=False),
                    dict(retained_tree_storage='host'), dict(public_hash_kernel='sbox-pair-v1'),
                    dict(command=['/usr/bin/cargo', 'test']),
                    dict(command=original + ['another_test']),
                    dict(command=[original[0], 'another_test', *original[2:]]),
                    dict(command=[word for word in original if word != '--exact']),
                    dict(command=[word.replace('--test-threads=1', '--test-threads=2')
                                  for word in original])]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                runner.build_plan(self.note_arguments(**changed))

    def test_owned_note_research_selectors_are_exact_and_keep_the_same_envelope(self):
        original = self.note_arguments().command
        baseline = runner.build_plan(self.note_arguments())
        for selector in [runner.NOTE_HANDOFF_TEST, runner.NOTE_WORKFLOW_TEST]:
            argv = ['/tmp/lattica_pq_direct_spend_research-recorded', selector,
                    *original[2:]]
            plan = runner.build_plan(self.note_arguments(command=argv))
            self.assertEqual(plan['environment'], baseline['environment'])
            for key in ['memory_max_bytes', 'memory_high_bytes',
                        'fresh_memavailable_required_bytes', 'cpu_quota']:
                self.assertEqual(plan[key], baseline[key])
            rejected = [[original[0], *argv[1:]], [argv[0], *original[1:]],
                        argv + ['extra'],
                        [word for word in argv if word != '--exact'],
                        [word.replace('--test-threads=1', '--test-threads=2')
                         for word in argv]]
            for wrong in rejected:
                with self.subTest(command=wrong), self.assertRaises(ValueError):
                    runner.build_plan(self.note_arguments(command=wrong))

    def cpu_note_arguments(self, **changes):
        values = dict(profile='direct-full', expect_tests=True, build_label='owned-note-build',
                      note_workflow_cpu=True,
                      command=['/tmp/lattica_pq_direct_spend_research-recorded',
                               runner.NOTE_CPU_WORKFLOW_TEST, '--exact', '--ignored',
                               '--test-threads=1', '--nocapture'])
        values.update(changes)
        return arguments(**values)

    def test_cpu_note_workflow_keeps_limits_and_requires_cpu_proving(self):
        cpu = runner.build_plan(self.cpu_note_arguments())
        gpu = runner.build_plan(self.note_arguments(profile='direct-full'))
        for key in ['memory_max_bytes', 'memory_high_bytes',
                    'fresh_memavailable_required_bytes', 'cpu_quota', 'profile']:
            self.assertEqual(cpu[key], gpu[key])
        environment = cpu['environment']
        self.assertEqual(environment['RAYON_NUM_THREADS'], '8')
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertEqual(set(environment), {'PATH', 'HOME', 'CARGO_HOME', 'CARGO_TARGET_DIR',
                                          'CARGO_BUILD_JOBS', 'RAYON_NUM_THREADS',
                                          'LATTICA_PROVING_POLICY', 'LATTICA_PROVING_REPORT'})
        self.assertEqual(cpu['note_cpu_environment']['entry_count'], len(environment))
        self.assertFalse(cpu['note_cpu_environment']['dispatch_authority'])
        self.assertIsNone(cpu['note_startup_environment'])
        self.assertIsNone(cpu['owned_runtime_environment'])
        self.assertFalse(cpu['performance_qualified'])

    def test_cpu_note_workflow_rejects_gpu_or_inexact_modes(self):
        original = self.cpu_note_arguments().command
        rejected = [dict(profile='build'), dict(profile='smoke'), dict(build_label=None),
                    dict(expect_tests=False), dict(note_owned_proof=True),
                    dict(device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'),
                    dict(retained_tree_storage='host'), dict(public_hash_kernel='sbox-pair-v1'),
                    dict(command=original + ['extra']),
                    dict(command=[original[0], runner.NOTE_WORKFLOW_TEST, *original[2:]]),
                    dict(command=['/tmp/lattica_prover_p3-recorded', *original[1:]]),
                    dict(command=[x for x in original if x != '--exact']),
                    dict(command=[x.replace('--test-threads=1', '--test-threads=2') for x in original])]
        for changes in rejected:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.cpu_note_arguments(**changes))

    def runtime_arguments(self, selector='runtime', **changes):
        executable = ('/tmp/lattica_prover_p3-recorded' if selector == 'native-shake-rejection'
                      else '/tmp/lattica_pq_ringct_research-recorded')
        values = dict(profile='direct-full', expect_tests=True, build_label='owned-runtime-build',
                      device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c',
                      owned_runtime_test=selector,
                      retained_tree_storage='host' if selector in ('outer', 'native-shake-host', 'native-shake-continuation', 'native-shake-continuation-rejection', 'native-to-outer', 'outer-continuation', 'native-pair-sequence', 'native-odd-tail-sequence') else 'device',
                      command=[executable,
                               runner.OWNED_RUNTIME_TESTS[selector], '--exact', '--ignored',
                               '--test-threads=1', '--nocapture'])
        values.update(changes)
        return arguments(**values)

    def test_native_sequence_selectors_require_exact_isolated_host_gpu_profile(self):
        pair, tail = 'native-pair-sequence', 'native-odd-tail-sequence'
        for selector, other in ((pair, tail), (tail, pair)):
            args = self.runtime_arguments(selector)
            original = list(args.command)
            for changes in (
                dict(profile='build'), dict(profile='smoke'),
                dict(expect_tests=False), dict(build_label=None), dict(device_uuid=None),
                dict(retained_tree_storage='device'), dict(public_hash_kernel='sbox-pair-v1'),
                dict(note_owned_proof=True), dict(direct_ring_screen=True),
                dict(direct_ring_identity_test='receipt-v1'),
                dict(command=[original[0], runner.OWNED_RUNTIME_TESTS[other], *original[2:]]),
                dict(command=original + ['--skip', 'anything']),
            ):
                with self.subTest(selector=selector, changes=changes), self.assertRaises(ValueError):
                    runner.build_plan(self.runtime_arguments(selector, **changes))

    def test_owned_runtime_selectors_preserve_the_fixed_envelope(self):
        base = runner.build_plan(self.note_arguments(profile='direct-full'))
        for selector in runner.OWNED_RUNTIME_TESTS:
            with self.subTest(selector=selector):
                plan = runner.build_plan(self.runtime_arguments(selector))
                expected = dict(base['environment'])
                if selector == 'outer':
                    expected['LATTICA_OWNED_OUTER_QUALIFICATION'] = '1'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * runner.GIB)
                if selector == 'native-shake-host':
                    expected['LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION'] = '1'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * runner.GIB)
                if selector == 'native-shake-continuation':
                    expected['LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_QUALIFICATION'] = '1'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * runner.GIB)
                if selector == 'native-shake-continuation-rejection':
                    expected['LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_REJECTION_QUALIFICATION'] = '1'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * runner.GIB)
                sequence_flags = {
                    'native-pair-sequence': 'LATTICA_OWNED_SHAKE_PAIR_SEQUENCE_QUALIFICATION',
                    'native-odd-tail-sequence': 'LATTICA_OWNED_SHAKE_ODD_TAIL_SEQUENCE_QUALIFICATION',
                }
                if selector in sequence_flags:
                    expected[sequence_flags[selector]] = '1'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * runner.GIB)
                if selector == 'outer-continuation':
                    expected['LATTICA_OWNED_SHAKE_OUTER_RETIREMENT_QUALIFICATION'] = '1'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * runner.GIB)
                if selector == 'native-to-outer':
                    expected['LATTICA_OWNED_SHAKE_OUTER_CONTINUATION_QUALIFICATION'] = '1'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'host'
                    expected['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(8 * runner.GIB)
                if selector == 'native-shake':
                    expected['LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION'] = '1'
                if selector == 'native-shake-rejection':
                    expected['LATTICA_OWNED_NATIVE_SHAKE_REJECTION_QUALIFICATION'] = '1'
                self.assertEqual(plan['environment'], expected)
                for key in ['memory_max_bytes', 'memory_high_bytes',
                            'fresh_memavailable_required_bytes', 'cpu_quota']:
                    self.assertEqual(plan[key], base[key])
                self.assertEqual(plan['owned_runtime_environment']['entry_count'], len(expected))
                self.assertEqual(plan['owned_runtime_environment']['selector'], selector)
                self.assertFalse(plan['owned_runtime_environment']['dispatch_authority'])
                self.assertIsNone(plan['note_startup_environment'])

    def test_owned_runtime_environment_refuses_selector_or_policy_drift(self):
        original = self.runtime_arguments().command
        changes = [dict(profile=p) for p in ['build', 'smoke', 'research-compile-large']]
        changes += [dict(build_label=None), dict(device_uuid=None), dict(expect_tests=False),
                    dict(note_owned_proof=True), dict(owned_runtime_test='unknown'),
                    dict(retained_tree_storage='host'), dict(public_hash_kernel='sbox-pair-v1'),
                    dict(command=original + ['extra']),
                    dict(command=['/tmp/lattica_prover_p3-recorded', *original[1:]]),
                    dict(command=[original[0], runner.OWNED_RUNTIME_TESTS['outer'], *original[2:]]),
                    dict(command=[x for x in original if x != '--exact'])]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(**changed))

    def test_outer_host_tree_policy_cannot_select_device_or_escape_exact_worker(self):
        plan = runner.build_plan(self.runtime_arguments('outer'))
        environment = plan['environment']
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'], 'host')
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8 * runner.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * runner.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_CONTEXT_BYTES'], str(4 * runner.GIB))
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * runner.GIB))
        original = self.runtime_arguments('outer').command
        for changes in [dict(retained_tree_storage='device'), dict(build_label=None),
                        dict(public_hash_kernel='sbox-pair-v1'), dict(profile='smoke'),
                        dict(note_owned_proof=True), dict(command=original + ['extra']),
                        dict(command=[original[0], runner.OWNED_RUNTIME_TESTS['runtime'], *original[2:]])]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments('outer', **changes))
        for selector in ['runtime', 'raw-error', 'raw-graph', 'raw-differential',
                         'native-shake', 'native-shake-rejection']:
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(selector, retained_tree_storage='host'))

    def test_native_shake_mode_requires_its_exact_worker_and_device_tree_profile(self):
        plan = runner.build_plan(self.runtime_arguments('native-shake'))
        environment = plan['environment']
        self.assertEqual(environment['LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION'], '1')
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'], 'device')
        self.assertNotIn('LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES', environment)
        self.assertNotIn('LATTICA_OWNED_OUTER_QUALIFICATION', environment)
        self.assertIsNone(plan['note_startup_environment'])
        self.assertIsNone(plan['note_cpu_environment'])
        original = self.runtime_arguments('native-shake').command
        for changes in [dict(retained_tree_storage='host'), dict(build_label=None),
                        dict(device_uuid=None), dict(public_hash_kernel='sbox-pair-v1'),
                        dict(profile='smoke'), dict(expect_tests=False),
                        dict(note_owned_proof=True), dict(note_workflow_cpu=True),
                        dict(command=original + ['extra']),
                        dict(command=[word for word in original if word != '--exact']),
                        dict(command=[word.replace('--test-threads=1', '--test-threads=2')
                                      for word in original])]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments('native-shake', **changes))
        for selector in runner.OWNED_RUNTIME_TESTS:
            if selector == 'native-shake':
                continue
            changed = [original[0], runner.OWNED_RUNTIME_TESTS[selector], *original[2:]]
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments('native-shake', command=changed))
            other = runner.build_plan(self.runtime_arguments(selector))
            self.assertNotIn('LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION', other['environment'])

    def test_native_host_requires_exact_host_worker_and_original_limits(self):
        args = self.runtime_arguments('native-shake-host')
        plan = runner.build_plan(args)
        environment = plan['environment']
        self.assertEqual(environment['LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION'], '1')
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * runner.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8 * runner.GIB))
        self.assertNotIn('LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION', environment)
        self.assertNotIn('LATTICA_OWNED_OUTER_QUALIFICATION', environment)
        for changes in [dict(retained_tree_storage='device'), dict(build_label=None),
                        dict(device_uuid=None), dict(public_hash_kernel='sbox-pair-v1'),
                        dict(note_owned_proof=True), dict(note_workflow_cpu=True),
                        dict(direct_ring_screen=True), dict(profile='build'),
                        dict(command=args.command + ['extra']),
                        dict(command=[word for word in args.command if word != '--ignored'])]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments('native-shake-host', **changes))
        for selector in runner.OWNED_RUNTIME_TESTS:
            if selector == 'native-shake-host':
                continue
            changed = [args.command[0], runner.OWNED_RUNTIME_TESTS[selector], *args.command[2:]]
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments('native-shake-host', command=changed))
            other = runner.build_plan(self.runtime_arguments(selector))
            self.assertNotIn('LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION', other['environment'])

    def test_owned_native_continuation_is_exact_host_profile_and_isolated(self):
        selector = 'native-shake-continuation'
        args = self.runtime_arguments(selector)
        plan = runner.build_plan(args)
        environment = plan['environment']
        flag = 'LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_QUALIFICATION'
        self.assertEqual(environment[flag], '1')
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * runner.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'], 'host')
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8 * runner.GIB))
        for other in ('LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION',
                      'LATTICA_OWNED_OUTER_QUALIFICATION'):
            self.assertNotIn(other, environment)
        for changes in [dict(profile='build'), dict(profile='smoke'), dict(build_label=None),
                        dict(expect_tests=False), dict(note_owned_proof=True),
                        dict(device_uuid=None), dict(retained_tree_storage='device'),
                        dict(public_hash_kernel='sbox-pair-v1'),
                        dict(command=args.command + ['extra']),
                        dict(command=[w for w in args.command if w != '--exact']),
                        dict(command=[w for w in args.command if w != '--ignored']),
                        dict(command=[w.replace('--test-threads=1', '--test-threads=2')
                                      for w in args.command])]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(selector, **changes))
        for other in runner.OWNED_RUNTIME_TESTS:
            if other == selector:
                continue
            changed = [args.command[0], runner.OWNED_RUNTIME_TESTS[other], *args.command[2:]]
            with self.subTest(other=other), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(selector, command=changed))
            self.assertNotIn(flag, runner.build_plan(self.runtime_arguments(other))['environment'])

    def test_owned_native_continuation_rejection_is_exact_and_separate(self):
        selector = 'native-shake-continuation-rejection'
        args = self.runtime_arguments(selector)
        plan = runner.build_plan(args)
        environment = plan['environment']
        flag = 'LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_REJECTION_QUALIFICATION'
        self.assertEqual(environment[flag], '1')
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * runner.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'], 'host')
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8 * runner.GIB))
        for other in ('LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_QUALIFICATION',
                      'LATTICA_OWNED_OUTER_QUALIFICATION'):
            self.assertNotIn(other, environment)
        for changes in [dict(profile='build'), dict(profile='smoke'), dict(build_label=None),
                        dict(expect_tests=False), dict(note_owned_proof=True),
                        dict(device_uuid=None), dict(retained_tree_storage='device'),
                        dict(public_hash_kernel='sbox-pair-v1'),
                        dict(command=args.command + ['extra']),
                        dict(command=[w for w in args.command if w != '--exact']),
                        dict(command=[w for w in args.command if w != '--ignored']),
                        dict(command=[w.replace('--test-threads=1', '--test-threads=2')
                                      for w in args.command])]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(selector, **changes))
        for other in runner.OWNED_RUNTIME_TESTS:
            if other == selector:
                continue
            changed = [args.command[0], runner.OWNED_RUNTIME_TESTS[other], *args.command[2:]]
            with self.subTest(other=other), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(selector, command=changed))
            self.assertNotIn(flag, runner.build_plan(self.runtime_arguments(other))['environment'])

    def test_native_to_outer_is_exact_host_component_and_isolated(self):
        selector = 'native-to-outer'
        args = self.runtime_arguments(selector)
        plan = runner.build_plan(args)
        environment = plan['environment']
        flag = 'LATTICA_OWNED_SHAKE_OUTER_CONTINUATION_QUALIFICATION'
        self.assertEqual(environment[flag], '1')
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * runner.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'], 'host')
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8 * runner.GIB))
        for other in ('LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_REJECTION_QUALIFICATION',
                      'LATTICA_OWNED_OUTER_QUALIFICATION'):
            self.assertNotIn(other, environment)
        for changes in [dict(profile='build'), dict(profile='smoke'), dict(build_label=None),
                        dict(expect_tests=False), dict(note_owned_proof=True),
                        dict(device_uuid=None), dict(retained_tree_storage='device'),
                        dict(public_hash_kernel='sbox-pair-v1'),
                        dict(command=args.command + ['extra']),
                        dict(command=[w for w in args.command if w != '--exact']),
                        dict(command=[w for w in args.command if w != '--ignored']),
                        dict(command=[w.replace('--test-threads=1', '--test-threads=2')
                                      for w in args.command])]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(selector, **changes))
        for other in runner.OWNED_RUNTIME_TESTS:
            if other == selector:
                continue
            changed = [args.command[0], runner.OWNED_RUNTIME_TESTS[other], *args.command[2:]]
            with self.subTest(other=other), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(selector, command=changed))
            self.assertNotIn(flag, runner.build_plan(self.runtime_arguments(other))['environment'])

    def test_outer_continuation_is_exact_retirement_only_component(self):
        selector = 'outer-continuation'
        args = self.runtime_arguments(selector)
        plan = runner.build_plan(args)
        environment = plan['environment']
        flag = 'LATTICA_OWNED_SHAKE_OUTER_RETIREMENT_QUALIFICATION'
        self.assertEqual(environment[flag], '1')
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * runner.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'], 'host')
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8 * runner.GIB))
        for other in ('LATTICA_OWNED_SHAKE_OUTER_CONTINUATION_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_QUALIFICATION',
                      'LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_REJECTION_QUALIFICATION',
                      'LATTICA_OWNED_OUTER_QUALIFICATION'):
            self.assertNotIn(other, environment)
        for changes in [dict(profile='build'), dict(profile='smoke'), dict(build_label=None),
                        dict(expect_tests=False), dict(note_owned_proof=True),
                        dict(device_uuid=None), dict(retained_tree_storage='device'),
                        dict(public_hash_kernel='sbox-pair-v1'),
                        dict(command=args.command + ['extra']),
                        dict(command=[w for w in args.command if w != '--exact']),
                        dict(command=[w for w in args.command if w != '--ignored']),
                        dict(command=[w.replace('--test-threads=1', '--test-threads=2')
                                      for w in args.command])]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(selector, **changes))
        for other in runner.OWNED_RUNTIME_TESTS:
            if other == selector:
                continue
            changed = [args.command[0], runner.OWNED_RUNTIME_TESTS[other], *args.command[2:]]
            with self.subTest(other=other), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments(selector, command=changed))
            self.assertNotIn(flag, runner.build_plan(self.runtime_arguments(other))['environment'])

    def test_native_rejection_requires_exact_core_worker_and_its_own_flag(self):
        plan = runner.build_plan(self.runtime_arguments('native-shake-rejection'))
        environment = plan['environment']
        self.assertEqual(environment['LATTICA_OWNED_NATIVE_SHAKE_REJECTION_QUALIFICATION'], '1')
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(environment['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'], 'device')
        self.assertNotIn('LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES', environment)
        self.assertNotIn('LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION', environment)
        self.assertNotIn('LATTICA_OWNED_OUTER_QUALIFICATION', environment)
        original = self.runtime_arguments('native-shake-rejection').command
        for changes in [dict(retained_tree_storage='host'), dict(build_label=None),
                        dict(device_uuid=None), dict(public_hash_kernel='sbox-pair-v1'),
                        dict(profile='smoke'), dict(expect_tests=False),
                        dict(note_owned_proof=True), dict(note_workflow_cpu=True),
                        dict(command=original + ['extra']),
                        dict(command=['/tmp/lattica_pq_ringct_research-recorded', *original[1:]]),
                        dict(command=[word for word in original if word != '--exact']),
                        dict(command=[word.replace('--test-threads=1', '--test-threads=2')
                                      for word in original])]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments('native-shake-rejection', **changes))
        for selector in runner.OWNED_RUNTIME_TESTS:
            if selector == 'native-shake-rejection':
                continue
            changed = [original[0], runner.OWNED_RUNTIME_TESTS[selector], *original[2:]]
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                runner.build_plan(self.runtime_arguments('native-shake-rejection', command=changed))
            other = runner.build_plan(self.runtime_arguments(selector))
            self.assertNotIn('LATTICA_OWNED_NATIVE_SHAKE_REJECTION_QUALIFICATION', other['environment'])

    def test_physical_uuid_pin_is_explicit_canonical_and_gpu_only(self):
        uuid = 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'
        default = runner.build_plan(arguments(profile='full'))
        self.assertNotIn('LATTICA_GPU_DEVICE_UUID', default['environment'])
        pinned = runner.build_plan(arguments(profile='full', device_uuid=uuid))
        self.assertEqual(pinned['environment']['LATTICA_GPU_DEVICE_UUID'], uuid)
        for key in ['memory_max_bytes', 'memory_high_bytes', 'fresh_memavailable_required_bytes',
                    'cpu_quota', 'profile']:
            self.assertEqual(pinned[key], default[key])
        for profile in runner.CPU_PROFILES:
            with self.subTest(profile=profile), self.assertRaisesRegex(ValueError, 'GPU profile'):
                runner.build_plan(arguments(profile=profile, device_uuid=uuid))
        for invalid in ['', uuid + '\n', uuid + '\0', uuid.lower(), uuid[:-1], 7]:
            with self.subTest(uuid=invalid), self.assertRaisesRegex(ValueError, 'GPU UUID'):
                runner.build_plan(arguments(profile='full', device_uuid=invalid))

    def result(self):
        family = dict(reads=0, hits=0, bypasses=1, proof_attempts=1, fresh_proofs=1)
        case = dict(count=3, fresh_distinct_transactions=3, complete_graphs_verified=3,
                    statement_digests=[[1], [2], [3]], changed_public_rejected_count=25,
                    changed_proof_rejected=True, distinct_reordering_rejected=True,
                    distinct_substitution_rejected=True, graph_proof_substitution_rejected=True,
                    decoded_verification_after_gpu_shutdown=True, merges=[dict(backend='opencl',
                        strict_gpu_request=True, native_parent_verification=True, cache_policy='fresh_only',
                        proof_cache_hit=False, aggregate_children=n,
                        recursive_witness_checks=[dict(altered_opening_rejected=True)] * n) for n in [0, 1]],
                    cache=dict(policy='fresh_only', families={name: family.copy() for name in
                         ['sources', 'algebra', 'crypto', 'auxiliary', 'outer']}))
        return dict(schema='pq-opencl-opt-correctness-v2', passed=True, comparison_baseline=False,
                    proving_scope='native_private_spend_and_native_recursive_stark_proving', fixture_generation='cpu_ring_ask_inputs_only', native_private_spend_generation='gpu_required',
                    independent_verification='cpu', native_gpu_required=True, witness_preparation='gpu_required',
                    performance_qualified=False, fixture_pattern='fresh_distinct', original_profile=True,
                    hiding=True, num_queries=128, blowup=16, extension='Goldilocks cubic trinomial',
                    context=dict(session_closed=True, prepared_entries=0, maximum_prepared_entries=1,
                        metadata_cache_payload_bytes=1024, session_finish=dict(commits=3, allocations=3,
                        managed_peak_bytes=runner.GIB)), cases=[case])

    def test_results_require_fresh_work_tamper_checks_and_session_cleanup(self):
        result = self.result()
        runner.validate_result(result)
        mutations = [
            lambda r: r['context'].update(session_closed=False),
            lambda r: r['context'].update(metadata_cache_payload_bytes=(64 << 20) + 1),
            lambda r: r['cases'][0]['cache']['families']['sources'].update(reads=1),
            lambda r: r['cases'][0]['cache']['families']['outer'].update(proof_attempts=2),
            lambda r: r['cases'][0]['cache']['families']['auxiliary'].update(proof_attempts=0, fresh_proofs=0),
            lambda r: r['cases'][0].update(changed_public_rejected_count=24),
            lambda r: r['cases'][0].update(statement_digests=[[1], [1], [2]]),
            lambda r: r['cases'][0].update(decoded_verification_after_gpu_shutdown=False),
            lambda r: r.update(num_queries=64),
            lambda r: r['cases'][0]['merges'][1].update(recursive_witness_checks=[]),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(result)
            mutate(changed)
            with self.assertRaises(ValueError):
                runner.validate_result(changed)

    def test_resource_profiles_preserve_separate_host_and_device_limits(self):
        for profile, expected in [('build', (8, 6, 10)), ('research-compile', (16, 14, 20)),
                                  ('research-compile-large', (32, 30, 36)),
                                  ('smoke', (16, 14, 20)), ('full', (47, 45, 49))]:
            plan = runner.build_plan(arguments(profile=profile))
            self.assertEqual(tuple(plan[key] // runner.GIB for key in
                                   ['memory_max_bytes', 'memory_high_bytes', 'fresh_memavailable_required_bytes']), expected)
            self.assertFalse(plan['comparison_baseline'])
            self.assertFalse(plan['performance_qualified'])
            if profile not in runner.CPU_PROFILES:
                self.assertEqual(plan['environment']['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * runner.GIB))
                self.assertEqual(plan['environment']['LATTICA_V2_GPU_CONTEXT_BYTES'], str(4 * runner.GIB))
                self.assertEqual(plan['environment']['LATTICA_V2_QUOTIENT_FUSION'], '1')

    def test_larger_research_compiler_keeps_cpu_policy_and_two_threads(self):
        for profile in runner.RESEARCH_CPU_PROFILES:
            with self.subTest(profile=profile):
                plan = runner.build_plan(arguments(profile=profile, expect_tests=True,
                                                   command=['/usr/bin/cargo', 'test']))
                environment = plan['environment']
                self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'cpu-required')
                self.assertEqual(environment['CARGO_BUILD_JOBS'], '2')
                self.assertEqual(environment['RAYON_NUM_THREADS'], '2')
                self.assertEqual(plan['cpu_quota'], '200%')
                self.assertNotIn('LATTICA_NATIVE_SPEND_QUALIFICATION', environment)
                self.assertFalse(any(key.startswith('LATTICA_V2_GPU_') for key in environment))
                with self.assertRaisesRegex(ValueError, 'CPU-only'):
                    runner.build_plan(arguments(profile=profile, expect_result=True,
                                                build_label='build-test'))
                with self.assertRaisesRegex(ValueError, 'runtime exceeds'):
                    runner.build_plan(arguments(profile=profile, seconds=7201))

    def test_admission_arguments_are_bounded(self):
        for changes in [dict(label='../escape'), dict(command=['cargo']), dict(command=[]),
                        dict(seconds=0), dict(seconds=7201), dict(expect_tests=True, expect_result=True)]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.build_plan(arguments(**changes))
        runner.build_plan(arguments(profile='full', seconds=86400))
        with self.assertRaises(ValueError):
            runner.build_plan(arguments(profile='full', seconds=86401))

    def test_plan_does_not_inspect_or_launch_workloads(self):
        with patch.object(runner.sys, 'argv', ['validate', '--profile', 'full', '--label', 'dry', '--', '/usr/bin/true']), \
             patch.object(runner, 'admission_helpers', side_effect=AssertionError('planning inspected host')), \
             patch.object(runner, 'command', side_effect=AssertionError('planning launched command')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(), 0)
        self.assertFalse(json.loads(output.getvalue())['launch'])

    def simulate(self, *, launch_failure=False, source_changed=False, reap_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state'
            args = arguments()
            plan = runner.build_plan(args)
            helper = types.SimpleNamespace(available=lambda: 100 * runner.GIB,
                                           conflicting_processes=lambda: {'conflicts': [], 'protected_non_workers': []})
            terminal = {'MainPID': '0', 'SubState': 'exited', 'Result': 'success',
                        'ExecMainCode': '1', 'ExecMainStatus': '0',
                        'MemoryMax': str(8 * runner.GIB), 'MemoryHigh': str(6 * runner.GIB), 'MemorySwapMax': '0'}
            after = {'LoadState': 'loaded', 'MainPID': '1', 'ControlPID': '0'} if reap_failure else {'LoadState': 'not-found'}
            states = [{'LoadState': 'not-found'}] + ([] if launch_failure else [terminal]) + [after]
            def invoke(argv):
                failed = launch_failure and argv[0] == '/usr/bin/systemd-run'
                if argv[0] == '/usr/bin/systemd-run' and not failed:
                    (state / 'runs/policy-test.log').write_text('')
                return types.SimpleNamespace(returncode=int(failed), stderr='simulated launch failure' if failed else '', stdout='')
            manifests = [{'source': 'old'}, {'source': 'new' if source_changed else 'old'}]
            with patch.object(runner, 'ROOT', root), patch.object(runner, 'STATE', state), \
                 patch.object(runner, 'admission_helpers', return_value=helper), \
                 patch.object(runner, 'systemd_state', side_effect=states), \
                 patch.object(runner, 'command', side_effect=invoke), \
                 patch.object(runner, 'source_manifest', side_effect=manifests), \
                 patch.object(runner.signal, 'signal'), contextlib.redirect_stdout(io.StringIO()):
                code = runner.execute(args, plan)
            saved = json.loads((state / 'runs/policy-test.json').read_text())
            return code, saved

    def test_success_requires_cleanup_and_preserved_sources(self):
        code, record = self.simulate()
        self.assertEqual(code, 0)
        self.assertTrue(record['all_subprocesses_terminal_and_reaped'])
        self.assertTrue(record['source_inputs_unchanged'])
        self.assertFalse(record['performance_qualified'])

    def test_launch_failure_is_recorded_and_cleanup_attempted(self):
        code, record = self.simulate(launch_failure=True)
        self.assertEqual(code, 1)
        self.assertTrue(record['service_stop_completed'])
        self.assertIn('launch failed', record['error'])

    def test_mutated_sources_or_unreaped_processes_cannot_pass(self):
        for changes in [dict(source_changed=True), dict(reap_failure=True)]:
            with self.subTest(changes=changes):
                code, record = self.simulate(**changes)
                self.assertEqual(code, 1)
                self.assertEqual(record['status'], 'failed_or_incomplete')


if __name__ == '__main__':
    unittest.main()
