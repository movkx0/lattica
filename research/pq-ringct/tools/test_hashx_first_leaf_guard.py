"""Synthetic policy/receipt tests only; these fixtures are not actual proofs."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


guard = module('hashx_first_leaf_guard')
native = module('native_sequence_report')
ROOT = '/tmp/first-leaf-policy-source'
UUID = 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'
EXE = ROOT + '/target/release/deps/lattica_pq_ringct_research-recorded'


def arguments(mode='capacity', **changes):
    values = dict(profile='full' if mode == 'gpu' else 'research-compile-large',
                  expect_tests=True, build_label='first-leaf-recorded',
                  owned_hashx_leaf_test=mode, device_uuid=UUID if mode == 'gpu' else None)
    values.update(changes)
    return argparse.Namespace(**values)


def command(mode):
    return [EXE, guard.SELECTORS[mode], '--exact', '--ignored', '--test-threads=1', '--nocapture']


def environment(options):
    mode = options.owned_hashx_leaf_test
    base = guard.expected_environment(mode, ROOT, UUID if mode == 'gpu' else None)
    if mode == 'gpu':
        base.pop(guard.FLAG)
        base.pop('LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES')
        base['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    return guard.build_environment(options, command(mode), 'host' if mode == 'gpu' else 'device',
                                   'baseline', base, ROOT)


def identities(mode):
    env, note = environment(arguments(mode))
    maximum, high, admission, quota = (47, 45, 49, '800%') if mode == 'gpu' else (32, 30, 36, '200%')
    plan = dict(profile='full' if mode == 'gpu' else 'research-compile-large', command=command(mode),
                expect_tests=True, build_label='first-leaf-recorded', benchmark=False,
                memory_max_bytes=maximum * guard.GIB, memory_high_bytes=high * guard.GIB,
                fresh_memavailable_required_bytes=admission * guard.GIB, cpu_quota=quota,
                public_hash_kernel='baseline', environment=env, owned_hashx_leaf_environment=note)
    sources = {name: 'a' * 64 for name in guard.REQUIRED_SOURCES}
    executable = dict(path=EXE, resolved_path=EXE, sha256='b' * 64,
                      build_record=ROOT + '/.tools/pq-opencl-opt/runs/first-leaf-recorded.json',
                      build_record_sha256='c' * 64)
    plan['owned_hashx_leaf_binding'] = guard.bind_execution(plan, sources, executable, ROOT)
    return plan, sources, executable


def wire_receipt(entry):
    scope, stages = native.CONTRACTS[entry]
    return dict(schema='lattica-proving-stages-v1', entry_point=entry, policy='gpu_required',
                succeeded=True, stage_coverage_complete=True, completion_rejected=False,
                observation_errors=0, components=[], elapsed_ns=10,
                capabilities=dict(scope=scope, profile='block_v2_cubic', max_log_fri_arity=1,
                                  stages=[dict(stage=s, backend='open_cl') for s in sorted(stages)]),
                observations=[dict(stage=s, backend='open_cl', calls=1, completed_calls=1,
                                   device_calls=1, device_ns=1, inclusive_ns=2) for s in sorted(stages)])


def marker(name, values):
    def word(value):
        return str(value).lower() if type(value) is bool else str(value)
    return 'ringct_hashx_first_leaf_' + name + ' ' + ' '.join(k + '=' + word(v) for k, v in values.items())


def output(mode):
    gib = guard.GIB
    lines = ['running 1 test', 'test ' + guard.SELECTORS[mode] + ' ... ']
    lines.append(marker('source_claims', dict(native_outputs=10, native_attachments=10,
        retained_leaf_sources=5, compiler_claims=1, acceptance_claims=1, mutation_claims=1,
        host_bytes=1000, device_bytes=0, mode=mode, native_dispatch_started=False,
        complete_request_admitted=False)))
    if mode == 'capacity':
        lines.append(marker('capacity_complete', dict(native_proofs=0, recursive_proofs=0,
            original_claims_host_bytes=1000, startup_host_bytes=8 * gib, startup_device_bytes=1024,
            phase_wrappers_host_bytes=1000, phase_wrappers_device_bytes=0,
            pcs_host_bytes=24 * gib - 2000, pcs_device_bytes=8 * gib - 1024,
            simultaneous_host_bytes=32 * gib, simultaneous_device_bytes=8 * gib,
            projection_ns=5, source_preissue_ns=20, wrong_request_and_ledger_refused=True,
            original_claims_preserved=True, physical_backend_fit=False,
            native_dispatch_started=False, complete_ringct_workflow=False)))
    else:
        lines.append(marker('preissued', dict(native_proofs_expected=10, recursive_proofs_expected=1,
            source_preissue_ns=5, host_bytes=32 * gib, device_bytes=8 * gib,
            wrong_request_and_ledger_refused=True, native_dispatch_started=False,
            complete_request_admitted=False)))
        entries = ['ringct_owned_native_shake'] * 10 + ['block_v2_preprocessing', 'block_v2_registered_program']
        lines.extend('proving_stage_report ' + json.dumps(wire_receipt(entry)) for entry in entries)
        lines.append(marker('complete', dict(native_proofs=10, recursive_proofs=1, recursive_parent_proofs=0,
            active_rows=63, padded_rows=64, wires=90, input_values=20, compiler_ns=7,
            setup_ns=10, proving_ns=10, output_cpu_verification_ns=3, source_cpu_verification_ns=2,
            mutation_rejections=2, component_including_mutations_ns=200, source_key_authenticated=True,
            transaction_context_authenticated=False, complete_ringct_workflow=False)))
    lines.append(marker('terminal', dict(original_quota_released=True, current_host_bytes=0,
        current_device_bytes=0, peak_host_bytes=32 * gib, peak_device_bytes=8 * gib,
        component_wall_ns=250, component_success=True, mode=mode, complete_ringct_workflow=False)))
    lines.extend(['ok', '', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 50 filtered out; finished in 1.00s'])
    return '\n'.join(lines).replace(' ... \n', ' ... ', 1) + '\n'


class FirstLeafGuardTests(unittest.TestCase):
    def test_main_plan_hooks_use_exact_isolated_environment(self):
        runner = module('opencl_private_spend_validate')
        for mode in guard.SELECTORS:
            options = arguments(mode, label='first-leaf-hook', seconds=60,
                expect_result=False, expect_direct_result=False,
                execute=True, exclusive_window=True, record_artifact=[],
                retained_tree_storage='host' if mode == 'gpu' else 'device',
                public_hash_kernel='baseline', command=command(mode))
            with self.subTest(mode=mode):
                plan = runner.build_plan(options)
                expected = guard.expected_environment(mode, str(runner.ROOT),
                    UUID if mode == 'gpu' else None)
                self.assertEqual(plan['environment'], expected)
                self.assertEqual(plan['owned_hashx_leaf_environment'],
                    guard.receipt(expected, mode))
                self.assertEqual(plan['command'], command(mode))

    def test_exact_modes_bind_original_sources_and_keep_scope(self):
        for mode in guard.SELECTORS:
            plan, _, _ = identities(mode)
            report = guard.validate_log(output(mode), plan, native.receipt)
            self.assertFalse(report['complete_ringct_workflow'])
            self.assertEqual(report['native_proofs'], 10 if mode == 'gpu' else 0)
            self.assertEqual(report['recursive_proofs'], 1 if mode == 'gpu' else 0)
            if mode == 'capacity':
                self.assertFalse(report['physical_backend_fit'])

    def test_profiles_modes_and_identity_refuse_before_launch(self):
        for mode in guard.SELECTORS:
            changes = [dict(profile='build'), dict(profile='direct-full'), dict(build_label=None),
                       dict(expect_tests=False), dict(expect_result=True), dict(benchmark=True),
                       dict(record_artifact=[EXE])]
            changes += [{name: True} for name in guard.EXCLUSIVE]
            changes += [dict(device_uuid=None if mode == 'gpu' else UUID)]
            for change in changes:
                with self.subTest(mode=mode, change=change), self.assertRaises(ValueError):
                    environment(arguments(mode, **change))
            plan, sources, executable = identities(mode)
            for field, value in [('memory_max_bytes', 99 * guard.GIB), ('cpu_quota', '1600%'),
                                 ('profile', 'build'), ('command', command(mode) + ['--skip', 'x'])]:
                changed = copy.deepcopy(plan)
                changed[field] = value
                with self.subTest(mode=mode, field=field), self.assertRaises(ValueError):
                    guard.bind_execution(changed, sources, executable, ROOT)
            for path in guard.REQUIRED_SOURCES:
                changed = dict(sources)
                del changed[path]
                with self.subTest(path=path), self.assertRaises(ValueError):
                    guard.bind_execution(plan, changed, executable, ROOT)

    def test_missing_duplicate_failed_terminal_and_wrong_types_refuse(self):
        for mode in guard.SELECTORS:
            plan, _, _ = identities(mode)
            valid = output(mode)
            mutations = [valid.replace('component_success=true', 'component_success=false'),
                         valid.replace('current_host_bytes=0', 'current_host_bytes=1'),
                         valid.replace('original_quota_released=true', 'original_quota_released=false'),
                         valid.replace('native_outputs=10', 'native_outputs=true'),
                         valid.replace('mutation_claims=1', 'mutation_claims=0'),
                         valid.replace('complete_ringct_workflow=false', 'complete_ringct_workflow=true'),
                         valid.replace('host_bytes=1000', 'host_bytes=1000 extra=1', 1),
                         valid + 'thread panicked at synthetic fixture\n',
                         valid.replace('1 passed; 0 failed', '0 passed; 1 failed')]
            terminal = next(line for line in valid.splitlines() if line.startswith('ringct_hashx_first_leaf_terminal'))
            mutations += [valid.replace(terminal, ''), valid.replace(terminal, terminal + '\n' + terminal)]
            for index, changed in enumerate(mutations):
                with self.subTest(mode=mode, mutation=index), self.assertRaises(ValueError):
                    guard.validate_log(changed, plan, native.receipt)

    def test_capacity_does_not_accept_physical_or_proving_evidence(self):
        plan, _, _ = identities('capacity')
        valid = output('capacity')
        mutations = [valid.replace('physical_backend_fit=false', 'physical_backend_fit=true'),
                     valid.replace('native_proofs=0', 'native_proofs=1'),
                     valid.replace('original_claims_host_bytes=1000', 'original_claims_host_bytes=1001'),
                     valid.replace('simultaneous_host_bytes=' + str(32 * guard.GIB), 'simultaneous_host_bytes=1'),
                     valid + 'proving_stage_report ' + json.dumps(wire_receipt('ringct_owned_native_shake')) + '\n']
        for changed in mutations:
            with self.assertRaises(ValueError):
                guard.validate_log(changed, plan, native.receipt)

    def test_gpu_requires_all_strict_receipts_geometry_and_enclosing_timing(self):
        plan, _, _ = identities('gpu')
        valid = output('gpu')
        mutations = [valid.replace('mutation_rejections=2', 'mutation_rejections=1'),
                     valid.replace('padded_rows=64', 'padded_rows=65'),
                     valid.replace('setup_ns=10', 'setup_ns=11'),
                     valid.replace('component_including_mutations_ns=200', 'component_including_mutations_ns=5'),
                     valid.replace('"policy": "gpu_required"', '"policy": "cpu_required"', 1),
                     valid.replace('"device_calls": 1', '"device_calls": 0', 1),
                     valid.replace('"succeeded": true', '"succeeded": true, "succeeded": true', 1)]
        first = next(line for line in valid.splitlines() if line.startswith('proving_stage_report '))
        mutations += [valid.replace(first + '\n', '', 1), valid.replace(first, first + '\n' + first, 1)]
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                guard.validate_log(changed, plan, native.receipt)


if __name__ == '__main__':
    unittest.main()
