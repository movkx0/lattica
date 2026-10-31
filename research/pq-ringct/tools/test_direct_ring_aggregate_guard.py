"""Synthetic audit-policy mutations only; never generate or validate real proofs."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import direct_ring_aggregate_guard as guard
from test_direct_ring_screen_guard import arguments, runner
from test_opencl_private_spend_direct import complete_footprint, native


def args(**changes):
    value = dict(direct_ring_screen=False, direct_ring_aggregate=True,
                 command=['/tmp/lattica_pq_direct_spend_research-recorded', guard.SELECTOR,
                          '--exact', '--ignored', '--test-threads=1', '--nocapture'])
    value.update(changes)
    return arguments(**value)


class CompleteAggregateGuardTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        state = patch.object(runner, 'STATE', self.root)
        state.start()
        self.addCleanup(state.stop)

    def plan(self):
        value = runner.build_plan(args())
        value['observation_before_validation_ns'] = 6000
        return value

    def test_exact_mode_keeps_all_original_limits(self):
        selected = self.plan()
        baseline = runner.build_plan(args(direct_ring_aggregate=False))
        for key in ('memory_max_bytes', 'memory_high_bytes', 'fresh_memavailable_required_bytes',
                    'cpu_quota', 'profile'):
            self.assertEqual(selected[key], baseline[key])
        guard.plan_contract(selected)
        self.assertIsNone(baseline['direct_ring_aggregate_environment'])
        self.assertNotIn('LATTICA_DIRECT_RING_AGGREGATE_QUALIFICATION', baseline['environment'])

    def test_other_selectors_modes_and_envelopes_refuse_before_dispatch(self):
        for changed in (dict(profile='full'), dict(profile='build'), dict(profile='smoke'),
                dict(build_label=None), dict(device_uuid=None), dict(expect_tests=False),
                dict(public_hash_kernel='sbox-pair-v1'), dict(retained_tree_storage='device'),
                dict(direct_ring_screen=True), dict(note_owned_proof=True),
                dict(direct_ring_recursion_test='outer'), dict(benchmark=True)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                runner.build_plan(args(**changed))
        original = args().command
        for command in ([original[0], 'wrong', *original[2:]],
                [original[0], *original[2:]], ['/usr/bin/cargo', *original[1:]],
                [*original, '--exact'], [item.replace('--test-threads=1', '--test-threads=2') for item in original]):
            with self.subTest(command=command), self.assertRaises(ValueError):
                runner.build_plan(args(command=command))

    def test_fresh_path_and_source_path_bound(self):
        destination = self.root / 'artifacts' / args().label
        destination.parent.mkdir()
        destination.symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError):
            self.plan()
        destination.unlink()
        with patch.object(runner, 'STATE', self.root / ('a' * 200) / ('b' * 200)), self.assertRaises(ValueError):
            self.plan()

    def fixture(self):
        plan = self.plan()
        directory = Path(plan['direct_ring_aggregate_environment']['output_directory'])
        directory.mkdir(parents=True)
        uuid = list(bytes.fromhex(plan['environment']['LATTICA_GPU_DEVICE_UUID'][4:].replace('-', '')))
        reports, cases, blobs = [], [], {}
        for n, start in ((3, 0), (4, 3)):
            name = 'N' + str(n)
            retained = (4 << 20) + n * 30000 + (n + 1) * (128 << 20)
            active = 32 * guard.GIB - retained
            storage = dict(worker_host_bytes=32 * guard.GIB, device_bytes=8 * guard.GIB,
                context_reserve_bytes=4 * guard.GIB, native_host_ceiling_bytes=24 * guard.GIB,
                caller_reserved_bytes=4 << 20, expected_statement_bytes=n * 10000,
                native_witness_bytes=n * 20000, verifier_lifecycle_bytes_each=64 << 20,
                verifier_slots=n + 1, proof_slots=n + 1, proof_bytes_each=64 << 20,
                all_retained_reservation_bytes=retained, active_host_partition_bytes=active)
            order = ([('expected_child_source', i) for i in range(n)]
                     + [('fresh_whole_transaction_proof', i) for i in range(n)]
                     + [('fresh_fixed_aggregate_proof', None)]
                     + [('final_independent_child_source', i) for i in range(n)]
                     + [('final_independent_root_source', None)])
            phases = []
            for kind, index in order:
                fresh = kind.startswith('fresh_')
                identity = 20 + n if index is None else start + index + 1
                desc = dict(active_rows=7, padded_rows=8, wires=12, witness_values=6,
                    canonical_manifest_digest=[identity] * 32, registered_program_id=[identity, 2, 3, 4])
                footprint = complete_footprint()
                inputs = ((1 << 20) if index is None else (1 << 24) - 4) * 8
                native_host = min(24 * guard.GIB, active - inputs - (1 << 20) - 8 * guard.GIB)
                backend = native_host - (2 << 20)
                footprint.update(input_backing_host_bytes=inputs, physical_device_uuid=uuid,
                    worker_host_limit_bytes=active, native_host_budget_bytes=native_host,
                    backend_host_budget_bytes=backend, pcs_host_budget_bytes=backend - 1000,
                    worker_committed_host_bytes=native_host + inputs + (1 << 20) + 8 * guard.GIB,
                    host_phase_peak_bytes=footprint['backend_host_phase_peak_bytes'] + (3 << 20) + inputs + 8 * guard.GIB)
                phases.append(dict(kind=kind, child_index=index, fresh_proof=fresh, descriptor=desc,
                    footprint=footprint, registration=native(), proving=native(True) if fresh else None,
                    public_hash=dict(kernel='baseline', gpu_tuning_compiled=False, nvidia_supported=True),
                    terminal=dict(host_allowance_bytes=32 * guard.GIB, device_allowance_bytes=8 * guard.GIB,
                        gpu_context_allowance_bytes=4 * guard.GIB, max_rows=1 << 20, commits=1, allocations=1,
                        managed_peak_bytes=2048, uploaded_bytes=1, downloaded_bytes=1,
                        context_closed=True, queue_drained=True, completion_claimed=fresh),
                    setup_ns=2, proving_ns=3 if fresh else 0, teardown_ns=1, total_ns=10))
            report = dict(schema='lattica-research-direct-ring-fixed-aggregate-v1',
                scope='complete owned direct-ring N3/N4 research aggregation', selection=name,
                proof_generation='FreshOnly', fresh_whole_transaction_proofs=n, fresh_recursive_aggregate_proofs=1,
                independent_child_cpu_acceptances=n, independent_final_cpu_acceptances=1,
                public_mutation_rejections=4 * (n + 1), opening_mutation_rejections=n + 1,
                restored_proof_acceptances=n + 1, envelope_rejections=3,
                public_setup_reused_for_child_cpu_checks=n, synthetic_hints_evaluated=False,
                faithful_ringct_protocol=False, production_acceptance=False, redesign_2x_gate_passed=False,
                security_adoption_review_complete=False, compilation_ns=20, source_planning_ns=20,
                cpu_verification_ns=20, mutation_checks_ns=20, owned_workflow_ns=2000,
                source=dict(children=n, scalar_operations_upper_bound=1, cubic_operations_upper_bound=1,
                    poseidon_operations_upper_bound=1, active_rows_upper_bound=7, padded_rows_upper_bound=8,
                    wires_upper_bound=12, input_values_upper_bound=6, construction_reserved_bytes=1000,
                    source_closed_before_setup=True), storage=storage,
                artifact_roundtrip=dict(encoded_bytes=400, decoded_proof_retained_bytes=1000,
                    distinct_aggregate_domain=True, exact_disk_roundtrip=True, total_ns=10), phases=phases)
            case = dict(selection=name, fixture_start=start, transactions=n, whole_transaction_proofs=n,
                recursive_aggregate_proofs=1, independent_cpu_acceptances=n + 1,
                public_mutation_rejections=4 * (n + 1), opening_mutation_rejections=n + 1,
                setup_ns=2 * len(phases), proving_ns=3 * (n + 1), cpu_verification_ns=20, complete_workflow_ns=2200)
            data = bytearray(400)
            data[:8] = b'LDAGG301' if n == 3 else b'LDAGG401'
            data[8:40] = guard.profile_digest(n)
            struct.pack_into('<I', data, 40, 5)
            data[44:76] = bytes([0x73] * 32)
            struct.pack_into('<4Q', data, 76, 1, 2, 3, 4)
            desc = phases[-1]['descriptor']
            struct.pack_into('<4Q', data, 108, 7, 8, 12, 6)
            data[140:172] = bytes(desc['canonical_manifest_digest'])
            struct.pack_into('<4Q', data, 172, *desc['registered_program_id'])
            struct.pack_into('<Q', data, 204, 188)
            data[212:220] = b'LBV2RP02'
            blobs[name + '.aggregate'] = bytes(data)
            report['artifact_roundtrip']['artifact_sha3_256'] = list(hashlib.sha3_256(data).digest())
            reports.append(report)
            cases.append(case)
        suite = dict(schema='lattica-research-direct-ring-complete-n3-n4-v1', distinct_transactions=7,
            cases=cases, complete_workflow_ns=5000, final_artifacts_destroyed=True,
            faithful_ringct_protocol=False, redesign_2x_gate_passed=False, security_adoption_review_complete=False)
        return plan, directory, reports, suite, blobs

    def save(self, fixture):
        plan, directory, reports, suite, blobs = fixture
        for index, name in enumerate(('N3', 'N4')):
            (directory / (name + '.report.json')).write_text(json.dumps(reports[index]))
        (directory / 'complete.json').write_text(json.dumps(suite))
        for name, data in blobs.items():
            (directory / name).write_bytes(data)
        receipts = []
        for report in reports:
            for phase in report['phases']:
                receipts.append(phase['registration'])
                if phase['fresh_proof']:
                    receipts.append(phase['proving'])
        content = ('test ' + guard.SELECTOR + ' ... '
            + '\n'.join('proving_stage_report ' + json.dumps(receipt) for receipt in receipts)
            + '\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 100 filtered out; finished in 1s\n')
        return content, plan

    def test_synthetic_complete_evidence_is_only_source_driver_policy_evidence(self):
        result = guard.validate(*self.save(self.fixture()))
        self.assertEqual(result['fresh_whole_transaction_proofs'], 7)
        self.assertEqual(result['fresh_recursive_aggregate_proofs'], 2)
        self.assertEqual(result['terminal_phases'], 25)
        self.assertFalse(result['standalone_archived_artifact_qualified'])
        self.assertFalse(result['performance_qualified'])

    def test_missing_reordered_duplicate_or_unverified_work_cannot_earn_credit(self):
        original = self.fixture()
        changes = [lambda r, s: r[0]['phases'].pop(),
            lambda r, s: r[0]['phases'].reverse(),
            lambda r, s: r[0].update(fresh_recursive_aggregate_proofs=0),
            lambda r, s: r[0].update(independent_final_cpu_acceptances=0),
            lambda r, s: r[1].update(public_mutation_rejections=19),
            lambda r, s: r[1].update(opening_mutation_rejections=4),
            lambda r, s: r[1].update(restored_proof_acceptances=4),
            lambda r, s: r[1].update(public_setup_reused_for_child_cpu_checks=0),
            lambda r, s: r[1].update(synthetic_hints_evaluated=True),
            lambda r, s: s.update(final_artifacts_destroyed=False),
            lambda r, s: s['cases'][1].update(fixture_start=0),
            lambda r, s: r[0]['phases'][0]['terminal'].update(queue_drained=False),
            lambda r, s: r[0]['phases'][3]['proving']['observations'][0].update(device_calls=0),
            lambda r, s: r[1]['storage'].update(active_host_partition_bytes=32 * guard.GIB),
            lambda r, s: r[0]['phases'][0]['footprint'].update(worker_host_limit_bytes=32 * guard.GIB),
            lambda r, s: r[0]['artifact_roundtrip'].update(exact_disk_roundtrip=False),
            lambda r, s: r[0].update(owned_workflow_ns=1),
            lambda r, s: s.update(complete_workflow_ns=7000)]
        for index, mutate in enumerate(changes):
            current = copy.deepcopy(original)
            mutate(current[2], current[3])
            with self.subTest(index=index), self.assertRaises(ValueError):
                guard.validate(*self.save(current))

    def test_artifact_substitution_duplicate_json_extra_file_and_native_log_reject(self):
        fixture = self.fixture()
        content, plan = self.save(fixture)
        directory = fixture[1]
        for offset in (0, 8, 40, 44, 76, 140, 172, 204, 212, 250):
            changed = bytearray(fixture[4]['N3.aggregate'])
            changed[offset] ^= 1
            (directory / 'N3.aggregate').write_bytes(changed)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                guard.validate(content, plan)
        self.save(fixture)
        extra = directory / 'N3.failure.json'
        extra.write_text('{}')
        with self.assertRaises(ValueError):
            guard.validate(content, plan)
        extra.unlink()
        path = directory / 'complete.json'
        path.write_text(path.read_text().replace('"distinct_transactions": 7',
            '"distinct_transactions": 0, "distinct_transactions": 7'))
        with self.assertRaises(ValueError):
            guard.validate(content, plan)
        self.save(fixture)
        with self.assertRaises(ValueError):
            guard.validate(content + '\nproving_stage_report {}\n', plan)
        with self.assertRaises(ValueError):
            guard.validate(content.replace('proving_stage_report ', 'missing_report ', 1), plan)


if __name__ == '__main__':
    unittest.main()
