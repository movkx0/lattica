"""Synthetic parser fixtures; no proof, mutation, device or performance credit."""
import unittest

import hashx_root_public_capacity_guard as guard

GIB = 1 << 30
GROWTH = 'bounded_proof_input_growth old_values=0 new_values=4 live_bytes=32 value_limit=1048576'


def records():
    source = 9 * GIB
    startup = 8 * GIB + (64 << 20)
    wrappers = 16 << 20
    verifier, caller = 16 << 20, 256 << 10
    return [
        (guard.ROOT_CLAIMS, dict(guard.ROOT_FIXED, verifier_host_bytes=verifier,
                               caller_host_bytes=caller, total_host_bytes=verifier + caller)),
        (guard.SOURCE_CLAIMS, dict(guard.SOURCE_FIXED, host_bytes=source, device_bytes=0)),
        (guard.CAPACITY_COMPLETE, dict(guard.CAPACITY_FIXED, original_claims_host_bytes=source,
            startup_host_bytes=startup, startup_device_bytes=guard.STARTUP_DEVICE,
            phase_wrappers_host_bytes=wrappers, phase_wrappers_device_bytes=0,
            pcs_host_bytes=guard.HOST - source - startup - wrappers,
            pcs_device_bytes=guard.DEVICE - guard.STARTUP_DEVICE,
            simultaneous_host_bytes=guard.HOST, simultaneous_device_bytes=guard.DEVICE, projection_ns=20)),
        (guard.TERMINAL, dict(guard.TERMINAL_FIXED, peak_host_bytes=guard.HOST,
                             peak_device_bytes=guard.DEVICE, component_through_destruction_ns=200)),
    ]


def fixture(values=None, same_line=False, header_payload=''):
    if values is None:
        values = records()
    lines = ['test ' + guard.SELECTOR + ' ... ' + header_payload,
             *(name + ' ' + ' '.join(f'{key}={value}' for key, value in record.items())
               for name, record in values),
             'ok', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 510 filtered out; finished in 0.01s', '']
    if same_line:
        lines[:2] = [lines[0] + lines[1]]
    return '\n'.join(lines)


class HashxRootPublicCapacityGuardTests(unittest.TestCase):
    def test_valid_projection_has_only_source_quota_credit(self):
        for content in (fixture(), fixture(same_line=True), fixture(header_payload=GROWTH)):
            with self.subTest(content=content):
                result = guard.validate_log(content, 300)
                self.assertEqual(result['schema'], 'ringct-hashx-root-public-capacity-v1')
                self.assertEqual(result['scope'], 'root-public-quota-projection-only')
                self.assertEqual(result['cpu_heights'], 18)
                self.assertEqual(result['planned_public_probes'], 46)
                for key in ('native_proofs', 'recursive_proofs', 'stage_receipts',
                            'actual_root_public_probes', 'positive_checks'):
                    self.assertEqual(result[key], 0)
                self.assertTrue(result['original_quota_released'])
                self.assertTrue(result['owner_quota_cleanup_complete'])
                for key in ('process_engine_device_audit_complete', 'native_dispatch_started',
                            'physical_backend_fit', 'actual_proving_fit', 'root_public_recheck_complete',
                            'raw_proof_mutation_checks_complete', 'interior_mutation_checks_complete',
                            'mutation_checks_complete', 'artifact_roundtrip_complete',
                            'complete_ringct_workflow', 'performance_qualified'):
                    self.assertFalse(result[key], key)
                claim = result['root_recheck_claims']
                self.assertEqual(claim['total_host_bytes'], claim['verifier_host_bytes'] + claim['caller_host_bytes'])
                self.assertLessEqual(claim['total_host_bytes'], result['source_claims']['host_bytes'])

    def test_refuses_all_cpu_gpu_proof_and_returned_refusal_siblings(self):
        prefix = guard.SELECTOR.rsplit('::', 1)[0] + '::'
        for suffix in ('cpu_original_hashx_sequence_capacity', 'gpu_original_hashx_sequence_preissue',
                       'gpu_original_hashx_sequence_source_authenticated',
                       'gpu_original_hashx_sequence_root_public_recheck',
                       'gpu_original_hashx_sequence_refusal_after_preissue',
                       'gpu_original_hashx_sequence_refusal_before_first_start',
                       'gpu_original_hashx_sequence_refusal_after_first_producer',
                       'gpu_original_hashx_sequence_refusal_after_first_acceptance'):
            with self.subTest(selector=suffix), self.assertRaises(ValueError):
                guard.validate_log(fixture().replace(guard.SELECTOR, prefix + suffix), 300)

    def test_refuses_root_counts_mode_dispatch_and_success_escalation(self):
        for index, key, value in (
            (0, 'cpu_heights', 17), (0, 'planned_public_probes', 45), (0, 'actual_root_public_probes', 1),
            (0, 'mode', 'root-public'), (0, 'native_dispatch_started', 'true'),
            (1, 'mode', 'capacity'), (1, 'native_outputs', 9), (1, 'retained_parent_sources', 3),
            (2, 'native_proofs', 10), (2, 'recursive_proofs', 9),
            (2, 'wrong_request_and_ledger_refused', 'false'), (2, 'original_claims_preserved', 'false'),
            (2, 'physical_backend_fit', 'true'), (3, 'component_success', 'true'),
            (3, 'original_quota_released', 'false'), (3, 'current_host_bytes', 1),
            (3, 'current_device_bytes', 1), (3, 'mode', 'root-public'),
            (3, 'mutation_checks_complete', 'true'), (3, 'artifact_roundtrip_complete', 'true'),
            (3, 'complete_ringct_workflow', 'true'),
        ):
            values = records()
            values[index][1][key] = value
            with self.subTest(index=index, key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), 300)

    def test_refuses_incomplete_or_unbacked_root_claim(self):
        for changes in ({'verifier_host_bytes': 0}, {'caller_host_bytes': 64 << 10},
                        {'total_host_bytes': 1},
                        {'verifier_host_bytes': guard.HOST, 'total_host_bytes': guard.HOST + (256 << 10)}):
            values = records()
            values[0][1].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), 300)
        values = records()
        values[0][1].update(verifier_host_bytes=1, caller_host_bytes=1, total_host_bytes=2)
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), 300)
        # Keep verifier+caller internally coherent but larger than the actual
        # source-original reservation: projection totals alone cannot hide it.
        values = records()
        values[0][1]['verifier_host_bytes'] = values[1][1]['host_bytes']
        values[0][1]['total_host_bytes'] = values[0][1]['verifier_host_bytes'] + values[0][1]['caller_host_bytes']
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), 300)

    def test_refuses_source_startup_wrapper_pcs_and_terminal_accounting_drift(self):
        for index, key, value in (
            (1, 'host_bytes', 0), (1, 'host_bytes', guard.HOST + 1), (1, 'device_bytes', 1),
            (2, 'original_claims_host_bytes', 1), (2, 'startup_host_bytes', 8 * GIB),
            (2, 'phase_wrappers_host_bytes', 0), (2, 'pcs_host_bytes', 0),
            (2, 'pcs_host_bytes', guard.NATIVE_HOST + 1),
            (2, 'startup_device_bytes', guard.STARTUP_DEVICE + 1),
            (2, 'phase_wrappers_device_bytes', 1),
            (2, 'pcs_device_bytes', guard.DEVICE - guard.STARTUP_DEVICE - 1),
            (2, 'simultaneous_host_bytes', guard.HOST - 1),
            (2, 'simultaneous_device_bytes', guard.DEVICE - 1),
            (3, 'peak_host_bytes', guard.HOST - 1), (3, 'peak_host_bytes', guard.HOST + 1),
            (3, 'peak_device_bytes', guard.DEVICE - 1), (3, 'peak_device_bytes', guard.DEVICE + 1),
        ):
            values = records()
            values[index][1][key] = value
            with self.subTest(index=index, key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), 300)
        # Coherently reduce PCS, simultaneous host and peak: the unchanged
        # remaining-host allocation rule must still reject the projection.
        values = records()
        values[2][1]['pcs_host_bytes'] -= 1
        values[2][1]['simultaneous_host_bytes'] -= 1
        values[3][1]['peak_host_bytes'] -= 1
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), 300)
        # Swapping one device byte between startup and PCS preserves totals,
        # but no longer describes the original unchanged device quota pieces.
        values = records()
        values[2][1]['startup_device_bytes'] += 1
        values[2][1]['pcs_device_bytes'] -= 1
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), 300)

    def test_refuses_noncanonical_numbers_and_unowned_observation(self):
        for value in ('01', '-1', '+1', '1.0', '1e3', str(1 << 64), '1' * 40):
            values = records()
            values[0][1]['verifier_host_bytes'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), 300)
        for observation in (None, True, False, 0, -1, 300.0, '300', 199, 1 << 128):
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                guard.validate_log(fixture(), observation)
        for index, key, value in ((2, 'projection_ns', 0), (2, 'projection_ns', 201),
                                  (3, 'component_through_destruction_ns', 19),
                                  (3, 'component_through_destruction_ns', 301),
                                  (3, 'component_through_destruction_ns', '0200'),
                                  (3, 'component_through_destruction_ns', 1 << 128)):
            values = records()
            values[index][1][key] = value
            with self.subTest(index=index, key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), 300)

    def test_refuses_missing_extra_duplicate_or_reordered_fields_and_markers(self):
        content = fixture()
        lines = content.splitlines(True)
        invalid = []
        for index in range(1, 5):
            invalid.extend((''.join(lines[:index] + lines[index + 1:]), content + lines[index]))
        invalid.extend((''.join([lines[0], lines[2], lines[1], *lines[3:]]),
                        ''.join([lines[0], lines[1], lines[3], lines[2], *lines[4:]]),
                        content.replace('cpu_heights=18 ', ''),
                        content.replace('cpu_heights=18 ', 'cpu_heights=18 cpu_heights=18 '),
                        content.replace('cpu_heights=18 ', 'cpu_heights=18 invented=1 '),
                        content.replace('cpu_heights=18 ', 'cpu_heights=18\t'),
                        content.replace('cpu_heights=18 ', 'cpu_heights=18  ')))
        for changed in invalid:
            with self.subTest(content=changed), self.assertRaises(ValueError):
                guard.validate_log(changed, 300)

    def test_refuses_arbitrary_or_misplaced_header_payload(self):
        for payload in ('ok', 'ignored', 'failed', 'fixture', 'error: missing verifier',
                        guard.SOURCE_CLAIMS + ' mode=root-public-capacity',
                        guard.CAPACITY_COMPLETE + ' native_proofs=0',
                        GROWTH.replace('live_bytes=32', 'live_bytes=31'),
                        GROWTH.replace('old_values=0', 'old_values=00'),
                        GROWTH.replace('new_values=4', 'new_values=5'),
                        GROWTH.replace('value_limit=1048576', 'value_limit=1048577'),
                        GROWTH + ' extra=1'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                guard.validate_log(fixture(header_payload=payload), 300)
        content = fixture(same_line=True).replace('cpu_heights=18 ', 'cpu_heights=18 extra=1 ')
        with self.assertRaises(ValueError):
            guard.validate_log(content, 300)

    def test_refuses_foreign_evidence_or_nonpassing_test_footer(self):
        content = fixture()
        for token in ('proving_stage_report {}', 'NATIVE_EXECUTION_RECEIPT {}', 'PUBLIC_HASH_EXECUTION {}',
                      'OPENCL_OPT_RESULT {}', 'DIRECT_SPEND_RESULT {}', 'DIRECT_RING_RESULT {}',
                      'ringct_hashx_root_public_recheck_scope public_probes=46',
                      'ringct_hashx_root_public_recheck_complete native_proofs=10',
                      'ringct_hashx_sequence_preissue_complete native_proofs=0',
                      'ringct_hashx_sequence_returned_refusal_complete component_success=false',
                      'ringct_hashx_first_leaf_complete native_proofs=10',
                      'ringct_foreign_evidence complete=true', 'fallback=true', 'retry=true',
                      "thread 'test' panicked at fixture:1"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                guard.validate_log(content + token + '\n', 300)
        for old, new in (('\nok\n', '\n'), ('\nok\n', '\nFAILED\n'), ('\nok\n', '\nok\nok\n'),
                         ('1 passed;', '2 passed;'), ('0 failed;', '1 failed;'), ('0 ignored;', '1 ignored;')):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                guard.validate_log(content.replace(old, new), 300)
        for extra in ('test foreign::test ... ok\n', content.splitlines()[-1] + '\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                guard.validate_log(content + extra, 300)


if __name__ == '__main__':
    unittest.main()
