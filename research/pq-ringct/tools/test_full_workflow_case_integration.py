"""Compose receipt and disk audits using synthetic data, never real proofs.

The eight-byte inner fixture is only a transport marker. These tests exercise
the Python audit hooks; their qualification flags are not cryptographic evidence.
"""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import full_workflow_case_guard as guard
from opencl_private_spend_validate import collect_gpu_receipts
from test_owned_workflow_case_receipts import fixture, render
from test_owned_workflow_verification_receipts import enrich


class CompleteCaseIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ringct-composed-guard-test-')
        self.addCleanup(self.temp.cleanup)

    def case(self, count=3, layout='singleton'):
        events, report = fixture(count)
        directory = Path(self.temp.name) / f'n{count}-{layout}'
        directory.mkdir()
        context = [4] * 32
        seed = [1] * 32

        # Independent fixed wire layout: four identities, eight scalars,
        # 25 public field words, and 64 cap digests. All field words start at zero.
        header = bytearray(2456)
        header[:8] = b'LQRFN001'
        struct.pack_into('<Q', header, 8, 1)
        for offset, identity in ((16, [1] * 32), (48, [2] * 32),
                                 (80, [3] * 32), (112, context)):
            header[offset:offset + 32] = bytes(identity)
        struct.pack_into('<8Q', header, 144, count - 2, 0, count, count, 8, 25, 64, 8)
        packet = bytes(header) + b'LBV2RP02'
        digest = hashlib.sha3_256(packet).digest()
        path = directory / ('ringct-final-' + digest.hex() + '.bin')
        path.write_bytes(packet)
        info = path.stat()
        qualification = dict(report['final_qualification'],
            artifact_round_trip=True, public_mutation_rejected=True,
            proof_mutation_rejected=True, decoded_positive_checks=3,
            packet_sha3_256=list(digest), proof_bytes=8, packet_bytes=len(packet),
            file_device=info.st_dev, file_inode=info.st_ino,
            compiled_source_fingerprint=[1] * 32, source_fingerprint=[2] * 32,
            batch_profile=[3] * 32, context=context, height=8, public_values=25)
        for prefix, value in events:
            if prefix == 'owned_final_stage' and value['stage'] == 'verify':
                value['report']['qualification'] = qualification
        complete_ns = (report['generation_and_planning_ns']
                       + report['proving_and_verification_ns'] + 10_000_000)
        report.update(completed_phases=90, final_cpu_verification_ns=1_000,
                      complete_workflow_ns=complete_ns,
                      ledger_peak_host_bytes=8192, ledger_peak_device_bytes=8192,
                      cache_counter_scope='instrumented-cache-paths',
                      qualification_scope='final-aggregate',
                      final_qualification=qualification,
                      artifacts_qualified=True, mutations_qualified=True)
        events, report = enrich(events, report)
        from test_cpu_identity_receipts import add_finalizations
        events, totals = add_finalizations(events)
        report['owned_observations']['identity_preprocessing'] = totals
        envelope = dict(schema=guard.SCHEMA, case=f'n{count}', layout=layout,
                        setup_seed=seed, context=context, proof_policy='fresh-only',
                        proving_policy='gpu-required', report=report, identity_cpu={'requested_workers': 1, 'max_streams': 1})
        plan = {guard.KEY: dict(schema=guard.SCHEMA, case=f'n{count}', layout=layout,
                                setup_seed=seed, context=context,
                                output_directory=str(directory), screening_only=True, identity_cpu={'requested_workers': 1, 'max_streams': 1}),
                'observation_before_validation_ns': complete_ns + 1_000_000}
        return events, envelope, plan, path, packet

    @staticmethod
    def content(events, envelope):
        return render(events) + '\n' + guard.PREFIX + json.dumps(envelope) + '\n'

    def test_complete_n3_n4_both_layouts_reconcile_receipts_and_artifact(self):
        for count in (3, 4):
            for layout in ('singleton', 'paired-v1'):
                with self.subTest(count=count, layout=layout):
                    events, envelope, plan, path, packet = self.case(count, layout)
                    result = guard.validate_log(self.content(events, envelope), plan,
                                                collect_gpu_receipts)
                    self.assertEqual(result['report'], envelope['report'])
                    self.assertEqual((result['case'], result['layout']), (f'n{count}', layout))
                    self.assertEqual(result['receipts']['gpu_receipts']['native_reports'], 12)
                    self.assertEqual(result['receipts']['source_preparation']['reports'], count)
                    self.assertEqual(result['receipts']['owned_preparation']['reports'], count)
                    self.assertEqual(result['receipts']['final_compile_reports'], count - 1)
                    self.assertEqual(result['artifact']['path'], str(path))
                    self.assertEqual(result['artifact']['packet_bytes'], len(packet))
                    self.assertIs(result['screening_only'], True)
                    self.assertIs(result['comparison_baseline'], False)
                    self.assertIs(result['performance_qualified'], False)

    def test_complete_case_rejects_corrupt_native_gpu_receipt(self):
        events, envelope, plan, _, _ = self.case()
        native = next(value for prefix, value in events
                      if prefix == 'owned_source_native_report')
        native['observations'][0]['device_calls'] = 0
        with self.assertRaises(ValueError):
            guard.validate_log(self.content(events, envelope), plan, collect_gpu_receipts)

    def test_complete_case_rejects_corrupt_artifact_after_valid_receipts(self):
        events, envelope, plan, path, packet = self.case()
        corrupted = bytearray(packet)
        # Change a canonical public word while retaining shape, inode and length.
        # Only the expected packet digest binds this otherwise valid header word.
        corrupted[208] = 1
        path.write_bytes(corrupted)
        with self.assertRaisesRegex(ValueError, 'digest or EOF mismatch'):
            guard.validate_log(self.content(events, envelope), plan, collect_gpu_receipts)


if __name__ == '__main__':
    unittest.main()
