#!/usr/bin/env python3
"""Oracle and evidence-corruption tests; optional saved-artifact cases via env."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import compact_v3_audit as audit


def fixture(extreme=False):
    out = bytearray()
    for part in audit.v1.PARTS:
        if part is None:
            out.extend(bytes(range(32)))
            continue
        count, width, base, _ = part
        digit = base - 1 if extreme else (base - 1) // 2
        number = sum(digit << (width * i) for i in range(256))
        out.extend(number.to_bytes(width * 32, 'little') * count)
    return bytes(out)


class OracleTests(unittest.TestCase):
    def test_centered_and_extreme_domains(self):
        for extreme, expected_mode, expected_length in [(False, 1, audit.MIN_PROOF), (True, 0, audit.MAX_PROOF)]:
            original = fixture(extreme)
            encoded = audit.encode_v3(original)
            self.assertEqual((encoded[0], len(encoded)), (expected_mode, expected_length))
            self.assertEqual(audit.decode_v3(encoded), original)

    def test_noncanonical_modes_parameters_and_lengths(self):
        original = fixture()
        encoded = audit.encode_v3(original)
        bad = [b'', encoded[:-1], encoded + b'\0', b'\2' + encoded[1:],
               b'\0' + audit.v1.proof_encoding(original)]
        for offset, value in [(1, 2), (2, 17), (3, 11), (4, 17), (5, 24)]:
            changed = bytearray(encoded); changed[offset] = value; bad.append(bytes(changed))
        # Same centered proof with nonminimal k=1 for x.
        changed = bytearray(encoded); changed[1] = 1; changed.extend(bytes(32)); bad.append(bytes(changed))
        for value in bad:
            with self.assertRaises(ValueError):
                audit.decode_v3(value)

    def test_probability_tables_reproduce_from_native_sampler_scales(self):
        audit.check_models()

    @unittest.skipUnless(os.environ.get('RINGCT_V3_MEASUREMENT'), 'set RINGCT_V3_MEASUREMENT for artifact tests')
    def test_entropy_mode_state_head_and_fallback_canonicality(self):
        source = Path(os.environ['RINGCT_V3_MEASUREMENT'])
        encoded = (source / 'case-0-proof.bin').read_bytes()
        original = (source / 'case-0-native.bin').read_bytes()[202932:]
        self.assertEqual(encoded[0], 2)
        self.assertEqual(audit.decode_v3(encoded), original)
        bad = [encoded[:-1], encoded + b'\0', bytes([255]) + encoded[1:],
               (source / 'case-0-v2_proof.bin').read_bytes()]
        for state in [0, audit.LOWER - 1, audit.LOWER << 8, 0xffffffff]:
            changed = bytearray(encoded)
            changed[audit.ANS_START:audit.ANS_START + 4] = state.to_bytes(4, 'little')
            bad.append(bytes(changed))
        changed = bytearray(encoded)
        changed[1:848] = (audit.v1.Q ** 248).to_bytes(847, 'little')
        bad.append(bytes(changed))
        for data in bad:
            with self.assertRaises(ValueError):
                audit.decode_v3(data)

    @unittest.skipUnless(os.environ.get('RINGCT_V3_MEASUREMENT'), 'set RINGCT_V3_MEASUREMENT for artifact tests')
    def test_updated_checksums_do_not_hide_artifact_corruption(self):
        source = Path(os.environ['RINGCT_V3_MEASUREMENT'])
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / 'measurement'
            shutil.copytree(source, directory)
            saved = (directory / 'report.json').read_text()
            for kind, offset in [('proof', 11173), ('v1_proof', 11200), ('v2_proof', 11206),
                                 ('standalone', 80), ('referenced', 144), ('native', 12)]:
                report = json.loads(saved)
                record = report['cases'][0]['artifacts'][kind]
                path = directory / record['file']
                original = path.read_bytes()
                changed = bytearray(original); changed[offset] ^= 1
                path.write_bytes(changed)
                record['sha3_256'] = hashlib.sha3_256(changed).hexdigest()
                (directory / 'report.json').write_text(json.dumps(report))
                with self.assertRaises(ValueError, msg=kind):
                    audit.audit(directory)
                path.write_bytes(original)
            report = json.loads(saved)
            report['cases'][0]['ledger_checkpoint_hex'] = '00' * 32
            (directory / 'report.json').write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                audit.audit(directory)


if __name__ == '__main__':
    unittest.main()
