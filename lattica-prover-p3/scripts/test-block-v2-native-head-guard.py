#!/usr/bin/env python3
"""Head observation and application-phase handoff; no proving qualification."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import block_v2_native_head_guard as G


class NativeHeadGuard(unittest.TestCase):
    def native(self, observed):
        return SimpleNamespace(binding={'generation': 2, 'head_token': [17] * 32},
            current_head=SimpleNamespace(token='11' * 32, generation=2),
            store=SimpleNamespace(published_head_token=Mock(return_value=observed)))

    def owner(self, root):
        (root / 'coordinator-startup').mkdir()
        (root / 'coordinator-startup/started.json').write_text(json.dumps({'pid': os.getpid()}))
        (root / 'root-only').mkdir()
        (root / 'root-only/node.6.0').write_bytes(b'unit-test-root')

    def test_unbound_and_unchanged_head_need_no_application_files(self):
        self.assertIsNone(G.observe(None, '/missing/owner'))
        native = self.native('11' * 32)
        self.assertIsNone(G.observe(native, '/missing/owner'))
        native.store.published_head_token.assert_called_once_with()

    def test_changed_head_cancels_active_proving_without_claiming_native_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            change = G.observe(self.native('22' * 32), Path(tmp))
            self.assertEqual(change['expected_head_token'], '11' * 32)
            self.assertEqual(change['observed_head_token'], '22' * 32)
            self.assertEqual(change['expected_generation'], 2)
            self.assertFalse(change['observation_is_native_validation'])

    def test_atomic_application_handoff_defers_to_native_compare_and_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.owner(root)
            native = self.native('22' * 32)
            G.publish_handoff(native, root)
            self.assertIsNone(G.observe(native, root))
            self.assertFalse(list(root.glob('*.partial')))
            with self.assertRaises(FileExistsError):
                G.publish_handoff(native, root)

    def test_handoff_requires_the_actual_owner_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.owner(root)
            path = root / 'coordinator-startup/started.json'
            for pid in [os.getpid()+1, True, 0]:
                path.write_text(json.dumps({'pid': pid}))
                with self.subTest(pid=pid), self.assertRaises(ValueError):
                    G.publish_handoff(self.native('22' * 32), root)

    def test_changed_or_substituted_handoff_cannot_disable_head_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.owner(root)
            native = self.native('22' * 32)
            good = G.handoff_record(native, root, os.getpid())
            changes = [{'owner_pid': os.getpid()+1}, {'schema_version': True},
                       {'current_head_token': '33' * 32}, {'proof_sha256': '44' * 32},
                       {'native_host_binding': {'generation': 3}}]
            for change in changes:
                (root / 'native-application-started.json').write_text(json.dumps(good | change))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    G.observe(native, root)
            (root / 'native-application-started.json').write_text(json.dumps(good))
            (root / 'root-only/node.6.0').write_bytes(b'changed-root')
            with self.assertRaises(ValueError):
                G.observe(native, root)

    def test_failed_native_cas_is_classified_after_application_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = dict(status='failed', failure='StaleHead: compare-and-swap rejected', native_blocks_applied=0)
            (root / 'result.json').write_text(json.dumps(result))
            change = G.failed_application(self.native('22' * 32), root)
            self.assertTrue(change['detected_after_application_handoff'])
            self.assertIsNone(G.failed_application(self.native('11' * 32), root))
            for update in [{'native_blocks_applied': 1}, {'native_blocks_applied': None},
                           {'native_blocks_applied': False}, {'native_application_status': 'indeterminate'},
                           {'failure': 'OSError: unrelated failure'}, {'status': 'succeeded'}]:
                (root / 'result.json').write_text(json.dumps(result | update))
                with self.subTest(update=update):
                    self.assertIsNone(G.failed_application(self.native('22' * 32), root))


if __name__ == '__main__':
    unittest.main()
