#!/usr/bin/env python3
"""Public-file cache retirement preserves bytes and refuses unsafe ownership."""
import importlib
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import block_v2_public_artifact_cache as C

S = importlib.import_module('block-v2-typed-shared-gpu-run')


class CacheTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.deadline = time.monotonic_ns() // 1_000_000 + 30000

    def pins(self, files):
        return {name: {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
                for name, value in files.items()}

    def test_pinned_retirement_preserves_bytes_and_leaves_unlisted_files_alone(self):
        files = {'node.1.0': b'public proof', 'result.json': b'published receipt'}
        for name, value in files.items(): (self.root / name).write_bytes(value)
        untouched = self.root / 'active-journal'; untouched.write_bytes(b'never advise this')
        events = []
        def sync(fd): events.append(('sync', os.fstat(fd).st_ino))
        def advice(fd, start, length, flag):
            self.assertEqual((start, length, flag), (0, 0, os.POSIX_FADV_DONTNEED))
            events.append(('advice', os.fstat(fd).st_ino))
        with patch.object(C.os, 'fsync', side_effect=sync), patch.object(C.os, 'posix_fadvise', side_effect=advice):
            result = C.release_pinned(self.root, self.pins(files), self.deadline)
        self.assertEqual([event[0] for event in events], ['sync', 'advice', 'sync', 'advice'])
        self.assertNotIn(untouched.stat().st_ino, [event[1] for event in events])
        self.assertEqual(result['requested_bytes'], sum(map(len, files.values())))
        self.assertFalse(result['physical_release_measured'])
        self.assertFalse(result['proof_authority_granted'])
        self.assertEqual({name: (self.root / name).read_bytes() for name in files}, files)
        self.assertEqual(untouched.read_bytes(), b'never advise this')

    def test_every_pin_is_checked_before_any_file_is_advised(self):
        files = {'first': b'correct', 'second': b'correct'}
        for name, value in files.items(): (self.root / name).write_bytes(value)
        pins = self.pins(files)
        (self.root / 'second').write_bytes(b'corrupt')
        with patch.object(C.os, 'posix_fadvise') as advice:
            with self.assertRaisesRegex(ValueError, 'bytes changed'):
                C.release_pinned(self.root, pins, self.deadline)
            advice.assert_not_called()

    def test_pinned_paths_must_be_private_regular_and_not_aliases(self):
        value = b'proof'; path = self.root / 'proof'; path.write_bytes(value)
        pins = self.pins({'proof': value})
        alias = self.root / 'alias'; alias.symlink_to(path)
        with patch.object(C.os, 'posix_fadvise') as advice:
            with self.assertRaisesRegex(ValueError, 'type, owner or size'):
                C.release_pinned(self.root, self.pins({'alias': value}), self.deadline)
            alias.unlink(); os.mkfifo(alias)
            with self.assertRaisesRegex(ValueError, 'type, owner or size'):
                C.release_pinned(self.root, self.pins({'alias': value}), self.deadline)
            self.root.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'private'):
                C.release_pinned(self.root, pins, self.deadline)
            self.root.chmod(0o700)
            alias.unlink(); alias.symlink_to(self.root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'canonical'):
                C.release_pinned(alias, pins, self.deadline)
            advice.assert_not_called()

    def test_pinned_inventory_and_deadline_are_bounded_before_advice(self):
        value = b'proof'; (self.root / 'proof').write_bytes(value)
        pins = self.pins({'proof': value})
        bad = [{}, self.pins({'../proof': value}), self.pins({'/proof': value}),
               {str(i): pins['proof'] for i in range(64)},
               {'proof': {'bytes': 0, 'sha256': pins['proof']['sha256']}},
               {'proof': {'bytes': (2 << 20) + 1, 'sha256': pins['proof']['sha256']}},
               {'proof': {'bytes': True, 'sha256': pins['proof']['sha256']}},
               {'proof': {'bytes': 5, 'sha256': 'not-a-digest'}}]
        with patch.object(C.os, 'posix_fadvise') as advice:
            for inventory in bad:
                with self.subTest(inventory=inventory), self.assertRaisesRegex(ValueError, 'inventory'):
                    C.release_pinned(self.root, inventory, self.deadline)
            with self.assertRaisesRegex(TimeoutError, 'deadline'):
                C.release_pinned(self.root, pins, 1)
            advice.assert_not_called()

    def test_pinned_mutation_or_replacement_during_advice_invalidates_receipt(self):
        value = b'proof'; path = self.root / 'proof'; pins = self.pins({'proof': value})
        for replace in [False, True]:
            path.write_bytes(value)
            def change(*_):
                if replace: path.unlink()
                path.write_bytes(value if replace else b'changed')
            with patch.object(C.os, 'posix_fadvise', side_effect=change):
                with self.subTest(replace=replace), self.assertRaisesRegex(ValueError, 'changed during'):
                    C.release_pinned(self.root, pins, self.deadline)

    def test_pinned_advice_failure_propagates(self):
        value = b'proof'; (self.root / 'proof').write_bytes(value)
        with patch.object(C.os, 'posix_fadvise', side_effect=OSError('advice failed')):
            with self.assertRaisesRegex(OSError, 'advice failed'):
                C.release_pinned(self.root, self.pins({'proof': value}), self.deadline)

    def test_sync_precedes_advice_and_all_artifact_bytes_are_preserved(self):
        nested = self.root / 'proofs'; nested.mkdir()
        files = {self.root / 'journal': b'journal bytes', nested / 'node.6.0': b'proof bytes'}
        for p, value in files.items(): p.write_bytes(value)
        events = []
        def sync(fd): events.append(('sync', os.fstat(fd).st_ino))
        def advice(fd, start, length, flag):
            self.assertEqual((start, length, flag), (0, 0, os.POSIX_FADV_DONTNEED))
            events.append(('advice', os.fstat(fd).st_ino))
        with patch.object(C.os, 'fsync', side_effect=sync), patch.object(C.os, 'posix_fadvise', side_effect=advice):
            receipt = C.release(self.root, self.deadline)
        self.assertEqual(receipt['files'], 2)
        self.assertEqual(receipt['requested_bytes'], sum(map(len, files.values())))
        self.assertFalse(receipt['physical_release_measured'])
        self.assertEqual([e[0] for e in events], ['sync', 'advice', 'sync', 'advice'])
        self.assertEqual(events[0][1], events[1][1])
        self.assertEqual(events[2][1], events[3][1])
        self.assertEqual({p: p.read_bytes() for p in files}, files)

    def test_symlink_and_nonregular_input_are_never_advised(self):
        outside = self.root / 'outside'; outside.write_bytes(b'preserve external bytes')
        target = self.root / 'owner'; target.mkdir(mode=0o700)
        link = target / 'link'; link.symlink_to(outside)
        with patch.object(C.os, 'posix_fadvise') as advice:
            with self.assertRaisesRegex(ValueError, 'nonsymlink'): C.release(target, self.deadline)
            advice.assert_not_called()
        link.unlink(); os.mkfifo(link)
        with patch.object(C.os, 'posix_fadvise') as advice:
            with self.assertRaisesRegex(ValueError, 'regular'): C.release(target, self.deadline)
            advice.assert_not_called()
        self.assertEqual(outside.read_bytes(), b'preserve external bytes')

    def test_nonprivate_or_linked_root_is_rejected(self):
        target = self.root / 'owner'; target.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, 'private'): C.release(target, self.deadline)
        target.chmod(0o700)
        link = self.root / 'alias'; link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'canonical'): C.release(link, self.deadline)

    def test_advice_failure_is_not_treated_as_success(self):
        (self.root / 'proof').write_bytes(b'proof')
        with patch.object(C.os, 'posix_fadvise', side_effect=OSError('advice failed')):
            with self.assertRaisesRegex(OSError, 'advice failed'): C.release(self.root, self.deadline)

    def test_mutation_during_advice_invalidates_receipt(self):
        path = self.root / 'proof'; path.write_bytes(b'proof')
        with patch.object(C.os, 'posix_fadvise', side_effect=lambda *_: path.write_bytes(b'changed proof')):
            with self.assertRaisesRegex(ValueError, 'changed during'): C.release(self.root, self.deadline)

    def test_time_inventory_and_byte_bounds_prevent_unbounded_retirement(self):
        (self.root / 'proof').write_bytes(b'proof')
        with patch.object(C.os, 'posix_fadvise') as advice:
            with self.assertRaisesRegex(TimeoutError, 'deadline'): C.release(self.root, 1)
            with patch.object(C, 'MAX_ENTRIES', 0):
                with self.assertRaisesRegex(ValueError, 'entry bound'): C.release(self.root, self.deadline)
            with patch.object(C, 'MAX_BYTES', 1):
                with self.assertRaisesRegex(ValueError, 'byte bound'): C.release(self.root, self.deadline)
            advice.assert_not_called()

    def test_active_services_block_cache_retirement(self):
        with patch.object(S, 'quiescent_fleet', side_effect=ValueError('worker still running')):
            with patch.object(C, 'release') as release:
                with self.assertRaisesRegex(ValueError, 'still running'):
                    S.retire_public_artifacts('owner', [], self.root, self.deadline)
                release.assert_not_called()

    def test_closed_services_are_checked_before_and_after_advice(self):
        events = []
        with patch.object(S, 'quiescent_fleet', side_effect=lambda *_: events.append('stopped')):
            with patch.object(C, 'release', side_effect=lambda *_: events.append('advice') or {'files': 1}):
                self.assertEqual(S.retire_public_artifacts('owner', [], self.root, self.deadline), {'files': 1})
        self.assertEqual(events, ['stopped', 'advice', 'stopped'])


if __name__ == '__main__':
    unittest.main()
