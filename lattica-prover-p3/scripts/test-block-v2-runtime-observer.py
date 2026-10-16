"""Regression tests for trustworthy process identity and non-atomic observations."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from block_v2_runtime_observer import (
    MAPPING_FIELDS, RuntimeObserver, check_identity, mapping_details,
    mapping_residency, numeric_status, read_smaps,
    start_ticks, task_snapshot,
)


def proc_stat(ticks, name='worker ) name'):
    return '10 (' + name + ') S ' + '0 ' * 18 + str(ticks) + ' 0 0\n'


def smap(path='', *, inode=0, device='00:00', perms='rw-p', flags='rd wr mr mw me ac', rss=4):
    fields = dict.fromkeys((*MAPPING_FIELDS, 'Locked'), 0)
    fields.update(Size=4096, Rss=rss, Pss=rss, Private_Dirty=rss, Anonymous=rss)
    return (f'1000-2000 {perms} 00000000 {device} {inode} {path}\n'
            + ''.join(f'{key}: {value} kB\n' for key, value in fields.items())
            + f'VmFlags: {flags}\n')


class RuntimeTests(unittest.TestCase):
    def test_mapping_details_keep_file_identity_permissions_and_vm_flags(self):
        path = '/tmp/proof inputs/lat-spill-42-1.tmp (deleted)'
        text = (smap(path, inode=7, device='08:01', perms='rw-s') * 2
                + smap(path, inode=8, device='08:01', perms='rw-s')
                + smap(path, inode=7, device='08:02', perms='rw-s')
                + smap(path, inode=7, device='08:01', perms='r--s', flags='rd mr mw me')
                + smap(path, inode=7, device='08:01', perms='rw-s', flags='rd wr lo'))
        rows = mapping_details(text)
        self.assertEqual(len(rows), 5)
        self.assertEqual(sum(row['mappings'] for row in rows), 6)
        merged = next(row for row in rows if row['mappings'] == 2)
        self.assertEqual(merged['path'], path)
        self.assertEqual(merged['inode'], 7)
        self.assertEqual(merged['device'], '08:01')
        self.assertEqual(merged['permissions'], 'rw-s')
        self.assertEqual(merged['kib']['Rss'], 8)
        self.assertEqual(merged['kib']['Private_Dirty'], 8)
        # Shared mapping permissions do not imply shared resident-page counts.
        self.assertEqual(merged['kib']['Shared_Dirty'], 0)

    def test_mapping_details_reconcile_every_category_from_one_snapshot(self):
        text = ''.join(smap(path) for path in (
            '', '[heap]', '[stack]', '/usr/lib/libnvidia-opencl.so', '/dev/shm/a',
            '/usr/lib/libLLVM.so', '[vdso]', '[anon:runtime]'))
        coarse = mapping_residency(text)
        detailed = mapping_details(text)
        for category, metrics in coarse.items():
            for field in MAPPING_FIELDS:
                self.assertEqual(metrics[field], sum(row['kib'][field] for row in detailed
                                                     if row['category'] == category))
        self.assertEqual(sum(row['kib']['Rss'] for row in detailed), 32)
        self.assertEqual(sum(row['mappings'] for row in detailed), 8)

    def test_mapping_details_reject_partial_duplicate_or_malformed_records(self):
        valid = smap()
        invalid = [valid.replace('Rss: 4 kB\n', ''),
                   valid.replace('Rss: 4 kB', 'Rss: -4 kB'),
                   valid.replace('Rss: 4 kB', 'Rss: 4 B'),
                   valid + 'Rss: 4 kB\n',
                   valid.split('VmFlags:')[0],
                   valid + 'VmFlags: rd\n',
                   valid.replace('rd wr', 'rd rd wr'),
                   valid + '2000-3000 invalid 00000000 08:01 7 /unknown\n',
                   valid.replace('1000-2000', '2000-1000'),
                   'Rss: 4 kB\n', valid + 'truncated record\n']
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ValueError):
                mapping_details(text)

    def test_mapping_observation_limits_reject_instead_of_truncating(self):
        with mock.patch('block_v2_runtime_observer.MAX_MAPPING_GROUPS', 1):
            self.assertEqual(len(mapping_details(smap() * 2)), 1)
            with self.assertRaisesRegex(ValueError, 'groups exceed'):
                mapping_details(smap() + smap('/other'))
        with tempfile.TemporaryDirectory() as path:
            target = Path(path) / 'smaps'
            target.write_bytes(b'a' * 64)
            with mock.patch('block_v2_runtime_observer.MAX_SMAPS_BYTES', 64):
                self.assertEqual(read_smaps(target), 'a' * 64)
                target.write_bytes(b'a' * 65)
                with self.assertRaisesRegex(ValueError, 'exceeds observation limit'):
                    read_smaps(target)

    def test_non_utf8_mapping_paths_remain_distinguishable_in_json(self):
        import json
        with tempfile.TemporaryDirectory() as path:
            target = Path(path) / 'smaps'
            target.write_bytes(smap('/file-').encode().replace(b'/file-', b'/file-\xff'))
            rows = json.loads(json.dumps(mapping_details(read_smaps(target))))
            self.assertEqual(rows[0]['path'].encode('utf-8', 'surrogateescape'), b'/file-\xff')

    def test_live_mapping_details_reconcile_with_existing_census(self):
        text = read_smaps('/proc/self/smaps')
        rows = mapping_details(text)
        census = mapping_residency(text)
        self.assertGreater(len(rows), 0)
        for field in MAPPING_FIELDS:
            self.assertEqual(sum(row['kib'][field] for row in rows),
                             sum(row[field] for row in census.values()))

    def test_stat_comm_can_contain_parentheses_and_spaces(self):
        self.assertEqual(start_ticks(proc_stat(42)), 42)

    def test_status_does_not_confuse_virtual_and_resident_memory(self):
        values = numeric_status('Name:\tworker\nVmSize:\t1000000 kB\nVmRSS:\t20 kB\nThreads:\t12\n')
        self.assertEqual(values, {'VmSize': 1000000, 'VmRSS': 20, 'Threads': 12})

    def test_backing_census_keeps_anonymous_memory_unattributed(self):
        text = '''1000-2000 rw-p 00000000 00:00 0
Size: 8192 kB
Rss: 4 kB
Pss: 4 kB
2000-3000 r-xp 00000000 08:01 1 /usr/lib/libnvidia-opencl.so
Size: 4096 kB
Rss: 12 kB
Pss: 6 kB
3000-4000 rw-p 00000000 00:00 0 [stack]
Size: 1024 kB
Rss: 8 kB
4000-5000 rw-s 00000000 00:00 0 /dev/shm/nvidia (deleted)
Rss: 16 kB
'''
        census = mapping_residency(text)
        self.assertEqual(census['anonymous_unattributed']['Rss'], 4)
        self.assertEqual(census['anonymous_unattributed']['Size'], 8192)
        self.assertEqual(census['driver_backed']['Pss'], 6)
        self.assertEqual(census['labeled_stack']['Rss'], 8)
        self.assertEqual(census['shared_backing']['Rss'], 16)
        self.assertEqual(sum(item['Rss'] for item in census.values()), 40)

    def test_reject_reused_pid_cgroup_and_other_identity_changes(self):
        original = {'pid': 10, 'start_ticks': 42, 'group': '/fleet/worker',
                    'device': 29, 'inode': 100, 'boot': [3] * 16}
        check_identity(original, dict(original, invocation=[5] * 16))
        for key in original:
            changed = copy.deepcopy(original)
            changed[key] = '/other' if key == 'group' else [4] * 16 if key == 'boot' else 999
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, key):
                check_identity(original, changed)

    def test_disappearing_thread_does_not_end_worker_observation(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            for tid in ('1', '2'):
                task = root / 'task' / tid
                task.mkdir(parents=True)
                (task / 'stat').write_text(proc_stat(int(tid)))
            (root / 'task/1/comm').write_text('main\n')
            tasks, vanished = task_snapshot(root)
            self.assertEqual(tasks, {'1': {'name': 'main', 'start_ticks': 1}})
            self.assertEqual(vanished, [2])

    def test_reused_thread_is_not_misattributed(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root / 'task/1').mkdir(parents=True)
            with mock.patch.object(Path, 'read_text', side_effect=[proc_stat(1), 'thread', proc_stat(2)]):
                self.assertEqual(task_snapshot(root), ({}, [1]))

    def test_pidfd_observes_real_process_exit(self):
        observer = RuntimeObserver.__new__(RuntimeObserver)
        observer.result = {'pidfd_exit_observed': False}
        with subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'], stdin=subprocess.PIPE) as child:
            observer.pidfd = os.pidfd_open(child.pid)
            try:
                self.assertFalse(observer._exited())
                child.stdin.close()
                child.wait(timeout=5)
                self.assertTrue(observer._exited())
                self.assertTrue(observer.result['pidfd_exit_observed'])
            finally:
                os.close(observer.pidfd)

    def test_disappearing_process_files_wait_for_authoritative_pidfd_exit(self):
        with tempfile.TemporaryDirectory() as path:
            child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'],
                                     stdin=subprocess.PIPE)
            observer = RuntimeObserver(path, '/fleet.slice', sys.executable, duration=1)
            observer.observed = {'pid': child.pid}
            observer.pidfd = os.pidfd_open(child.pid)

            def exit_during_sample():
                child.stdin.close()
                raise FileNotFoundError('leader executable disappeared during exit')

            try:
                with (mock.patch.object(observer, '_protocol_identity'),
                      mock.patch.object(observer, '_sample', side_effect=exit_during_sample),
                      mock.patch.object(observer, '_exited', wraps=observer._exited) as exited):
                    observer.start()
                    observer.thread.join(2)
                    result = observer.finish(Path(path) / 'observation.json')
                self.assertEqual(result['ended'], 'pidfd_exit')
                self.assertEqual(result['interrupted_samples'], 1)
                self.assertTrue(result['pidfd_exit_observed'])
                self.assertEqual(result['errors'], [])
                self.assertEqual(result['samples'], [])
                self.assertTrue(any(0 < call.kwargs.get('timeout', 0) <= 0.25
                                    for call in exited.call_args_list))
            finally:
                child.stdin.close()
                child.wait(timeout=5)

    def test_missing_live_worker_file_fails_and_writes_no_exit_claim(self):
        with tempfile.TemporaryDirectory() as path:
            observer = RuntimeObserver(path, '/fleet.slice', sys.executable, duration=1)
            observer.observed = {'pid': os.getpid()}
            with mock.patch.object(observer, '_protocol_identity'), \
                 mock.patch.object(observer, '_exited', return_value=False), \
                 mock.patch.object(observer, '_sample', side_effect=FileNotFoundError('leader status')):
                observer.start()
                observer.thread.join(2)
                result = observer.finish(Path(path) / 'observation.json')
            self.assertEqual(result['ended'], 'error')
            self.assertEqual(result['interrupted_samples'], 1)
            self.assertFalse(result['pidfd_exit_observed'])
            self.assertIn('FileNotFoundError', result['errors'][0])

    def test_refuses_stale_identity_and_unbounded_capture(self):
        with tempfile.TemporaryDirectory() as path:
            identity = Path(path) / 'service-identity.json'
            identity.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'before'):
                RuntimeObserver(path, '/fleet.slice', sys.executable)
            identity.unlink()
            for settings in ({'duration': 1000}, {'interval': 0.001}):
                with self.assertRaisesRegex(ValueError, 'bounded'):
                    RuntimeObserver(path, '/fleet.slice', sys.executable, **settings)

    def test_retries_denied_pre_exec_discovery_without_claiming_attachment(self):
        with tempfile.TemporaryDirectory() as path:
            observer = RuntimeObserver(path, '/fleet.slice', sys.executable)
            observer.group = Path('/sys/fs/cgroup/fleet.slice/worker.service')
            with mock.patch.object(Path, 'read_text', return_value='42\n'), \
                 mock.patch.object(Path, 'stat', side_effect=PermissionError('executor')):
                observer._discover()
            self.assertIsNone(observer.observed)
            self.assertIsNone(observer.pidfd)
            self.assertEqual(observer.result['pre_attach_permission_retries'], 1)
            self.assertFalse(observer.result['protocol_identity_verified'])


if __name__ == '__main__':
    unittest.main()
