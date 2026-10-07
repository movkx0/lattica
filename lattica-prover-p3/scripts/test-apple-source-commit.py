#!/usr/bin/env python3
"""Exercise the next-Mac-commit guard in isolated repositories."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('source_check', Path(__file__).with_name('check-apple-source-commit.py'))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class SourceCheckpoint(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        for name in C.REQUIRED:
            self.write(name, '// source\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.STDOUT)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def test_missing_module_blocks_even_a_clean_index(self):
        self.git('rm', '-q', C.REQUIRED[0])
        with self.assertRaisesRegex(C.IncompleteSource, 'modules missing'):
            C.check(self.root)

    def test_unstaged_edits_and_new_helpers_block(self):
        self.write(C.REQUIRED[0], '// changed\n')
        self.write(f'{C.CRATE}/scripts/check-apple-priorities.py', 'print("check")\n')
        with self.assertRaises(C.IncompleteSource) as error:
            C.check(self.root)
        self.assertIn('Source edits omitted', str(error.exception))
        self.assertIn('New source files omitted', str(error.exception))

    def test_stage_captures_current_source_but_excludes_benchmark_outputs(self):
        self.write(C.REQUIRED[0], '// version one\n')
        self.git('add', C.REQUIRED[0])
        self.write(C.REQUIRED[0], '// version two\n')
        helper = f'{C.CRATE}/scripts/metal_kernel_variants.py'
        self.write(helper, 'print("variants")\n')
        self.write('benchmark-results/large-proof.bin', 'proof')
        changed = C.check(self.root, stage=True)
        self.assertEqual(changed, sorted([C.REQUIRED[0], helper]))
        self.assertEqual(self.git('show', ':' + C.REQUIRED[0]), b'// version two\n')
        self.assertNotIn(b'large-proof.bin', self.git('ls-files'))

    def test_ignored_source_is_not_silently_omitted_or_force_added(self):
        self.write('.gitignore', 'hidden.rs\n')
        hidden = f'{C.CRATE}/src/hidden.rs'
        self.write(hidden, '// new module\n')
        with self.assertRaisesRegex(C.IncompleteSource, 'Ignored source'):
            C.check(self.root, stage=True)
        self.assertNotIn(hidden.encode(), self.git('ls-files'))

    def test_complete_source_passes_without_creating_a_commit(self):
        before = self.git('rev-parse', 'HEAD')
        self.assertEqual(C.check(self.root), [])
        self.assertEqual(self.git('rev-parse', 'HEAD'), before)

    def test_stage_records_source_deletions(self):
        old = f'{C.CRATE}/src/old_helper.rs'
        self.write(old, '// obsolete\n')
        self.git('add', old)
        self.git('commit', '-qm', 'old helper')
        (self.root / old).unlink()
        self.assertEqual(C.check(self.root, stage=True), [old])
        self.assertNotIn(old.encode(), self.git('ls-files'))

    def test_conflicts_block_before_staging_other_source(self):
        name = C.REQUIRED[0]
        self.git('checkout', '-qb', 'other')
        self.write(name, '// other\n')
        self.git('commit', '-qam', 'other source')
        self.git('checkout', '-qb', 'checkpoint', 'HEAD~1')
        self.write(name, '// checkpoint\n')
        self.git('commit', '-qam', 'checkpoint source')
        with self.assertRaises(subprocess.CalledProcessError):
            self.git('merge', '--no-edit', 'other')
        helper = f'{C.CRATE}/scripts/new_helper.py'
        self.write(helper, 'print("new")\n')
        with self.assertRaisesRegex(C.IncompleteSource, 'Resolve merge conflicts'):
            C.check(self.root, stage=True)
        self.assertNotIn(helper.encode(), self.git('ls-files'))


if __name__ == '__main__':
    unittest.main()
