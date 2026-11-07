"""Focused CPU latency qualification. Builds are separate from a 3600s test ledger.

Use build, tests, screen, smoke, native, targets, then summary. Public N3/N4
input files must already exist as n3-w0.json and n4-w0.json in --input-dir.
No transaction generation or full-workflow proof run is started here.
"""
import argparse
import json
from pathlib import Path
import statistics
import subprocess
import sys

from cpu_proof_budget import Budget

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / '.tools/cpu-proof-latency'
RUNS = ROOT / '.tools/pq-opencl-opt/runs'
GUARD = ROOT / 'research/pq-ringct/tools/opencl_private_spend_validate.py'
CARGO = Path('/home/access/code/lattica/.tools/rust-1.96.0/bin/cargo')
SIMD = ROOT / '.tools/target-cpu-v3'
GENERIC = ROOT / '.tools/target-opencl'


class Campaign:
    def __init__(self, revision, inputs, data=DATA, prefix="cpu-latency"):
        self.data, self.prefix = data, prefix
        self.revision, self.inputs = revision, inputs
        self.data.mkdir(parents=True, exist_ok=True)
        self.budget = Budget(self.data / 'test-budget.json')

    def label(self, name):
        return f'{self.prefix}-{name}-{self.revision}'

    def guard(self, name, flags, command, build=False, test_seconds=300):
        label = self.label(name)
        def argv(seconds):
            return [sys.executable, str(GUARD), '--label', label, '--seconds', str(seconds),
                '--execute', '--exclusive-window', *flags, '--', *map(str, command)]
        print('START', label, 'build' if build else f'test_remaining={self.budget.remaining():.1f}s', flush=True)
        if build:
            with (self.data / (label + '.controller.log')).open('w') as out:
                code = subprocess.run(argv(1200), cwd=ROOT, stdout=out, stderr=subprocess.STDOUT).returncode
        else:
            attempt = self.budget.run(label, argv, guard_unit='lattica-opencl-opt-' + label + '.service', cwd=ROOT, seconds=test_seconds)
            code = 0 if attempt['status'] == 'passed' else 1
        path = RUNS / (label + '.json')
        record = json.loads(path.read_text()) if path.exists() else {}
        print('DONE', label, record.get('status'), record.get('wall_seconds'), record.get('error', ''), flush=True)
        if code or record.get('status') != 'passed':
            log = self.data / (label + '.controller.log')
            raise RuntimeError(log.read_text()[-3000:])
        return record

    def build(self, only=None):
        test_common = ['test', '--release', '--locked', '--offline', '--no-default-features',
            '--config', 'profile.release.lto=false', '--config', 'profile.release.codegen-units=16',
            '--no-run', '--lib', '-j2']
        jobs = {
            'core-generic': ([], [*test_common, '--manifest-path', 'lattica-prover-p3/Cargo.toml',
                '--features', 'cpu-proof-experiment,block-v2-wide-lanes,recursion,lookup']),
            'core-v3': (['--build-cpu-target', 'x86-64-v3'], [*test_common, '--target-dir', str(SIMD),
                '--manifest-path', 'lattica-prover-p3/Cargo.toml', '--features', 'cpu-proof-experiment,block-v2-wide-lanes,recursion,lookup']),
            'research': ([], [*test_common, '--manifest-path', 'research/pq-ringct/Cargo.toml', '--features', 'cpu-proof-experiment']),
            'screen': (['--build-cpu-target', 'x86-64-v3', '--record-artifact', str(SIMD / 'release/examples/cpu_commitment_profile')],
                ['build', '--release', '--locked', '--offline', '--no-default-features', '--manifest-path', 'lattica-prover-p3/Cargo.toml',
                    '--features', 'cpu-proof-experiment', '--example', 'cpu_commitment_profile', '--target-dir', str(SIMD), '-j2']),
            'runner': (['--build-cpu-target', 'x86-64-v3', '--record-artifact', str(SIMD / 'release/pq-ringct-cpu-proof')],
                ['build', '--release', '--locked', '--offline', '--no-default-features', '--manifest-path', 'research/pq-ringct/Cargo.toml',
                    '--features', 'cpu-proof-experiment', '--bin', 'pq-ringct-cpu-proof', '--target-dir', str(SIMD), '-j2']),
        }
        for name, (flags, args) in jobs.items():
            if only is None or name == only:
                self.guard(name + '-build', ['--profile', 'build', *flags], [CARGO, *args], build=True)

    def tests(self):
        attempt = self.budget.run(self.label('python-all'), [sys.executable, '-m', 'unittest',
            'test_cpu_proof_profile', 'test_cpu_proof_budget', 'test_opencl_private_spend_validate', 'test_cpu_build_target'],
            cwd=ROOT / 'research/pq-ringct/tools')
        if attempt['status'] != 'passed':
            raise RuntimeError(Path(attempt['log']).read_text())
        for name, filters in [('core-generic', ['cpu_commitment::', 'compact_salts::tests', 'identity_cpu::tests', 'proof_capacity::tests']),
                ('core-v3', ['cpu_commitment::', 'compact_salts::tests', 'identity_cpu::tests', 'proof_capacity::tests']),
                ('research', ['cpu_proof::tests'])]:
            build = json.loads((RUNS / (self.label(name + '-build') + '.json')).read_text())
            executables = build['cargo_test_emitted_executables']
            if len(executables) != 1:
                raise RuntimeError('ambiguous unit-test executable')
            self.guard(name + '-tests', ['--profile', 'build', '--expect-tests',
                '--build-label', self.label(name + '-build')], [executables[0], '--test-threads=1', *filters])

    def screen(self):
        samples = {}
        for threads in (4, 16):
            for kernel in ('existing', 'interleaved2', 'interleaved4'):
                record = self.guard(f'screen-{threads}-{kernel}', ['--profile', 'cpu-commitment',
                    '--build-label', self.label('screen-build')],
                    [SIMD / 'release/examples/cpu_commitment_profile', 'combined', '256', kernel, str(threads)])
                for row in record['cpu_commitment_acceptance']:
                    samples.setdefault((kernel, threads, row['width'], row['matrices']), []).append(row['commit_ns'])
        scores = {}
        for kernel in ('interleaved2', 'interleaved4'):
            ratios = [statistics.median(v) / statistics.median(samples[('existing', t, w, n)])
                for (k, t, w, n), v in samples.items() if k == kernel]
            scores[kernel] = dict(geomean_ratio=statistics.geometric_mean(ratios), worst_ratio=max(ratios),
                eligible=max(ratios) <= 1.03 and statistics.geometric_mean(ratios) < 1)
        eligible = [k for k in scores if scores[k]['eligible']]
        kernel = min(eligible, key=lambda k: scores[k]['geomean_ratio']) if eligible else 'existing'
        selection = dict(schema='cpu-proof-kernel-selection-v1', revision=self.revision,
            hash_kernel=kernel, identity_overlap=True, scores=scores)
        (self.data / ('selection-' + self.revision + '.json')).write_text(json.dumps(selection, indent=2) + '\n')
        print('SELECTION', json.dumps(selection), flush=True)

    def selection(self):
        selected = json.loads((self.data / ('selection-' + self.revision + '.json')).read_text())
        if selected.get('revision') != self.revision:
            raise RuntimeError('selection build revision mismatch')
        return selected

    def proof(self, name, n=4, candidate=True, mode='native-mix', request=0, compare=False, first=False):
        kernel = self.selection()['hash_kernel'] if candidate else 'existing'
        workers = 1 if compare else (2 if n == 3 else 4)
        args = [SIMD / 'release/pq-ringct-cpu-proof', '--case', f'n{n}', '--workload', '0',
            '--input', self.inputs / f'n{n}-w0.json', '--cpu-variant', 'combined' if candidate else 'reference',
            '--cpu-hash-kernel', kernel, '--identity-overlap', '1' if candidate else '0',
            '--workers', str(workers), '--threads-per-proof', str(16 // workers), '--retain', '0',
            '--mode', mode, '--request', str(request), '--segments', '2' if compare else '1']
        if compare:
            args += ['--transaction', '0', '--compare-target', '1', '--candidate-first', '1' if first else '0']
        return self.guard(name, ['--profile', 'cpu-proof', '--cpu-proof', '--cpu-proof-detail',
            '--host-profile', 'standard' if n == 3 else 'expanded-36', '--build-label', self.label('runner-build')], args)

    def native(self):
        for trial in range(3):
            for candidate in ((False, True) if trial % 2 == 0 else (True, False)):
                self.proof(f'native-t{trial}-' + ('candidate' if candidate else 'reference'), candidate=candidate)

    def targets(self):
        for trial in range(3):
            for mode, request in [('paired', 1), ('graph-parent', 4)]:
                self.proof(f'{mode}-t{trial}', mode=mode, request=request, compare=True, first=trial % 2 == 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('build', 'tests', 'screen', 'smoke', 'native', 'targets', 'summary'))
    parser.add_argument('--revision', default='r1')
    parser.add_argument('--input-dir', type=Path, default=DATA)
    parser.add_argument('--build-kind', choices=('core-generic', 'core-v3', 'research', 'screen', 'runner'))
    args = parser.parse_args()
    campaign = Campaign(args.revision, args.input_dir)
    if args.phase == 'build':
        campaign.build(args.build_kind)
    elif args.phase == 'smoke':
        campaign.proof('n3-smoke', n=3)
    elif args.phase == 'summary':
        print(json.dumps(campaign.budget.read(), indent=2))
    else:
        getattr(campaign, args.phase)()


if __name__ == '__main__':
    main()
