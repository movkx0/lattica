"""Bounded imported-proof GPU campaign. Builds are outside the 3600s test ledger.

Never launches full N3/N4 implicitly: prepare-inputs, screens, and run are
separate commands. Every hardware job uses the existing exclusive guard.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from gpu_aggregation_profile import AggregationBudget, qualification

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / '.tools/gpu-aggregation'
RUNS = ROOT / '.tools/pq-opencl-opt/runs'
GUARD = ROOT / 'research/pq-ringct/tools/opencl_private_spend_validate.py'
CARGO = Path('/home/access/code/lattica/.tools/rust-1.96.0/bin/cargo')
TARGET = ROOT / '.tools/target-opencl'


class Campaign:
    def __init__(self, revision='r1', data=DATA):
        self.revision, self.data = revision, data
        data.mkdir(parents=True, exist_ok=True)
        self.budget = AggregationBudget(data / 'test-budget.json')

    def label(self, name):
        return f'gpu-agg-{name}-{self.revision}'

    def guard(self, name, flags, command, build=False, seconds=600):
        label = self.label(name)
        def argv(timeout):
            actual_command=list(map(str,command))
            if '--timeout-seconds' in actual_command:
                index=actual_command.index('--timeout-seconds')+1
                actual_command[index]=str(min(timeout,int(actual_command[index])))
            return [sys.executable, str(GUARD), '--label', label, '--seconds', str(timeout),
                    '--execute', '--exclusive-window', *flags, '--', *actual_command]
        print('START', label, 'build' if build else f'remaining={self.budget.remaining():.1f}s', flush=True)
        if build:
            with (self.data / (label + '.controller.log')).open('w') as out:
                code = subprocess.run(argv(1200), cwd=ROOT, stdout=out, stderr=subprocess.STDOUT).returncode
        else:
            attempt = self.budget.run(label, argv, guard_unit='lattica-opencl-opt-' + label + '.service',
                                      cwd=ROOT, seconds=seconds)
            code = 0 if attempt['status'] == 'passed' else 1
        record_path = RUNS / (label + '.json')
        record = json.loads(record_path.read_text()) if record_path.exists() else {}
        print('DONE', label, record.get('status'), record.get('wall_seconds'), record.get('error', ''), flush=True)
        if code or record.get('status') != 'passed':
            raise RuntimeError((self.data / (label + '.controller.log')).read_text()[-3000:])
        return record

    def build(self, kind):
        common = ['--release', '--locked', '--offline', '--no-default-features',
                  '--config', 'profile.release.lto=false', '--config', 'profile.release.codegen-units=16', '-j2']
        if kind == 'runner':
            self.guard('runner-build', ['--profile', 'build', '--record-artifact', str(TARGET / 'release/pq-ringct-gpu-aggregate')],
                       [CARGO, 'build', *common, '--manifest-path', 'research/pq-ringct/Cargo.toml',
                        '--features', 'gpu-aggregation-experiment', '--bin', 'pq-ringct-gpu-aggregate'], build=True)
        else:
            core = kind == 'core'
            self.guard(kind + '-build', ['--profile', 'build'], [CARGO, 'test', *common, '--no-run', '--lib',
                       '--manifest-path', 'lattica-prover-p3/Cargo.toml' if core else 'research/pq-ringct/Cargo.toml',
                       '--features', 'block-v2-wide-lanes,gpu,gpu-tuning,stream,ringct-research-quota,gpu-bounded-info'
                       if core else 'gpu-aggregation-experiment'], build=True)

    def test(self, kind, gpu=False, uuid=None):
        record = json.loads((RUNS / (self.label(kind + '-build') + '.json')).read_text())
        executables = record['cargo_test_emitted_executables']
        if len(executables) != 1:
            raise RuntimeError('ambiguous test executable')
        filters = (['gpu_fused_witness_matches_cpu', 'gpu_same_epoch_prefix', 'gpu_specialized_cache_reuses'] if gpu else
                   ['wave_batches::tests', 'program_cache_is_bounded_lru', 'tuning::tests', 'identity_batch_plan_rejects']
                   if kind == 'core' else ['gpu_aggregation::', 'imported_group_layout_tests'])
        flags = ['--profile', 'full' if gpu else 'build', '--expect-tests', '--build-label', self.label(kind + '-build')]
        if gpu:
            if not uuid:
                raise RuntimeError('GPU tests need a physical UUID')
            flags += ['--device-uuid', uuid, '--retained-tree-storage', 'host']
        return self.guard(kind + ('-gpu-tests' if gpu else '-tests'), flags,
                          [executables[0], *filters, '--test-threads=1', '--nocapture', *(['--ignored'] if gpu else [])])

    def python_tests(self):
        result = self.budget.run(self.label('python-tests'), [sys.executable, '-m', 'unittest',
            'test_gpu_aggregation_profile', 'test_gpu_aggregation_memory', 'test_cpu_proof_budget', 'test_opencl_private_spend_validate'],
            cwd=ROOT / 'research/pq-ringct/tools')
        if result['status'] != 'passed':
            raise RuntimeError(Path(result['log']).read_text())
        return result

    def driver(self, name, command, case, bundle, uuid, extra=(), seconds=600):
        return self.guard(name, ['--profile', 'full', '--gpu-aggregation', '--device-uuid', uuid,
            '--retained-tree-storage', 'host', '--host-profile', 'standard' if case == 'n3' else 'expanded-36',
            '--build-label', self.label('runner-build')], [TARGET / 'release/pq-ringct-gpu-aggregate', command,
            '--case', case, '--input-bundle', bundle, '--timeout-seconds', str(seconds), *extra], seconds=seconds)

    def summary(self):
        records = [json.loads(p.read_text()) for p in RUNS.glob(f'gpu-agg-*-{self.revision}.json')]
        return dict(budget=self.budget.read(), **qualification(records))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('build', 'tests', 'gpu-tests', 'python-tests', 'driver', 'summary', 'extend-budget'))
    parser.add_argument('--revision', default='r1')
    parser.add_argument('--kind', choices=('core', 'research', 'runner'), default='runner')
    parser.add_argument('--label')
    parser.add_argument('--command', choices=('plan', 'prepare-inputs', 'screen', 'run', 'qualify-memory'))
    parser.add_argument('--case', choices=('n3', 'n4'), default='n3')
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--device-uuid')
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--extension-id')
    parser.add_argument('--additional-seconds', type=int)
    args, extra = parser.parse_known_args()
    if args.phase != 'driver' and extra:
        parser.error('unexpected arguments')
    campaign = Campaign(args.revision)
    if args.phase == 'extend-budget':
        result = campaign.budget.extend(args.extension_id, args.additional_seconds)
    elif args.phase == 'build':
        result = campaign.build(args.kind)
    elif args.phase in ('tests', 'gpu-tests'):
        result = campaign.test(args.kind, args.phase == 'gpu-tests', args.device_uuid)
    elif args.phase == 'python-tests':
        result = campaign.python_tests()
    elif args.phase == 'summary':
        result = campaign.summary()
    else:
        if not all((args.label, args.command, args.bundle, args.device_uuid)):
            parser.error('driver requires label, command, bundle and device UUID')
        extra = extra[1:] if extra[:1] == ['--'] else extra
        result = campaign.driver(args.label, args.command, args.case, args.bundle, args.device_uuid, extra, args.seconds)
    if result is not None:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
