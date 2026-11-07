"""Commitment data-path qualification based on afb529b, with a fresh 60-minute ledger.

Builds are excluded. Failed/stopped tests count. Existing public fixtures only.
Both proof arms use combined/existing hash/identity overlap; only the path varies.
"""
import argparse
import collections
import json
from pathlib import Path
import statistics

from cpu_proof_latency_campaign import Campaign, ROOT, RUNS, SIMD, CARGO

DATA = ROOT / '.tools/cpu-proof-commitment'
BASE_COMMIT = 'afb529bf198b8f4afbcbf56efdec61aed3e2e6fc'
PATHS = ('existing', 'replay', 'packed', 'chunked')


def body(record):
    return record['cpu_proof_acceptance']['records'][0]


def screen_score(rows, candidate):
    keys = {(h, t, w, n) for h in (18, 21) for t in (4, 16)
        for w, n in ((94, 1), (200, 1), (51, 1), (3, 16))}
    def samples(path):
        return {k: [r['commit_ns'] for r in rows if r['commitment_path'] == path and
            (r['height'].bit_length()-1, r['threads'], r['width'], r['matrices']) == k] for k in keys}
    baseline, values = samples('existing'), samples(candidate)
    if any(not baseline[k] or not values[k] for k in keys):
        raise RuntimeError('incomplete commitment screen grid')
    ratios = [statistics.median(values[k]) / statistics.median(baseline[k]) for k in sorted(keys)]
    return dict(geomean_ratio=statistics.geometric_mean(ratios), worst_ratio=max(ratios),
        eligible=max(ratios) <= 1.03 and statistics.geometric_mean(ratios) < 1)


def proof_gates(targets, references, candidates):
    target_times = [c['observation']['service_ns'] for r in targets for j in body(r)['jobs']
        for c in j.get('comparisons', []) if c['candidate']]
    if not target_times or not references or len(references) != len(candidates):
        raise RuntimeError('incomplete initial proof grid')
    def families(records):
        out = collections.defaultdict(list)
        for r in records:
            for j in body(r)['jobs']:
                out[j['id'] % 9].append(j['cold_input_service_upper_ns'])
        if set(out) != set(range(9)):
            raise RuntimeError('all nine native families required')
        return out
    ref, cand = families(references), families(candidates)
    return dict(cold_recursive_under_60s=max(target_times) < 60e9,
        cold_native_under_60s=max(max(v) for v in cand.values()) < 60e9,
        throughput_preserved=statistics.median(body(r)['wall_ns'] for r in candidates)
            <= statistics.median(body(r)['wall_ns'] for r in references),
        no_family_regression_over_3pct=all(statistics.median(cand[k]) <= 1.03*statistics.median(ref[k]) for k in ref))


class CommitmentCampaign(Campaign):
    def __init__(self, revision, inputs=DATA):
        super().__init__(revision, inputs, data=DATA, prefix='cpu-commit')

    def save(self, name, value):
        (self.data / f'{name}-{self.revision}.json').write_text(json.dumps(value, indent=2) + '\n')

    def tests(self):
        super().tests()
        result = self.budget.run(self.label('campaign-tests'), ['python3', '-m', 'unittest',
            'test_cpu_commitment_campaign'], cwd=ROOT / 'research/pq-ringct/tools')
        if result['status'] != 'passed':
            raise RuntimeError(Path(result['log']).read_text())

    def screen(self):
        rows = []
        def one(phase, path, height, threads, repetitions):
            # Correctness and screen allowance is eight charged minutes, not wall
            # time spent editing/building or the old campaign's elapsed time.
            remaining = 480 - (3600 - self.budget.remaining())
            if remaining <= 31:
                raise RuntimeError('correctness/screen budget exhausted; no candidate qualified')
            record = self.guard(f'{phase}-{path}-h{height}-w{threads}', ['--profile', 'cpu-commitment',
                '--build-label', self.label('screen-build')], [SIMD / 'release/examples/cpu_commitment_profile',
                'combined', '256', 'existing', str(threads), path, str(height), str(repetitions)],
                test_seconds=min(300, int(remaining - 30)))
            return record['cpu_commitment_acceptance']
        for height in (18, 21):
            for threads in (4, 16):
                for path in PATHS:
                    rows.extend(one('screen', path, height, threads, 1))
        scores = {p: screen_score(rows, p) for p in PATHS[1:]}
        eligible = [p for p in PATHS[1:] if scores[p]['eligible']]
        selection = dict(schema='cpu-commitment-selection-v1', base_commit=BASE_COMMIT,
            revision=self.revision, commitment_path='existing', eligible=False, scores=scores,
            preliminary_rows=rows, confirmation_rows=[])
        self.save('selection', selection)
        if eligible:
            winner = min(eligible, key=lambda p: scores[p]['geomean_ratio'])
            confirmed = []
            for height in (18, 21):
                for threads in (4, 16):
                    order = ('existing', winner) if threads == 4 else (winner, 'existing')
                    for path in order:
                        confirmed.extend(one('confirm', path, height, threads, 3))
            score = screen_score(confirmed, winner)
            selection.update(confirmation=score, confirmation_rows=confirmed,
                commitment_path=winner if score['eligible'] else 'existing', eligible=score['eligible'])
            self.save('selection', selection)
        print('SELECTION', json.dumps({k:v for k,v in selection.items() if not k.endswith('_rows')}), flush=True)

    def proof(self, name, n=4, candidate=True, mode='native-mix', request=0, compare=False, first=False):
        selected = self.selection()
        if not selected['eligible']:
            raise RuntimeError('no commitment path passed screening')
        path = selected['commitment_path'] if candidate else 'existing'
        workers = 1 if compare else (2 if n == 3 else 4)
        args = [SIMD / 'release/pq-ringct-cpu-proof', '--case', f'n{n}', '--workload', '0',
            '--input', self.inputs / f'n{n}-w0.json', '--cpu-variant', 'combined',
            '--cpu-hash-kernel', 'existing', '--cpu-commitment-path', path, '--identity-overlap', '1',
            '--workers', str(workers), '--threads-per-proof', str(16 // workers), '--retain', '0',
            '--mode', mode, '--request', str(request), '--segments', '2' if compare else '1']
        if compare:
            args += ['--transaction', '0', '--compare-target', '1', '--candidate-first', '1' if first else '0',
                '--baseline-identity-overlap', '1']
        return self.guard(name, ['--profile', 'cpu-proof', '--cpu-proof', '--cpu-proof-detail',
            '--host-profile', 'standard' if n == 3 else 'expanded-36', '--build-label', self.label('runner-build')], args)

    def qualify(self):
        if not self.selection()['eligible']:
            self.save('qualification', dict(qualified=False, complete=False, reason='component screen failed'))
            return
        targets, references, candidates = [], [], []
        for trial in range(3):
            for mode, request in [('paired', 1), ('graph-parent', 4)]:
                targets.append(self.proof(f'{mode}-t{trial}', mode=mode, request=request, compare=True, first=trial % 2 == 1))
            for candidate in ((False, True) if trial % 2 == 0 else (True, False)):
                record = self.proof(f'native-t{trial}-' + ('candidate' if candidate else 'reference'), candidate=candidate)
                (candidates if candidate else references).append(record)
            gates = proof_gates(targets, references, candidates)
            self.save('qualification', dict(qualified=False, complete=False, completed_pairs=trial+1, gates=gates))
            if not all(gates.values()):
                self.save('qualification', dict(qualified=False, complete=False, completed_pairs=trial+1, gates=gates,
                    reason='latency or throughput gate failed; additional qualification stopped'))
                print('EARLY_EXIT', json.dumps(gates), flush=True)
                return
        smoke = self.proof('n3-smoke', n=3)
        gates['n3_cold_under_60s'] = max(j['cold_input_service_upper_ns'] for j in body(smoke)['jobs']) < 60e9
        self.save('qualification', dict(qualified=all(gates.values()), complete=True, completed_pairs=3, gates=gates))

    def compatibility(self):
        for name, manifest, features in [('cpu-default', 'lattica-prover-p3/Cargo.toml', 'block-v2-wide-lanes,recursion,lookup'),
                ('opencl', 'research/pq-ringct/Cargo.toml', 'native-matrict,opencl')]:
            self.guard(name+'-compat-build', ['--profile','build'], [CARGO,'check','--locked','--offline',
                '--no-default-features','--manifest-path',manifest,'--features',features,'--lib','-j2'],build=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('build','tests','screen','qualify','compatibility','summary'))
    parser.add_argument('--revision', default='r1')
    parser.add_argument('--input-dir', type=Path, default=DATA)
    parser.add_argument('--build-kind', choices=('core-generic','core-v3','research','screen','runner'))
    args = parser.parse_args()
    campaign = CommitmentCampaign(args.revision, args.input_dir)
    if args.phase == 'build':
        campaign.build(args.build_kind)
    elif args.phase == 'summary':
        print(json.dumps(campaign.budget.read(), indent=2))
    else:
        getattr(campaign, args.phase)()


if __name__ == '__main__':
    main()
