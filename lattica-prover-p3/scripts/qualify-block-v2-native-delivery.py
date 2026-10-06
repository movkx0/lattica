#!/usr/bin/env python3
"""Qualify three native heights and an alternate branch with fresh real roots.

This is an opt-in boundary qualification, not the two-hour throughput pilot.
The pinned GPU command must already perform resource admission and an
independent CPU root audit. No builds or report rendering run during proving.
"""

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import block_v2_host_store as H
import block_v2_native_delivery as D


def open_host(config):
    for source in config['pins']:
        if D.pin(Path(source['path'])) != source:
            raise ValueError('pinned delivery input changed: ' + source['path'])
    return H.NativeVerifier(
        config['library'], Path(config['registry']).read_bytes(),
        bytes.fromhex(config['profile_id']), bytes.fromhex(config['chain_id']),
        Path(config['genesis']).read_bytes(),
        H.IssuancePolicy({int(h): {int(i): n for i, n in grants.items()}
                         for h, grants in config['issuance_grants'].items()}))


def child(config_path, directory):
    config = json.loads(Path(config_path).read_bytes())
    view = H.Store(directory, open_host(config)).read()
    print(json.dumps(asdict(view), sort_keys=True))


def run(command, log, timeout):
    with log.open('x') as handle:
        process = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            return 124


def qualify(config, out, result):
    verifier = open_host(config)
    # The qualified resource profile accounts tmpfs spill against host RAM.
    # Reject a different filesystem before preparing any fresh wallet proofs.
    scratch_root = Path(config['scratch_root']).resolve()
    scratch_root.mkdir(parents=True, exist_ok=False)
    filesystem = subprocess.run(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(scratch_root)],
                                check=True, capture_output=True, text=True).stdout.strip()
    if filesystem != 'tmpfs':
        raise ValueError('qualified GPU profile requires explicitly selected tmpfs scratch')
    result['scratch'] = {'path': str(scratch_root), 'filesystem': filesystem,
                         'spill_charged_to_host_ram': True}
    store = H.Store.create(out / 'journal', verifier)
    checks, stages = result['checks'], result['stages']

    def save():
        temporary = out / 'summary.json.tmp'
        temporary.write_bytes(H.canonical(result))
        temporary.replace(out / 'summary.json')

    def check(name, condition):
        if not condition:
            raise ValueError(name)
        checks.append(name)
        save()

    def rejected(name, action, exception=H.RejectedBlock):
        before = store.read()
        try:
            action()
        except exception:
            check(name, store.read() == before)
        else:
            raise ValueError('unexpected acceptance: ' + name)

    def restart(label, expected):
        log = out / (label + '-restart.json')
        command = [sys.executable, str(Path(__file__).resolve()), '--child',
                   str(out / 'inputs.json'), str(store.directory)]
        status = run(command, log, 180)
        check(label + ': fresh process replays exact published state',
              status == 0 and json.loads(log.read_bytes()) == asdict(expected))

    def deliver(label, indices):
        begin = time.monotonic()
        fixture, root = out / (label + '-fixture'), out / (label + '-root')
        stage = {'label': label, 'status': 'preparing', 'indices': indices}
        stages.append(stage)
        save()
        prepared = D.prepare_batch(store, indices, config['registry_fixture'], config['cpu_probe'], fixture)
        stage['preparation'] = D.pin(fixture / 'manifest.json')
        stage['preparation_seconds'] = prepared['elapsed_seconds']
        stage['height'] = prepared['height']
        # Check that explicit later-height host policy cannot silently fall back
        # to the fixed demo policy, nor accept a worker-selected context/mint.
        stage['policy_rejections'] = []
        for mutation in ('height', 'issuance', 'chain', 'root'):
            changed = json.loads((fixture / 'expected.json').read_bytes())
            if mutation == 'height':
                changed['block_height'] += 1
            elif mutation == 'issuance':
                changed['authorized_issuance']['3'] += 1
            else:
                changed[mutation][0] ^= 1
            path = out / (label + '-wrong-' + mutation + '.json')
            path.write_bytes(H.canonical(changed))
            log = out / (label + '-wrong-' + mutation + '.log')
            rejected_status = run([config['cpu_probe'], 'plan', str(fixture), str(path)], log, 60)
            check(label + ': Rust rejects changed host ' + mutation, rejected_status == 1)
            stage['policy_rejections'].append({'case': mutation, 'exit_code': rejected_status,
                                               'input': D.pin(path), 'log': D.pin(log)})
        stage['status'] = 'proving'
        scratch = scratch_root / label
        scratch.mkdir(exist_ok=False)
        substitutions = {'fixture': str(fixture), 'output': str(root),
                         'scratch': str(scratch)}
        command = [part.format(**substitutions) for part in config['gpu_command']]
        stage['command'] = command
        save()
        print(json.dumps({'event': 'proving', 'stage': label, 'height': prepared['height']}), flush=True)
        log = out / (label + '-controller.log')
        status = run(command, log, 7500)
        stage.update(exit_code=status, log=D.pin(log))
        if status:
            raise ValueError(label + ': proving controller failed')
        root_result = json.loads((root / 'summary.json').read_bytes())
        if (root_result.get('status') != 'succeeded'
                or not root_result['result'].get('cpu_audited')
                or root_result['result'].get('count') != len(indices)
                or root_result['result'].get('fresh_proofs') != 4
                or not 0 < root_result['result'].get('root_bytes', 0) <= H.MAX_PROOF_BYTES):
            raise ValueError('root audit/coverage/size requirement failed')
        proof = root / '001-typed/root-only/node.6.0'
        candidate = H.Candidate(prepared['height'], (fixture / 'complete-body.bin').read_bytes(), proof.read_bytes())
        commit_started = time.monotonic()
        view = D.apply_prepared(store, fixture, proof)
        stage.update(status='succeeded', root_summary=D.pin(root / 'summary.json'),
                     proof=D.pin(proof), root_bytes=len(candidate.proof),
                     fresh_recursive_proofs=root_result['result']['fresh_proofs'],
                     worker_seconds=root_result['result']['elapsed_seconds'],
                     native_commit_seconds=time.monotonic() - commit_started,
                     preparation_through_commit_seconds=time.monotonic() - begin,
                     native_state=view.state, head_token=view.token,
                     resource_accounting=root_result['accounting'])
        check(label + ': complete bodies and proof retained',
              store.snapshot()[1][-1] == candidate)
        restart(label, view)
        print(json.dumps({'event': 'delivered', 'stage': label, 'height': view.state['height']}), flush=True)
        return view, candidate, fixture, proof

    genesis = store.read()
    check('public funded genesis covers planned arrivals',
          genesis.state['height'] == 9 and genesis.state['outputs'] == 1408
          and genesis.state['supply']['issued'] == '704000')
    rejected('unfunded slot rejected before proving', lambda: verifier.prepare_wallet([], 704))
    first, first_candidate, first_fixture, first_proof = deliver('first', [0, 5, 10, 15])
    _, history = store.snapshot()
    rejected('spent delivery slot rejected before leaf proof', lambda: verifier.prepare_wallet(history, 0))
    corrupt = H.Candidate(10, first_candidate.body, first_candidate.proof[:-1])
    rejected('wallet preparation verifies history proofs', lambda: verifier.prepare_wallet([corrupt], 64))
    second, second_candidate, second_fixture, second_proof = deliver('second', [64, 69, 74, 79])
    third, third_candidate, third_fixture, third_proof = deliver('third', [688, 693, 698, 703])
    check('three heights have exact supply, notes, nullifiers and events',
          third.state['height'] == 12 and third.state['blocks'] == 3
          and third.state['outputs'] == 1432 and third.state['nullifiers'] == 24
          and third.state['events'] == 3
          and third.state['supply'] == {'issued': '704021', 'shielded_pool': '704021',
                                       'burned': '0', 'fees_paid': '0'})
    check('each height uses a different current anchor',
          len({genesis.state['anchor'], first.state['anchor'], second.state['anchor'], third.state['anchor']}) == 4)
    rejected('completed preparation cannot be applied twice',
             lambda: D.apply_prepared(store, third_fixture, third_proof), H.StaleHead)
    bad_height = H.Candidate(13, third_candidate.body, third_candidate.proof)
    rejected('prior proof and bodies cannot be reused at a later height',
             lambda: store.commit(bad_height, expected_head=third.token))
    rolled_back = store.reorganize(first.tip, [], expected_head=third.token)
    check('rollback restores exact first-height native state', rolled_back.state == first.state)
    rejected('ABA return to a parent fences old prepared result',
             lambda: D.apply_prepared(store, second_fixture, second_proof), H.StaleHead)
    alternate, alternate_candidate, _, _ = deliver('alternate-second', [80, 85, 90, 95])
    check('alternative height 11 changes the native state and event roots',
          alternate.state['height'] == 11 and alternate.state['state_root'] != second.state['state_root']
          and alternate.state['event_root'] != second.state['event_root'])
    rejected('old third-height result is fenced after reorg',
             lambda: D.apply_prepared(store, third_fixture, third_proof), H.StaleHead)
    # A second-height proof anchors to the original first block. It cannot be
    # grafted directly on the alternate second block even if its height is edited.
    rejected('native replay rejects mismatched replacement ancestry',
             lambda: store.reorganize(first.tip, [alternate_candidate, third_candidate],
                                     expected_head=alternate.token))
    restored = store.reorganize(first.tip, [second_candidate, third_candidate], expected_head=alternate.token)
    check('multi-height reorg restores exact former native state', restored.state == third.state)
    restart('restored-three-heights', restored)
    check('reorg retains all four immutable records', len(list((store.directory / 'records').glob('*.json'))) == 4)
    check('all funding participants exercised at each height', all(
        {wallet['participant'] for wallet in json.loads((out / (stage['label'] + '-fixture/manifest.json')).read_bytes())['wallets']} == {0, 1, 2, 3}
        for stage in stages))
    open_host(config)
    result.update(status='succeeded', multi_height_native_delivery_qualified=True,
                  fresh_recursive_proofs=16, fresh_leaf_proofs=16, canonical_blocks=3,
                  canonical_useful_transactions=9, alternate_useful_transactions=3,
                  final_state=restored.state,
                  limitations=['No sustained arrival-driven throughput campaign.',
                               'GPU-worker termination and coordinator restart during active proving remain unqualified.',
                               'Bounded history replays at most 128 blocks; no physical power-loss qualification.',
                               'Four serial count-four roots; no larger shared-fleet geometry qualification.'])
    save()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        child(sys.argv[2], sys.argv[3])
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_bytes())
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'inputs.json').write_bytes(H.canonical(config))
    result = {'schema_version': 1, 'record_type': 'native_multi_height_qualification',
              'status': 'running', 'checks': [], 'stages': [], 'production_ready': False,
              'multi_height_native_delivery_qualified': False, 'pilot_started': False,
              'inputs': D.pin(out / 'inputs.json')}
    start = time.monotonic()
    try:
        qualify(config, out, result)
    except Exception as error:
        result.update(status='failed', failure=f'{type(error).__name__}: {error}')
    result['elapsed_seconds'] = time.monotonic() - start
    (out / 'summary.json').write_bytes(H.canonical(result))
    print(json.dumps({'status': result['status'], 'failure': result.get('failure'),
                      'summary': str(out / 'summary.json')}), flush=True)
    return int(result['status'] != 'succeeded')


if __name__ == '__main__':
    raise SystemExit(main())
