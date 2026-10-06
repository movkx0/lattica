#!/usr/bin/env python3
"""Qualify the research journal with two real four-wallet native fixture roots.

Run between timed campaigns, after both complete-body fixtures have matching
recursive proofs. Trusted context, registry, genesis and issuance grants must be
supplied independently. Retains every journal, child log, input pin and failure.
These repeated recovery exercises do not measure delivered transaction rates.
"""

import argparse
import base64
import datetime
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import block_v2_host_store as H


STAGES = ('record_file_synced', 'record_directory_synced', 'head_file_synced',
          'head_replaced', 'head_directory_synced')
PUBLISHED_STAGES = STAGES[-2:]


def pin(path):
    path = Path(path).resolve(strict=True)
    return {'path': str(path), 'bytes': path.stat().st_size,
            'sha256': H.sha(path.read_bytes())}


def unchanged(pins):
    for item in pins:
        if pin(item['path']) != item:
            raise ValueError('qualification input changed: ' + item['path'])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def open_inputs(config):
    unchanged(config['pins'])
    grants = {int(index): amount for index, amount in config['issuance_grants'].items()}
    verifier = H.NativeVerifier(
        config['library'], Path(config['registry']).read_bytes(),
        bytes.fromhex(config['profile_id']), bytes.fromhex(config['chain_id']),
        Path(config['genesis']).read_bytes(), H.IssuancePolicy({10: grants}))
    candidates = [H.Candidate(10, Path(row['body']).read_bytes(),
                              Path(row['proof']).read_bytes())
                  for row in config['candidates']]
    return verifier, candidates


def child(config_path, directory, mode, value, token):
    config = json.loads(Path(config_path).read_text())
    verifier, candidates = open_inputs(config)
    if mode == 'restart':
        view = H.Store(directory, verifier).read()
        print(json.dumps({'token': view.token, 'state': view.state,
                          'generation': view.generation}), flush=True)
        return 0
    if mode == 'crash':
        require(value in STAGES, 'unknown crash boundary')

        def fault(stage):
            if stage == value:
                os._exit(77)

        H.Store(directory, verifier, fault_hook=fault).commit(
            candidates[0], expected_head=token)
        return 79  # The requested crash boundary must have been reached.
    require(mode == 'compete' and value in ('0', '1'), 'unknown child mode')
    (Path(directory) / ('writer-ready-' + value)).write_text('ready\n')
    deadline = time.monotonic() + 120
    while not (Path(directory) / 'writers-go').exists():
        require(time.monotonic() < deadline, 'competing writer release timed out')
        time.sleep(0.02)
    try:
        H.Store(directory, verifier).commit(candidates[int(value)], expected_head=token)
        return 0
    except H.StaleHead:
        return 78


def fixture_inputs(fixture, expected_indices):
    manifest = json.loads((fixture / 'manifest.json').read_text())
    require(manifest.get('status') == 'succeeded' and
            manifest.get('native_rust_expected_statements_equal') is True and
            manifest.get('fresh_leaf_proofs') == 4 and
            manifest.get('indices') == expected_indices,
            'fresh complete-body fixture preparation did not pass')
    wallets = manifest.get('wallets', [])
    require(len(wallets) == 4 and all(row.get('cpu_leaf_verified') is True and
            row.get('recipient_ciphertexts_checked') == 2 for row in wallets),
            'four CPU-verified leaves and eight usable ciphertexts are required')
    pins = list(manifest['sources']) + list(manifest['registry_sources'])
    pins += [row[key] for row in wallets for key in ('complete_body', 'wallet')]
    pins += [manifest['library'], manifest['cpu_probe'], pin(fixture / 'manifest.json')]
    unchanged(pins)
    return pins


def prepare(args, out):
    grants = {}
    for value in args.issuance_grant:
        index, amount = map(int, value.split(':'))
        require(index not in grants, 'duplicate independent issuance grant')
        grants[index] = amount
    require(grants == {3: 7}, 'this fixture qualification requires the host grant 3:7')
    require(len(bytes.fromhex(args.profile_id)) == 32 and
            len(bytes.fromhex(args.chain_id)) == 32, 'host context must contain two 32-byte ids')
    context = bytes.fromhex(args.profile_id + args.chain_id)
    pins, candidates = [], []
    for fixture, proof, indices in ((args.fixture, args.proof, [0, 1, 2, 3]),
                                    (args.alternate_fixture, args.alternate_proof, [4, 5, 6, 7])):
        fixture = fixture.resolve(strict=True)
        pins.extend(fixture_inputs(fixture, indices))
        require((fixture / 'genesis.bin').read_bytes() == args.genesis.read_bytes() and
                (fixture / 'host-registry.bin').read_bytes() == args.registry.read_bytes(),
                'fixture differs from independently selected host genesis/registry')
        expected = (fixture / 'native-expected.bin').read_bytes()
        require(len(expected) == 112 and expected[:8] == b'LBV2EX01' and
                expected[8:72] == context and int.from_bytes(expected[104:112], 'little') == 4,
                'fixture differs from independently selected host context or count')
        body = fixture / 'complete-body.bin'
        require(H.body_count(body.read_bytes()) == 4, 'four complete transactions required')
        candidates.append({'body': str(body), 'proof': str(proof.resolve(strict=True))})
        pins.extend([pin(body), pin(proof)])
    require(candidates[0] != candidates[1], 'two distinct candidate fixtures required')
    frozen = out / 'tools'
    frozen.mkdir()
    for path in (Path(__file__), Path(H.__file__)):
        shutil.copy2(path, frozen / path.name)
        pins.extend([pin(path), pin(frozen / path.name)])
    pins.extend(pin(path) for path in (args.library, args.registry, args.genesis))
    config = {'schema_version': 1, 'library': str(args.library.resolve(strict=True)),
              'registry': str(args.registry.resolve(strict=True)),
              'genesis': str(args.genesis.resolve(strict=True)),
              'profile_id': args.profile_id, 'chain_id': args.chain_id,
              'issuance_grants': grants, 'candidates': candidates, 'pins': pins,
              'runner': str(frozen / Path(__file__).name)}
    unchanged(pins)
    path = out / 'inputs.json'
    path.write_bytes(H.canonical(config))
    return config, path


def qualify(config, config_path, out, result):
    verifier, candidates = open_inputs(config)
    first, alternate = candidates
    require(first.body != alternate.body and first.proof != alternate.proof,
            'alternate branch must contain different real transactions and proof')

    def check(name, condition, **details):
        require(condition, name)
        result['checks'].append({'name': name, 'passed': True, **details})
        (out / 'summary.json.tmp').write_bytes(H.canonical(result))
        (out / 'summary.json.tmp').replace(out / 'summary.json')

    def fresh(name):
        return H.Store.create(out / name, verifier)

    def invoke(directory, mode, value, token, label):
        command = [sys.executable, config['runner'], '--child', str(config_path),
                   str(directory), mode, value, token]
        with (out / (label + '.log')).open('xb') as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                       timeout=120, env={**os.environ, 'RAYON_NUM_THREADS': '2'})
        return completed.returncode

    genesis = verifier.replay([])[0]
    check('independent genesis has the expected native state',
          genesis['height'] == 9 and genesis['blocks'] == 0 and
          genesis['nullifiers'] == 0 and genesis['outputs'] == 128 and
          genesis['events'] == 0 and genesis['supply'] == {
              'issued': '64000', 'burned': '0', 'shielded_pool': '64000', 'fees_paid': '0'})
    expected = [verifier.replay([candidate])[-1] for candidate in candidates]
    check('real CPU verifier accepts both complete-body roots', len(expected) == 2)
    for state in expected:
        check('native supply/nullifier/output/event totals',
              state['height'] == 10 and state['blocks'] == 1 and state['nullifiers'] == 8 and
              state['outputs'] == 136 and state['events'] == 1 and
              state['supply'] == {'issued': '64007', 'burned': '0',
                                  'shielded_pool': '64007', 'fees_paid': '0'})
    check('different wallet inputs produce different native state', expected[0] != expected[1])

    store = fresh('commit-restart-reorg')
    initial = store.read()
    before = time.monotonic()
    applied = store.commit(first, expected_head=initial.token)
    result['commit_including_history_replay_seconds'] = time.monotonic() - before
    check('durable commit matches independent native replay', applied.state == expected[0])
    record = json.loads((store.directory / 'records' / (applied.tip + '.json')).read_text())
    check('journal retains complete ciphertext body and exact root proof',
          base64.b64decode(record['body']) == first.body and
          base64.b64decode(record['proof']) == first.proof)
    check('fresh process reopens and verifies published branch',
          invoke(store.directory, 'restart', '-', '-', 'restart') == 0)
    restarted = json.loads((out / 'restart.log').read_text())
    check('fresh process restores exact state and head',
          restarted == {'token': applied.token, 'state': applied.state,
                        'generation': applied.generation})
    switched = store.reorganize(None, [alternate], expected_head=applied.token)
    check('real-proof reorg restores alternate supply/events/notes/nullifiers',
          switched.state == expected[1] and H.Store(store.directory, verifier).read() == switched)
    check('reorg retains previous immutable branch',
          (store.directory / 'records' / (applied.tip + '.json')).is_file())
    rolled = store.reorganize(None, [], expected_head=switched.token)
    check('rollback restores trusted genesis without head-token ABA',
          rolled.state == genesis and rolled.token != initial.token)
    try:
        store.commit(first, expected_head=initial.token)
        raise ValueError('old genesis token was accepted after rollback')
    except H.StaleHead:
        check('rollback fences stale writer', True)
    check('original real proof can be applied after explicit rollback',
          store.commit(first, expected_head=rolled.token).state == expected[0])

    for name, candidate in (
            ('mismatched-body', H.Candidate(10, first.body, alternate.proof)),
            ('truncated-root', H.Candidate(10, first.body, first.proof[:-1])),
            ('wrong-height', H.Candidate(11, first.body, first.proof))):
        rejected = fresh(name)
        original = rejected.read()
        try:
            rejected.commit(candidate, expected_head=original.token)
            raise ValueError(name + ' was accepted')
        except H.RejectedBlock:
            check(name + ' cannot publish', rejected.read() == original and
                  not list((rejected.directory / 'records').glob('*.json')))

    for stage in STAGES:
        crashing = fresh('crash-' + stage)
        original = crashing.read()
        check('child exits at ' + stage,
              invoke(crashing.directory, 'crash', stage, original.token, 'crash-' + stage) == 77)
        recovered = H.Store(crashing.directory, verifier).read()
        published = stage in PUBLISHED_STAGES
        check('recovery verifies published history at ' + stage,
              recovered.state == (expected[0] if published else genesis))
        if not published:
            check('orphan records are not adopted at ' + stage, recovered == original)
            check('retry after crash at ' + stage,
                  crashing.commit(first, expected_head=recovered.token).state == expected[0])

    for code in (errno.ENOSPC, errno.EIO):
        for stage in STAGES:
            failing = fresh('io-' + str(code) + '-' + stage)
            original = failing.read()

            def fault(actual):
                if actual == stage:
                    raise OSError(code, 'injected storage failure at ' + stage)

            required_error = H.CommitIndeterminate if stage in PUBLISHED_STAGES else OSError
            try:
                H.Store(failing.directory, verifier, fault_hook=fault).commit(
                    first, expected_head=original.token)
                raise ValueError('storage fault did not reach ' + stage)
            except required_error:
                recovered = failing.read()
            published = stage in PUBLISHED_STAGES
            check('storage error recovery ' + str(code) + ' at ' + stage,
                  recovered.state == (expected[0] if published else genesis))
            if not published:
                check('storage retry ' + str(code) + ' at ' + stage,
                      failing.commit(first, expected_head=recovered.token).state == expected[0])
            else:
                try:
                    failing.commit(first, expected_head=original.token)
                    raise ValueError('indeterminate publication did not fence stale retry')
                except H.StaleHead:
                    check('indeterminate retry is fenced ' + str(code) + ' at ' + stage, True)

    race = fresh('competing-writers')
    original = race.read()
    processes, logs = [], []
    try:
        for index in range(2):
            log = (out / ('writer-' + str(index) + '.log')).open('xb')
            logs.append(log)
            processes.append(subprocess.Popen(
                [sys.executable, config['runner'], '--child', str(config_path),
                 str(race.directory), 'compete', str(index), original.token],
                stdout=log, stderr=subprocess.STDOUT,
                env={**os.environ, 'RAYON_NUM_THREADS': '2'}))
        deadline = time.monotonic() + 120
        while not all((race.directory / ('writer-ready-' + str(i))).exists() for i in range(2)):
            require(all(process.poll() is None for process in processes),
                    'competing writer failed before release')
            require(time.monotonic() < deadline, 'competing writers did not become ready')
            time.sleep(0.02)
        (race.directory / 'writers-go').write_text('start\n')
        codes = [process.wait(timeout=120) for process in processes]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()
        for log in logs:
            log.close()
    check('one competing real-proof writer publishes and one is fenced', sorted(codes) == [0, 78])
    check('competing writer recovery matches winner', race.read().state == expected[codes.index(0)])
    result['native_state_after_first_block'] = expected[0]
    result['native_state_after_alternate_block'] = expected[1]
    unchanged(config['pins'])
    result['durable_complete_body_application_qualified'] = True
    result['process_exit_recovery_qualified'] = True
    result['injected_storage_error_recovery_qualified'] = True


def main():
    if len(sys.argv) == 7 and sys.argv[1] == '--child':
        return child(*sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('library', 'registry', 'genesis', 'fixture', 'proof',
                 'alternate-fixture', 'alternate-proof', 'output'):
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--profile-id', required=True)
    parser.add_argument('--chain-id', required=True)
    parser.add_argument('--issuance-grant', action='append', required=True, metavar='INDEX:AMOUNT')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    result = {'schema_version': 1, 'record_type': 'research_native_host_qualification',
              'status': 'running', 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'checks': [], 'durable_complete_body_application_qualified': False,
              'process_exit_recovery_qualified': False,
              'injected_storage_error_recovery_qualified': False,
              'power_loss_recovery_tested': False, 'delivered_transactions_measured': False,
              'production_ready': False,
              'scope': 'Two independently supplied four-transaction roots at height 10; '
                       'real CPU authorization, durable application and journal recovery. '
                       'Process exits and injected storage exceptions are retained as separate checks. '
                       'No sustained delivery, power failure or throughput qualification.'}
    started = time.monotonic()
    (out / 'summary.json').write_bytes(H.canonical(result))
    try:
        config, config_path = prepare(args, out)
        result['inputs'] = pin(config_path)
        qualify(config, config_path, out, result)
        require(pin(config_path) == result['inputs'], 'qualification configuration changed')
        result['status'] = 'succeeded'
    except Exception as error:
        result['status'] = 'failed'
        result['failure'] = f'{type(error).__name__}: {error}'
        for key in ('durable_complete_body_application_qualified', 'process_exit_recovery_qualified',
                    'injected_storage_error_recovery_qualified'):
            result[key] = False
    result['elapsed_seconds'] = time.monotonic() - started
    result['logs'] = [pin(path) for path in sorted(out.glob('*.log'))]
    (out / 'summary.json').write_bytes(H.canonical(result))
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']),
                      'failure': result.get('failure'), 'summary': str(out / 'summary.json')}))
    return int(result['status'] != 'succeeded')


if __name__ == '__main__':
    raise SystemExit(main())
