"""Run bounded native pool phases under one original workflow deadline.

The result is proof availability only. Fresh wallets, independent CPU audit and
durable application belong to the enclosing workflow and consume its horizon.
"""
import importlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

import block_v2_capacity as Capacity
import block_v2_pool_timing as T
import block_v2_pool_seal as Seal
import block_v2_pool_handoff as Handoff

S = importlib.import_module('block-v2-typed-shared-gpu-run')
MAX_PHASES = 8


def read(path):
    return json.loads(T.regular(Path(path).absolute(), 1 << 20), object_pairs_hook=T.unique_object)


def publish(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.pending')
    with temporary.open('xb') as output:
        os.chmod(temporary, 0o600)
        output.write(T.canonical(value))
        output.flush()
        os.fsync(output.fileno())
    os.link(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
        temporary.unlink()
        os.fsync(directory)
    finally:
        os.close(directory)


def phase_result(directory, workflow, binding, previous_jobs, *, prefix=False,
                 sequence=0, completed_requests=1, live=False, block_capacity=64):
    """Validate supervisor receipts, never promote them into proof verification."""
    root_file = Capacity.root_file(capacity=block_capacity)
    max_jobs = 2 * block_capacity - 1
    directory = Path(directory)
    summary = read(directory / 'summary.json')
    if live:
        ready = read(directory / 'owner/proofs/pool-ready.json')
        if (not prefix or sequence != 0 or ready.get('max_requests') != 2
                or ready.get('preseal_only') is not True or ready.get('pool_workflow') != workflow
                or (directory / 'owner/proofs/pool-stopped.json').exists()):
            raise ValueError('live handoff requires a waiting bounded prefix service')
    elif (summary.get('status') != 'succeeded' or summary.get('pool_service') is not True
            or summary.get('pool_workflow') != workflow or summary.get('cleanup_failure')
            or summary.get('pool_result', {}).get('workers_drained') is not True):
        raise ValueError('native pool phase lacks successful drained supervision')
    result_directory = directory / f'owner/proofs/candidate-{sequence:06}'
    complete = (result_directory / 'result.json').exists()
    if live and not complete:
        raise ValueError('live handoff requires a complete prefix')
    records = read(result_directory / 'execution-jobs.json')
    if (not isinstance(records, list) or len(records) > max_jobs
            or not records and (not complete or not previous_jobs)):
        raise ValueError('pool phase made no bounded fresh proof progress')
    jobs = set()
    for record in records:
        job = record.get('job')
        if (not isinstance(job, str) or len(job) != 64
                or any(c not in '0123456789abcdef' for c in job)
                or job in jobs or job in previous_jobs
                or type(record.get('proof_bytes')) is not int
                or not 0 < record['proof_bytes'] <= 2 << 20):
            raise ValueError('pool phase accepted-job inventory changed or duplicated')
        jobs.add(job)
    if len(jobs | previous_jobs) > max_jobs:
        raise ValueError('pool phase lineage exceeds the candidate job bound')
    result = read(result_directory / ('result.json' if complete else 'phase.json'))
    if (result.get('native_host') != binding or result.get('native_applied') is not False
            or result.get('preseal_only', False) is not prefix
            or result.get('worker_failures') != [] or type(result.get('fresh_proofs')) is not int
            or result.get('fresh_proofs') != len(jobs)):
        raise ValueError('pool phase candidate or fresh result binding changed')
    started, finished = result.get('started_ms'), result.get('completed_ms' if complete else 'stopped_ms')
    if (type(started) is not int or type(finished) is not int
            or not 0 <= started <= finished < T.WORKFLOW_MS):
        raise ValueError('phase receipt expired outside the original workflow clock')
    if complete:
        if (type(result.get('reused_proofs')) is not int or result.get('reused_proofs') != len(previous_jobs)
                or not live and summary['pool_result'].get('completed_requests') != completed_requests):
            raise ValueError('pool completion differs from the original candidate lineage')
        if prefix:
            if (result.get('status') != 'preseal_verified' or result.get('pool_workflow') != workflow
                    or result.get('root_file') is not None or (result_directory / root_file).exists()):
                raise ValueError('pool prefix completion cannot contain a root or replace its workflow')
            S.pin_preseal([result_directory], block_capacity)
            ids = [node.get('job') for node in result['stable_nodes']]
            if any(not T.nonzero_digest(job) for job in ids):
                raise ValueError('prefix cache contains an invalid job identity')
            ids = [bytes(job).hex() for job in ids]
            if len(set(ids)) != len(ids) or set(ids) != jobs | previous_jobs:
                raise ValueError('prefix cache inventory differs from accepted complete subtrees')
        else:
            if result.get('status') != 'proved_cpu_audit_pending' or result.get('root_file') != root_file:
                raise ValueError('pool completion is not a candidate root')
            T.regular(result_directory / root_file, 2 << 20)
    elif (result.get('status') != 'partial' or result.get('pool_workflow') != workflow
            or result.get('deadline_ms') != T.WORKFLOW_MS
            or result.get('candidate_journaled') is not True or result.get('workers_drained') is not True
            or summary['pool_result'].get('partial_candidate') is not True
            or summary['pool_result'].get('completed_requests') != 0):
        raise ValueError('partial phase cannot renew or replace its candidate')
    return complete, jobs, result_directory


def command(config, fixture, requests, workflow, output, previous):
    uuids = config['gpu_uuids']
    approvals = config['pool_timing_approvals']
    owned = config.get('owned_public_gpu', False)
    if type(owned) is not bool:
        raise ValueError('owned_public_gpu must be a boolean')
    prefix = config.get('preseal_only', False)
    if type(prefix) is not bool:
        raise ValueError('preseal_only must be a boolean')
    S.check_pool_scope(True, prefix, config.get('reuse_preseal', []),
                       config.get('arrival_store'), config.get('arrival_selection'))
    if not isinstance(approvals, dict) or set(approvals) != set(uuids):
        raise ValueError('phase controller requires exact-image approvals for every GPU')
    result = [sys.executable, str(Path(S.__file__).resolve()),
              '--gpu-binary', config['gpu_binary'], '--cpu-binary', config['cpu_binary'],
              '--fixture', str(fixture), '--host-config', config['host_config'],
              '--host-journal', config['host_journal'], '--count', str(config['count']),
              '--block-capacity', str(Capacity.configured(config)),
              '--workload', config['workload'], '--scratch', config['scratch'],
              '--pool-requests', str(requests), '--pool-workflow', str(workflow),
              '--pool-runtime-seconds', str(T.SERVICE_SECONDS), '--evidence', str(output)]
    if owned:
        result.append('--owned-public-gpu')
    if prefix:
        result.append('--preseal')
    if config.get('pool_prefix_handoff'):
        result.append('--pool-prefix-handoff')
    if config.get('arrival_store'):
        result += ['--arrival-store', config['arrival_store']]
    if config.get('arrival_selection'):
        result += ['--arrival-selection', config['arrival_selection']]
    for directory in config.get('reuse_preseal', []):
        result += ['--reuse-preseal', str(directory)]
    for uuid in uuids:
        result += ['--gpu-uuid', uuid, '--pool-timing-approval', uuid + '=' + str(approvals[uuid])]
    if previous is not None:
        result += ['--recover-owner', str(previous / 'owner')]
    elif config.get('resource_assignment'):
        result += ['--resource-assignment', config['resource_assignment']]
    for trial in config.get('calibration_trials', []):
        result += ['--calibration-trial', trial]
    return result


def imported_jobs(directory, required, block_capacity=64):
    """Inventory only; import CPU verification and the final audit remain mandatory."""
    path = Path(directory) / 'owner/proofs/execution-reused.json'
    if not path.exists() and not required:
        return set()
    records = read(path)
    if not required or not isinstance(records, list) or not 1 <= len(records) <= Capacity.validate(block_capacity) - 2:
        raise ValueError('pool prefix import inventory is absent or outside its bound')
    jobs = set()
    for record in records:
        job = record.get('job')
        if (not isinstance(job, str) or not re.fullmatch('[0-9a-f]{64}', job)
                or job in jobs or record.get('cpu_reverified') is not True):
            raise ValueError('pool prefix import is duplicated or lacks CPU verification')
        jobs.add(job)
    return jobs


def reconcile(directory):
    # Revoke delayed controller startup as well as checking its process lifetime.
    # The existing controller reconciles exact coordinator/worker startup gates.
    S.Controller.reconcile(directory)
    config = read(Path(directory) / 'config.json')
    summary = read(Path(directory) / 'summary.json')
    S.quiescent_fleet(config['owner_unit'], summary['attempts'])


def retire_workflow_inputs(directories, fixtures, deadline_ms):
    """Retire reopened public inputs after every workflow reader has stopped.

    Later phases reopen the first phase's durable journal. Retiring only the
    last owner's files leaves those earlier pages charged to the coordinator
    slice. The final native fixture has the same lifetime across the handoff.
    Advice preserves every byte and never establishes proof or memory validity.
    """
    directories = list(dict.fromkeys(map(Path, directories)))
    fixtures = list(dict.fromkeys(map(Path, fixtures)))
    if not 1 <= len(directories) <= MAX_PHASES or not 1 <= len(fixtures) <= 2:
        raise ValueError('closed workflow cache inventory exceeds its bound')
    # Reconcile all readers before touching even the first retained directory.
    for directory in directories:
        reconcile(directory)
    roots = [directory / 'owner' for directory in directories]
    skipped = []
    for fixture in fixtures:
        info = fixture.lstat()
        if not stat.S_ISDIR(info.st_mode) or fixture.resolve(strict=True) != fixture:
            raise ValueError('closed workflow fixture must be canonical and nonsymlink')
        if info.st_mode & 0o077:
            # Older caller-owned fixtures can be readable by others. Do not
            # widen the cache helper's private-directory ownership contract.
            skipped.append(str(fixture))
        else:
            roots.append(fixture)
    receipts = [S.PublicCache.release(root, deadline_ms) for root in dict.fromkeys(roots)]
    for directory in directories:
        reconcile(directory)
    return {'schema_version': 1, 'cleanup_only': True, 'directories': receipts,
            'skipped_nonprivate_fixtures': skipped, 'artifact_bytes_preserved': True,
            'physical_release_measured': False}


def check_binding(config, fixture, binding, host_config_sha256):
    """Pin the bounded controller's verified binding without opening another FFI host.

    Native history verification happens in the admitted controller. HEAD is
    only a change detector here; it never grants validity or application rights.
    """
    configuration = T.regular(Path(config['host_config']).absolute(), 1 << 20)
    if hashlib.sha256(configuration).hexdigest() != host_config_sha256:
        raise ValueError('native host configuration file changed between pool phases')
    for path, field in [(fixture / 'manifest.json', 'preparation_sha256'),
                        (fixture / 'complete-body.bin', 'complete_body_sha256')]:
        data = T.regular(path.absolute(), 1 << 20)
        if list(hashlib.sha256(data).digest()) != binding.get(field):
            raise ValueError('native preparation pins changed between pool phases')
    # The verifier hashes its trusted semantic inputs, not the JSON file which
    # also names libraries and paths. The admitted controller authenticates this
    # digest; the separate file pin above detects changes to its configuration.
    semantic = binding.get('configuration_sha256')
    if (not T.nonzero_digest(semantic)
            or read(fixture / 'manifest.json').get('host_configuration_sha256') != bytes(semantic).hex()):
        raise ValueError('native preparation differs from the verified host configuration')
    if read(fixture / 'expected.json') != binding.get('expected'):
        raise ValueError('native phase expected statement changed')
    check_head(config, binding)


def check_head(config, binding):
    data = T.regular(Path(config['host_journal']).absolute() / 'HEAD.json', 16384)
    if list(hashlib.sha256(data).digest()) != binding.get('head_token'):
        raise ValueError('native head changed during bounded pool proving')


def stop_owned_services(directory):
    """Stop exact admitted services after launcher exit, then check quiescence."""
    directory = Path(directory)
    gate = directory / 'controller-startup'
    if not gate.exists():
        return
    deadline = time.monotonic() + 30
    def stop(unit):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('phase shutdown reserve exhausted')
        subprocess.run(['systemctl', '--user', 'stop', unit], check=True,
                       timeout=remaining, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    intent = gate / 'intent.json'
    if intent.exists():
        value = S.Controller.intent(intent)[1]
        if S.Controller.observation(value['unit']).get('LoadState') != 'not-found':
            stop(value['unit'])
    config = directory / 'config.json'
    if config.exists():
        value = read(config)
        units = [value['owner_unit']] + [worker['budget']['unit'] for worker in value['workers']]
        for unit in units:
            if not re.fullmatch(r'lattica-v2-multi-(?:owner|persistent)-[0-9a-f]{64}\.service', unit):
                raise ValueError('phase cleanup unit differs from its admitted namespace')
            if S.G.systemctl('show', unit, '--property=LoadState', '--value').strip() != 'not-found':
                stop(unit)
        S.quiescent_fleet(value['owner_unit'], [{'unit': u} for u in units[1:]])
    S.Controller.reconcile(directory)


def prepared_request(directory, fixture, binding, workflow):
    """Select the exact private snapshot independently verified by this owner."""
    directory, fixture = Path(directory), Path(fixture)
    launch = read(directory / 'config.json')
    expected = directory / 'expected.json'
    owner = directory / 'owner'
    if (not directory.is_absolute() or not fixture.is_absolute()
            or launch.get('fixture') != str(fixture)
            or launch.get('owner_directory') != str(owner)
            or launch.get('expected') != str(expected)
            or launch.get('native_host') != binding
            or launch.get('pool_workflow') != workflow):
        raise ValueError('bounded request differs from its verified owner snapshot')
    return {'schema_version': 1, 'fixture': str(owner / 'input'),
            'expected': str(expected), 'native_host': binding, 'deadline_ms': T.WORKFLOW_MS}


def check_unstarted_handoff(directory, inbox):
    """Deferral is forbidden once callback preparation or a seal transition starts."""
    proofs = directory / 'owner/proofs'
    paths = [directory / 'handoff', inbox / '000001.json',
             proofs / 'prefix-transition-intent.json', proofs / 'prefix-transition.json',
             proofs / 'candidate-000001']
    if any(path.exists() or path.is_symlink() for path in paths):
        raise ValueError('cannot defer a started handoff or native seal transition')


def defer_handoff(directory, inbox, workflow, cache, unavailable):
    """Publish a planned graceful stop only for pre-service window admission."""
    check_unstarted_handoff(directory, inbox)
    config = read(directory / 'config.json')
    fleet = read(config['fleet_plan'])
    window = unavailable.window
    reserve = Handoff.continuation_reserve_ms(window.get('continuation_reserve_ms'))
    required = Handoff.MIN_HANDOFF_MS + reserve
    boot, now = T.workflow_clock()
    T.validate_workflow(workflow, boot, now)
    if (window['pool_workflow'] != workflow or config.get('pool_workflow') != workflow
            or config.get('pool_seal') is not None or config.get('arrival_selection') is not None
            or config.get('pool_prefix_handoff') is not True or config.get('preseal_only') is not True
            or window['phase_deadline_monotonic_ms'] != fleet['pool_scheduling']['dispatch_deadline_monotonic_ms']
            or window['minimum_handoff_ms'] != Handoff.MIN_HANDOFF_MS
            or window.get('required_window_ms') != required
            or not workflow['started_monotonic_ms'] <= window['observed_monotonic_ms'] <= now
            or not 0 < window['phase_deadline_monotonic_ms'] - now < required
            or workflow['deadline_monotonic_ms'] - now < required):
        raise ValueError('handoff deferral changed its original admission or workflow')
    if (inbox / 'stop').exists() or (inbox / 'stop').is_symlink():
        raise ValueError('handoff deferral requires an unrequested stop')
    paths = [directory / 'config.json', Path(config['fleet_plan']),
             cache / 'result.json', inbox / '000000.json']
    record = {'schema_version': 1, 'reason': 'insufficient_phase_handoff_window',
              **window, 'pins': {str(path): T.digest(path) for path in paths}}
    publish(directory / 'handoff-deferral.json', record)
    publish(inbox / 'stop', record)
    return record


def check_deferred_handoff(directory, inbox, record):
    """Successful drained supervision and the unchanged prefix remain mandatory."""
    check_unstarted_handoff(directory, inbox)
    if read(directory / 'handoff-deferral.json') != record or read(inbox / 'stop') != record:
        raise ValueError('planned handoff deferral changed during worker drain')
    for path, digest in record['pins'].items():
        if T.digest(path) != digest:
            raise ValueError('deferred handoff input changed during worker drain')
    stopped = read(directory / 'owner/proofs/pool-stopped.json')
    if (stopped.get('schema_version') != 1 or stopped.get('workers_drained') is not True
            or type(stopped.get('completed_requests')) is not int or stopped['completed_requests'] != 1
            or stopped.get('partial_candidate', False) is not False or stopped.get('reason') is not None
            or type(stopped.get('stopped_ms')) is not int or not 0 <= stopped['stopped_ms'] < T.WORKFLOW_MS):
        raise ValueError('deferred handoff requires the planned successful worker drain')


def run(config, fixture, workflow_path, output, *, handoff=None):
    if handoff is not None:
        Handoff.validate_callback(handoff)
    config = dict(config)
    config['pool_prefix_handoff'] = handoff is not None
    fixture, output = Path(fixture).resolve(strict=True), Path(output).absolute()
    host_config_sha256 = hashlib.sha256(T.regular(Path(config['host_config']).absolute(), 1 << 20)).hexdigest()
    workflow, pins = T.workflow(workflow_path)
    prefix = config.get('preseal_only', False)
    if type(prefix) is not bool:
        raise ValueError('preseal_only must be a boolean')
    if handoff is not None and (not prefix or not config.get('arrival_store')):
        raise ValueError('handoff requires the original native arrival prefix')
    seal = config.get('pool_seal')
    if prefix and seal is not None:
        raise ValueError('an unsealed prefix cannot carry a seal clock')
    if not prefix and config.get('arrival_selection'):
        Seal.check(seal, workflow)
    elif seal is not None:
        raise ValueError('post-seal timing requires a durable arrival selection')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    bound_workflow = output / 'workflow.json'
    publish(bound_workflow, workflow)
    summary = {'schema_version': 1, 'status': 'running', 'pool_workflow': workflow,
               'host_config_sha256': host_config_sha256,
               'workflow_input_pins': pins, 'phases': [], 'gpu_stage_coverage_independently_audited': False,
               'independent_cpu_audit_pending': True, 'native_applied': False}
    summary['preseal_only'] = prefix
    summary['imported_proofs'] = 0
    summary['pool_seal'] = seal
    previous, accepted, binding = None, set(), None
    launched_directories, retained_fixtures = [], [fixture]
    try:
        for phase in range(MAX_PHASES):
            boot, now = T.workflow_clock()
            T.validate_workflow(workflow, boot, now)
            if seal is not None:
                Seal.check(seal, workflow, clock=(boot, now))
            if binding is not None:
                check_binding(config, fixture, binding, host_config_sha256)
            inbox = output / f'requests-{phase:03}'
            inbox.mkdir(mode=0o700)
            directory = output / f'phase-{phase:03}'
            argv = command(config, fixture, inbox, bound_workflow, directory, previous)
            publish(output / f'command-{phase:03}.json', argv)
            with (output / f'phase-{phase:03}.log').open('xb') as log:
                process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
                launched_directories.append(directory)
                submitted = False
                final_request = None
                deferred = None
                live_jobs = set()
                try:
                    while process.poll() is None:
                        boot, now = T.workflow_clock()
                        T.validate_workflow(workflow, boot, now)
                        if seal is not None:
                            Seal.check(seal, workflow, clock=(boot, now))
                        native_host = directory / 'native-host.json'
                        if not submitted and native_host.exists() and (directory / 'config.json').exists():
                            if seal is not None and read(directory / 'config.json').get('pool_seal') != seal:
                                raise ValueError('replacement phase changed the durable seal clock')
                            observed = read(native_host)
                            if (observed.get('scope', 'candidate') == 'prefix') is not prefix:
                                raise ValueError('pool phase changed native proving scope')
                            if binding is not None and observed != binding:
                                raise ValueError('replacement controller changed its verified native binding')
                            check_binding(config, fixture, observed, host_config_sha256)
                            binding = observed
                            publish(inbox / '000000.json', prepared_request(directory, fixture, binding, workflow))
                            submitted = True
                        if (handoff is not None and submitted and final_request is None and deferred is None
                                and (directory / 'owner/proofs/candidate-000000/result.json').exists()):
                            _, live_jobs, cache = phase_result(directory, workflow, binding, accepted,
                                                               prefix=True, live=True, block_capacity=Capacity.configured(config))
                            try:
                                final_request = Handoff.run(directory, cache, handoff)
                            except Handoff.HandoffWindowUnavailable as unavailable:
                                deferred = defer_handoff(directory, inbox, workflow, cache, unavailable)
                                continue
                            final_fixture = Path(final_request['fixture']).absolute()
                            if final_fixture not in retained_fixtures:
                                retained_fixtures.append(final_fixture)
                            seal = final_request['pool_seal']
                            Seal.check(seal, workflow)
                            check_head(config, binding)
                            # The callback service is terminal and reconciled before
                            # the existing GPU worker receives another context.
                            publish(inbox / '000001.json', final_request)
                        if binding is not None:
                            check_head(config, binding)
                        time.sleep(0.1)
                    if process.returncode != 0:
                        raise RuntimeError('native pool phase failed; no automatic retry')
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                    # Launcher exit alone never proves GPU users have stopped.
                    if process.returncode != 0:
                        stop_owned_services(directory)
            reconcile(directory)
            if not submitted or binding is None:
                raise ValueError('phase exited before accepting the original native request')
            check_binding(config, fixture, binding, host_config_sha256)
            if previous is None:
                imported = imported_jobs(directory, bool(config.get('reuse_preseal')), Capacity.configured(config))
                accepted |= imported
                summary['imported_proofs'] = len(imported)
            complete, jobs, result_directory = phase_result(directory, workflow, binding, accepted, prefix=prefix,
                completed_requests=2 if final_request is not None else 1, block_capacity=Capacity.configured(config))
            if deferred is not None:
                check_deferred_handoff(directory, inbox, deferred)
                if not complete or jobs != live_jobs or final_request is not None or seal is not None:
                    raise ValueError('deferred handoff changed its completed unsealed prefix')
            accepted |= jobs
            summary['phases'].append({'phase': phase, 'directory': str(directory),
                'fresh_proofs': len(jobs), 'accepted_proofs': len(accepted), 'complete': complete,
                'supervisor_sha256': T.digest(directory / 'summary.json'), 'old_workers_quiescent': True})
            if deferred is not None:
                summary['phases'][-1]['handoff_deferral'] = deferred
            if final_request is not None:
                if not complete or jobs != live_jobs:
                    raise ValueError('live prefix receipt changed during handoff')
                prefix_summary = dict(summary)
                prefix_summary.update(status='preseal_cpu_audit_pending', prefix_cache=str(result_directory),
                                      root=None, phases=list(summary['phases']))
                final_binding = final_request['native_host']
                complete, final_jobs, final_directory = phase_result(directory, workflow, final_binding, accepted,
                    prefix=False, sequence=1, completed_requests=2, block_capacity=Capacity.configured(config))
                if not complete:
                    raise ValueError('live sealed continuation incomplete; no automatic retry')
                accepted |= final_jobs
                summary.update(status='proved_cpu_audit_pending', root=str(final_directory / Capacity.root_file(config)),
                               prefix_cache=str(result_directory), prefix_handoff=prefix_summary,
                               preseal_only=False, native_host=final_binding, pool_seal=seal,
                               final_fixture=final_request['fixture'], arrival_selection=final_request['arrival_selection'],
                               accepted_proofs=len(accepted), postseal_fresh_proofs=len(final_jobs),
                               workflow_elapsed_ms=T.workflow_clock()[1] - workflow['started_monotonic_ms'])
                summary['phases'].append({'phase': phase, 'candidate_sequence': 1, 'directory': str(directory),
                    'fresh_proofs': len(final_jobs), 'accepted_proofs': len(accepted), 'complete': True,
                    'supervisor_sha256': T.digest(directory / 'summary.json'), 'old_workers_quiescent': True})
                Seal.check(seal, workflow)
                return summary
            boot, now = T.workflow_clock()
            T.validate_workflow(workflow, boot, now)
            if seal is not None:
                Seal.check(seal, workflow, clock=(boot, now))
            if complete:
                if handoff is not None:
                    if deferred is not None:
                        previous = directory
                        continue
                    raise ValueError('prefix service stopped before its live handoff; no automatic retry')
                summary.update(status='preseal_cpu_audit_pending' if prefix else 'proved_cpu_audit_pending',
                               root=None if prefix else str(result_directory / Capacity.root_file(config)),
                               prefix_cache=str(result_directory) if prefix else None,
                               workflow_elapsed_ms=now - workflow['started_monotonic_ms'])
                return summary
            previous = directory
        raise ValueError('bounded phase count exhausted; candidate deadline was not renewed')
    except BaseException as error:
        summary.update(status='failed', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        failed = sys.exc_info()[0] is not None
        try:
            readers = [directory for directory in launched_directories if (directory / 'config.json').exists()]
            if config.get('owned_public_gpu', False) and readers:
                # This reserve is only for stopped-service cleanup. It neither
                # replaces the candidate clock nor permits further dispatch.
                summary['closed_workflow_input_retirement'] = retire_workflow_inputs(
                    readers, retained_fixtures, T.workflow_clock()[1] + 30000)
        except BaseException as error:
            summary.update(status='failed', input_retirement_failure=f'{type(error).__name__}: {error}')
            if not failed:
                raise
        finally:
            publish(output / 'summary.json', summary)
