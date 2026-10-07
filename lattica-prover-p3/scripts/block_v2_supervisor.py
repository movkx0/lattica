"""Bounded, durable supervision of sealed native shared-GPU candidates.

Controllers retain proving and native-validity authority. A retry always enters
their existing fenced recovery path after every old service is quiescent.
"""
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

Controller = importlib.import_module('block_v2_controller_bootstrap')
B = Controller.B
G = Controller.G
read = Controller.read
publish = Controller.publish
MAX_RESTARTS = 8
LIVE = {'active', 'activating', 'deactivating', 'reloading'}
PROPERTIES = 'LoadState,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID,ControlGroup,Result,ExecMainStatus,KillMode,Restart'


def unit_name(unit):
    if not isinstance(unit, str) or not re.fullmatch(r'lattica-v2-supervisor-[0-9a-f]{64}\.service', unit):
        raise ValueError('invalid supervisor service')


def observe(unit):
    output = G.systemctl('show', unit, '--property='+PROPERTIES)
    state = dict(row.split('=', 1) for row in output.splitlines())
    for key in ('MainPID', 'ControlPID'):
        state[key] = int(state[key])
    return state


def alive(pid, ticks, boot):
    if boot != B.boot():
        return False
    try:
        return B.birth(pid) == ticks
    except FileNotFoundError:
        return False


def terminal(state):
    # An observation timeout, transient read failure, or missing result file is
    # never interpreted as process termination.
    return (state.get('ActiveState') in ('failed', 'inactive')
            and state.get('MainPID') == state.get('ControlPID') == 0
            and state.get('Job') in ('', '0'))


def validate_options(args):
    if (not args.host_config or not args.host_journal or not args.arrival_store
            or not args.arrival_selection or args.preseal or args.reuse_preseal
            or args.recover_owner or args.recover_controller or args.recover_cached_only):
        raise ValueError('supervision requires a fresh sealed native intake candidate')
    if type(args.supervisor_max_restarts) is not int or not 0 <= args.supervisor_max_restarts <= MAX_RESTARTS:
        raise ValueError('supervisor restart budget must be between zero and eight')
    if type(args.supervisor_restart_delay) is not int or not 0 <= args.supervisor_restart_delay <= 60:
        raise ValueError('supervisor restart delay must be between zero and sixty seconds')


def request(path, script):
    path = Path(path).resolve(strict=True)
    value = read(path)
    unit_name(value.get('unit'))
    if (value.get('schema_version') != 1 or path.name != 'supervisor-request.json'
            or value.get('directory') != str(path.parent)
            or value.get('script') != str(Path(script).resolve(strict=True))
            or value.get('command') != [value.get('executable'), value.get('script'), '--supervisor-request', str(path)]
            or value.get('executable_sha256') != G.digest(Path(value['executable']))
            or not Path(value.get('cwd', '')).is_absolute()
            or not isinstance(value.get('arguments'), list)
            or not all(isinstance(item, str) for item in value['arguments'])
            or type(value.get('max_restarts')) is not int or not 0 <= value['max_restarts'] <= MAX_RESTARTS
            or type(value.get('restart_delay')) is not int or not 0 <= value['restart_delay'] <= 60):
        raise ValueError('supervisor immutable request changed')
    Controller.check_pins(value['pins'])
    if value['pins'].get(value['script']) != G.digest(Path(value['script'])):
        raise ValueError('supervisor script is not pinned')
    return value


def create(args, script, pins):
    validate_options(args)
    directory = args.evidence.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    fd = os.open(directory/'lock', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    script = str(Path(script).resolve(strict=True))
    executable = str(Path(sys.executable).resolve(strict=True))
    path = directory/'supervisor-request.json'
    value = dict(schema_version=1, directory=str(directory), script=script, executable=executable,
        executable_sha256=G.digest(Path(executable)), cwd=str(Path.cwd().resolve()),
        unit='lattica-v2-supervisor-'+secrets.token_hex(32)+'.service',
        arguments=Controller.arguments(args), pins=pins,
        max_restarts=args.supervisor_max_restarts, restart_delay=args.supervisor_restart_delay,
        created_time_ns=time.time_ns(), command=[executable, script, '--supervisor-request', str(path)])
    publish(path, value)
    request(path, script)
    return path, value


def attempt_command(value, number, previous, *, cached=False):
    if not 1 <= number <= value['max_restarts'] + 1:
        raise ValueError('supervisor restart budget exhausted')
    directory = Path(value['directory'])/f'attempt-{number:03d}'
    if previous is None:
        arguments = list(value['arguments'])
        index = arguments.index('--evidence')
        arguments[index+1] = str(directory)
    else:
        arguments = ['--recover-controller', str(previous), '--evidence', str(directory)]
        if cached:
            arguments.append('--recover-cached-only')
    return dict(schema_version=1, number=number, directory=str(directory),
        previous=str(previous) if previous else None, cached_only=cached,
        command=[value['executable'], value['script'], *arguments])


def controller_state(directory, shared):
    """Observe one exact attempt; leave live services and launchers running."""
    directory = Path(directory)
    gate = directory/'controller-startup'
    if not gate.is_dir():
        return dict(action='fresh', reason='controller request was not created')
    launcher = gate/'launcher-started.json'
    if launcher.exists():
        identity = read(launcher)
        if alive(identity['pid'], identity['start_ticks'], identity['boot']):
            return dict(action='wait', reason='foreground controller launcher is live')
    intent = gate/'intent.json'
    if not intent.exists():
        # Reconciliation takes the launch and controller locks and fences an
        # interrupted pre-admission attempt before a fresh attempt is possible.
        receipt = Controller.reconcile(directory)
        if receipt['intent'] is not None:
            raise ValueError('controller intent changed during observation')
        return dict(action='fresh', reason='controller request was not published', reconciliation=receipt)
    _, pinned = Controller.intent(intent)
    state = Controller.observation(pinned['unit'])
    if not terminal(state):
        return dict(action='wait', reason='controller service is not terminal', state=state)
    B.quiescent(state, pinned['unit'], read(gate/'started.json') if (gate/'started.json').exists() else None)
    config_path = directory/'config.json'
    config = read(config_path) if config_path.exists() else None
    if config is not None:
        Controller.check_pins(config['pins'])
        attempts = [dict(unit=row['budget']['unit']) for row in config['workers']]
        units = [config['owner_unit'], *[row['unit'] for row in attempts]]
        for unit in units:
            if not re.fullmatch(r'lattica-v2-multi-(owner|persistent)-[0-9a-f]{64}\.service', unit):
                raise ValueError('supervisor encountered an invalid recorded fleet service')
            observed = observe(unit)
            if not terminal(observed):
                return dict(action='wait', reason='old fleet service is not terminal', unit=unit, state=observed)
        shared.quiescent_fleet(config['owner_unit'], attempts)
    # Reuse the authoritative handoff and startup reconciliation checks. They
    # pin the owner configuration and reject substituted units or live leases.
    reconciliation = Controller.reconcile(directory)
    summary_path = directory/'summary.json'
    summary = read(summary_path) if summary_path.exists() else {}
    if summary.get('native_head_change') or (directory/'stale-head.json').exists():
        return dict(action='stale', reason='candidate native head changed', state=state)
    if summary.get('status') == 'succeeded':
        result = summary['result']
        if (not config or result.get('cpu_audited') is not True
                or result.get('durable_host_applied') is not True
                or result.get('native_blocks_applied') != 1
                or summary.get('cleanup_failure')):
            raise ValueError('supervised success lacks CPU audit and native application')
        shared.validate_execution(result['execution_result'], config['count'], config['workers'],
            config['native_host'], allow_worker_failover=config.get('allow_worker_failover', False),
            recovery_source=config.get('recover_from'), recover_cached_only=config.get('recover_cached_only', False))
        return dict(action='succeeded', state=state, result=summary['result'],
                    summary_sha256=G.digest(summary_path), reconciliation=reconciliation)
    # A published export is a hint to use the existing strict cached recovery
    # verifier. It supplies no proof validity or journal authority on its own.
    cached = (directory/'owner/root-only/node.6.0').is_file() or (directory/'owner/proofs/node.6.0').is_file()
    return dict(action='recover', reason=summary.get('failure', 'controller stopped before result'),
                state=state, cached_only=cached, reconciliation=reconciliation)


def candidate_current(value, parser, shared, previous):
    args = parser.parse_args(value['arguments'])
    native = importlib.import_module('block_v2_native_shared')
    extra = {}
    if previous is not None and (previous/'config.json').exists():
        extra = shared.application_recovery_inputs(previous/'owner')
    try:
        candidate = native.Candidate(args.host_config, args.host_journal, args.fixture, args.count, **extra)
        candidate.check(candidate.binding)
        return True
    except native.H.StaleHead:
        return False


def entry_identity(value, path):
    state = observe(value['unit'])
    actual = [os.fsdecode(arg) for arg in Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').split(b'\0')]
    if (actual != value['command'] or state['MainPID'] != os.getpid()
            or str(Path.cwd().resolve()) != value['cwd']
            or G.digest(Path('/proc/self/exe')) != value['executable_sha256']
            or state['ActiveState'] != 'active' or state['SubState'] != 'running'
            or state['KillMode'] != 'control-group' or state['Restart'] != 'on-failure'):
        raise ValueError('supervisor is not its exact admitted service process')
    return dict(schema_version=1, pid=os.getpid(), start_ticks=B.birth(os.getpid()), boot=B.boot(),
                invocation=state['InvocationID'], request_sha256=G.digest(Path(path)), time_ns=time.time_ns())


def run_request(path, script, parser, shared):
    value = request(path, script)
    directory = Path(value['directory'])
    lock = Controller.lock(directory, 'lock')
    try:
        identity = entry_identity(value, path)
        publish(directory/f"invocation-{identity['invocation']}.json", identity)
        if (directory/'result.json').exists():
            return
        started = time.monotonic()
        previous = None
        cached = False
        outcomes = []
        for number in range(1, value['max_restarts']+2):
            intent_path = directory/f'attempt-{number:03d}.intent.json'
            outcome_path = directory/f'attempt-{number:03d}.outcome.json'
            if outcome_path.exists():
                outcome = read(outcome_path)
                intent = read(intent_path)
                if outcome['intent_sha256'] != G.digest(intent_path):
                    raise ValueError('supervisor attempt outcome changed its request')
            else:
                Controller.check_pins(value['pins'])
                expected = attempt_command(value, number, previous, cached=cached)
                if intent_path.exists():
                    intent = read(intent_path)
                    if intent != expected:
                        raise ValueError('supervisor attempt command changed')
                    launch = directory/f'attempt-{number:03d}.launched.json'
                    if launch.exists():
                        child_identity = read(launch)
                        if alive(child_identity['pid'], child_identity['start_ticks'], child_identity['boot']):
                            # The parent service can only re-enter after its old
                            # cgroup drained. Refuse an unexpected live launcher.
                            raise ValueError('supervisor previous launcher still exists')
                    child = None
                else:
                    if not candidate_current(value, parser, shared, previous):
                        finish(directory, outcomes, 'stale_candidate', started, reason='native candidate is stale')
                        return
                    intent = expected
                    publish(intent_path, intent)
                    with (directory/f'attempt-{number:03d}.log').open('xb') as log:
                        child = subprocess.Popen(intent['command'], cwd=value['cwd'], stdout=log, stderr=subprocess.STDOUT)
                    publish(directory/f'attempt-{number:03d}.launched.json', dict(pid=child.pid,
                        start_ticks=B.birth(child.pid), boot=B.boot(), invocation=identity['invocation']))
                while True:
                    if child is not None:
                        code = child.poll()
                        if code is None:
                            time.sleep(0.5)
                            continue
                        child.wait()
                        exit_path = directory/f'attempt-{number:03d}.exit.json'
                        if not exit_path.exists():
                            publish(exit_path, dict(returncode=code, time_ns=time.time_ns()))
                    try:
                        outcome = controller_state(Path(intent['directory']), shared)
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
                        # Monitoring transport failures are retained observations,
                        # not authority to restart the controller or GPU fleet.
                        with (directory/f'attempt-{number:03d}.observation-errors.jsonl').open('a') as log:
                            log.write(json.dumps(dict(time_ns=time.time_ns(), error=type(error).__name__,
                                                      detail=str(error)[:2048]))+'\n')
                            log.flush()
                            os.fsync(log.fileno())
                        time.sleep(0.5)
                        continue
                    if outcome['action'] != 'wait':
                        break
                    time.sleep(0.5)
                outcome.update(intent_sha256=G.digest(intent_path), directory=intent['directory'], number=number,
                               observed_time_ns=time.time_ns())
                publish(outcome_path, outcome)
            outcomes.append(outcome)
            if outcome['action'] == 'succeeded':
                finish(directory, outcomes, 'succeeded', started)
                return
            if outcome['action'] == 'stale':
                finish(directory, outcomes, 'stale_candidate', started)
                return
            if outcome['action'] not in ('fresh', 'recover'):
                raise ValueError('invalid terminal supervisor decision')
            previous = Path(intent['directory']) if outcome['action'] == 'recover' else None
            cached = outcome.get('cached_only', False)
            if number <= value['max_restarts']:
                time.sleep(value['restart_delay'])
        finish(directory, outcomes, 'restart_budget_exhausted', started)
    finally:
        os.close(lock)


def finish(directory, outcomes, status, started, **extra):
    publish(directory/'result.json', dict(schema_version=1, record_type='typed_native_supervision',
        status=status, attempts=outcomes, retries=max(0, len(outcomes)-1),
        current_invocation_seconds=time.monotonic()-started, finished_time_ns=time.time_ns(),
        proofs_and_failed_attempts_retained=True, production_ready=False, **extra))


def capture_accounting(path, script):
    value = request(path, script)
    invocation = os.environ.get('INVOCATION_ID', '')
    if not re.fullmatch('[0-9a-f]{32}', invocation):
        raise ValueError('supervisor accounting lacks service invocation')
    membership = [line.split('::', 1)[1] for line in Path('/proc/self/cgroup').read_text().splitlines()
                  if line.startswith('0::')]
    if len(membership) != 1 or Path(membership[0]).name != value['unit']:
        raise ValueError('supervisor accounting is outside its admitted cgroup')
    state = observe(value['unit'])
    if state['InvocationID'] != invocation or state['ControlGroup'] != membership[0]:
        raise ValueError('supervisor accounting service identity changed')
    group = Path('/sys/fs/cgroup')/membership[0].lstrip('/')
    fields = ('memory.current', 'memory.peak', 'memory.max', 'memory.swap.max',
              'memory.events', 'cpu.stat', 'cpu.max', 'cgroup.events')
    publish(Path(value['directory'])/f'accounting-{invocation}.json', dict(schema_version=1,
        unit=value['unit'], invocation=invocation, state=state, captured_time_ns=time.time_ns(),
        counters={name:(group/name).read_text().strip() for name in fields}))


def launch(args, script, pins):
    path, value = create(args, script, pins)
    directory = path.parent
    def quote(argument):
        return '"'+str(argument).replace('%', '%%').replace('\\', '\\\\').replace('"', '\\"')+'"'
    stop = ' '.join(quote(argument) for argument in [value['executable'], value['script'],
                                                     '--supervisor-accounting', str(path)])
    command = ['systemd-run', '--user', '--quiet', '--expand-environment=no', '--service-type=exec',
        '--wait', '--pipe', '--unit='+value['unit'], '--working-directory='+value['cwd'],
        '--property=MemoryMax=4G', '--property=MemorySwapMax=0', '--property=CPUQuota=100%',
        '--property=TasksMax=256', '--property=KillMode=control-group', '--property=OOMPolicy=kill',
        '--property=TimeoutStopSec=30', '--property=RuntimeMaxSec=7200', '--property=LimitCORE=0',
        '--property=UMask=0077', '--property=Restart=on-failure', '--property=RestartSec=2',
        '--property=StartLimitIntervalSec=7200', '--property=StartLimitBurst='+str(value['max_restarts']+2),
        '--property=ExecStopPost='+stop,
        '--setenv=RAYON_NUM_THREADS=1', *value['command']]
    publish(directory/'service-command.json', dict(command=command))
    result = subprocess.run(command)
    state = observe(value['unit'])
    if not terminal(state):
        raise ValueError('supervisor service is still live; inspect this request instead of launching another')
    publish(directory/'launcher-result.json', dict(returncode=result.returncode, state=state))
    if result.returncode:
        raise SystemExit(result.returncode)
    result = read(directory/'result.json')
    print(json.dumps({k: result[k] for k in ('status', 'retries')}))
    if result['status'] != 'succeeded':
        raise SystemExit(1)
