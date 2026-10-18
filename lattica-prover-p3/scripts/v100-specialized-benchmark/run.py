#!/usr/bin/env python3
"""Pinned four-input research measurements with a container resource watchdog."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import resource
import shutil
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
CRATE = ROOT.parents[1]
OUT = None
UUID = None
GIB = 1 << 30
import monitor as E
C = E


def add_arguments(parser):
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--gpu-uuid', required=True)


def configure(args):
    global OUT, UUID
    OUT, UUID = args.evidence.resolve(), args.gpu_uuid


def verify_pins():
    manifest = json.loads((OUT / 'manifest.json').read_text())
    if manifest['gpu']['gpu']['uuid'] != UUID:
        raise RuntimeError('device UUID differs from prepared evidence')
    for filename, pin in manifest['binaries'].items():
        if C.digest(OUT / filename) != pin:
            raise RuntimeError('benchmark binary changed: ' + filename)
    for filename, pin in json.loads((OUT / 'fixture-hashes.json').read_text()).items():
        if C.digest(OUT / 'fixture' / filename) != pin:
            raise RuntimeError('benchmark fixture changed: ' + filename)
    for filename, pin in json.loads((OUT / 'source-hashes.json').read_text()).items():
        if C.digest(CRATE / filename) != pin:
            raise RuntimeError('benchmark source changed; rebuild and prepare: ' + filename)
    for filename, pin in manifest.get('adapter_files', {}).items():
        if C.digest(ROOT / filename) != pin:
            raise RuntimeError('benchmark adapter changed; rebuild and prepare: ' + filename)
    for filename, pin in manifest.get('controller_files', {}).items():
        if C.digest(ROOT / filename) != pin:
            raise RuntimeError('benchmark controller changed; prepare fresh evidence: ' + filename)
    return manifest


def admit():
    bounds, hardware = C.cgroup(), C.gpu(UUID)
    maximum, current = int(bounds['memory.max']), int(bounds['memory.current'])
    if not 56*GIB <= maximum <= 64*GIB or maximum-current < 54*GIB or bounds['memory.swap.max'] != '0':
        raise RuntimeError('requires existing 56..64 GiB cgroup, 54 GiB headroom and zero swap')
    quota, period = bounds['cpu.max'].split()
    if len(os.sched_getaffinity(0)) < 4 or (quota != 'max' and int(quota)/int(period) < 4):
        raise RuntimeError('requires four CPU cores of quota')
    if hardware['compute_processes'] or float(hardware['gpu']['memory.free']) < 28*1024:
        raise RuntimeError('requires idle GPU with 28 GiB free VRAM')


def environment(gpu=False, tuning=''):
    env = {k:v for k,v in os.environ.items() if not k.startswith(('LATTICA_', 'RAYON_'))}
    env.update(RAYON_NUM_THREADS='4', LATTICA_SPILL_BACKING='memory',
               LATTICA_SPILL_MAX_BYTES=str(32*GIB), LATTICA_PROVING_POLICY='cpu-required')
    if gpu:
        on = ('HASH', 'RETAIN_TREES', 'RESIDENT_LDE', 'OPENINGS', 'OPENING_COMPACT',
              'COMPACT_PROVER_DATA', 'DIRECT_READBACK', 'PARALLEL_READBACK',
              'QUERY_GATHER', 'QUOTIENT_LDE', 'QUOTIENT_EVAL', 'QUOTIENT_RESIDENT',
              'LOOKUP', 'OPENING_EVAL', 'FRI_RESIDENT', 'PCS_DEVICE_ONLY', 'WITNESS',
              'RANDOMNESS', 'TRANSCRIPT', 'FRI_FOLD', 'OPENING_DENOMINATOR_CACHE')
        env.update({'LATTICA_V2_GPU_'+k:'1' for k in on})
        env.update(LATTICA_V2_GPU_PIPELINE='0', LATTICA_V2_GPU_OPENING_PINNED='0',
                   LATTICA_V2_QUOTIENT_FUSION='1', LATTICA_V2_GPU_WORKERS='1',
                   LATTICA_V2_GPU_MANAGED_BYTES=str(16*GIB),
                   LATTICA_V2_GPU_CONTEXT_BYTES=str(4*GIB),
                   LATTICA_V2_HOST_OUTPUT_BYTES=str(32*GIB),
                   LATTICA_BENCHMARK_CONTAINER='1', LATTICA_GPU_DEVICE_UUID=UUID,
                   LATTICA_PROVING_POLICY='gpu-required', LATTICA_PROVING_REPORT='1',
                   LATTICA_V2_GPU_TUNING=tuning, OCL_DEFAULT_DEVICE_TYPE='GPU')
    return env

def stage(argv, name, gpu=False, tuning=''):
    return E.run_stage(argv, OUT/name, environment(gpu, tuning), UUID, gpu_work=gpu)

def prepare(args):
    admit()
    OUT.mkdir(parents=True, exist_ok=False)
    for name, source in (('cpu-probe', args.cpu_binary), ('gpu-probe', args.gpu_binary),
                         ('gpu-tests', args.gpu_tests)):
        if source is not None:
            shutil.copy2(source.resolve(strict=True), OUT/name)
    fixture = OUT/'fixture'
    fixture.mkdir()
    origin = args.fixture.resolve(strict=True)
    for name in ('height', 'key.1', 'key.2', 'key.3', *(f'wallet.{i}' for i in range(4))):
        source = origin/name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError('fixture inputs must be regular nonsymlink files')
        shutil.copy2(source, fixture/name)
    if int.from_bytes((fixture/'height').read_bytes(), 'little') != 262144:
        raise RuntimeError('resource screen requires registered height 262144')
    stage([OUT/'cpu-probe', 'describe', fixture], 'expectation')
    expected, = E.records(OUT/'expectation/benchmark.log', 'four_expectation')
    if (expected['count'], expected['level'], expected['fresh_recursive_proofs']) != (4, 2, 3):
        raise RuntimeError('unexpected four-input workload geometry')
    C.write_json(OUT/'expected.json', expected)
    C.write_json(OUT/'fixture-hashes.json', {p.name: C.digest(p) for p in fixture.iterdir()})
    pins = {str(p.relative_to(CRATE)): C.digest(p) for p in C.source_files(CRATE) if p.is_relative_to(CRATE)}
    for p in (CRATE/'vendor').rglob('*'):
        if p.is_file(): pins[str(p.relative_to(CRATE))] = C.digest(p)
    C.write_json(OUT/'source-hashes.json', pins)
    C.write_json(OUT/'manifest.json', {
        'git_commit': C.capture(['git', 'rev-parse', 'HEAD'], cwd=CRATE),
        'git_status': C.capture(['git', 'status', '--porcelain'], cwd=CRATE),
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'gpu': C.gpu(UUID), 'cgroup': C.cgroup(),
        'binaries': {name: C.digest(OUT/name) for name in ('cpu-probe', 'gpu-probe', 'gpu-tests') if (OUT/name).is_file()},
        'adapter_files': {str(p.relative_to(ROOT)): C.digest(p) for p in (ROOT/'adapter').rglob('*') if p.is_file()},
        'controller_files': {p.name: C.digest(p) for p in ROOT.glob('*.py')},
        'scope': 'four existing JoinSplit wallet proofs, two pair wrappers, one level-two merge root',
        'policy': 'gpu-required; all 16 arithmetic stages; independent CPU root-only audit',
        'managed_gpu_bytes': 16*GIB, 'driver_reserve_bytes': 4*GIB, 'host_budget_bytes': 32*GIB,
        'sampled_rss_watchdog_bytes': E.RSS_LIMIT, 'sampled_vram_watchdog_bytes': 20*GIB,
        'isolation': 'existing zero-swap container cgroup plus process-group watchdog; no systemd per-worker cgroup',
        'timing': 'includes fresh process program setup, all proving stages, native proof verification and serialization; excludes wallet generation, registration, executable build, GPU context initialization and final separate CPU audit',
        'production_qualified': False})

def sample(name, tuning):
    if not name or Path(name).name != name or name in ('.', '..'):
        raise RuntimeError('sample name must be one path component')
    verify_pins()
    admit()
    expected = json.loads((OUT/'expected.json').read_text())
    external = [expected[k] for k in ('profile','chain','root')]
    job = OUT/(name+'-job')
    result_path = OUT/name/'result.json'
    if result_path.exists():
        telemetry=json.loads(result_path.read_text())
        if telemetry['status']!='passed': raise RuntimeError('cannot resume failed GPU execution')
    else:
        shutil.copytree(OUT/'fixture', job)
        telemetry = stage([OUT/'gpu-probe','aggregate',job,*external],name,True,tuning)
    log = OUT/name/'benchmark.log'
    text = log.read_text()
    result, = E.records(log,'specialized_benchmark_complete')
    reports = E.records(log,'proving_stage_report')
    registered = [r for r in reports if r['entry_point']=='block_v2_registered_program']
    if len(registered)!=3 or any(not r['succeeded'] or not r['stage_coverage_complete']
        or r['completion_rejected'] or r['observation_errors'] or r['policy']!='gpu_required' for r in reports):
        raise RuntimeError('missing complete required-GPU proving receipts')
    stages = {'public_values','witness_trace','preprocessing','lookup','transform','quotient','randomness',
              'hiding','commitment','opening','fri_fold','fri_query','final_polynomial','scalar','transcript','grinding'}
    full = [r for r in reports if r['entry_point'] in ('block_v2_recursive_wrap_pair','block_v2_recursive_merge')]
    if len(full)!=3: raise RuntimeError('missing recursive request reports')
    for r in full:
        observed = {o['stage'] for o in r['observations'] if o['backend']=='open_cl' and o['device_calls']>0}
        if not stages.issubset(observed):
            raise RuntimeError('recursive request is missing device receipts: '+str(stages-observed))
    special = [line for line in text.splitlines() if line.startswith('bounded_gpu_quotient_specialization selected=true')]
    rejected = [line for line in text.splitlines() if line.startswith('bounded_gpu_quotient_specialization selected=false')]
    executions = [line for line in text.splitlines() if line.startswith('bounded_gpu_quotient_specialized_execution ')]
    if len(special)!=3 or len(executions)!=3 or rejected:
        raise RuntimeError('four-input workload requires three confirmed specialized quotient executions')
    if (tuning and ('bounded_gpu_tuning ' not in text or 'nvidia_supported=true' not in text)) or result['tuning']!=tuning:
        raise RuntimeError('tuning configuration missing from actual worker')
    audit = OUT/(name+'-root-only')
    audit.mkdir(exist_ok=True)
    for filename in ('height','key.1','key.2','key.3','node.2.0'):
        shutil.copy2(job/filename,audit/filename)
    audit_result=OUT/(name+'-cpu-audit')/'result.json'
    verification = json.loads(audit_result.read_text()) if audit_result.exists() else stage(
        [OUT/'cpu-probe','verify-root',audit,*external],name+'-cpu-audit')
    if verification['status']!='passed': raise RuntimeError('independent CPU audit failed')
    if 'four_root_audit=PASS' not in (OUT/(name+'-cpu-audit')/'benchmark.log').read_text():
        raise RuntimeError('independent CPU verification missing')
    result.update(name=name,telemetry=telemetry,cpu_audit=verification,
                  required_gpu_reports=len(reports),registered_proofs=len(registered),
                  specialized_compilations=len(special),specialized_executions=len(executions),
                  quotient_specialization_rejections=rejected,
                  root_sha256=C.digest(audit/'node.2.0'),root_bytes=(audit/'node.2.0').stat().st_size,
                  aggregation_user_transactions_per_hour=4*3600/result['seconds'])
    C.write_json(OUT/name/'verified-sample.json',result)
    print(json.dumps(result),flush=True)

def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    p=argparse.ArgumentParser()
    add_arguments(p)
    p.add_argument('action',choices=['prepare','sample','test'])
    p.add_argument('--fixture', type=Path)
    p.add_argument('--cpu-binary', type=Path)
    p.add_argument('--gpu-binary', type=Path)
    p.add_argument('--gpu-tests', type=Path)
    p.add_argument('--name')
    p.add_argument('--tuning',default='')
    p.add_argument('--filter',default='gpu_tuning_')
    p.add_argument('--host-tests',action='store_true')
    p.add_argument('--skip',action='append',default=[])
    a=p.parse_args()
    configure(a)
    if a.action=='prepare':
        if any(getattr(a, k) is None for k in ('fixture', 'cpu_binary', 'gpu_binary')):
            p.error('prepare requires --fixture, --cpu-binary and --gpu-binary')
        prepare(a)
    elif a.action=='sample': sample(a.name,a.tuning)
    else:
        verify_pins()
        admit()
        if not (OUT/'gpu-tests').is_file(): p.error('prepare with --gpu-tests before running tests')
        E.RSS_LIMIT=3*GIB
        command=[OUT/'gpu-tests',a.filter,'--test-threads=1','--nocapture']
        if not a.host_tests: command.append('--ignored')
        for skipped in a.skip: command.extend(['--skip',skipped])
        stage(command,a.name or 'gpu-tuning-tests',not a.host_tests,a.tuning)

if __name__=='__main__': main()
