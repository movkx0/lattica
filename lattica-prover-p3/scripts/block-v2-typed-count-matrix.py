#!/usr/bin/env python3
"""Qualify mixed counts with fresh roots and device-specific bootstrap admission.

Run serially so every unmeasured count gets the conservative context allowance.
Existing count qualifications can be reused only after their full provenance,
root, CPU audit, proof plan, binary, profile and GPU identity are rechecked.
This does not measure the complete cold or post-seal transaction boundary.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

SPEC = importlib.util.spec_from_file_location('typed_fleet', Path(__file__).with_name('block-v2-typed-multi-gpu-run.py'))
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
C, T, G = F.C, F.T, F.G


def validate_selection(counts, uuids):
    if not counts or len(set(counts)) != len(counts) or any(type(c) is not int or c not in T.COUNTS for c in counts):
        raise ValueError('matrix counts must be unique members of the qualification contract')
    if not uuids or len(set(uuids)) != len(uuids) or any(not isinstance(u,str) or not u.startswith('GPU-') for u in uuids):
        raise ValueError('matrix requires unique explicit GPU UUIDs')
    return [(count, uuid) for count in counts for uuid in uuids]


def checked_trial(directory, construction, profile, gpu_sha, cpu_sha, fixture_pins):
    config = json.loads((directory/'config.json').read_text())
    summary = json.loads((directory/'summary.json').read_text())
    result = json.loads((directory/'001-typed/result.json').read_text())
    T.check_pins(config['pins'])
    count = result['count']
    if count not in T.COUNTS:
        raise ValueError('retained trial count is outside the qualification contract')
    source = Path(config['fixture'])
    files = T.fixture_files(source, count, construction)
    if (config['workload'] != profile or result['profile_sha256'] != G.profile_digest(config)
            or G.digest(config['cpu_binary']) != cpu_sha
            or any(fixture_pins.get(p.name) != G.digest(p) for p in files)):
        raise ValueError('matrix trial profile, auditor or public fixture differs')
    assignment, sha, assignment_paths = F.calibration_assignment(directory, config, result)
    trial = C.checked_trial(directory, construction, count, assignment, sha, gpu_sha)
    uuid = summary['attempt']['uuid']
    if uuid != result['budget']['gpu']['uuid'] or uuid != trial['context_measurement']['uuid']:
        raise ValueError('matrix trial GPU identity differs across retained records')
    trial.update(count=count, gpu_uuid=uuid, profile_sha256=result['profile_sha256'],
                 binary_sha256=gpu_sha, cpu_binary_sha256=cpu_sha,
                 config_source=C.pin(directory/'config.json'), budget=result['budget'],
                 assignment_sources=[C.pin(p) for p in assignment_paths],
                 audit_artifact_pins=result['artifacts'])
    return trial


def coverage(counts, uuids, trials):
    expected = validate_selection(counts, uuids)
    seen = [(t['count'],t['gpu_uuid']) for t in trials]
    if len(seen) != len(set(seen)) or any(key not in expected for key in seen):
        raise ValueError('duplicate or unrequested matrix trial')
    if any(t.get('cpu_audited') is not True for t in trials):
        raise ValueError('matrix includes a root without an independent CPU audit')
    return {'completed':len(seen), 'requested':len(expected),
            'pending':[{'count':c,'gpu_uuid':u} for c,u in expected if (c,u) not in seen],
            'all_requested_counts_passed':set(seen)==set(expected),
            'all_required_counts_passed':set(counts)==set(T.COUNTS) and set(seen)==set(expected),
            'counts_by_gpu':{u:sorted(c for c,v in seen if v==u) for u in uuids}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('gpu-binary','cpu-binary','fixture','evidence'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--gpu-uuid',action='append',required=True)
    parser.add_argument('--counts',nargs='+',type=int,default=list(T.COUNTS))
    parser.add_argument('--construction',choices=T.CONSTRUCTIONS,default='paired')
    parser.add_argument('--ram-admission',choices=('full','compact'),default='compact')
    parser.add_argument('--workload',type=Path,default=Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json'))
    parser.add_argument('--prior-trial',type=Path,action='append',default=[])
    parser.add_argument('--scratch',type=Path,default=Path('/tmp'))
    parser.add_argument('--trial-timeout',type=int,default=7100)
    args=parser.parse_args()
    requested=validate_selection(args.counts,args.gpu_uuid)
    if not 0 < args.trial_timeout <= 7100:
        parser.error('trial timeout must be 1 through 7100 seconds')
    os.umask(0o077)
    out=args.evidence.resolve();out.mkdir(parents=True,exist_ok=False)
    started=time.monotonic()
    report={'schema':'lattica-typed-count-matrix-v1','status':'preparing','construction':args.construction,
            'counts':args.counts,'gpu_uuids':args.gpu_uuid,'trials':[],'active_trial':None,
            'production_ready':False,'delivered_transactions_measured':False,
            'cold_full64_qualified':False,'post_seal_qualified':False,
            'scope':'Serial independently CPU-audited mixed roots. Each fresh count/device uses live bootstrap admission. Existing public wallets and registered keys exclude complete cold and post-seal timing.'}
    try:
        gpu,cpu,fixture,workload=(p.resolve(strict=True) for p in (args.gpu_binary,args.cpu_binary,args.fixture,args.workload))
        profile=T.resource_profile(workload,args.construction,args.ram_admission)
        files=T.fixture_files(fixture,max(args.counts),args.construction)
        fixture_pins={p.name:G.digest(p) for p in files}
        sources=[Path(__file__),Path(F.__file__),Path(C.__file__),Path(T.__file__),Path(G.__file__),Path(T.R.__file__),gpu,cpu,workload,*files]
        pins=dict(T.pin(p) for p in sources)
        gpu_sha,cpu_sha=G.digest(gpu),G.digest(cpu)
        report.update(input_pins=pins,profile=profile,profile_sha256=G.profile_digest({'workload':profile}),
                      gpu_sha256=gpu_sha,cpu_sha256=cpu_sha,fixture_pins=fixture_pins)
        for directory in args.prior_trial:
            directory=directory.resolve(strict=True)
            trial=checked_trial(directory,args.construction,profile,gpu_sha,cpu_sha,fixture_pins)
            trial['origin']='retained_and_revalidated'
            report['trials'].append(trial)
            coverage(args.counts,args.gpu_uuid,report['trials'])
        report['coverage']=coverage(args.counts,args.gpu_uuid,report['trials'])
        report['status']='running';G.durable(out/'summary.json',report)
        for count,uuid in requested:
            if any(t['count']==count and t['gpu_uuid']==uuid for t in report['trials']):
                continue
            T.check_pins(pins)
            index=args.gpu_uuid.index(uuid)+1
            directory=out/f'count-{count:02d}-gpu-{index:02d}'
            command=[sys.executable,str(Path(T.__file__)),'--construction',args.construction,
                     '--ram-admission',args.ram_admission,'--gpu-binary',str(gpu),'--cpu-binary',str(cpu),
                     '--fixture',str(fixture),'--gpu-uuid',uuid,'--count',str(count),
                     '--scratch',str(args.scratch.resolve()),'--workload',str(workload),'--evidence',str(directory)]
            report['active_trial']={'count':count,'gpu_uuid':uuid,'command':command}
            G.durable(out/'summary.json',report)
            print(json.dumps({'event':'matrix_trial_started','count':count,'gpu_uuid':uuid}),flush=True)
            C.execute_controller(command,out/f'count-{count:02d}-gpu-{index:02d}.controller.log',args.trial_timeout)
            T.check_pins(pins)
            trial=checked_trial(directory,args.construction,profile,gpu_sha,cpu_sha,fixture_pins)
            if trial['count']!=count or trial['gpu_uuid']!=uuid:
                raise ValueError('matrix worker returned a different count/device')
            trial['origin']='fresh_matrix_trial';report['trials'].append(trial)
            report['coverage']=coverage(args.counts,args.gpu_uuid,report['trials'])
            report['active_trial']=None;G.durable(out/'summary.json',report)
            print(json.dumps({'event':'matrix_trial_succeeded','count':count,'gpu_uuid':uuid,
                              'worker_seconds':trial['worker_seconds'],'fresh_proofs':trial['fresh_proofs']}),flush=True)
        T.check_pins(pins)
        for trial in report['trials']:
            directory=Path(trial['summary_source']['path']).parent
            current=checked_trial(directory,args.construction,profile,gpu_sha,cpu_sha,fixture_pins)
            if current != {k:v for k,v in trial.items() if k != 'origin'}:
                raise ValueError('a previously recorded matrix trial changed')
        report.update(status='succeeded',input_pins_unchanged=True,
                      cpu_audited_roots=len(report['trials']),fresh_recursive_proofs=sum(t['fresh_proofs'] for t in report['trials']))
    except BaseException as error:
        report.update(status='failed',failure=f'{type(error).__name__}: {error}')
    finally:
        report['controller_elapsed_seconds']=time.monotonic()-started
        G.durable(out/'summary.json',report)
        print(json.dumps({'status':report['status'],'completed_trials':len(report['trials'])}),flush=True)
    return 0 if report['status']=='succeeded' else 1


if __name__=='__main__':
    sys.exit(main())
