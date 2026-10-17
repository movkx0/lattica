#!/usr/bin/env python3
"""Run only unstarted candidate jobs after a pressure-stopped reference.

Never retries a proof job. Preserves the failed reference; there is no elapsed
time ceiling. No speedup can be claimed without a verified reference.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import signal

spec=importlib.util.spec_from_file_location('throughput',Path(__file__).with_name('bench-apple-throughput.py'))
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--html',type=Path,required=True);args=p.parse_args()
    out=args.output.resolve();report=json.loads((out/'result.json').read_text())
    failed=report.get('failed_windows',[])
    options=report.get('candidate_options',{})
    label='candidate-reference' if options.get('pipeline')=='reference' else 'resident'
    if report['status']!='FAILED' or report['windows'] or len(failed)!=1 or failed[0]['label']!='reference' or not failed[0]['memory_pressure_incident'] or (out/label).exists():
        raise RuntimeError('only unstarted candidates after one pressure-stopped reference are permitted')
    if T.observations()['pressure']!=1:raise RuntimeError('memory pressure must be normal before starting remaining candidates')
    for name, sha in report['build']['source_hashes'].items():
        if T.digest(T.ROOT/name)!=sha:raise RuntimeError('preserved build does not match current worker memory policy/source')
    binaries={role:out/'bin'/name for role,name in {'cpu':'block-v2-grouped-probe','audit':'block-v2-grouped-artifact-audit','metal':'block-v2-metal-grouped-probe'}.items()}
    for binary in binaries.values():
        if T.digest(binary)!=report['build']['binaries'][binary.name]['sha256']:raise RuntimeError('preserved binary changed')
    for name,sha in report['fixture_sha256'].items():
        if T.digest(out/'fixture'/name)!=sha:raise RuntimeError('preserved fixture changed')
    plan=T.resident_worker_plan(report.get('resident_worker_plan',{}).get('selected_workers',2))
    args.workers=plan['selected_workers'];args.kernel_variant=report['kernel_variant'];args.workgroup=report['workgroup']
    args.diagnostic_profile=report.get('diagnostic_profile',False)
    for key,value in options.items():setattr(args,'candidate_'+key,value)
    report['benchmark_budget_seconds']=None;report['worker_timeout_seconds']=None
    report['continuation']={'controller_sha256':T.digest(__file__),'benchmark_budget_seconds':None,'worker_timeout_seconds':None,'additional_jobs':args.workers,'resident_worker_plan':plan,'reason':'execute previously unstarted candidates; do not retry stopped reference'}
    report['resident_worker_plan']=plan
    T.save(out/'result.json',report)
    def interrupted(signum,frame):raise KeyboardInterrupt(f'controller signal {signum}')
    signal.signal(signal.SIGTERM,interrupted)
    try:
        report['windows'].append(T.run_window(args,out,binaries,report['external'],True))
        report.update(status='CANDIDATE_VERIFIED_REFERENCE_STOPPED',valid_comparison=False,target_met=False)
    except BaseException as error:
        report['failed_windows']=[json.loads(p.read_text()) for p in out.glob('*/result.json')]
        report.update(status='FAILED',candidate_failure=str(error));raise
    finally:
        T.save(out/'result.json',report);T.render(report,args.html)

if __name__=='__main__':
    with T.coordinator_lease():main()
