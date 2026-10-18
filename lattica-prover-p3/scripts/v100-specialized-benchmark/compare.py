#!/usr/bin/env python3
"""Single-candidate screens, followed by five alternating paired measurements."""
import argparse
import json
import statistics
from pathlib import Path
import run

OUT=run.OUT
COMBINED='events,commitment,scale,ntt'

def completed(name,tuning):
    path=OUT/name/'verified-sample.json'
    if not path.exists(): run.sample(name,tuning)
    result=json.loads(path.read_text())
    if result['tuning']!=tuning: raise RuntimeError('existing sample has wrong selection')
    return result

def summarize():
    samples=[json.loads(p.read_text()) for p in OUT.glob('*/verified-sample.json')]
    result={'git_commit':json.loads((OUT/'manifest.json').read_text())['git_commit'],
            'status':'measuring','production_qualified':False,
            'scope':'four previously proved user transactions; three recursive proofs; level-two subtree',
            'samples':samples,'measured_arms':{}}
    for arm in ('baseline','combined'):
        values=[s for s in samples if s['name'].startswith('paired-') and s['name'].endswith('-'+arm)]
        if values:
            times=[s['seconds'] for s in values]
            result['measured_arms'][arm]={
                'repeats':len(values),'seconds':times,'median_seconds':statistics.median(times),
                'min_seconds':min(times),'max_seconds':max(times),
                'aggregation_user_transactions_per_hour':14400/statistics.median(times),
                'peak_gpu_mib':max(s['telemetry']['peak_gpu_mib'] for s in values),
                'peak_host_rss_bytes':max(s['telemetry']['peak_rss_bytes'] for s in values)}
    arms=result['measured_arms']
    if len(arms)==2:
        base,tuned=arms['baseline']['median_seconds'],arms['combined']['median_seconds']
        result['combined_time_reduction_percent']=100*(base-tuned)/base
        result['combined_speedup']=base/tuned
        if all(a['repeats']==5 for a in arms.values()): result['status']='passed'
    run.C.write_json(OUT/'comparison.json',result)
    return result

def main():
    global OUT
    parser=argparse.ArgumentParser(description=__doc__)
    run.add_arguments(parser)
    run.configure(parser.parse_args())
    OUT=run.OUT
    completed('warmup-baseline-validated','')
    for candidate in ('events','commitment','scale','ntt'):
        completed('screen-'+candidate,candidate)
        summarize()
    completed('warmup-combined',COMBINED)
    for pair in range(1,6):
        order=[('baseline',''),('combined',COMBINED)]
        if pair%2==0: order.reverse()
        for arm,tuning in order:
            completed(f'paired-{pair:02d}-{arm}',tuning)
            summarize()
    print(json.dumps(summarize()['measured_arms'],indent=2),flush=True)

if __name__=='__main__': main()
