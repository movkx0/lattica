#!/usr/bin/env python3
"""Focused correctness qualification for the resident Metal research pipeline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]

def hashes():
    paths=[ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'build.rs',*sorted((ROOT/'src').rglob('*'))]
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file() and p.name!='.DS_Store'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    args.out.mkdir(parents=True,exist_ok=False)
    cases=[
        ('proof-opt','gpu_compact_quotient_pipeline_preserves_full_proof_bytes','resident','optimized',128),
        ('proof-reference-kernels','gpu_compact_quotient_pipeline_preserves_full_proof_bytes','resident','reference',256),
        ('ntt','gpu_resident_lde_columns_caps_and_paths_match_cpu','resident','optimized',128),
        ('ntt-multigroup','gpu_resident_lde_multigroup_ntt_and_unequal_input_heights_match_cpu','resident','optimized',256),
        ('arithmetic','arithmetic_matches_full_width_integer_oracle_in_both_memory_modes','reference','optimized',256),
        ('batch','resident_batches_count_each_interval_once_and_flush_incomplete_work','resident','reference',256),
        ('storage','frozen_storage_rejects_writable_aliases_and_compacts_after_completion','resident','reference',256),
        ('accounting','backing_tracks_above_estimate_and_rejects_only_overflow','resident','reference',256),
        ('unwind','gpu_lde_error_and_unwind_drain_before_transform_reservations_release','resident','reference',256),
        ('process-death','gpu_failed_drain_aborts_worker_and_releases_job_lease','resident','reference',256),
    ]
    report={'status':'RUNNING','proof_source_sha256':hashes(),'binary_sha256':hashlib.sha256(args.binary.read_bytes()).hexdigest(),'tests':[]}
    try:
        for label,suffix,pipeline,variant,group in cases:
            env={**os.environ,'RAYON_NUM_THREADS':'2','LATTICA_V2_GPU_RETAIN_TREES':'1','LATTICA_V2_GPU_PIPELINE':'0',
                 'LATTICA_V2_METAL_PIPELINE':pipeline,'LATTICA_V2_METAL_KERNEL_VARIANT':variant,'LATTICA_V2_METAL_WORKGROUP':str(group),
                 'LATTICA_V2_METAL_MEMORY':'shared','LATTICA_V2_METAL_DEFER_TIMING':'1','LATTICA_V2_GPU_OPENING_COMPACT':'1',
                 'LATTICA_SPILL_BACKING':'memory','LATTICA_SPILL_MAX_BYTES':str(1<<30),'LATTICA_V2_GPU_PARALLEL_READBACK':'0'}
            path=args.out/(label+'.log');started=time.monotonic()
            with path.open('w') as log:
                result=subprocess.run([str(args.binary.resolve()),suffix,'--ignored','--test-threads=1','--nocapture'],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=90)
            passed=result.returncode==0 and '1 passed; 0 failed' in path.read_text()
            report['tests'].append({'label':label,'test':suffix,'pipeline':pipeline,'variant':variant,'workgroup':group,'status':'PASS' if passed else 'FAIL','seconds':time.monotonic()-started,'log_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
            print(label,report['tests'][-1]['status'],flush=True)
            if not passed:raise RuntimeError(path.read_text()[-3500:])
        if hashes()!=report['proof_source_sha256']:raise RuntimeError('sources changed during qualification')
        report['status']='PASS'
    except BaseException as error:
        report.update(status='FAIL',failure=str(error));raise
    finally:
        (args.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
