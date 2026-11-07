import argparse
import copy
import json
import unittest
from cpu_proof_profile import selection, validate, validate_commitment

class CpuProofAcceptance(unittest.TestCase):
    def args(self, **changes):
        values=dict(cpu_proof=True, profile='cpu-proof', build_label='cpu-build', seconds=1200,
                    expect_tests=False,expect_result=False,expect_direct_result=False,
                    full_workflow_case=False,benchmark=False,generation_only=False,host_profile='standard')
        values.update(changes)
        return argparse.Namespace(**values)

    def selected(self):
        return selection(self.args(), ['/tmp/pq-ringct-cpu-proof','--input','/tmp/public.json'])

    def report(self):
        s=self.selected()
        return dict(schema='ringct-cpu-proof-profile-v2',backend='cpu',layout='paired-v1',options=s['options'],
                    gpu_contexts=0,gpu_proof_calls=0,fresh_stark_randomness=True,complete_workflow=False,
                    cleanup_complete=True,input_sha3_256='12'*32,records=[dict(repetition=0,wall_ns=10,cleanup_complete=True,
                        admitted_device_bytes=0,completed_jobs=3,planned_jobs=3,peak_workers=1,
                        peak_admitted_host_bytes=100,jobs=[dict(id=i,kind='native',elapsed_ns=9,
                            mutation_checks=2,proof_digest=f'{i:064x}') for i in range(3)])])

    def terminal(self, report):
        inventory=dict(input_sha3_256='12'*32,requests=[dict(case=i,request=0,kind='shake',segments=1) for i in range(3)])
        return 'CPU_PROOF_INVENTORY '+json.dumps(inventory)+'\nCPU_PROOF_PROFILE '+json.dumps(report)
    def test_missing_inventory_and_fake_coverage(self):
        with self.assertRaises(RuntimeError):
            validate('CPU_PROOF_PROFILE '+json.dumps(self.report()),self.selected())
        r=self.report();r['records'][0]['jobs'].pop();r['records'][0].update(completed_jobs=2,planned_jobs=2)
        with self.assertRaises(RuntimeError):validate(self.terminal(r),self.selected())
    def test_valid_cpu_slice(self):
        self.assertEqual(validate(self.terminal(self.report()),self.selected())['backend'],'cpu')

    def test_scope_does_not_accept_gpu_or_full_workflow(self):
        for key,value in [('gpu_contexts',1),('gpu_proof_calls',1),('complete_workflow',True),
                          ('cleanup_complete',False),('fresh_stark_randomness',False),('layout','singleton')]:
            r=self.report();r[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                validate(self.terminal(r),self.selected())

    def test_incomplete_duplicate_and_memory_results_rejected(self):
        for mutate in [lambda r:r['records'][0].update(completed_jobs=0),
                       lambda r:r['records'][0].update(peak_admitted_host_bytes=33<<30),
                       lambda r:r['records'][0]['jobs'][0].update(mutation_checks=0),
                       lambda r:r.update(records=[]),
                       lambda r:r['records'].append(copy.deepcopy(r['records'][0]))]:
            r=self.report();mutate(r)
            with self.assertRaises(RuntimeError):validate(self.terminal(r),self.selected())

    def test_budget_features_and_timebox(self):
        for args,argv in [(self.args(seconds=1201),[]),(self.args(profile='full'),[]),
                          (self.args(full_workflow_case=True),[]),(self.args(host_profile='expanded-36'),[]),
                          (self.args(),['--workers','16','--threads-per-proof','16']),
                          (self.args(),['--mode','full'])]:
            with self.assertRaises((RuntimeError,KeyError)):
                selection(args,['/tmp/pq-ringct-cpu-proof','--input','/tmp/public.json',*argv])


class CommitmentAcceptance(unittest.TestCase):
    def rows(self):
        return [dict(variant='combined',tile_rows=1024,threads=16,height=1<<18,width=w,
                     repetition=i,commit_ns=1,verified=True) for w in (94,200) for i in range(3)]
    def output(self, rows):
        return '\n'.join('CPU_COMMITMENT_SCREEN '+json.dumps(r) for r in rows)
    def test_complete_screen(self):
        self.assertEqual(len(validate_commitment(self.output(self.rows()),'combined',1024)),6)
    def test_incomplete_or_mismatched_screen(self):
        for change in [lambda r:r.pop(),lambda r:r[0].update(verified=False),
                       lambda r:r[0].update(variant='reference'),lambda r:r[0].update(commit_ns=0),
                       lambda r:r[0].update(tile_rows=256),lambda r:r[0].update(threads=4)]:
            rows=self.rows();change(rows)
            with self.assertRaises(RuntimeError): validate_commitment(self.output(rows),'combined',1024)

if __name__=='__main__':unittest.main()
