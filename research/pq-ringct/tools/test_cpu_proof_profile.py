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
        return dict(schema='ringct-cpu-proof-profile-v4',backend='cpu',layout='paired-v1',options=s['options'],
                    gpu_contexts=0,gpu_proof_calls=0,fresh_stark_randomness=True,complete_workflow=False,
                    cleanup_complete=True,input_sha3_256='12'*32,records=[dict(repetition=0,wall_ns=10,cleanup_complete=True,
                        admitted_device_bytes=0,completed_jobs=3,planned_jobs=3,peak_workers=1,
            peak_admitted_host_bytes=100,jobs=[dict(id=i,kind='native',elapsed_ns=9,service_ns=8,cold_input_service_upper_ns=8,
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
    def test_tuning_and_target_selections_are_explicit(self):
        for argv in (['--cpu-hash-kernel','interleaved2'], ['--transaction','3'],
            ['--identity-overlap','yes'], ['--cpu-commitment-path','replay'], ['--baseline-identity-overlap','1'], ['--compare-target','1'], ['--candidate-first','1']):
            with self.assertRaises(RuntimeError):
                selection(self.args(), ['/tmp/pq-ringct-cpu-proof','--input','fixture',*argv])
        chosen=selection(self.args(), ['/tmp/pq-ringct-cpu-proof','--input','fixture',
            '--cpu-variant','combined','--cpu-hash-kernel','interleaved2','--identity-overlap','1',
            '--mode','paired','--transaction','0','--compare-target','1'])
        self.assertTrue(chosen['options']['compare_target'])
    def test_target_proofs_require_cold_setup_and_bound_kernel_selection(self):
        import copy
        selected=selection(self.args(), ['/tmp/pq-ringct-cpu-proof','--input','/tmp/public.json',
            '--cpu-variant','combined','--cpu-hash-kernel','interleaved2','--identity-overlap','1',
            '--mode','paired','--transaction','0','--compare-target','1'])
        report=self.report()
        report['options']=selected['options']
        row=report['records'][0]
        row.update(completed_jobs=4,planned_jobs=4)
        row['jobs']=row['jobs'][:2]+[
            dict(id=2,kind='target_compile',elapsed_ns=2,service_ns=2,compiled_storage_bytes=5000,dependency_storage_bytes=10),
            dict(id=3,kind='target_comparison',elapsed_ns=40,service_ns=40,mutation_checks=4,
                comparisons=[dict(candidate=c,hash_kernel='interleaved2' if c else 'existing',identity_overlap=c,commitment_path='existing',
                    observation=dict(id=3,kind='recursive_proof',elapsed_ns=20,service_ns=22,
                        compile_ns=2,registration_ns=3,prepared_hit=False,mutation_checks=2,proof_digest=f'{10+i:064x}'))
                    for i,c in enumerate((False,True))])]
        def output(r):
            inventory=dict(input_sha3_256='12'*32,requests=[dict(case=i,request=0,kind='shake',segments=2) for i in range(3)])
            return 'CPU_PROOF_INVENTORY '+json.dumps(inventory)+'\nCPU_PROOF_PROFILE '+json.dumps(r)
        validate(output(report),selected)
        for field,value in [('prepared_hit',True),('compile_ns',0),('service_ns',1),('proof_digest','0'*64)]:
            changed=copy.deepcopy(report)
            changed['records'][0]['jobs'][3]['comparisons'][0]['observation'][field]=value
            with self.subTest(field=field),self.assertRaises(RuntimeError):
                validate(output(changed),selected)
        changed=copy.deepcopy(report)
        changed['records'][0]['jobs'][3]['comparisons'][1]['hash_kernel']='existing'
        with self.assertRaises(RuntimeError):validate(output(changed),selected)

    def test_latest_baseline_and_candidate_paths_are_bound(self):
        args=['/tmp/pq-ringct-cpu-proof','--input','fixture','--cpu-variant','combined',
            '--cpu-commitment-path','packed','--identity-overlap','1','--baseline-identity-overlap','1',
            '--mode','paired','--transaction','0','--compare-target','1']
        chosen=selection(self.args(),args)['options']
        self.assertEqual(chosen['cpu_commitment_path'],'packed')
        self.assertTrue(chosen['baseline_identity_overlap'])
        with self.assertRaises(RuntimeError): selection(self.args(),args+['--cpu-hash-kernel','interleaved2'])


class CommitmentAcceptance(unittest.TestCase):
    def rows(self):
        return [dict(variant='combined',hash_kernel='existing',commitment_path='existing',tile_rows=1024,threads=16,height=1<<18,width=w,matrices=n,
            repetition=i,commit_ns=1,verified=True) for w,n in ((94,1),(200,1),(51,1),(3,16)) for i in range(3)]
    def output(self, rows):
        return '\n'.join('CPU_COMMITMENT_SCREEN '+json.dumps(r) for r in rows)
    def test_complete_screen(self):
        self.assertEqual(len(validate_commitment(self.output(self.rows()),'combined',1024)),12)
    def test_incomplete_or_mismatched_screen(self):
        for change in [lambda r:r.pop(),lambda r:r[0].update(verified=False),
                       lambda r:r[0].update(variant='reference'),lambda r:r[0].update(commit_ns=0),
                       lambda r:r[0].update(tile_rows=256),lambda r:r[0].update(threads=4)]:
            rows=self.rows();change(rows)
            with self.assertRaises(RuntimeError): validate_commitment(self.output(rows),'combined',1024)

if __name__=='__main__':unittest.main()
