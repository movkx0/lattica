import copy
import unittest
from test_owned_workflow_case_receipts import fixture, render, validate, collect_gpu_receipts

def cpu_fixture(count=3):
    events, report = fixture(count)
    cpu = dict(run_id=1, verified=count, whole_stage_ns=count*1000+100,
               spend_ns=count*300, verification_ns=count*200, attempts=count,
               random_calls=count*2, random_blocks=count*3, proposals=count*8,
               parameter_cache_hits=0, cleanup_complete=True, gpu_contexts=0, gpu_generation_calls=0)
    generation = dict(cpu=cpu, spends=count, seconds=cpu['whole_stage_ns']/1e9,
                      managed_peak_bytes=0, witness_completed_calls=0, witness_device_calls=0, witness_device_ns=0)
    converted = []
    for prefix, value in events:
        if prefix == 'owned_generation_report': continue
        if prefix == 'owned_generation_spend':
            value = dict(run_id=1, ordinal=value['ordinal'], elapsed_ns=1000, generation_ns=700,
                         verification_ns=200, statistics=dict(parameters_ns=50, inputs_ns=100, spend_ns=300,
                            encoding_ns=50, cleanup_ns=50, attempts=1, random_calls=2, random_blocks=3,
                            proposals=8, parameter_cache_hits=0, status=0))
            prefix = 'owned_generation_cpu_spend'
        if prefix == 'owned_generation_terminal':
            value = dict(schema='ringct-cpu-generation-terminal-v1', session_id=None, cpu_run_id=1,
                         session=None, operations=copy.deepcopy(generation), stark_proofs=0, registrations=0)
        converted.append([prefix,value])
    report['generation_session_id'] = None
    report['generation'] = generation
    return converted,report

class CpuGenerationCaseTests(unittest.TestCase):
    def audit(self, events, report): return validate(render(events),report,collect_gpu_receipts)
    def test_n3_n4_cpu_completion_keeps_gpu_proof_requirements(self):
        for n in (3,4):
            events,report=cpu_fixture(n)
            result=self.audit(events,report)
            self.assertIsNone(result['generation_session_id'])
            self.assertEqual(result['cpu_transaction_generation']['verified'],n)
            self.assertEqual(result['gpu_receipts']['native_reports'],12)
            self.assertEqual(result['gpu_receipts']['private_spend_reports'],0)
    def test_premature_or_reordered_cpu_completion_refused(self):
        events,report=cpu_fixture()
        del events[0]
        with self.assertRaises(ValueError): self.audit(events,report)
        events,report=cpu_fixture();events[0],events[1]=events[1],events[0]
        with self.assertRaises(ValueError): self.audit(events,report)
    def test_cpu_cannot_fabricate_gpu_session(self):
        events,report=cpu_fixture();report['generation_session_id']=1
        with self.assertRaises(ValueError): self.audit(events,report)
    def test_cpu_cleanup_and_exact_spend_totals_required(self):
        for key,value in [('cleanup_complete',False),('spend_ns',1),('verified',2),('gpu_contexts',1),('gpu_generation_calls',1)]:
            events,report=cpu_fixture();report['generation']['cpu'][key]=value
            for prefix,terminal in events:
                if prefix=='owned_generation_terminal':terminal['operations']=copy.deepcopy(report['generation'])
            with self.assertRaises(ValueError): self.audit(events,report)
    def test_cpu_does_not_relax_native_proof_backend(self):
        events,report=cpu_fixture()
        native=next(v for p,v in events if p.startswith('owned_native_') and p.endswith('_report'))
        native['policy']='cpu-required'
        with self.assertRaises(ValueError): self.audit(events,report)
    def test_mixed_generation_backends_refused(self):
        old,_=fixture();events,report=cpu_fixture();events.insert(0,old[0])
        with self.assertRaises(ValueError): self.audit(events,report)
    def test_metadata_handoff_requires_retirement_before_gpu_receipts(self):
        from cpu_generation_receipts import metadata_handoff
        events,_=cpu_fixture()
        self.assertEqual(metadata_handoff(render(events),3)['verified'],3)
        with self.assertRaises(ValueError):
            metadata_handoff('proving_stage_report {}\n'+render(events),3)
        with self.assertRaises(ValueError): metadata_handoff('',3)

if __name__=='__main__':unittest.main()
