import json
import unittest
import cpu_scaling_profile as p

class CpuScalingTests(unittest.TestCase):
    def test_exact_cpu_only_selector(self):
        argv=['/tmp/lattica_pq_ringct_research-abc',p.PREFIXES['native']+'native_cpu_scaling_16','--exact','--ignored','--test-threads=1','--nocapture']
        self.assertEqual(p.selection('native',16,argv)['workers'],16)
        for changed in [argv[:1]+['recursive_proof']+argv[2:],argv+['--skip','something']]:
            with self.assertRaises(ValueError):p.selection('native',16,changed)
        with self.assertRaises(ValueError):p.selection('native',32,argv)

    def test_complete_perf_counters_and_scope(self):
        row={'kind':'native','workers':16,'cases':159,'elapsed_ns':1,'counts_equal':True,'gpu_used':False,'cache':{'threads_spawned':0,'jobs_started':0,'admitted_host_bytes_peak':1},'original_host_bytes':1,'phase_host_bytes_peak':1,'ledger_all_claims_released':True}
        text='CPU_SCALING_RESULT '+json.dumps(row)+'\n'
        events=''.join('1;;'+e+';100;100.00;\n' for e in p.EVENTS)
        self.assertEqual(len(p.validate(text+events,row)['counters']),5)
        for bad in [text, text+events+events, text+events.replace('1;;cycles:u','<not supported>;;cycles:u')]:
            with self.assertRaises(ValueError):p.validate(bad,row)

    def test_native_phase_receipt_requires_bounded_claim_and_retirement(self):
        row={'kind':'native','workers':12,'cases':159,'elapsed_ns':1,'counts_equal':True,'gpu_used':False,
             'ledger_all_claims_released':True,'original_host_bytes':2 << 30,
             'phase_host_bytes_peak':3 << 30,'cache':{'threads_spawned':0,'jobs_started':0,'admitted_host_bytes_peak':3 << 30}}
        selected={'kind':'native','workers':12}
        events=''.join('1;;'+e+';100;100.00;\n' for e in p.EVENTS)
        render=lambda r:'CPU_SCALING_RESULT '+json.dumps(r)+'\n'+events
        p.validate(render(row),selected)
        for changes in [{'ledger_all_claims_released':False}, {'phase_host_bytes_peak':(3 << 30)+1}, {'phase_host_bytes_peak':(2 << 30)-1}]:
            with self.assertRaises(ValueError):p.validate(render({**row,**changes}),selected)

if __name__=='__main__':unittest.main()
