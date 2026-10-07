#!/usr/bin/env python3
"""Synthetic query comparisons test withholding; they are not benchmark runs."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from benchmark_report.history import comparison_windows
from benchmark_report.model import blank_run, digest, json_bytes, reference
from benchmark_report.typed import GPU_SCHEMA
from benchmark_report.query import resource_limits


class QueryReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.series = self.root/'series'; self.series.mkdir()
        budget = {'cpu':{'rayon_threads':8}, 'host':{'worker_bytes':100},
                  'gpu':{'uuid':'synthetic', 'managed_bytes':50, 'context_bytes':10},
                  'detected_gpu':{'nvidia':{'driver':'synthetic'},'opencl':{'driver':'synthetic'}}}
        assignment = self.series/'assignment.json'
        assignment.write_bytes(json_bytes({'schema':'lattica-typed-resource-assignment-v1','limits':resource_limits(budget)}))
        gpu = self.series/'gpu'; gpu.write_text('synthetic GPU')
        cpu = self.series/'cpu'; cpu.write_text('synthetic CPU')
        fixture = self.series/'fixture'; fixture.mkdir()
        for name in ('body.json','height.json',*(f'key.{n}' for n in range(1,13)),*(f'wallet.{n}' for n in range(4))):
            (fixture/name).write_text('synthetic public '+name)
        inputs = {str(p):digest(p) for p in (gpu,cpu,assignment,*fixture.iterdir())}
        profiles = {'rows':{'version':1,'name':'synthetic','height':262144,'geometry':{'columns':98}}}
        profiles['gather'] = copy.deepcopy(profiles['rows'])
        profiles['gather']['geometry']['query_readback_layout'] = 'gather'
        hashes = {k:hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest() for k,v in profiles.items()}
        self.data = {'schema':'lattica-typed-query-comparison-v1','status':'succeeded',
                     'construction':'paired','count':4,'requested_pairs':5,
                     'baseline_query_layout':'rows','candidate_query_layout':'gather',
                     'profiles':profiles,'profile_sha256':hashes,'input_pins':inputs,
                     'gpu_sha256':digest(gpu),'cpu_sha256':digest(cpu),
                     'resource_assignment':reference(assignment,self.root),'trials':[],'pairs':[]}
        self.runs = []
        for n in range(1,6):
            order = ['rows','gather'] if n % 2 else ['gather','rows']
            self.data['pairs'].append({'pair':n,'order':order,'worker_seconds':{'rows':40,'gather':30},'worker_reduction_percent':25})
            for layout in order:
                directory = self.series/f'pair-{n}-{layout}'; directory.mkdir()
                result = {'schema':GPU_SCHEMA,'status':'succeeded','construction':'paired','count':4,
                          'cpu_audited':True,'fresh_proofs':4,'elapsed_seconds':40 if layout=='rows' else 30,
                          'binary_sha256':digest(gpu),'profile_sha256':hashes[layout],
                          'budget':{**copy.deepcopy(budget),'query_readback_layout':layout},'artifacts':{'node.6.0':'1'*64},
                          'resource_assignment_sha256':self.data['resource_assignment']['sha256']}
                result_path = directory/'result.json';result_path.write_bytes(json_bytes(result))
                summary_path = directory/'summary.json';summary_path.write_bytes(json_bytes({'schema':GPU_SCHEMA,'status':'succeeded','result':result}))
                config_path = directory/'config.json';config_path.write_bytes(json_bytes({
                    'workload':profiles[layout],'gpu_binary':str(gpu),'cpu_binary':str(cpu),'fixture':str(fixture),'pins':inputs}))
                trial = {'pair':n,'construction':'paired','query_readback_layout':layout,
                         'worker_seconds':result['elapsed_seconds'],'cpu_audited':True,'fresh_proofs':4,
                         'root_sha256':'1'*64,'binary_sha256':digest(gpu),'cpu_binary_sha256':digest(cpu),
                         'profile_sha256':hashes[layout],'result_source':reference(result_path,self.root),
                         'summary_source':reference(summary_path,self.root),'config_source':reference(config_path,self.root)}
                self.data['trials'].append(trial)
                run = blank_run(f'synthetic-{n}-{layout}','Synthetic query readback')
                run.update(status='succeeded',root_bytes=1)
                run['workload'].update(user_transactions=3,issuance_transactions=1,count_evidence='Synthetic test')
                run['verification']['cpu_audited'] = True
                run['sources'] = [reference(result_path,self.root)]
                self.runs.append(run)

    def windows(self):
        (self.series/'summary.json').write_bytes(json_bytes(self.data))
        return comparison_windows(self.root,[self.series],self.runs)

    def withheld(self):
        groups = self.windows(); self.assertTrue(groups)
        self.assertTrue(all(not w['complete_mapping'] for ws in groups.values() for w in ws))

    def test_complete_pairs_retain_each_worker_window_once(self):
        groups = self.windows()
        self.assertEqual(len(groups),2)
        for name, windows in groups.items():
            self.assertEqual(len(windows),5)
            self.assertTrue(all(w['complete_mapping'] and w['recorded']['repeat_qualified'] for w in windows))
            self.assertEqual(sum(w['elapsed_seconds'] for w in windows),200 if name.endswith(':rows') else 150)

    def test_partial_or_failed_series_withholds_both_rates(self):
        self.data['status']='failed';self.withheld()
        self.data['status']='succeeded';self.data['trials'].pop();self.withheld()

    def test_order_or_arithmetic_changes_withhold_both_rates(self):
        self.data['pairs'][0]['worker_reduction_percent']=24;self.withheld()
        self.data['pairs'][0]['worker_reduction_percent']=25
        self.data['trials'][0],self.data['trials'][1]=self.data['trials'][1],self.data['trials'][0]
        self.withheld()

    def test_profile_changes_withhold_both_rates(self):
        self.data['profiles']['gather']['geometry']['columns']=99;self.withheld()

    def test_changed_binary_or_fixture_pin_withholds_both_rates(self):
        path=Path(next(p for p in self.data['input_pins'] if p.endswith('/gpu')))
        path.write_text('changed binary');self.withheld()

    def test_changed_config_withholds_both_rates(self):
        source=self.data['trials'][0]['config_source'];path=self.root/source['path']
        path.write_text('{}');self.withheld()

    def test_duplicate_or_missing_run_mapping_withholds_both_rates(self):
        self.runs[0]['run_id']=self.runs[1]['run_id'];self.withheld()
        self.runs=self.runs[1:];self.withheld()

    def test_nonpositive_timing_withholds_both_rates(self):
        self.data['pairs'][0]['worker_seconds']['rows']=-1;self.withheld()

    def test_malformed_profile_withholds_both_rates(self):
        self.data['profiles']['gather']['geometry']=None;self.withheld()

    def test_rehashed_changed_budget_withholds_both_rates(self):
        trial=self.data['trials'][0]
        result_path=self.root/trial['result_source']['path']
        summary_path=self.root/trial['summary_source']['path']
        result=json.loads(result_path.read_text())
        result['budget']['cpu']['rayon_threads']=9
        result_path.write_bytes(json_bytes(result))
        summary_path.write_bytes(json_bytes({'schema':GPU_SCHEMA,'status':'succeeded','result':result}))
        trial['result_source']=reference(result_path,self.root)
        trial['summary_source']=reference(summary_path,self.root)
        self.runs[0]['sources']=[reference(result_path,self.root)]
        self.withheld()

    def test_missing_wallet_pin_withholds_both_rates(self):
        trial=self.data['trials'][0]
        path=self.root/trial['config_source']['path']
        config=json.loads(path.read_text())
        del config['pins'][str(self.series/'fixture/wallet.0')]
        path.write_bytes(json_bytes(config));trial['config_source']=reference(path,self.root)
        self.withheld()


if __name__ == '__main__':
    unittest.main()
