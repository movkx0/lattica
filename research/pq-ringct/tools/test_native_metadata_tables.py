import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import generate_native_metadata_tables as generator
from native_metadata_profile import validate
import test_native_metadata_profile as fixtures

class NativeTablesTests(unittest.TestCase):
    def receipt(self):
        fixture = fixtures.NativeMetadataProfileTests()
        rows, summary = fixture.fixture()
        for row in rows: row['descriptor_key'] = row['key']
        cohorts = []
        for workers in [1,2,4,8,16]:
            stats = dict(entries=39,misses=39,table_hits=0,evictions=0,failed_computations=0,
                         jobs_started=39,peak_workers=min(workers,4),periodic_preparations=1,
                         admitted_host_bytes_peak=2 << 30)
            cohorts.append(dict(workers=workers,elapsed_ns=100,counts_equal=True,gpu_used=False,
                original_host_bytes_peak=2 << 30,phase_host_bytes_peak=2 << 30,
                ledger_all_claims_released=True,cache=stats))
        identity = dict(source=[1]*32,profile=[2]*32,available=False)
        return rows,summary,cohorts,identity
    def content(self, rows, summary, cohorts, identity):
        fixture=fixtures.NativeMetadataProfileTests()
        return fixture.text(rows,summary)+'\n'+'\n'.join('NATIVE_METADATA_COHORT '+json.dumps(c) for c in cohorts)+'\nNATIVE_METADATA_TABLE_IDENTITY '+json.dumps(identity)+'\n'
    def test_rejects_unsafe_cohorts_and_unqualified_tables(self):
        fixture=self.receipt()
        accepted=validate(self.content(*fixture))
        self.assertEqual(len(accepted['cohorts']),5)
        extended=copy.deepcopy(fixture)
        extended[2][-1]['phase_host_bytes_peak']=3 << 30
        extended[2][-1]['cache']['admitted_host_bytes_peak']=3 << 30
        validate(self.content(*extended))
        for mutate in [lambda r,s,c,i:c[0]['cache'].update(peak_workers=2),
                       lambda r,s,c,i:c[0]['cache'].update(admitted_host_bytes_peak=3 << 30),
                       lambda r,s,c,i:c[0]['cache'].update(table_hits=1),
                       lambda r,s,c,i:c[0].update(counts_equal=False),
                       lambda r,s,c,i:c[0].update(ledger_all_claims_released=False),
                       lambda r,s,c,i:c[0].update(phase_host_bytes_peak=(3 << 30)+1),
                       lambda r,s,c,i:r[0].update(descriptor_key=r[1]['descriptor_key']),
                       lambda r,s,c,i:i.update(available=True),
                       lambda r,s,c,i:i.update(source=[1])]:
            changed=copy.deepcopy(fixture); mutate(*changed)
            with self.assertRaises(ValueError): validate(self.content(*changed))
    def test_generation_is_deterministic_and_binds_each_number(self):
        accepted=validate(self.content(*self.receipt()))
        rendered=generator.render(accepted)
        reordered=copy.deepcopy(accepted); reordered['rows'].reverse()
        self.assertEqual(rendered,generator.render(reordered))
        self.assertEqual(rendered.count('Row {'),39)
        changed=copy.deepcopy(accepted);changed['rows'][0]['values'][0]+=1
        self.assertNotEqual(rendered,generator.render(changed))
    def test_requires_passed_terminal_source_bound_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory); log=path/'run.log'; build=path/'build.json'; record=path/'run.json'
            log.write_text(self.content(*self.receipt()))
            sources={'research/pq-ringct/src/ntt_air/example.rs':'abc',generator.DESTINATION:'old',generator.REGISTERED:'old'}
            build.write_text(json.dumps(dict(status='passed',input_sha256=sources)))
            valid=dict(status='passed',native_metadata_profile=True,source_inputs_unchanged=True,executable_unchanged=True,all_subprocesses_terminal_and_reaped=True,
                       service_stop_completed=True,expect_tests=True,command=['/bin/test',generator.TEST,'--exact','--ignored','--test-threads=1','--nocapture'],
                       raw_log=str(log),raw_log_sha256=generator.sha(log),input_sha256=sources,
                       executable_provenance=dict(build_record=str(build),build_record_sha256=generator.sha(build)))
            record.write_text(json.dumps(valid))
            with patch.object(generator,'source_manifest',return_value=sources):
                self.assertEqual(len(generator.verified(record)['rows']),39)
                for field,value in [('status','failed'),('all_subprocesses_terminal_and_reaped',False),('native_metadata_profile',False),('raw_log_sha256','bad')]:
                    bad=copy.deepcopy(valid);bad[field]=value;record.write_text(json.dumps(bad))
                    with self.assertRaises(ValueError): generator.verified(record)
            record.write_text(json.dumps(valid))
            changed=dict(sources);changed[generator.DESTINATION]='new';changed[generator.REGISTERED]='new'
            with patch.object(generator,'source_manifest',return_value=changed): generator.verified(record)
            changed['research/pq-ringct/src/ntt_air/example.rs']='changed'
            with patch.object(generator,'source_manifest',return_value=changed):
                with self.assertRaises(ValueError):generator.verified(record)
