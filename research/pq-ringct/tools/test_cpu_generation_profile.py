import copy
import json
import unittest
from cpu_generation_profile import validate

class GenerationReceiptTests(unittest.TestCase):
    def setUp(self):
        self.selected = dict(transactions=1, samples=1, aes_lanes=1, setup_seed='11'*32,
                             context='22'*32, cache_public_parameters=False, reuse_workspace=True)
        self.report = dict(self.selected, schema='lattica-cpu-generation-profile-v1', backend='cpu',
                           private_entropy='os-fresh', gpu_contexts=0, gpu_generation_calls=0,
                           recursive_workflow_started=False, context_lifetime='cold-per-sample', workspace_bytes=2048,
                           records=[dict(sample=0, whole_stage_ns=20, transactions=[dict(verified=True,
                               output_sha3_256='ab'*32, whole_transaction_ns=19, generation_ns=12, verification_ns=5,
                               statistics=dict(status=0, attempts=1, random_calls=10, random_blocks=30, proposals=8,
                                   parameter_cache_hits=0, parameters_ns=1, inputs_ns=2, spend_ns=5, encoding_ns=1, cleanup_ns=1))])])
    def check(self, report=None):
        return validate('CPU_GENERATION_PROFILE ' + json.dumps(report or self.report), self.selected)
    def test_complete_cpu_report(self):
        self.assertEqual(self.check(), self.report)
    def test_gpu_entropy_and_workflow_claims_refused(self):
        for key, value in [('gpu_contexts',1), ('gpu_generation_calls',1), ('backend','gpu'),
                           ('private_entropy','deterministic'), ('recursive_workflow_started',True)]:
            changed = copy.deepcopy(self.report); changed[key] = value
            with self.assertRaises(RuntimeError): self.check(changed)
    def test_incomplete_or_unverified_refused(self):
        self.report['records'][0]['transactions'][0]['verified'] = False
        with self.assertRaises(RuntimeError): self.check()
        self.report['records'] = []
        with self.assertRaises(RuntimeError): self.check()
    def test_limits_and_cleanup_are_checked(self):
        for key, value in [('status',3), ('attempts',1025), ('random_calls',(1<<24)+1),
                           ('random_blocks',(1<<32)+1), ('proposals',(1<<28)+1), ('parameter_cache_hits',1)]:
            changed = copy.deepcopy(self.report)
            changed['records'][0]['transactions'][0]['statistics'][key] = value
            with self.assertRaises(RuntimeError): self.check(changed)
    def test_whole_stage_cannot_omit_verification(self):
        self.report['records'][0]['whole_stage_ns'] = 12
        with self.assertRaises(RuntimeError): self.check()
    def test_selection_must_match(self):
        self.report['aes_lanes'] = 8
        with self.assertRaises(RuntimeError): self.check()

if __name__ == '__main__': unittest.main()
