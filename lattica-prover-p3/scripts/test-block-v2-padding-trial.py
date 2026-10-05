#!/usr/bin/env python3
"""Fast fail-closed controller checks; no proof, device or systemd worker is launched."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location("padding_trial", Path(__file__).with_name("block-v2-padding-trial.py"))
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)
support = trial.load_support(Path(__file__).with_name("block-v2-grouped-trial.py"))

class TrialTests(unittest.TestCase):
    def account(self, **changes):
        fields = dict(unit="test.service", scope="exec_stop_post_snapshot", memory_peak="1234",
                      memory_swap_peak="0", memory_max=str(44*trial.GIB), memory_swap_max="0", cpu_usage_usec="5")
        fields.update(changes)
        return "stage_cgroup_accounting " + " ".join(f"{key}={value}" for key,value in fields.items())
    def duration(self):
        return "padding_stage_elapsed_ms=123 spill_peak_bytes=456"
    def check(self):
        return "padding_input_check=PASS source_level=3 target_level=6 count=8 production_ready=false"
    def parse(self, lines, name="check"):
        return trial.telemetry("\n".join(lines),"test.service",name,support)
    def test_valid_check_ignores_unrelated_logs(self):
        got = self.parse(["Running as unit: test.service", self.check(), self.duration(), self.account(), "arbitrary profiler output"])
        self.assertEqual(got["duration"]["elapsed_ms"],123)
    def test_missing_duplicate_wrong_unit_or_swap_accounting(self):
        for lines in [[self.check(),self.duration()],
                      [self.check(),self.duration(),self.account(),self.account()],
                      [self.check(),self.duration(),self.account(unit="wrong")],
                      [self.check(),self.duration(),self.account(memory_swap_peak="1")],
                      [self.check(),self.duration(),self.account(memory_peak=str(45*trial.GIB))]]:
            with self.assertRaises((RuntimeError, ValueError)): self.parse(lines)
    def test_duplicate_duration_and_forged_production_marker(self):
        for lines in [[self.check(),self.duration(),self.duration(),self.account()],
                      [self.check().replace("production_ready=false","production_ready=true"),self.duration(),self.account()],
                      [self.check(),self.duration().replace("456",str(121*trial.GIB)),self.account()]]:
            with self.assertRaises((RuntimeError, ValueError)): self.parse(lines)
    def test_empty_and_merge_sequences_are_exact(self):
        for name,files in [("empties",trial.EMPTIES),("merges",trial.MERGES)]:
            nodes = [f"padding_node_complete artifact={file} elapsed_ms=2 setups=1 cache_hits={i} production_ready=false"
                     for i,file in enumerate(files)]
            got = self.parse(nodes+[self.duration(),self.account()],name)
            self.assertEqual(len(got["nodes"]),3)
            for changed in [nodes[:-1],nodes[::-1],nodes+[nodes[0]]]:
                with self.assertRaises(RuntimeError): self.parse(changed+[self.duration(),self.account()],name)
    def test_root_prune_and_audit_scope(self):
        root = "padding_root_verification=PASS level=6 count=8 inner_proofs_loaded=0 full_count_qualified=false full_tree_security=UNREVIEWED production_ready=false"
        prune = "padding_inner_artifacts_removed=6 pruning_does_not_approve_profile=true"
        self.parse([root,self.duration(),self.account()],"root")
        self.parse([root,prune,self.duration(),self.account()],"prune")
        audit = "grouped_artifact_audit=PASS kind=level6-count8-padded proof_bytes=1683948 native_mutation_rejections=38 registry_policy_rejections=4 expected_statement_policy_rejections=2 bundle_files=5 inner_proofs_loaded=0 level6_qualified=false full_tree_security=UNREVIEWED production_ready=false"
        self.assertEqual(self.parse([audit,self.account()],"audit")["audit_proof_bytes"],1683948)
        for changed in [audit.replace("count8","count64"),audit.replace("loaded=0","loaded=1"),
                        audit.replace("1683948","2097153"),audit.replace("rejections=38","rejections=37")]:
            with self.assertRaises(RuntimeError): self.parse([changed,self.account()],"audit")
    def test_failure_marker_duplicate_fields_and_missing_marker_reject(self):
        for lines in [["padding_probe=FAIL error=test",self.duration(),self.account()],
                      [self.check()+" count=8",self.duration(),self.account()],
                      [self.duration(),self.account()]]:
            with self.assertRaises((RuntimeError, ValueError)): self.parse(lines)
    def test_transitions_preserve_inputs_and_only_remove_known_inners(self):
        before = {k:{"sha256":k,"bytes":1} for k in trial.SOURCE_FILES}
        empty = before | {k:{"sha256":k,"bytes":1} for k in trial.EMPTIES}
        merged = empty | {k:{"sha256":k,"bytes":1} for k in trial.MERGES}
        pruned = {k:v for k,v in merged.items() if k not in trial.INNERS}
        trial.transition("check",before,before)
        trial.transition("empties",before,empty)
        trial.transition("merges",empty,merged)
        trial.transition("prune",merged,pruned)
        trial.transition("audit",pruned,pruned)
        changed = copy.deepcopy(empty); changed["key.1"]["sha256"]="wrong"
        with self.assertRaises(RuntimeError): trial.transition("empties",before,changed)
        with self.assertRaises(RuntimeError): trial.transition("prune",merged,{})
        with self.assertRaises(RuntimeError): trial.transition("merges",empty,merged|{"wallet.0":{}})
    def test_support_specialization_does_not_change_frozen_file(self):
        config = dict(auditor="auditor",runner="runner",job="job",evidence="evidence",
                      external=["profile","chain","source","padded"])
        self.assertEqual(support.invocation(config,"audit",""),["auditor","root-padded-eight","evidence/root-only","profile","chain","padded"])
        self.assertEqual(support.invocation(config,"empties","empty-all"),["runner","empty-all","job","profile","chain","source","padded"])
        import hashlib
        self.assertEqual(hashlib.sha256(Path(support.__file__).read_bytes()).hexdigest(),trial.HELPER_SHA)
    def test_failed_or_uncertain_attempt_is_durable_stopped_and_not_retried(self):
        for failure in [1, TimeoutError("observation timeout")]:
            with tempfile.TemporaryDirectory() as directory:
                class Fake:
                    def __init__(self): self.saved=[]; self.calls=0
                    def save(self,path,state): self.saved.append(copy.deepcopy(state))
                    def stage_command(self,*args): return ["fake"]
                    def capture_stage(self,*args):
                        self.calls+=1
                        if isinstance(failure,Exception): raise failure
                        return failure
                fake=Fake()
                state={"attempts":[],"artifacts":{},"status":"RUNNING"}
                with patch.object(trial.subprocess,"run") as stop:
                    with self.assertRaises((RuntimeError,TimeoutError)):
                        trial.run_stage({"evidence":directory,"job":directory},"controller","check","check",state,fake)
                    stop.assert_called_once()
                self.assertEqual(fake.calls,1)
                self.assertEqual(fake.saved[0]["attempts"][0]["status"],"attempted")
                self.assertEqual(state["status"],"FAILED_OR_INTERRUPTED")
                self.assertEqual(state["attempts"][0]["status"],"failed_or_interrupted")

if __name__ == "__main__":
    unittest.main()
