#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import tempfile
import unittest

from apple_benchmark_export import export_campaign, export_component
from benchmark_report.measurements import collect, unpack
from benchmark_report.model import digest, validate_run, transaction_rate


class AppleExport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.result = self.root / "result.json"
        self.output = self.root / "portable"
        self.label = "01-measured-shared-18t-quotient-compact-deferred-r1"
        self.stages = []
        for suffix in ("fixture-publics", "check", "pairs", "merges", "prune", "audit"):
            label = suffix if suffix == "fixture-publics" else self.label + "-" + suffix
            path = self.root / (label + ".log")
            count = 4 if suffix == "pairs" else 3 if suffix == "merges" else 0
            lines = [f"grouped_node_complete artifact=node.{i} resumed=false elapsed_ms=1000" for i in range(count)]
            if suffix == "fixture-publics": lines = ["grouped_public_export=VERIFIED_WALLET_STATEMENTS count=8 fields=26 kind=1"]
            if suffix == "pairs": lines += ["metal_checkpoint kernel_calls=32 kernel_ns=123 memory=Shared",
                "gpu_timeline_interval kind=leaf start_ns=100 end_ns=123 clock=metal_device"]
            path.write_text("\n".join(lines) + "\n")
            self.stages.append({"label":label,"log":str(path),"log_sha256":digest(path),"status":"PASS", "wall_seconds":2,
                                "reported_seconds":1,"maximum_resident_bytes":1024,"spill_peak_bytes":512})
        resource = self.root / "rss.jsonl"
        resource.write_text('{"utc_ns":"1791067912123456789","rss_bytes":1024}\n')
        self.stages[2].update(resource_log=str(resource),resource_sha256=digest(resource))
        self.data = {"status":"COMPLETE_VERIFIED_COMPARISON","hardware":"machdep.cpu.brand_string: Apple M5 Pro\nhw.memsize: 68719476736",
            "platform":"macOS", "git_base":"a"*40,"git_diff":"", "source_archive_sha256":"b"*64, "source_hashes":{},
            "fixture_sha256":{"key.1":"c"*64},"binary_sha256":{k:"d"*64 for k in ("cpu","metal","audit")}, "build":{},
            "timing_boundary":"pairs and merges","memory_policy":"bounded","stages":self.stages,
            "trials":[{"label":self.label,"backend":"shared","threads":18,"level":"quotient-compact-deferred","phase":"measured", "repeat":1,
                       "compact":1,"defer_timing":1,"verified":True,"controller_seconds":9,"recursive_seconds":7,"wrappers_seconds":4,"merges_seconds":3,
                       "peak_rss_bytes":1024,"peak_mapped_bytes":512,"root_bytes":1024,"root_sha256":"e"*64}]}

    def export(self):
        self.result.write_text(json.dumps(self.data))
        return export_campaign(self.result,self.output)

    def test_verified_proof_records_retain_exact_samples_clocks_counters_and_hashes(self):
        path, = self.export()
        record = json.loads(path.read_text())
        validate_run(record)
        self.assertEqual(record["workload"]["user_transactions"],8)
        self.assertEqual(len(record["proofs"]),7)
        self.assertEqual(record["platform"]["unified_memory_bytes"],64 << 30)
        self.assertEqual(record["configuration"]["apple_metal"]["compact"],1)
        tables = {t["kind"]:t for t in record["measurements"]["tables"]}
        self.assertEqual(tables["gpu_timeline_interval"]["clock"],"metal_device_unaligned")
        self.assertEqual(next(unpack(tables["resource_samples"]))["utc_ns"],"1791067912123456789")
        self.assertEqual(next(unpack(tables["metal_checkpoint"]))["kernel_ns"],123)
        before = path.read_bytes()
        self.assertEqual(self.export()[0].read_bytes(),before)

    def test_incomplete_and_unverified_campaigns_are_rejected(self):
        self.data["status"] = "RUNNING"
        with self.assertRaises(ValueError): self.export()
        self.data["status"] = "COMPLETE_VERIFIED_COMPARISON"
        self.data["trials"][0]["verified"] = False
        with self.assertRaises(ValueError): self.export()

    def test_screening_preserves_reused_pilot_and_single_observation_limit(self):
        self.data.update(status="COMPLETE_VERIFIED_SCREENING", suite="screening",
                         screening_reference={"status":"FAILED", "trial":self.label})
        self.data["trials"][0].update(phase="pilot", screening_reused=True)
        path, = self.export()
        record = json.loads(path.read_text())
        self.assertEqual(record["kind"], "diagnostic")
        self.assertTrue(record["configuration"]["apple_metal"]["screening_reused"])
        self.assertTrue(record["configuration"]["apple_metal"]["screening"])
        self.assertEqual(record["configuration"]["screening_reference"]["status"], "FAILED")
        self.assertTrue(any("one observation" in text for text in record["limitations"]))

    def test_modified_logs_and_resumed_proofs_are_rejected(self):
        log = Path(self.stages[2]["log"])
        log.write_text(log.read_text().replace("resumed=false","resumed=true"))
        with self.assertRaisesRegex(ValueError,"hash changed"): self.export()
        self.stages[2]["log_sha256"] = digest(log)
        with self.assertRaisesRegex(ValueError,"fresh"): self.export()

    def test_component_data_has_no_proof_or_transaction_throughput(self):
        component = self.root / "component.json"
        metadata = self.root / "metadata.json"
        component.write_text(json.dumps({"status":"PASS","samples":[{"backend":"sme2","elements":32,"verified":True,
            "elapsed_ns":"9007199254740993","ns_per_element":1.5}], "streaming_u64_lanes":8,"p3_packing_width":2,"limitations":["component only"]}))
        metadata.write_text(json.dumps({"platform":{"memory_model":"unified"},"revision":{"git_commit":"a"*40}}))
        path, = export_component(component,metadata,self.output)
        record = json.loads(path.read_text())
        self.assertEqual(record["kind"],"component")
        self.assertEqual(record["proofs"],[])
        self.assertIsNone(transaction_rate(record))
        self.assertIsNone(record["verification"]["cpu_audited"])


if __name__ == "__main__": unittest.main()
