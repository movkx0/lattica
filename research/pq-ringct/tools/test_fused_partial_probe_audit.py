"""Synthetic parser tests only; these fixtures are never GPU evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import fused_partial_probe_audit as audit


def fixture():
    raw = "public_hash_fused_partial_raw_probe"
    baseline = "device_public_hash_cooperative"
    pair = "device_public_hash_sbox_pair"
    fused = "device_public_hash_fused_partial_probe"

    def common(kernel):
        lanes = 8 if kernel == baseline else 16
        return {
            "kernel": kernel,
            "storage": {"lanes": lanes, "compiled_geometry": [lanes, 1, 1],
                        "local_bytes": 0, "private_bytes_per_lane": 0},
            "gpu_tuning_compiled": True, "nvidia_supported": True,
            "global_workspace_bytes": 32800, "max_allocation_bytes": 32768,
            "constant_buffer_bytes": 752, "total_global_buffer_bytes": 33552,
            "standalone_probe": True,
            "experimental_production_selector_available": False,
        }

    records = []
    for kernel in (raw, baseline, pair, fused):
        value = common(kernel)
        value["before_global_buffer_allocation"] = True
        records.append(("FUSED_PARTIAL_KERNEL_CENSUS ", value))
    for round_number, kernels in enumerate(((baseline, pair, fused),
                                             (fused, pair, baseline),
                                             (baseline, pair, fused))):
        for kernel in kernels:
            value = common(kernel)
            offset = {baseline: 0, pair: 3, fused: 6}[kernel]
            value.update(
                round=round_number, fields=1048577,
                device_ns=(40, 20, 30)[round_number] + offset,
                wall_ns=(100, 80, 90)[round_number] + offset,
                cpu_oracle_equal=True, raw_partial_round_oracle_equal=True,
                raw_negative_two_oracle_equal=True, all_kernels_reused=True,
                complete_workflow_measurement=False,
            )
            records.append(("FUSED_PARTIAL_COMPONENT_TIMING ", value))
    return records


def encode(records):
    return [prefix + json.dumps(record) + "\n" for prefix, record in records]


def numeric_paths(value, prefix=()):
    if type(value) in (int, bool):
        yield prefix, value
    elif type(value) is dict:
        for key, child in value.items():
            yield from numeric_paths(child, prefix + (key,))
    elif type(value) is list:
        for index, child in enumerate(value):
            yield from numeric_paths(child, prefix + (index,))


def replace(value, path, changed):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = changed


class ProbeAuditTests(unittest.TestCase):
    def read(self, records=None, lines=None, source_inputs=None):
        return audit.audit_lines(
            encode(fixture() if records is None else records) if lines is None else lines,
            source_inputs=dict(audit.SOURCE_SHA256) if source_inputs is None else source_inputs,
        )

    def test_complete_alternating_triples_have_only_component_medians(self):
        result = self.read(lines=["unrelated compiler output\n", *encode(fixture()), "test ok\n"])
        self.assertEqual(result["alternating_complete_triples"], 3)
        self.assertEqual(result["component_medians_ns"], {
            "device_public_hash_cooperative": {"device_ns": 30, "wall_ns": 90},
            "device_public_hash_sbox_pair": {"device_ns": 33, "wall_ns": 93},
            "device_public_hash_fused_partial_probe": {"device_ns": 36, "wall_ns": 96},
        })
        self.assertEqual(len(result["kernel_census"]), 4)
        self.assertEqual(len(result["component_timings"]), 9)
        self.assertFalse(result["workload"]["runtime_input_digest_reported"])
        for field in ("production_selector_available", "fresh_proof_qualification",
                      "complete_workflow_measurement", "faithful_ringct_performance_qualified"):
            self.assertIs(result[field], False)
        self.assertIs(result["enclosing_recorded_build_and_terminal_audit_required"], True)

    def test_every_record_is_required_and_duplicate_records_are_rejected(self):
        original = fixture()
        for index in range(len(original)):
            with self.subTest(index=index, change="missing"), self.assertRaises(ValueError):
                self.read(records=original[:index] + original[index + 1:])
            with self.subTest(index=index, change="duplicate"), self.assertRaises(ValueError):
                self.read(records=original[:index] + [original[index]] + original[index:])
        with self.assertRaises(ValueError):
            self.read(records=original + original)

    def test_reordered_census_rounds_and_triples_are_rejected(self):
        for first, second in ((0, 1), (3, 4), (4, 5), (7, 9), (4, 10)):
            records = fixture()
            records[first], records[second] = records[second], records[first]
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                self.read(records=records)

    def test_integer_boolean_and_float_substitution_is_rejected_everywhere(self):
        original = fixture()
        for index, (_, record) in enumerate(original):
            for path, value in numeric_paths(record):
                alternatives = (int(value),) if type(value) is bool else (True, False, float(value), str(value))
                for replacement in alternatives:
                    records = copy.deepcopy(original)
                    replace(records[index][1], path, replacement)
                    with self.subTest(index=index, path=path, replacement=replacement), self.assertRaises(ValueError):
                        self.read(records=records)

    def test_missing_extra_fields_and_unknown_kernel_fail_closed(self):
        for index in (0, 4):
            for key in fixture()[index][1]:
                records = fixture()
                del records[index][1][key]
                with self.subTest(index=index, missing=key), self.assertRaises(ValueError):
                    self.read(records=records)
            records = fixture()
            records[index][1]["unexpected"] = False
            with self.assertRaises(ValueError):
                self.read(records=records)
            records = fixture()
            records[index][1]["kernel"] = "unreviewed_kernel"
            with self.assertRaises(ValueError):
                self.read(records=records)
        for field in ("lanes", "compiled_geometry", "local_bytes", "private_bytes_per_lane"):
            records = fixture()
            del records[0][1]["storage"][field]
            with self.assertRaises(ValueError):
                self.read(records=records)

    def test_resource_boundaries_and_timed_census_agreement(self):
        records = fixture()
        for _, record in records:
            record["storage"]["local_bytes"] = 256
            record["storage"]["private_bytes_per_lane"] = 4096
        self.read(records=records)
        for field, value in (("local_bytes", 257), ("private_bytes_per_lane", 4097),
                             ("local_bytes", -1)):
            records = fixture()
            records[0][1]["storage"][field] = value
            with self.assertRaises(ValueError):
                self.read(records=records)
        records = fixture()
        records[4][1]["storage"]["local_bytes"] = 1  # In bounds, but not the inspected kernel.
        with self.assertRaises(ValueError):
            self.read(records=records)
        for field in ("global_workspace_bytes", "max_allocation_bytes",
                      "constant_buffer_bytes", "total_global_buffer_bytes"):
            records = fixture()
            records[0][1][field] += 1
            with self.assertRaises(ValueError):
                self.read(records=records)

    def test_workload_geometry_and_duration_mutations(self):
        for field, value in (("fields", 1048576), ("round", 3), ("device_ns", 0),
                             ("device_ns", 101), ("wall_ns", 39),
                             ("device_ns", 1 << 64), ("wall_ns", 1 << 128)):
            records = fixture()
            records[4][1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.read(records=records)
        for value in ([8, 1], [8, 1, 1, 1], [8, 2, 1], [16, 1, 1], "[8,1,1]"):
            records = fixture()
            records[1][1]["storage"]["compiled_geometry"] = value
            with self.assertRaises(ValueError):
                self.read(records=records)

    def test_json_duplicate_keys_nonfinite_values_and_bad_prefixes(self):
        lines = encode(fixture())
        for malformed in (
            lines[0].replace('"kernel":', '"kernel":"duplicate", "kernel":', 1),
            lines[0].replace('"lanes":', '"lanes":16, "lanes":', 1),
            lines[0].replace('"local_bytes": 0', '"local_bytes": NaN'),
            lines[0].replace('"local_bytes": 0', '"local_bytes": Infinity'),
            " FUSED_PARTIAL_KERNEL_CENSUS {}\n",
            "FUSED_PARTIAL_UNKNOWN {}\n",
            "FUSED_PARTIAL_KERNEL_CENSUS []\n",
            "FUSED_PARTIAL_KERNEL_CENSUS {broken}\n",
            lines[0].rstrip() + " trailing\n",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                self.read(lines=[malformed, *lines[1:]])

    def test_source_pins_are_required_and_cannot_be_claimed_by_a_record(self):
        for source in (None, [], {}):
            with self.assertRaises(ValueError):
                audit.audit_lines(encode(fixture()), source_inputs=source)
        for path in audit.SOURCE_SHA256:
            source = dict(audit.SOURCE_SHA256)
            source[path] = "0" * 64
            with self.assertRaises(ValueError):
                self.read(source_inputs=source)
        records = fixture()
        records[0][1]["source_sha256"] = dict(audit.SOURCE_SHA256)
        with self.assertRaises(ValueError):
            self.read(records=records)

    def test_reader_limits_and_wrong_line_types(self):
        for lines in ([b"FUSED_PARTIAL_KERNEL_CENSUS {}\n"],
                      ["x" * (audit.MAX_LINE_BYTES + 1)],
                      ["FUSED_PARTIAL_KERNEL_CENSUS " + " " * audit.MAX_RECORD_BYTES],
                      ["x" * audit.MAX_LINE_BYTES] * 65):
            with self.assertRaises(ValueError):
                self.read(lines=lines)

    def test_run_record_binds_raw_bytes_and_refuses_unfinished_or_changed_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "probe.log"
            raw = "".join(encode(fixture())).encode()
            log.write_bytes(raw)
            record_path = Path(temporary) / "probe.json"
            record = {
                "status": "passed", "all_subprocesses_terminal_and_reaped": True,
                "source_inputs_unchanged": True, "executable_unchanged": True,
                "input_sha256": dict(audit.SOURCE_SHA256), "raw_log": str(log),
                "raw_log_sha256": hashlib.sha256(raw).hexdigest(),
            }
            record_path.write_text(json.dumps(record))
            result = audit.audit_run_record(record_path)
            self.assertEqual(result["raw_log_sha256"], record["raw_log_sha256"])
            self.assertEqual(result["run_record_sha256"], hashlib.sha256(record_path.read_bytes()).hexdigest())
            for field, value in (("status", "running"), ("raw_log_sha256", "0" * 64),
                                 ("source_inputs_unchanged", 1), ("executable_unchanged", False),
                                 ("all_subprocesses_terminal_and_reaped", 1)):
                changed = {**record, field: value}
                record_path.write_text(json.dumps(changed))
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    audit.audit_run_record(record_path)
            record_path.write_text(json.dumps(record))
            log.write_bytes(raw + b"changed unrelated line\n")
            with self.assertRaises(ValueError):
                audit.audit_run_record(record_path)


if __name__ == "__main__":
    unittest.main()
