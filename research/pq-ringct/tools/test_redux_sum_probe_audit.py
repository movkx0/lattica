"""Synthetic parser tests only; these fixtures are never GPU evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import redux_sum_probe_audit as audit


def fixture():
    def common(kernel):
        lanes = 8 if kernel == audit.BASELINE else 16
        return {
            "kernel": kernel,
            "storage": {"lanes": lanes, "compiled_geometry": [lanes, 1, 1],
                        "local_bytes": 1, "private_bytes_per_lane": 0},
            "capability": {"vendor_id": 4318, "compute_major": 12,
                           "compute_minor": 0, "warp_size": 32},
            "gpu_tuning_compiled": True, "nvidia_supported": True,
            "redux_supported": True, "standalone_probe": True,
            "experimental_production_selector_available": False,
            "global_workspace_bytes": 32800, "max_allocation_bytes": 32768,
            "constant_buffer_bytes": 752, "total_global_buffer_bytes": 33552,
        }
    records = []
    for kernel in audit.CENSUS_ORDER:
        record = common(kernel)
        record["before_global_buffer_allocation"] = True
        records.append((audit.CENSUS_PREFIX, record))
    records.append((audit.VALIDATION_PREFIX, {
        "raw_cases": 608, "compared_raw_words": 29184, "different_raw_words": 0,
        "raw_field_equivalent": True, "exact_pair_representatives_equal": True,
        "chained_partial_rounds": 22, "complete_sponge_cases_per_kernel": 36,
        "cpu_oracle_equal": True, "standalone_probe": True,
        "complete_workflow_measurement": False,
    }))
    for round_number, kernel in audit.TIMING_ORDER:
        record = common(kernel)
        offset = {audit.BASELINE: 0, audit.PAIR: 3, audit.REDUX: 6}[kernel]
        record.update(
            round=round_number, fields=1048577, domain=0x4C42563210,
            input_encoding=audit.INPUT_ENCODING,
            input_sha3_256=list(audit.input_sha3_256()),
            expected_digest=list(audit.REFERENCE_DIGEST),
            actual_digest=list(audit.REFERENCE_DIGEST),
            device_ns=(40, 20, 30)[round_number] + offset,
            wall_ns=(100, 80, 90)[round_number] + offset,
            cpu_oracle_equal=True, raw_sum_oracle_equal=True,
            raw_internal_oracle_equal=True, chained_partial_round_oracle_equal=True,
            exact_pair_representatives_equal=True, all_kernels_reused=True,
            complete_workflow_measurement=False,
        )
        records.append((audit.TIMING_PREFIX, record))
    return records


def encode(records):
    return [prefix + json.dumps(record) + "\n" for prefix, record in records]


def scalar_paths(value, prefix=()):
    if type(value) in (int, bool):
        yield prefix, value
    elif type(value) is dict:
        for key, child in value.items():
            yield from scalar_paths(child, prefix + (key,))
    elif type(value) is list:
        for index, child in enumerate(value):
            yield from scalar_paths(child, prefix + (index,))


def replace(value, path, changed):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = changed


class ReduxAuditTests(unittest.TestCase):
    def read(self, records=None, lines=None, source_inputs=None):
        return audit.audit_lines(
            encode(fixture() if records is None else records) if lines is None else lines,
            source_inputs=dict(audit.SOURCE_SHA256) if source_inputs is None else source_inputs,
        )

    def reject_mutation(self, index, path, value):
        records = fixture()
        replace(records[index][1], path, value)
        with self.assertRaises(ValueError):
            self.read(records)

    def test_three_triples_include_all_validation_and_only_component_claims(self):
        result = self.read()
        self.assertEqual(result["alternating_complete_triples"], 3)
        self.assertEqual(len(result["kernel_census"]), 4)
        self.assertEqual(len(result["component_timings"]), 9)
        for kernel, offset in ((audit.BASELINE, 0), (audit.PAIR, 3), (audit.REDUX, 6)):
            self.assertEqual(result["component_medians_ns"][kernel],
                             {"device_ns": 30 + offset, "wall_ns": 90 + offset})
        for name in ("production_selector_available", "fresh_proof_qualification",
                     "complete_workflow_measurement", "faithful_ringct_performance_qualified"):
            self.assertIs(result[name], False)

    def test_recomputed_runtime_input_matches_recorded_fixed_fixture(self):
        self.assertEqual(bytes(audit.input_sha3_256()).hex(),
                         "dc56ccbea6f5530cc35a40948dcd493713d1dd604462550dc2cdb3158aaca9fd")

    def test_every_record_is_required_and_may_appear_only_once(self):
        for index in range(14):
            records = fixture()
            del records[index]
            with self.subTest(missing=index), self.assertRaises(ValueError):
                self.read(records)
            records = fixture()
            records.insert(index, copy.deepcopy(records[index]))
            with self.subTest(duplicate=index), self.assertRaises(ValueError):
                self.read(records)

    def test_reordered_records_and_partial_triples_are_rejected(self):
        for first, second in ((0, 1), (3, 4), (4, 5), (5, 6), (5, 11), (8, 10)):
            records = fixture()
            records[first], records[second] = records[second], records[first]
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                self.read(records)

    def test_integer_and_boolean_types_are_strict_at_every_nested_scalar(self):
        original = fixture()
        for index, (_, record) in enumerate(original):
            for path, value in scalar_paths(record):
                substitutions = (int(value), float(value), not value) if type(value) is bool else (
                    bool(value), float(value))
                for changed in substitutions:
                    with self.subTest(index=index, path=path, changed=changed):
                        self.reject_mutation(index, path, changed)

    def test_missing_extra_fields_and_nonobjects_are_rejected(self):
        for index, (_, record) in enumerate(fixture()):
            for name in record:
                records = fixture()
                del records[index][1][name]
                with self.subTest(index=index, missing=name), self.assertRaises(ValueError):
                    self.read(records)
            records = fixture()
            records[index][1]["unrecognized"] = 1
            with self.assertRaises(ValueError):
                self.read(records)
            for value in ([], None, "record"):
                records = fixture()
                records[index] = (records[index][0], value)
                with self.assertRaises(ValueError):
                    self.read(records)
        for name in ("storage", "capability"):
            records = fixture()
            records[0][1][name]["unrecognized"] = 1
            with self.assertRaises(ValueError):
                self.read(records)

    def test_device_capability_is_complete_supported_and_identical(self):
        for name, value in (("vendor_id", 0), ("compute_major", 7),
                            ("compute_minor", -1), ("compute_minor", 1 << 32),
                            ("warp_size", 64)):
            self.reject_mutation(0, ("capability", name), value)
        self.reject_mutation(5, ("capability", "compute_minor"), 1)
        for name in ("vendor_id", "compute_major", "compute_minor", "warp_size"):
            records = fixture()
            del records[0][1]["capability"][name]
            with self.assertRaises(ValueError):
                self.read(records)

    def test_fixed_validation_coverage_and_raw_difference_range(self):
        for name in ("raw_cases", "compared_raw_words", "chained_partial_rounds",
                     "complete_sponge_cases_per_kernel"):
            self.reject_mutation(4, (name,), fixture()[4][1][name] + 1)
        for value in (-1, 29185):
            self.reject_mutation(4, ("different_raw_words",), value)
        for value in (1, 29184):
            records = fixture()
            records[4][1]["different_raw_words"] = value
            self.assertEqual(self.read(records)["component_validation"]["different_raw_words"], value)

    def test_workload_encoding_digest_and_count_are_exact(self):
        for path, value in ((('fields',), 1048576), (('domain',), 0),
                            (('input_encoding',), 'different'),
                            (('input_sha3_256', 0), 0),
                            (('input_sha3_256',), [0] * 31),
                            (('input_sha3_256', 0), 256),
                            (('expected_digest', 0), 1),
                            (('actual_digest', 0), 1),
                            (('actual_digest', 0), audit.MODULUS),
                            (('actual_digest',), [1] * 5)):
            self.reject_mutation(5, path, value)
        records = fixture()
        for _, record in records[5:]:
            record['expected_digest'][0] = record['actual_digest'][0] = 1
        with self.assertRaises(ValueError):
            self.read(records)

    def test_geometry_resources_time_and_census_agreement(self):
        for path, value in ((('storage', 'lanes'), 8),
                            (('storage', 'compiled_geometry'), [16, 1, 2]),
                            (('storage', 'compiled_geometry'), [16, 1]),
                            (('storage', 'local_bytes'), 257),
                            (('storage', 'private_bytes_per_lane'), 4097),
                            (('total_global_buffer_bytes',), 33551),
                            (('constant_buffer_bytes',), 751),
                            (('max_allocation_bytes',), 32767),
                            (('global_workspace_bytes',), 32799)):
            self.reject_mutation(0, path, value)
        self.reject_mutation(5, ('storage', 'local_bytes'), 2)
        for path, value in ((('device_ns',), 0), (('wall_ns',), 0),
                            (('device_ns',), 101), (('device_ns',), 1 << 64),
                            (('wall_ns',), 1 << 128), (('round',), 1),
                            (('kernel',), audit.PAIR)):
            self.reject_mutation(5, path, value)
        records = fixture()
        records[0][1]['storage']['local_bytes'] = 256
        records[0][1]['storage']['private_bytes_per_lane'] = 4096
        self.read(records)

    def test_json_duplicate_keys_nonfinite_and_unknown_prefixes(self):
        for value in ('NaN', 'Infinity', '-Infinity'):
            lines = encode(fixture())
            lines[5] = lines[5].replace('"wall_ns": 100', '"wall_ns": ' + value)
            with self.assertRaises(ValueError):
                self.read(lines=lines)
        lines = encode(fixture())
        lines[5] = lines[5].replace('"round": 0', '"round": 0, "round": 0')
        with self.assertRaises(ValueError):
            self.read(lines=lines)
        for extra in ('REDUX_SUM_UNKNOWN {}\n', ' REDUX_SUM_COMPONENT_TIMING {}\n',
                      'REDUX_SUM_COMPONENT_TIMING \n', 'REDUX_SUM_KERNEL_CENSUS []\n'):
            with self.assertRaises(ValueError):
                self.read(lines=encode(fixture()) + [extra])

    def test_recorded_source_pins_are_required(self):
        for source in audit.SOURCE_SHA256:
            pins = dict(audit.SOURCE_SHA256)
            del pins[source]
            with self.assertRaises(ValueError):
                self.read(source_inputs=pins)
            pins[source] = '0' * 64
            with self.assertRaises(ValueError):
                self.read(source_inputs=pins)
        for pins in ([], '', False):
            with self.assertRaises(ValueError):
                self.read(source_inputs=pins)

    def test_reader_limits_are_enforced_before_parsing_or_success(self):
        for lines in ([b'bytes'], [None], [1]):
            with self.assertRaises(ValueError):
                self.read(lines=lines)
        for limit in ('MAX_RECORD_BYTES', 'MAX_LINE_BYTES', 'MAX_LOG_BYTES'):
            with patch.object(audit, limit, 10), self.assertRaises(ValueError):
                self.read()
        self.read(lines=['ordinary test-runner output\n'] + encode(fixture()))

    def test_enclosing_record_binds_exact_log_bytes_and_terminal_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_log = Path(directory) / 'probe.log'
            record_path = Path(directory) / 'record.json'
            raw = ''.join(encode(fixture())).encode('utf-8')
            raw_log.write_bytes(raw)
            record = {
                'status': 'passed', 'all_subprocesses_terminal_and_reaped': True,
                'source_inputs_unchanged': True, 'executable_unchanged': True,
                'raw_log': str(raw_log), 'raw_log_sha256': hashlib.sha256(raw).hexdigest(),
                'input_sha256': dict(audit.SOURCE_SHA256),
            }
            def save(value):
                record_path.write_text(json.dumps(value), encoding='utf-8')
            save(record)
            result = audit.audit_run_record(record_path)
            self.assertEqual(result['raw_log_sha256'], hashlib.sha256(raw).hexdigest())
            for name, value in (('status', 'running'), ('executable_unchanged', False),
                                ('all_subprocesses_terminal_and_reaped', False),
                                ('source_inputs_unchanged', 1), ('raw_log_sha256', '0' * 64),
                                ('input_sha256', {}), ('raw_log', None)):
                changed = copy.deepcopy(record)
                changed[name] = value
                save(changed)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    audit.audit_run_record(record_path)
            save(record)
            with patch.object(audit, 'MAX_RUN_RECORD_BYTES', 8), self.assertRaises(ValueError):
                audit.audit_run_record(record_path)
            raw_log.write_bytes(raw + b'changed ordinary output\n')
            with self.assertRaises(ValueError):
                audit.audit_run_record(record_path)
            raw_log.write_bytes(raw + b'\xff\n')
            with self.assertRaises(ValueError):
                audit.audit_run_record(record_path)


if __name__ == '__main__':
    unittest.main()
