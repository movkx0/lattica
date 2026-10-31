#!/usr/bin/env python3
"""Validate the exact frozen A003 standalone probe records, not a workflow.

The coordinator must separately audit the recorded build, exact test selection,
native execution, process limits and terminal cleanup. ``audit_log`` accepts
that build's source manifest; it cannot establish executable provenance itself.
The probe reports its field count but no runtime input/domain/digest identifier.
Its workload formula is therefore bound through the two frozen source hashes.

CLI: fused_partial_probe_audit.py RUN_RECORD.json
This checks the passed record's source pins and raw-log digest and prints a new
component summary. It does not modify the record, log, sources or prior reports.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


PROBE_DIRECTORY = "lattica-prover-p3/src/block_v2/gpu_hash/engine/device/public_hash/"
SOURCE_SHA256 = {
    PROBE_DIRECTORY + "fused_partial_probe.rs":
        "cbbbeb8aa3f881c159314fa2069d3f3b80ccc434b9e2d9b160334576ebf55342",
    PROBE_DIRECTORY + "fused_partial_probe.cl":
        "0624c67b398db6557f8e0b56334c043fe06b4c38486b3e844fdfe7f9cd640162",
}
RAW_KERNEL = "public_hash_fused_partial_raw_probe"
BASELINE = "device_public_hash_cooperative"
PAIR = "device_public_hash_sbox_pair"
FUSED = "device_public_hash_fused_partial_probe"
CENSUS_ORDER = (RAW_KERNEL, BASELINE, PAIR, FUSED)
TIMING_ORDER = (
    (0, BASELINE), (0, PAIR), (0, FUSED),
    (1, FUSED), (1, PAIR), (1, BASELINE),
    (2, BASELINE), (2, PAIR), (2, FUSED),
)
FIELD_COUNT = (1 << 20) + 1
CENSUS_PREFIX = "FUSED_PARTIAL_KERNEL_CENSUS "
TIMING_PREFIX = "FUSED_PARTIAL_COMPONENT_TIMING "
MAX_LOG_BYTES = 64 << 20
MAX_LINE_BYTES = 1 << 20
MAX_RECORD_BYTES = 8 << 10
MAX_RUN_RECORD_BYTES = 64 << 20
U64_MAX = (1 << 64) - 1
U128_MAX = (1 << 128) - 1

_STORAGE_FIELDS = frozenset((
    "lanes", "compiled_geometry", "local_bytes", "private_bytes_per_lane",
))
_BUFFER_BYTES = {
    "global_workspace_bytes": 32800,
    "max_allocation_bytes": 32768,
    "constant_buffer_bytes": 752,
    "total_global_buffer_bytes": 33552,
}
_COMMON_FIELDS = frozenset((
    "kernel", "storage", "gpu_tuning_compiled", "nvidia_supported",
    "standalone_probe", "experimental_production_selector_available",
    *_BUFFER_BYTES,
))
_CENSUS_FIELDS = _COMMON_FIELDS | {"before_global_buffer_allocation"}
_TIMING_FIELDS = _COMMON_FIELDS | {
    "round", "fields", "device_ns", "wall_ns", "cpu_oracle_equal",
    "raw_partial_round_oracle_equal", "raw_negative_two_oracle_equal",
    "all_kernels_reused", "complete_workflow_measurement",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, name, minimum=0, maximum=U64_MAX):
    require(type(value) is int and minimum <= value <= maximum,
            "invalid integer: " + name)
    return value


def exact_fields(value, expected, name):
    require(type(value) is dict and set(value) == expected,
            "missing or unexpected fields: " + name)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def _constant(value):
    raise ValueError("nonfinite JSON number: " + value)


def _json(encoded):
    try:
        return json.loads(encoded, object_pairs_hook=_object, parse_constant=_constant)
    except (TypeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("malformed probe JSON") from error


def _source_pins(source_inputs):
    require(type(source_inputs) is dict, "missing recorded-build source manifest")
    for path, expected in SOURCE_SHA256.items():
        actual = source_inputs.get(path)
        require(type(actual) is str and actual == expected,
                "frozen A003 source differs or is absent: " + path)
    return dict(SOURCE_SHA256)


def _storage(value, kernel):
    exact_fields(value, _STORAGE_FIELDS, "storage")
    lanes = 8 if kernel == BASELINE else 16
    require(integer(value["lanes"], "lanes") == lanes, "wrong lane count")
    geometry = value["compiled_geometry"]
    require(type(geometry) is list and len(geometry) == 3,
            "invalid compiled geometry")
    for index, dimension in enumerate(geometry):
        integer(dimension, "compiled geometry dimension " + str(index), 1)
    require(geometry == [lanes, 1, 1], "wrong compiled workgroup geometry")
    integer(value["local_bytes"], "local bytes", maximum=256)
    integer(value["private_bytes_per_lane"], "private bytes per lane", maximum=4096)


def _common(record, expected_kernel):
    require(type(record["kernel"]) is str and record["kernel"] == expected_kernel,
            "unexpected, duplicate or reordered kernel")
    for name in ("gpu_tuning_compiled", "nvidia_supported", "standalone_probe"):
        require(record[name] is True, "expected true boolean: " + name)
    require(record["experimental_production_selector_available"] is False,
            "probe cannot claim a production selector")
    for name, expected in _BUFFER_BYTES.items():
        require(integer(record[name], name) == expected, "changed probe buffer: " + name)
    _storage(record["storage"], expected_kernel)


def audit_lines(lines, *, source_inputs):
    """Audit a bounded log iterable after its enclosing provenance audit.

    Non-probe lines are ignored. Every line mentioning FUSED_PARTIAL_ must be an
    exact known record; malformed/extra/duplicate records fail the whole audit.
    No success can be inferred from a prefix of the emitted sequence.
    """
    pins = _source_pins(source_inputs)
    census = []
    timings = []
    byte_count = 0
    for line in lines:
        require(type(line) is str, "log lines must be decoded strings")
        encoded_size = len(line.encode("utf-8"))
        byte_count += encoded_size
        require(encoded_size <= MAX_LINE_BYTES and byte_count <= MAX_LOG_BYTES,
                "probe log exceeds reader allowance")
        if "FUSED_PARTIAL_" not in line:
            continue
        require(encoded_size <= MAX_RECORD_BYTES, "probe record exceeds reader allowance")
        if line.startswith(CENSUS_PREFIX):
            require(not timings and len(census) < len(CENSUS_ORDER),
                    "extra census or census after timing")
            record = _json(line[len(CENSUS_PREFIX):])
            exact_fields(record, _CENSUS_FIELDS, "kernel census")
            _common(record, CENSUS_ORDER[len(census)])
            require(record["before_global_buffer_allocation"] is True,
                    "kernel census must precede global buffer allocation")
            census.append(record)
        elif line.startswith(TIMING_PREFIX):
            require(len(census) == len(CENSUS_ORDER) and len(timings) < len(TIMING_ORDER),
                    "timing before complete census or extra timing")
            record = _json(line[len(TIMING_PREFIX):])
            exact_fields(record, _TIMING_FIELDS, "component timing")
            expected_round, expected_kernel = TIMING_ORDER[len(timings)]
            _common(record, expected_kernel)
            require(integer(record["round"], "round", maximum=2) == expected_round,
                    "wrong alternating timing round")
            require(integer(record["fields"], "field count") == FIELD_COUNT,
                    "timing workload field count changed")
            device_ns = integer(record["device_ns"], "device duration", 1)
            wall_ns = integer(record["wall_ns"], "wall duration", 1, U128_MAX)
            require(device_ns <= wall_ns, "device time exceeds enclosing wall time")
            for name in ("cpu_oracle_equal", "raw_partial_round_oracle_equal",
                         "raw_negative_two_oracle_equal", "all_kernels_reused"):
                require(record[name] is True, "expected true boolean: " + name)
            require(record["complete_workflow_measurement"] is False,
                    "component probe cannot claim a complete workflow")
            inspected = census[CENSUS_ORDER.index(expected_kernel)]["storage"]
            require(record["storage"] == inspected,
                    "timed kernel storage differs from its preallocation census")
            timings.append(record)
        else:
            raise ValueError("malformed or unknown FUSED_PARTIAL_ record prefix")
    require(len(census) == 4 and len(timings) == 9,
            "missing kernel census or incomplete alternating timing triples")
    medians = {}
    for kernel in (BASELINE, PAIR, FUSED):
        samples = [record for record in timings if record["kernel"] == kernel]
        # Each kernel has exactly three samples after the ordered checks above.
        medians[kernel] = {
            metric: sorted(record[metric] for record in samples)[1]
            for metric in ("device_ns", "wall_ns")
        }
    return {
        "schema": "lattica-fused-partial-a003-component-audit-v1",
        "scope": "standalone public-hash component",
        "source_sha256": pins,
        "workload": {
            "identity_basis": "frozen probe source plus emitted field count",
            "fields": FIELD_COUNT,
            "source_domain_hex": "0x4c42563210",
            "source_field_formula": "((i * 0x9e3779b97f4a7c15) mod 2^64) mod 0xffffffff00000001",
            "runtime_input_digest_reported": False,
        },
        "alternating_complete_triples": 3,
        "component_medians_ns": medians,
        "kernel_census": census,
        "component_timings": timings,
        "enclosing_recorded_build_and_terminal_audit_required": True,
        "production_selector_available": False,
        "fresh_proof_qualification": False,
        "complete_workflow_measurement": False,
        "faithful_ringct_performance_qualified": False,
        "limitations": [
            "Component wall time excludes harness/kernel setup and compilation.",
            "Oracle flags require the enclosing exact-test and terminal audit.",
            "No proof generation, transaction graph or workflow throughput is measured.",
            "Buffer census covers explicit probe buffers; driver/context and source compilation remain separately guarded.",
        ],
    }


def audit_log(path, *, source_inputs):
    """Audit exact log bytes and return their digest for the enclosing guard."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        def lines():
            while True:
                raw = handle.readline(MAX_LINE_BYTES + 1)
                if not raw:
                    return
                require(len(raw) <= MAX_LINE_BYTES, "log line exceeds reader allowance")
                digest.update(raw)
                try:
                    yield raw.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ValueError("probe log is not UTF-8") from error
        result = audit_lines(lines(), source_inputs=source_inputs)
    result["raw_log_sha256"] = digest.hexdigest()
    return result


def audit_run_record(path):
    """Bind this component audit to a passed record, without replacing its guard."""
    with Path(path).open("rb") as handle:
        encoded = handle.read(MAX_RUN_RECORD_BYTES + 1)
    require(len(encoded) <= MAX_RUN_RECORD_BYTES, "run record exceeds reader allowance")
    record = _json(encoded)
    require(type(record) is dict and record.get("status") == "passed",
            "component audit requires a passed enclosing record")
    for name in ("all_subprocesses_terminal_and_reaped", "source_inputs_unchanged",
                 "executable_unchanged"):
        require(record.get(name) is True, "missing passed-record prerequisite: " + name)
    require(type(record.get("raw_log")) is str, "missing recorded log path")
    result = audit_log(record["raw_log"], source_inputs=record.get("input_sha256"))
    require(type(record.get("raw_log_sha256")) is str
            and result["raw_log_sha256"] == record["raw_log_sha256"],
            "raw log no longer matches recorded execution")
    result["run_record_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_record", type=Path)
    arguments = parser.parse_args()
    result = audit_run_record(arguments.run_record)
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
