#!/usr/bin/env python3
"""Audit frozen A005 standalone public-hash evidence, not workflow throughput.

The enclosing coordinator guard remains responsible for recorded-build and
exact-test provenance, native execution, resource limits, and terminal cleanup.
The four-field reference digest below is the independent CPU oracle emitted by
the frozen exact test. This parser checks that pinned result; it does not itself
implement Poseidon2 or authenticate the executable. Input SHA3 is independently
recomputed from the frozen synthetic fixture using bounded working storage.

CLI: redux_sum_probe_audit.py RUN_RECORD.json
No record, source, raw log, or prior report is modified.
"""
from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path

PROBE_DIRECTORY = "lattica-prover-p3/src/block_v2/gpu_hash/engine/device/public_hash/"
SOURCE_SHA256 = {
    PROBE_DIRECTORY + "redux_sum_probe.rs":
        "7ca2236c5f4f92843392c96034e4964f43342ebacf6b03e712155bd15fadb1fd",
    PROBE_DIRECTORY + "redux_sum_probe.cl":
        "e711af212896926ba8c372742cf58df8e32a83d09fb2b586ebebef3f5879633e",
}
RAW_KERNEL = "public_hash_redux_sum_raw_probe"
BASELINE = "device_public_hash_cooperative"
PAIR = "device_public_hash_sbox_pair"
REDUX = "device_public_hash_redux_sum_probe"
CENSUS_ORDER = (RAW_KERNEL, BASELINE, PAIR, REDUX)
TIMING_ORDER = (
    (0, BASELINE), (0, PAIR), (0, REDUX),
    (1, REDUX), (1, PAIR), (1, BASELINE),
    (2, BASELINE), (2, PAIR), (2, REDUX),
)
FIELD_COUNT = (1 << 20) + 1
DOMAIN = 0x4C42563210
MODULUS = 0xFFFFFFFF00000001
INPUT_ENCODING = "lattica-redux-sum-input-v1/domain-u64le/length-u64le/fields-u64le"
REFERENCE_DIGEST = (
    9794416103781300712, 4756606832771721594,
    5307240493000710151, 11963553263942151644,
)
CENSUS_PREFIX = "REDUX_SUM_KERNEL_CENSUS "
VALIDATION_PREFIX = "REDUX_SUM_COMPONENT_VALIDATION "
TIMING_PREFIX = "REDUX_SUM_COMPONENT_TIMING "
MAX_LOG_BYTES = 64 << 20
MAX_LINE_BYTES = 1 << 20
MAX_RECORD_BYTES = 8 << 10
MAX_RUN_RECORD_BYTES = 64 << 20
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
U128_MAX = (1 << 128) - 1

_STORAGE_FIELDS = frozenset((
    "lanes", "compiled_geometry", "local_bytes", "private_bytes_per_lane",
))
_CAPABILITY_FIELDS = frozenset((
    "vendor_id", "compute_major", "compute_minor", "warp_size",
))
_BUFFER_BYTES = {
    "global_workspace_bytes": 32800,
    "max_allocation_bytes": 32768,
    "constant_buffer_bytes": 752,
    "total_global_buffer_bytes": 33552,
}
_COMMON_FIELDS = frozenset((
    "kernel", "storage", "gpu_tuning_compiled", "nvidia_supported",
    "redux_supported", "capability", "standalone_probe",
    "experimental_production_selector_available", *_BUFFER_BYTES,
))
_CENSUS_FIELDS = _COMMON_FIELDS | {"before_global_buffer_allocation"}
_TIMING_FIELDS = _COMMON_FIELDS | {
    "round", "fields", "domain", "input_encoding", "input_sha3_256",
    "expected_digest", "actual_digest", "device_ns", "wall_ns", "cpu_oracle_equal",
    "raw_sum_oracle_equal", "raw_internal_oracle_equal",
    "chained_partial_round_oracle_equal", "exact_pair_representatives_equal",
    "all_kernels_reused", "complete_workflow_measurement",
}
_VALIDATION_FIELDS = frozenset((
    "raw_cases", "compared_raw_words", "different_raw_words", "raw_field_equivalent",
    "exact_pair_representatives_equal", "chained_partial_rounds",
    "complete_sponge_cases_per_kernel", "cpu_oracle_equal", "standalone_probe",
    "complete_workflow_measurement",
))


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
                "frozen A005 source differs or is absent: " + path)
    return dict(SOURCE_SHA256)


@lru_cache(maxsize=1)
def input_sha3_256():
    """Recreate the source fixture, never allocate its full field vector."""
    digest = hashlib.sha3_256()
    digest.update(b"lattica-redux-sum-input-v1")
    digest.update(DOMAIN.to_bytes(8, "little"))
    digest.update(FIELD_COUNT.to_bytes(8, "little"))
    buffer = bytearray()
    for index in range(FIELD_COUNT):
        value = ((index * 0x9E3779B97F4A7C15) & U64_MAX) % MODULUS
        buffer.extend(value.to_bytes(8, "little"))
        if len(buffer) == 32768:
            digest.update(buffer)
            buffer.clear()
    digest.update(buffer)
    return tuple(digest.digest())


def _words(value, count, maximum, name):
    require(type(value) is list and len(value) == count, "invalid word array: " + name)
    for index, word in enumerate(value):
        integer(word, name + "[" + str(index) + "]", maximum=maximum)


def _storage(value, kernel):
    exact_fields(value, _STORAGE_FIELDS, "storage")
    lanes = 8 if kernel == BASELINE else 16
    require(integer(value["lanes"], "lanes") == lanes, "wrong lane count")
    _words(value["compiled_geometry"], 3, U64_MAX, "compiled geometry")
    require(value["compiled_geometry"] == [lanes, 1, 1],
            "wrong compiled workgroup geometry")
    integer(value["local_bytes"], "local bytes", maximum=256)
    integer(value["private_bytes_per_lane"], "private bytes per lane", maximum=4096)


def _capability(value):
    exact_fields(value, _CAPABILITY_FIELDS, "capability")
    for name in _CAPABILITY_FIELDS:
        integer(value[name], "capability " + name, maximum=U32_MAX)
    require(value["vendor_id"] == 0x10DE and value["compute_major"] >= 8
            and value["warp_size"] == 32, "unsupported redux device capability")


def _common(record, expected_kernel, first_capability):
    require(type(record["kernel"]) is str and record["kernel"] == expected_kernel,
            "unexpected, duplicate or reordered kernel")
    for name in ("gpu_tuning_compiled", "nvidia_supported", "redux_supported",
                 "standalone_probe"):
        require(record[name] is True, "expected true boolean: " + name)
    require(record["experimental_production_selector_available"] is False,
            "probe cannot claim a production selector")
    for name, expected in _BUFFER_BYTES.items():
        require(integer(record[name], name) == expected, "changed probe buffer: " + name)
    _storage(record["storage"], expected_kernel)
    _capability(record["capability"])
    if first_capability is not None:
        require(record["capability"] == first_capability,
                "device capability differs from preallocation census")


def _validation(record):
    exact_fields(record, _VALIDATION_FIELDS, "component validation")
    for name, expected in (("raw_cases", 608), ("compared_raw_words", 608 * 48),
                           ("chained_partial_rounds", 22),
                           ("complete_sponge_cases_per_kernel", 36)):
        require(integer(record[name], name) == expected,
                "changed validation coverage: " + name)
    integer(record["different_raw_words"], "different raw words", maximum=608 * 48)
    for name in ("raw_field_equivalent", "exact_pair_representatives_equal",
                 "cpu_oracle_equal", "standalone_probe"):
        require(record[name] is True, "expected true boolean: " + name)
    require(record["complete_workflow_measurement"] is False,
            "component validation cannot claim complete workflow")


def _workload(record):
    require(integer(record["fields"], "field count") == FIELD_COUNT
            and integer(record["domain"], "domain") == DOMAIN,
            "timing workload field count or domain changed")
    require(type(record["input_encoding"]) is str
            and record["input_encoding"] == INPUT_ENCODING, "changed input encoding")
    _words(record["input_sha3_256"], 32, 255, "input SHA3-256")
    require(tuple(record["input_sha3_256"]) == input_sha3_256(),
            "runtime input digest differs from exact source fixture")
    for name in ("expected_digest", "actual_digest"):
        _words(record[name], 4, MODULUS - 1, name)
        require(tuple(record[name]) == REFERENCE_DIGEST,
                "changed independent CPU oracle digest: " + name)


def audit_lines(lines, *, source_inputs):
    """Fail closed on missing/extra/reordered/unknown REDUX_SUM_ records.

    Non-probe lines are ignored. The enclosing guard must authenticate the
    exact test and terminal status; a valid synthetic transcript is no evidence
    that the corresponding GPU operations ever took place.
    """
    pins = _source_pins(source_inputs)
    census, timings = [], []
    validation = None
    byte_count = 0
    for line in lines:
        require(type(line) is str, "log lines must be decoded strings")
        encoded_size = len(line.encode("utf-8"))
        byte_count += encoded_size
        require(encoded_size <= MAX_LINE_BYTES and byte_count <= MAX_LOG_BYTES,
                "probe log exceeds reader allowance")
        if "REDUX_SUM_" not in line:
            continue
        require(encoded_size <= MAX_RECORD_BYTES, "probe record exceeds reader allowance")
        capability = census[0]["capability"] if census else None
        if line.startswith(CENSUS_PREFIX):
            require(validation is None and not timings and len(census) < len(CENSUS_ORDER),
                    "extra census or census after validation/timing")
            record = _json(line[len(CENSUS_PREFIX):])
            exact_fields(record, _CENSUS_FIELDS, "kernel census")
            _common(record, CENSUS_ORDER[len(census)], capability)
            require(record["before_global_buffer_allocation"] is True,
                    "kernel census must precede global buffer allocation")
            census.append(record)
        elif line.startswith(VALIDATION_PREFIX):
            require(len(census) == 4 and validation is None and not timings,
                    "missing census, duplicate or reordered validation")
            validation = _json(line[len(VALIDATION_PREFIX):])
            _validation(validation)
        elif line.startswith(TIMING_PREFIX):
            require(len(census) == 4 and validation is not None
                    and len(timings) < len(TIMING_ORDER),
                    "timing before complete validation/census or extra timing")
            record = _json(line[len(TIMING_PREFIX):])
            exact_fields(record, _TIMING_FIELDS, "component timing")
            expected_round, expected_kernel = TIMING_ORDER[len(timings)]
            _common(record, expected_kernel, capability)
            require(integer(record["round"], "round", maximum=2) == expected_round,
                    "wrong alternating timing round")
            _workload(record)
            device_ns = integer(record["device_ns"], "device duration", 1)
            wall_ns = integer(record["wall_ns"], "wall duration", 1, U128_MAX)
            require(device_ns <= wall_ns, "device time exceeds enclosing wall time")
            for name in ("cpu_oracle_equal", "raw_sum_oracle_equal",
                         "raw_internal_oracle_equal", "chained_partial_round_oracle_equal",
                         "exact_pair_representatives_equal", "all_kernels_reused"):
                require(record[name] is True, "expected true boolean: " + name)
            require(record["complete_workflow_measurement"] is False,
                    "component probe cannot claim complete workflow")
            inspected = census[CENSUS_ORDER.index(expected_kernel)]["storage"]
            require(record["storage"] == inspected,
                    "timed kernel storage differs from preallocation census")
            timings.append(record)
        else:
            raise ValueError("malformed or unknown REDUX_SUM_ record prefix")
    require(len(census) == 4 and validation is not None and len(timings) == 9,
            "missing census/validation or incomplete alternating timing triples")
    medians = {}
    for kernel in (BASELINE, PAIR, REDUX):
        samples = [record for record in timings if record["kernel"] == kernel]
        medians[kernel] = {
            metric: sorted(record[metric] for record in samples)[1]
            for metric in ("device_ns", "wall_ns")
        }
    return {
        "schema": "lattica-redux-sum-a005-component-audit-v1",
        "scope": "standalone public-hash component",
        "source_sha256": pins,
        "workload": {
            "identity_basis": "frozen source and recomputed runtime input SHA3-256",
            "input_kind": "synthetic source fixture; no captured registration metadata",
            "fields": FIELD_COUNT, "domain": DOMAIN, "input_encoding": INPUT_ENCODING,
            "source_field_formula": "((i * 0x9e3779b97f4a7c15) mod 2^64) mod 0xffffffff00000001",
            "input_sha3_256": list(input_sha3_256()),
            "independent_cpu_reference_digest": list(REFERENCE_DIGEST),
        },
        "alternating_complete_triples": 3,
        "component_medians_ns": medians,
        "kernel_census": census, "component_validation": validation,
        "component_timings": timings,
        "enclosing_recorded_build_and_terminal_audit_required": True,
        "production_selector_available": False, "fresh_proof_qualification": False,
        "complete_workflow_measurement": False,
        "faithful_ringct_performance_qualified": False,
        "limitations": [
            "Component wall time excludes harness/kernel setup and compilation.",
            "Oracle flags and pinned reference digest require the enclosing exact-test audit.",
            "Raw representatives need field equivalence; different_raw_words need not be zero.",
            "No proof generation, transaction graph or workflow throughput is measured.",
            "Explicit buffer census excludes driver/context and source compilation.",
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
    """Bind to a passed enclosing record, without replacing its guard."""
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
    print(json.dumps(audit_run_record(arguments.run_record), indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
