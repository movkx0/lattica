"""Source-bound in-memory outer transport evidence, not archived artifact acceptance."""

GIB = 1 << 30
MAX_ENCODED_BYTES = 2_097_364
MAX_RETAINED_PROOF_BYTES = 64 << 20
# Measured by fullgpu-outer-artifact-focused-tests-1, source and build bound.
# phase_bytes=69_234_780; fixed_additional_bytes=12_168. Metadata pins the evidence.
TRANSPORT_FIXED_BYTES = 12_168
TRANSPORT_PEAK_BASE_BYTES = 70_271_188
STORAGE_FIELDS = {
    'caller_reserved_bytes', 'source_construction_bytes', 'source_comparison_peak_bytes',
    'reconstruction_with_retained_outer_peak_bytes', 'retained_outer_proof_allowance_bytes',
    'cpu_verifier_with_proof_reserved_bytes', 'cpu_phase_peak_bytes',
    'artifact_roundtrip_peak_bytes', 'independent_registration_host_partition_bytes',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def integer(value, low=1, high=(1 << 128) - 1):
    require(type(value) is int and low <= value <= high, 'invalid outer transport integer')
    return value


def validate(result):
    require(result.get('artifact_roundtrip') is True, 'outer artifact round trip missing')
    transport = result.get('artifact_transport')
    require(type(transport) is dict and set(transport) == {
        'encoded_bytes', 'decoded_proof_retained_bytes', 'total_ns'},
        'outer transport fields differ')
    integer(transport['encoded_bytes'], 220, MAX_ENCODED_BYTES)
    integer(transport['decoded_proof_retained_bytes'], 1, MAX_RETAINED_PROOF_BYTES)
    proving = result.get('proving')
    require(type(proving) is dict, 'outer proving report missing')
    integer(proving.get('retained_proof_bytes'), 1, MAX_RETAINED_PROOF_BYTES)
    # Decoder capacities need not match the original proving capacities.
    # Transport is included in proving.total_ns, so never add it a second time.
    require(integer(transport['total_ns']) <= integer(proving.get('total_ns'))
            <= integer(result.get('total_qualification_ns')), 'outer transport time escapes scope')
    storage = result.get('storage')
    require(type(storage) is dict and set(storage) == STORAGE_FIELDS,
            'outer storage fields differ')
    for value in storage.values():
        integer(value, 1, 32 * GIB)
    require(type(TRANSPORT_FIXED_BYTES) is int and TRANSPORT_FIXED_BYTES > 0,
            'compiled outer transport census missing')
    require(storage['artifact_roundtrip_peak_bytes'] ==
            TRANSPORT_PEAK_BASE_BYTES + TRANSPORT_FIXED_BYTES,
            'outer transport preclaim differs from compiled census')
    require(storage['caller_reserved_bytes'] == 1 << 20
            and storage['retained_outer_proof_allowance_bytes'] == MAX_RETAINED_PROOF_BYTES
            and storage['independent_registration_host_partition_bytes'] ==
                32 * GIB - MAX_RETAINED_PROOF_BYTES, 'outer original storage limits changed')
    for report, field, expected in [
        (result.get('child_verification'), 'mutation_checks', 2),
        (result.get('independent_verification'), 'public_mutation_rejections', 4),
        (result.get('independent_verification'), 'opening_mutation_rejections', 1),
    ]:
        require(type(report) is dict and type(report.get(field)) is int
                and report[field] == expected, 'outer typed mutation credit differs')
    return {'artifact_roundtrip': True, 'artifact_transport_scope': 'in-memory-encode-decode',
            'archived_artifact_qualified': False, 'complete_faithful_ringct_workflow': False,
            'performance_qualified': False}
