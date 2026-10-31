"""Audit complete direct-ring research evidence, separate from RingCT throughput."""
import hashlib
import json
import struct
from pathlib import Path

GIB = 1 << 30
WORKFLOW_SCHEMA = 'lattica-research-direct-ring-complete-gpu-workflow-v1'
REPRESENTATION = 'fused-ternary-ranges-v1'
SETUP_STAGES = {'preprocessing', 'randomness', 'transform', 'commitment'}
PROOF_STAGES = SETUP_STAGES | {
    'witness_trace', 'lookup', 'quotient', 'hiding', 'opening', 'fri_fold',
    'fri_query', 'final_polynomial', 'scalar', 'transcript', 'grinding',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, label, minimum=0, maximum=None):
    require(type(value) is int and value >= minimum
            and (maximum is None or value <= maximum), 'invalid ' + label)
    return value


def native(report, proof):
    stages = PROOF_STAGES if proof else SETUP_STAGES
    require(report.get('schema') == 'lattica-proving-stages-v1'
            and report.get('entry_point') == ('block_v2_registered_program' if proof else 'block_v2_preprocessing')
            and report.get('policy') == 'gpu_required'
            and report.get('succeeded') is True
            and report.get('stage_coverage_complete') is True
            and report.get('completion_rejected') is False
            and integer(report.get('observation_errors'), 'observation errors') == 0
            and report.get('components') == [], 'incomplete fresh native GPU receipt')
    capabilities = report.get('capabilities', {})
    require(capabilities.get('profile') == 'block_v2_cubic'
            and capabilities.get('scope') == ('registered_proof' if proof else 'preprocessing')
            and integer(capabilities.get('max_log_fri_arity'), 'FRI arity') == 1, 'native scope or parameters changed')
    inventory = capabilities.get('stages', [])
    require(len(inventory) == len(stages)
            and {entry.get('stage') for entry in inventory} == stages
            and all(entry.get('backend') == 'open_cl' for entry in inventory),
            'native stage inventory differs from the pinned contract')
    observations = report.get('observations', [])
    require(len(observations) == len(stages)
            and {entry.get('stage') for entry in observations} == stages,
            'missing or duplicated native execution observations')
    for entry in observations:
        calls = integer(entry.get('calls'), 'native calls', 1)
        integer(entry.get('device_calls'), 'native device calls', 1, calls)
        require(entry.get('backend') == 'open_cl'
                and integer(entry.get('completed_calls'), 'completed native calls') == calls,
                'native stage lacks completed device execution')


def terminal(report, completed):
    require(report.get('context_closed') is True and report.get('queue_drained') is True
            and report.get('completion_claimed') is completed, 'terminal GPU cleanup not established')
    for field, expected in [('host_allowance_bytes', 32 * GIB), ('device_allowance_bytes', 8 * GIB),
                            ('gpu_context_allowance_bytes', 4 * GIB), ('max_rows', 1 << 20)]:
        require(integer(report.get(field), field) == expected, 'changed terminal allowance: ' + field)
    integer(report.get('managed_peak_bytes'), 'managed GPU peak', 1, 8 * GIB)
    for field in ('commits', 'allocations', 'uploaded_bytes', 'downloaded_bytes'):
        integer(report.get(field), field, 1)


def bounds(report, workflow):
    compiler = report.get('compiler', {})
    require(compiler.get('representation') == REPRESENTATION
            and integer(compiler.get('deferred_crypto_obligations'), 'deferred obligations') == 0
            and compiler.get('cryptographic_proof_available') is True,
            'incomplete direct relation')
    for field in ('active_rows', 'padded_rows', 'wires'):
        require(compiler.get(field) == workflow[field], 'compiler geometry changed: ' + field)
    memory = {'256m': 256 << 20, '2g': 2 * GIB, '8g': 8 * GIB, '24g': 24 * GIB}
    wires = {'16m': 1 << 24, '64m': 1 << 26}
    require(compiler.get('memory_profile') in memory and compiler.get('wire_profile') in wires,
            'unknown compiler capacity selection')
    program = memory[compiler['memory_profile']]
    for field, expected in [('program_byte_limit', program), ('witness_byte_limit', 128 << 20),
                            ('auxiliary_byte_limit', 16 << 20), ('worker_host_byte_limit', 32 * GIB),
                            ('wire_limit', wires[compiler['wire_profile']]),
                            ('input_limit', (1 << 24) - 4), ('row_limit', 1 << 24),
                            ('required_host_bytes', program + (144 << 20))]:
        require(integer(compiler.get(field), field) == expected, 'compiler allowance changed: ' + field)
    integer(compiler.get('host_allowance_bytes'), 'compiler host allowance',
            compiler['required_host_bytes'], 32 * GIB)
    for field in ('compiler_requested_bytes_peak', 'compiler_packed_admitted_bytes_peak'):
        integer(compiler.get(field), field, 1, program)
    integer(compiler['wires'], 'compiled wires', 4, compiler['wire_limit'])
    integer(compiler.get('witness_values'), 'witness values', 1, compiler['input_limit'])
    require(integer(report.get('caller_reserved_bytes'), 'caller reservation') == 1 << 20,
            'changed caller reservation')
    integer(report.get('caller_requested_bytes'), 'caller owners', 1, 1 << 20)
    footprint = report.get('footprint', {})
    require(footprint.get('host_phase_bound_complete') is True
            and footprint.get('device_phase_bound_complete') is True,
            'partial phase bounds cannot authorize a full proof')
    require(footprint.get('rows') == workflow['padded_rows'], 'footprint row geometry changed')
    backend = integer(footprint.get('backend_host_budget_bytes'), 'backend host budget', 1, 24 * GIB)
    tree = integer(footprint.get('host_tree_quota_bytes'), 'host tree quota', 0, 8 * GIB)
    inputs = integer(footprint.get('input_backing_host_bytes'), 'input backing')
    caller = integer(footprint.get('caller_reserved_host_bytes'), 'footprint caller reserve')
    runtime = integer(footprint.get('runtime_host_reserved_bytes'), 'runtime host reserve')
    native_host = integer(footprint.get('native_host_budget_bytes'), 'native host budget', 1, 24 * GIB)
    worker = integer(footprint.get('worker_committed_host_bytes'), 'worker committed host', 1, 32 * GIB)
    require(caller == 1 << 20 and runtime == 2 << 20
            and backend == min(24 * GIB, 32 * GIB - tree - inputs - caller) - runtime
            and native_host == backend + runtime
            and worker == native_host + tree + inputs + caller,
            'simultaneous host partitions differ from the admitted worker envelope')
    mode = footprint.get('tree_storage_mode')
    require((mode == 'device' and tree == 0) or (mode == 'host_backing' and tree > 0),
            'tree storage selection and reservation disagree')
    phase_bounds(footprint)


def phase_bounds(footprint, *, worker_host_limit=32 * GIB):
    """Check complete numerical bounds independently of the success booleans."""
    device = integer(footprint.get('managed_limit_bytes'), 'managed device limit')
    context = integer(footprint.get('context_reserve_bytes'), 'device context reserve')
    worker = integer(footprint.get('worker_host_limit_bytes'), 'worker host limit')
    integer(worker_host_limit, 'expected worker partition', 1, 32 * GIB)
    require((device, context, worker) == (8 * GIB, 4 * GIB, worker_host_limit),
            'complete plan changed the resource envelope')
    physical = integer(footprint.get('physical_global_bytes'), 'physical device bytes', device + context)
    max_allocation = integer(footprint.get('physical_max_allocation_bytes'), 'physical allocation cap', 1, physical)
    byte_array(footprint.get('physical_device_uuid'), 16, 'physical device UUID')
    require(footprint.get('requires_consuming_registration') is True
            and footprint.get('witness_instructions_retired_before_quotient_required') is True,
            'complete plan does not require the qualified registration lifetime')
    precommit = footprint.get('precommit_phases', {})
    opening = footprint.get('opening_phases', {})
    require(isinstance(precommit, dict) and isinstance(opening, dict),
            'complete phase censuses missing')
    early_names = (
        'compiler_device_peak_bytes', 'preprocessing_device_peak_bytes',
        'witness_device_peak_bytes', 'main_commit_device_peak_bytes',
        'lookup_reconstruction_device_peak_bytes', 'lookup_device_peak_bytes',
        'permutation_commit_device_peak_bytes', 'quotient_evaluation_device_peak_bytes',
        'quotient_commit_device_peak_bytes', 'randomization_commit_device_peak_bytes',
    )
    early = [integer(precommit.get(name), name, 1, device) for name in early_names]
    late = [integer(opening.get(name), name, 1, device) for name in (
        'opening_device_peak_bytes', 'fri_device_peak_bytes', 'query_device_peak_bytes')]
    require(integer(precommit.get('peak_device_bytes'), 'precommit aggregate peak') == max(early),
            'precommit aggregate omits a phase')
    integer(precommit.get('common_device_bytes'), 'common retained device backing', 1, min(early))
    require(integer(footprint.get('device_phase_peak_bytes'), 'aggregate device peak', 1, device)
            == max(*early, *late), 'aggregate device peak omits a phase')
    minima = [integer(phases.get('minimum_required_device_bytes'), 'minimum device feasibility', 1, device)
              for phases in (precommit, opening)]
    maxima = [integer(phases.get('largest_allocation_bytes'), 'largest device allocation', 1, max_allocation)
              for phases in (precommit, opening)]
    require(integer(footprint.get('minimum_required_device_bytes'), 'aggregate minimum feasibility') == max(minima)
            and integer(footprint.get('largest_allocation_bytes'), 'aggregate largest allocation') == max(maxima),
            'aggregate feasibility or allocation cap omits a phase')
    require(minima[0] <= max(early) and minima[1] <= max(late),
            'minimum feasibility exceeds an enforced phase ceiling')
    require(maxima[0] <= max(early) and maxima[1] <= max(late),
            'largest allocation exceeds its component phase ceiling')
    require(opening.get('host_bound_complete') is True, 'opening host census incomplete')
    tree_required = integer(opening.get('required_tree_host_bytes'), 'complete tree host backing',
                            1, footprint['host_tree_quota_bytes'])
    require(integer(footprint.get('required_tree_host_bytes'), 'aggregate tree host backing') == tree_required,
            'aggregate tree backing omits an owner')
    pcs = integer(footprint.get('pcs_host_budget_bytes'), 'PCS host budget', 1, footprint['backend_host_budget_bytes'])
    workspace = integer(opening.get('host_workspace_peak_bytes'), 'opening host workspace', 1, pcs)
    metadata = integer(opening.get('retained_host_metadata_bytes'), 'retained opening metadata', 1, pcs)
    backend_peak = integer(footprint.get('backend_host_phase_peak_bytes'), 'backend host peak',
                           1, footprint['backend_host_budget_bytes'])
    witness = integer(footprint.get('witness_reserved_host_bytes'), 'witness/compiler host reservation', 1)
    require(pcs == footprint['backend_host_budget_bytes'] - witness,
            'PCS host allowance differs from the remaining native partition')
    require(backend_peak == witness + workspace + metadata,
            'backend host peak omits a simultaneous owner')
    host_peak = integer(footprint.get('host_phase_peak_bytes'), 'complete host peak', backend_peak,
                        footprint['worker_committed_host_bytes'])
    require(host_peak == backend_peak + footprint['runtime_host_reserved_bytes']
            + footprint['input_backing_host_bytes'] + footprint['caller_reserved_host_bytes']
            + footprint['host_tree_quota_bytes'], 'complete host peak omits a partition')
    construction = integer(footprint.get('program_construction_host_bytes'), 'program construction peak', 1)
    require(construction + footprint['input_backing_host_bytes']
            + footprint['caller_reserved_host_bytes'] <= host_peak,
            'construction exceeds the complete host peak')


def byte_array(value, length, label):
    require(isinstance(value, list) and len(value) == length, 'invalid ' + label)
    return bytes(integer(n, label, 0, 255) for n in value)


def field_array(value, label):
    require(isinstance(value, list) and len(value) == 4, 'invalid ' + label)
    return [integer(n, label, 0, 0xffffffff00000000) for n in value]


def header(artifact, verification):
    require(artifact[:8] == b'LDRING01' and artifact[212:220] == b'LBV2RP02',
            'artifact profile or wide registered-proof layout differs')
    require(struct.unpack_from('<I', artifact, 40)[0] == 5, 'artifact representation differs')
    require(artifact[8:40] == byte_array(verification.get('artifact_profile_digest'), 32, 'profile digest')
            and artifact[44:76] == byte_array(verification.get('expected_context'), 32, 'expected context'),
            'artifact profile/context differs from independently reconstructed inputs')
    public = struct.unpack_from('<4Q', artifact, 76)
    require(list(public) == field_array(verification.get('expected_public_binding'), 'expected public binding'),
            'artifact public binding differs from independently verified statement')
    descriptor = verification['descriptor']
    for i, field in enumerate(('active_rows', 'padded_rows', 'wires', 'witness_values')):
        require(struct.unpack_from('<Q', artifact, 108 + 8 * i)[0] == integer(descriptor.get(field), field),
                'artifact descriptor differs: ' + field)
    require(artifact[140:172] == byte_array(descriptor.get('canonical_manifest_digest'), 32, 'manifest digest'),
            'artifact manifest differs from independently reconstructed program')
    identity = struct.unpack_from('<4Q', artifact, 172)
    require(list(identity) == field_array(descriptor.get('registered_program_id'), 'registered program ID'),
            'artifact registration identity differs from independently reconstructed program')
    for word in (*public, *identity):
        integer(word, 'canonical Goldilocks field', 0, 0xffffffff00000000)
    length = struct.unpack_from('<Q', artifact, 204)[0]
    require(8 <= length <= 2 << 20 and length + 212 == len(artifact), 'artifact inner length differs')


def read_report(path):
    require(path.is_file() and path.stat().st_size <= 1 << 20, 'report missing or exceeds size bound')
    return json.loads(path.read_bytes())


def validate_directory(directory):
    directory = Path(directory)
    expected_files = {'workflow.json', 'proving.json', 'verification.json', 'proof.bin'}
    require({path.name for path in directory.iterdir()} == expected_files,
            'direct research evidence is incomplete or contains failure results')
    workflow = read_report(directory / 'workflow.json')
    proving = read_report(directory / 'proving.json')
    verification = read_report(directory / 'verification.json')
    from public_hash_evidence import workflow_records
    public_hash = workflow_records(workflow, proving, verification)
    require(workflow.get('schema') == WORKFLOW_SCHEMA
            and workflow.get('profile') == 'ring-direct-v1'
            and workflow.get('representation') == REPRESENTATION
            and workflow.get('research_only') is True
            and workflow.get('production_acceptance_changed') is False
            and workflow.get('complete_faithful_ringct_workflow') is False
            and integer(workflow.get('fresh_relation_proofs'), 'fresh proofs') == 1
            and integer(workflow.get('recursive_aggregate_proofs'), 'aggregate proofs') == 0
            and workflow.get('independently_verified') is True
            and workflow.get('artifact_roundtrip') is True
            and workflow.get('cryptographic_mutation_checks') == 2,
            'direct research workflow scope or verification incomplete')
    padded = integer(workflow.get('padded_rows'), 'padded rows', 8, 1 << 20)
    require(padded & (padded - 1) == 0, 'non-power-of-two padded rows')
    integer(workflow.get('active_rows'), 'active rows', 1, padded)
    integer(workflow.get('wires'), 'wires', 4, 1 << 26)
    require(proving.get('schema') == 'lattica-research-direct-ring-gpu-proof-v1'
            and proving.get('proof_generation') == 'fresh-only'
            and proving.get('registration_lifetime') == 'consumed-once'
            and proving.get('witness_instructions_retired_before_quotient') is True
            and proving.get('policy') == 'gpu_required'
            and proving.get('independent_verification_required') is True,
            'fresh GPU proving policy changed')
    require(verification.get('schema') == 'lattica-research-direct-ring-independent-verification-v1'
            and verification.get('verified') is True
            and verification.get('public_reconstruction') == 'complete-program-and-fresh-preprocessing-cap'
            and verification.get('verifier_preprocessing_policy') == 'gpu_required'
            and verification.get('proof_verification_backend') == 'cpu'
            and verification.get('reused_prover_state') is False
            and verification.get('synthetic_hints_evaluated') is False
            and verification.get('mutation_checks') == 2,
            'independent reconstruction/CPU verification incomplete')
    for report in (proving, verification):
        bounds(report, workflow)
        native(report.get('registration', {}), False)
    native(proving.get('proving', {}), True)
    terminal(proving.get('terminal', {}), True)
    terminal(verification.get('terminal', {}), False)
    proof_backing = integer(proving.get('retained_proof_bytes'), 'retained native proof backing', 1, 64 << 20)
    integer(verification.get('retained_artifact_bytes'), 'retained artifact backing', 1, (64 << 20) + (16 << 10))
    cpu = integer(verification.get('cpu_verifier_reserved_bytes'), 'CPU verifier reservation', 64 << 20, 257 << 20)
    require(cpu + (1 << 20) <= 32 * GIB, 'CPU verifier and caller exceed host allowance')
    require(proving['footprint'].get('tree_storage_mode') == verification['footprint'].get('tree_storage_mode'),
            'prover and verifier storage selection differ')
    for field in ('active_rows', 'padded_rows', 'wires'):
        require(verification.get('descriptor', {}).get(field) == workflow[field],
                'independently reconstructed descriptor differs')
    proof_path = directory / 'proof.bin'
    size = integer(proof_path.stat().st_size, 'artifact size', 220, (2 << 20) + 212)
    require(size == workflow.get('artifact_bytes'), 'artifact size differs from round trip')
    artifact = proof_path.read_bytes()
    require(hashlib.sha3_256(artifact).digest() == byte_array(workflow.get('artifact_sha3_256'), 32, 'artifact digest'),
            'artifact bytes differ from independently verified round trip')
    header(artifact, verification)
    require(integer(workflow.get('artifact_encode_required_host_bytes'), 'encoder peak')
            == proof_backing + (2 << 20) + 212 + (16 << 10), 'encoder backing reservation differs')
    require(integer(workflow.get('artifact_decode_required_host_bytes'), 'decoder peak')
            == size + (64 << 20) + (16 << 10), 'decoder backing reservation differs')
    total = integer(workflow.get('complete_research_workflow_ns'), 'complete workflow time', 1)
    disjoint = ('fixture_ns', 'compilation_ns', 'prover_lifecycle_ns', 'codec_and_disk_ns', 'verifier_lifecycle_ns')
    require(sum(integer(workflow.get(field), field, 1) for field in disjoint) <= total,
            'workflow total excludes measured phases')
    for outer, names in [('prover_lifecycle_ns', ('prover_setup_ns', 'proving_ns')),
                         ('verifier_lifecycle_ns', ('verifier_reconstruction_ns', 'verifier_setup_ns',
                                                   'cpu_verification_ns', 'mutation_checks_ns'))]:
        require(sum(integer(workflow.get(field), field, 1) for field in names) <= workflow[outer],
                'lifecycle total excludes measured phases')
    return {
        'schema': 'lattica-direct-ring-research-evidence-audit-v1',
        'workflow': workflow, 'production_throughput_qualified': False,
        'public_hash': public_hash, 'public_hash_kernel': public_hash['kernel'],
        'tree_storage_mode': proving['footprint']['tree_storage_mode'],
        'artifact_sha256': {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                            for name in sorted(expected_files)},
    }
