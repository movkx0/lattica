"""Research evidence policy tests with synthetic receipts; no proof/GPU claims."""
import copy
import hashlib
import json
import struct
from pathlib import Path
import tempfile
import unittest

import opencl_direct_spend_audit as audit
from test_opencl_private_spend_validate import arguments, runner


def native(proof=False):
    stages = sorted(audit.PROOF_STAGES if proof else audit.SETUP_STAGES)
    return {
        'schema': 'lattica-proving-stages-v1',
        'entry_point': 'block_v2_registered_program' if proof else 'block_v2_preprocessing',
        'policy': 'gpu_required', 'succeeded': True, 'stage_coverage_complete': True,
        'completion_rejected': False, 'observation_errors': 0, 'components': [],
        'capabilities': {
            'profile': 'block_v2_cubic', 'scope': 'registered_proof' if proof else 'preprocessing',
            'max_log_fri_arity': 1,
            'stages': [dict(stage=stage, backend='open_cl') for stage in stages],
        },
        'observations': [dict(stage=stage, backend='open_cl', calls=1,
                              device_calls=1, completed_calls=1) for stage in stages],
    }


def complete_footprint():
    """Synthetic consistent bounds, never measurements of a real proof."""
    early = dict.fromkeys((
        'compiler_device_peak_bytes', 'preprocessing_device_peak_bytes',
        'witness_device_peak_bytes', 'main_commit_device_peak_bytes',
        'lookup_reconstruction_device_peak_bytes', 'lookup_device_peak_bytes',
        'permutation_commit_device_peak_bytes', 'quotient_evaluation_device_peak_bytes',
        'quotient_commit_device_peak_bytes', 'randomization_commit_device_peak_bytes',
    ), 1024)
    early.update(common_device_bytes=32, peak_device_bytes=1024,
                 minimum_required_device_bytes=512, largest_allocation_bytes=256)
    late = dict(opening_device_peak_bytes=2048, fri_device_peak_bytes=2048,
                query_device_peak_bytes=2048, minimum_required_device_bytes=1024,
                largest_allocation_bytes=512, host_workspace_peak_bytes=8192,
                retained_host_metadata_bytes=1024, required_tree_host_bytes=6 * audit.GIB,
                host_bound_complete=True)
    backend = 24 * audit.GIB - (128 << 20) - (1 << 20) - (2 << 20)
    backend_peak = 1000 + 8192 + 1024
    return dict(host_phase_bound_complete=True, device_phase_bound_complete=True,
                rows=8, tree_storage_mode='host_backing', backend_host_budget_bytes=backend,
                host_tree_quota_bytes=8 * audit.GIB, input_backing_host_bytes=128 << 20,
                caller_reserved_host_bytes=1 << 20, runtime_host_reserved_bytes=2 << 20,
                native_host_budget_bytes=backend + (2 << 20), worker_committed_host_bytes=32 * audit.GIB,
                managed_limit_bytes=8 * audit.GIB, context_reserve_bytes=4 * audit.GIB,
                worker_host_limit_bytes=32 * audit.GIB, physical_global_bytes=16 * audit.GIB,
                physical_max_allocation_bytes=4 * audit.GIB, physical_device_uuid=[17] * 16,
                requires_consuming_registration=True, witness_instructions_retired_before_quotient_required=True,
                precommit_phases=early, opening_phases=late, device_phase_peak_bytes=2048,
                minimum_required_device_bytes=1024, largest_allocation_bytes=512,
                required_tree_host_bytes=6 * audit.GIB, pcs_host_budget_bytes=backend - 1000,
                backend_host_phase_peak_bytes=backend_peak, witness_reserved_host_bytes=1000,
                host_phase_peak_bytes=backend_peak + (131 << 20) + 8 * audit.GIB,
                program_construction_host_bytes=1000)


class DirectResearchPolicyTests(unittest.TestCase):
    def test_stricter_research_profile_does_not_qualify_faithful_workflows(self):
        output = runner.STATE / 'artifacts' / 'policy-test'
        args = arguments(profile='direct-full', expect_direct_result=True,
                         retained_tree_storage='host', build_label='built-direct',
                         command=['/usr/bin/direct', 'ring-direct', '--prove', '--output-dir', str(output)])
        plan = runner.build_plan(args)
        self.assertEqual((plan['memory_max_bytes'], plan['memory_high_bytes'],
                          plan['fresh_memavailable_required_bytes']),
                         (45 * audit.GIB, 43 * audit.GIB, 47 * audit.GIB))
        self.assertEqual(plan['cpu_quota'], '800%')
        env = plan['environment']
        self.assertEqual(env['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * audit.GIB))
        self.assertEqual(env['LATTICA_V2_GPU_CONTEXT_BYTES'], str(4 * audit.GIB))
        self.assertEqual(env['LATTICA_V2_HOST_OUTPUT_BYTES'], str(32 * audit.GIB))
        self.assertEqual(env['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'], str(8 * audit.GIB))
        self.assertEqual(env['LATTICA_V2_GPU_LDE_WORKSPACE_BYTES'], '0')
        self.assertFalse(plan['expect_result'])
        self.assertFalse(plan['performance_qualified'])
        for change in [dict(expect_result=True), dict(expect_tests=True), dict(build_label=None),
                       dict(profile='research-compile'), dict(profile='smoke'),
                       dict(command=['/usr/bin/direct', 'ring-direct', '--compile']),
                       dict(command=['/usr/bin/direct', 'ring-direct', '--prove', '--output-dir', '/tmp/elsewhere'])]:
            mutated = copy.deepcopy(args)
            for key, value in change.items():
                setattr(mutated, key, value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.build_plan(mutated)

    def test_cpu_diagnostic_host_selection_does_not_enable_gpu_execution(self):
        plan = runner.build_plan(arguments(profile='research-compile', retained_tree_storage='host'))
        self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertEqual(plan['environment']['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'], 'host')
        self.assertNotIn('LATTICA_V2_GPU_HASH', plan['environment'])
        self.assertEqual(plan['cpu_quota'], '200%')

    def test_native_receipts_cannot_hide_missing_host_or_incomplete_stages(self):
        for proof in (False, True):
            good = native(proof)
            audit.native(good, proof)
            changes = [lambda r: r.update(policy='cpu_required'),
                       lambda r: r['observations'].pop(),
                       lambda r: r['observations'].append(r['observations'][0]),
                       lambda r: r['observations'][0].update(device_calls=0),
                       lambda r: r['observations'][0].update(completed_calls=0),
                       lambda r: r['observations'][0].update(completed_calls=True),
                       lambda r: r['observations'][0].update(backend='cpu'),
                       lambda r: r['capabilities'].update(max_log_fri_arity=2),
                       lambda r: r['capabilities']['stages'].pop(),
                       lambda r: r.update(components=[{}])]
            for change in changes:
                bad = copy.deepcopy(good)
                change(bad)
                with self.assertRaises(ValueError):
                    audit.native(bad, proof)

    def evidence(self):
        payload = bytearray(400)
        payload[:8] = b'LDRING01'
        payload[8:40] = bytes([3] * 32)
        struct.pack_into('<I', payload, 40, 5)
        payload[44:76] = bytes([19] * 32)
        struct.pack_into('<4Q', payload, 76, 1, 2, 3, 4)
        struct.pack_into('<4Q', payload, 108, 7, 8, 12, 6)
        payload[140:172] = bytes([4] * 32)
        struct.pack_into('<4Q', payload, 172, 9, 8, 7, 6)
        struct.pack_into('<Q', payload, 204, len(payload) - 212)
        payload[212:220] = b'LBV2RP02'
        payload = bytes(payload)
        workflow = dict(
            schema=audit.WORKFLOW_SCHEMA, profile='ring-direct-v1', representation=audit.REPRESENTATION,
            research_only=True, production_acceptance_changed=False,
            complete_faithful_ringct_workflow=False, fresh_relation_proofs=1,
            recursive_aggregate_proofs=0, independently_verified=True, artifact_roundtrip=True,
            cryptographic_mutation_checks=2, active_rows=7, padded_rows=8, wires=12,
            artifact_bytes=len(payload), artifact_sha3_256=list(hashlib.sha3_256(payload).digest()),
            artifact_encode_required_host_bytes=1000 + (2 << 20) + 212 + (16 << 10),
            artifact_decode_required_host_bytes=len(payload) + (64 << 20) + (16 << 10),
            fixture_ns=1, compilation_ns=1, prover_lifecycle_ns=4, codec_and_disk_ns=1,
            verifier_lifecycle_ns=4, complete_research_workflow_ns=12, prover_setup_ns=1,
            proving_ns=1, verifier_reconstruction_ns=1, verifier_setup_ns=1,
            cpu_verification_ns=1, mutation_checks_ns=1)
        common = dict(
            compiler=dict(representation=audit.REPRESENTATION, deferred_crypto_obligations=0,
                          cryptographic_proof_available=True, active_rows=7, padded_rows=8, wires=12,
                          witness_values=6, memory_profile='2g', wire_profile='16m',
                          program_byte_limit=2 * audit.GIB, witness_byte_limit=128 << 20,
                          auxiliary_byte_limit=16 << 20, worker_host_byte_limit=32 * audit.GIB,
                          wire_limit=1 << 24, input_limit=(1 << 24) - 4, row_limit=1 << 24,
                          required_host_bytes=2 * audit.GIB + (144 << 20),
                          host_allowance_bytes=2 * audit.GIB + (144 << 20),
                          compiler_requested_bytes_peak=1000, compiler_packed_admitted_bytes_peak=1000),
            caller_reserved_bytes=1 << 20, caller_requested_bytes=1000,
            footprint=complete_footprint(), registration=native(),
            terminal=dict(context_closed=True, queue_drained=True, completion_claimed=True,
                          host_allowance_bytes=32 * audit.GIB, device_allowance_bytes=8 * audit.GIB,
                          gpu_context_allowance_bytes=4 * audit.GIB, max_rows=1 << 20,
                          managed_peak_bytes=123, commits=1, allocations=1, uploaded_bytes=1, downloaded_bytes=1))
        proving = dict(copy.deepcopy(common), schema='lattica-research-direct-ring-gpu-proof-v1',
                       proof_generation='fresh-only', policy='gpu_required', registration_lifetime='consumed-once',
                       witness_instructions_retired_before_quotient=True, retained_proof_bytes=1000,
                       independent_verification_required=True, proving=native(True))
        verification = dict(copy.deepcopy(common), schema='lattica-research-direct-ring-independent-verification-v1',
                            verified=True, public_reconstruction='complete-program-and-fresh-preprocessing-cap',
                            verifier_preprocessing_policy='gpu_required', proof_verification_backend='cpu',
                            reused_prover_state=False, synthetic_hints_evaluated=False,
                            mutation_checks=2, retained_artifact_bytes=1200, cpu_verifier_reserved_bytes=128 << 20,
                            expected_context=[19] * 32, expected_public_binding=[1, 2, 3, 4],
                            artifact_profile_digest=[3] * 32,
                            descriptor=dict(active_rows=7, padded_rows=8, wires=12, witness_values=6,
                                            canonical_manifest_digest=[4] * 32, registered_program_id=[9, 8, 7, 6]))
        verification['terminal']['completion_claimed'] = False
        for report in (workflow, proving, verification):
            report['public_hash'] = dict(kernel='baseline', gpu_tuning_compiled=False,
                                         nvidia_supported=True)
        return [workflow, proving, verification, payload]

    def check_evidence(self, evidence):
        workflow, proving, verification, payload = evidence
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, value in [('workflow', workflow), ('proving', proving), ('verification', verification)]:
                (directory / (name + '.json')).write_text(json.dumps(value))
            (directory / 'proof.bin').write_bytes(payload)
            return audit.validate_directory(directory)

    def test_roundtrip_audit_rejects_false_scope_lifetime_and_mutation_evidence(self):
        self.assertFalse(self.check_evidence(self.evidence())['production_throughput_qualified'])
        changes = [lambda e: e[0].update(complete_faithful_ringct_workflow=True),
                   lambda e: e[0].pop('public_hash'),
                   lambda e: e[1].pop('public_hash'),
                   lambda e: e[2].pop('public_hash'),
                   lambda e: e[1]['public_hash'].update(kernel='sbox-pair-v1', gpu_tuning_compiled=True),
                   lambda e: e[2]['public_hash'].update(gpu_tuning_compiled=0),
                   lambda e: e[0].update(fresh_relation_proofs=True),
                   lambda e: e[1].update(witness_instructions_retired_before_quotient=False),
                   lambda e: e[1]['proving'].update(observation_errors=False),
                   lambda e: e[2].update(expected_public_binding=[True, 2, 3, 4]),
                   lambda e: e[1]['compiler'].update(worker_host_byte_limit=33 * audit.GIB),
                   lambda e: e[1]['footprint'].update(host_tree_quota_bytes=9 * audit.GIB),
                   lambda e: e[1]['footprint'].update(backend_host_budget_bytes=25 * audit.GIB),
                   lambda e: e[2].update(cpu_verifier_reserved_bytes=258 << 20),
                   lambda e: e[2].update(retained_artifact_bytes=65 << 20),
                   lambda e: e[0].update(cryptographic_mutation_checks=0),
                   lambda e: e[0].update(artifact_sha3_256=[0] * 32),
                   lambda e: e[0].update(complete_research_workflow_ns=2),
                   lambda e: e[1]['footprint'].update(device_phase_bound_complete=False),
                   lambda e: e[1]['terminal'].update(context_closed=False),
                   lambda e: e[1]['terminal'].update(managed_peak_bytes=9 * audit.GIB),
                   lambda e: e[2].update(reused_prover_state=True),
                   lambda e: e[2].update(synthetic_hints_evaluated=True),
                   lambda e: e[2]['terminal'].update(completion_claimed=True),
                   lambda e: e[2]['descriptor'].update(wires=13)]
        for change in changes:
            evidence = self.evidence()
            change(evidence)
            with self.assertRaises(ValueError):
                self.check_evidence(evidence)

    def test_rehashed_wrong_header_cannot_match_independent_descriptor(self):
        for offset in (0, 8, 40, 44, 76, 108, 116, 124, 132, 140, 172, 204, 219):
            evidence = self.evidence()
            packet = bytearray(evidence[3])
            packet[offset] ^= 1
            evidence[3] = bytes(packet)
            evidence[0]['artifact_sha3_256'] = list(hashlib.sha3_256(packet).digest())
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.check_evidence(evidence)

    def test_complete_flags_cannot_hide_inconsistent_numeric_phase_bounds(self):
        mutations = [
            lambda f: f.update(runtime_host_reserved_bytes=0),
            lambda f: f.update(native_host_budget_bytes=24 * audit.GIB),
            lambda f: f.update(worker_committed_host_bytes=31 * audit.GIB),
            lambda f: f.update(managed_limit_bytes=9 * audit.GIB),
            lambda f: f.update(physical_global_bytes=11 * audit.GIB),
            lambda f: f.update(physical_max_allocation_bytes=511),
            lambda f: f.update(physical_device_uuid=[True] * 16),
            lambda f: f.update(requires_consuming_registration=False),
            lambda f: f.update(precommit_phases=None),
            lambda f: f['precommit_phases'].update(quotient_commit_device_peak_bytes=9 * audit.GIB),
            lambda f: f['precommit_phases'].update(peak_device_bytes=1000),
            lambda f: f['opening_phases'].update(query_device_peak_bytes=9 * audit.GIB),
            lambda f: f['opening_phases'].update(host_bound_complete=False),
            lambda f: f['opening_phases'].update(required_tree_host_bytes=9 * audit.GIB),
            lambda f: f['opening_phases'].update(host_workspace_peak_bytes=f['pcs_host_budget_bytes'] + 1),
            lambda f: f.update(device_phase_peak_bytes=1024),
            lambda f: f.update(minimum_required_device_bytes=1),
            lambda f: f.update(largest_allocation_bytes=1),
            lambda f: (f['precommit_phases'].update(largest_allocation_bytes=1025),
                       f.update(largest_allocation_bytes=1025)),
            lambda f: (f['opening_phases'].update(largest_allocation_bytes=2049),
                       f.update(largest_allocation_bytes=2049)),
            lambda f: f.update(pcs_host_budget_bytes=f['pcs_host_budget_bytes'] - 1),
            lambda f: f.update(pcs_host_budget_bytes=f['pcs_host_budget_bytes'] + 1),
            lambda f: f.update(required_tree_host_bytes=5 * audit.GIB),
            lambda f: f.update(backend_host_phase_peak_bytes=1000),
            lambda f: f.update(host_phase_peak_bytes=f['host_phase_peak_bytes'] - 1),
            lambda f: f.update(program_construction_host_bytes=f['host_phase_peak_bytes']),
        ]
        for index, mutate in enumerate(mutations):
            for report in (1, 2):
                evidence = self.evidence()
                mutate(evidence[report]['footprint'])
                with self.subTest(mutation=index, report=report), self.assertRaises(ValueError):
                    self.check_evidence(evidence)


if __name__ == '__main__':
    unittest.main()
