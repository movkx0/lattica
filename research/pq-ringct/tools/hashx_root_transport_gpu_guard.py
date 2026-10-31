"""Exact source-bound single-root GPU transport evidence; never RingCT workflow evidence."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re

GIB = 1 << 30
HOST, DEVICE = 32 * GIB, 8 * GIB
U64_MAX, U128_MAX = (1 << 64) - 1, (1 << 128) - 1
SELECTOR = ('component_tree::owned_shake::request_merge::source::capture::acceptance::'
            'parent::production::sequence::qualification::transport::gpu_original_hashx_sequence_root_transport_roundtrip')
FLAG = 'LATTICA_OWNED_HASHX_ROOT_TRANSPORT_QUALIFICATION'
ENV_KEY = 'owned_hashx_root_transport_environment'
BINDING_KEY = 'owned_hashx_root_transport_binding'
EXCLUSIVE = ('owned_hashx_interior_opening_test', 'owned_hashx_root_opening_test', 'note_owned_proof', 'note_workflow_cpu', 'owned_runtime_test', 'direct_ring_screen',
             'direct_ring_identity_test', 'owned_source_shape_test', 'active_hashx_preflight',
             'owned_request_source_test', 'direct_ring_recursion_test', 'owned_native_hashx_test',
             'owned_hashx_leaf_test', 'owned_hashx_sequence_test', 'owned_hashx_sequence_refusal_test',
             'owned_hashx_root_public_test',
             'expect_result', 'expect_direct_result',
             'benchmark', 'correctness_label', 'record_artifact', 'direct_ring_recursion_census_label')
FOREIGN_RECEIPTS = ('owned_hashx_interior_opening_environment', 'owned_hashx_root_opening_environment', 'note_startup_environment', 'note_cpu_environment', 'owned_runtime_environment',
                    'direct_ring_screen_environment', 'direct_ring_identity_environment',
                    'direct_ring_recursion_environment', 'owned_source_shape_environment',
                    'active_hashx_preflight_environment', 'owned_request_source_environment',
                    'owned_native_hashx_environment', 'owned_hashx_leaf_environment',
                    'owned_hashx_sequence_environment', 'owned_hashx_sequence_refusal_environment',
                    'owned_hashx_root_public_environment')
SEQUENCE = ('research/pq-ringct/src/component_tree/owned_shake/request_merge/source/'
            'capture/acceptance/parent/production/sequence')
# Source closure includes current transport semantics, ancestors, codec and caller.
REQUIRED_SOURCES = (
    'lattica-prover-p3/Cargo.lock',
    'lattica-prover-p3/Cargo.toml',
    'lattica-prover-p3/src/block_v2/codec.rs',
    'lattica-prover-p3/src/block_v2/codec/fixed_u64.rs',
    'lattica-prover-p3/src/block_v2/codec/proofs.rs',
    'lattica-prover-p3/src/block_v2/codec/proofs/schema.rs',
    'lattica-prover-p3/src/block_v2/commitment.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/ringct_runtime.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/ringct_runtime/retirement.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/ringct_runtime/retirement/outer_startup.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/wallet/proof_storage.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/wallet/proof_storage/phases.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/wallet/proof_storage/phases/runtime_geometry.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/wallet/proof_storage/phases/shake_source.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/device/wallet/proof_storage/phases/shake_source/transfer_storage.rs',
    'lattica-prover-p3/src/block_v2/gpu_hash/engine/retained_storage.rs',
    'lattica-prover-p3/src/block_v2/machine/air.rs',
    'lattica-prover-p3/src/block_v2/machine/analysis.rs',
    'lattica-prover-p3/src/block_v2/machine/backend.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/consuming.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_call.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_call/storage.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_call/tests.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_envelope.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_envelope/tests.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_lifetimes.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_outcome.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_outcome/tests.rs',
    'lattica-prover-p3/src/block_v2/machine/backend/verification_scratch.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/opening.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/opening/native_device.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/outer_producer.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/outer_producer/source.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/outer_producer/source/BOUNDS.md',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/outer_producer/source/continuation.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/outer_producer/source/tests.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/selection.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/shake_pcs.rs',
    'lattica-prover-p3/src/block_v2/machine/gpu_backend/resources/admission/shake_pcs/preopening.rs',
    'lattica-prover-p3/src/block_v2/machine/mod.rs',
    'lattica-prover-p3/src/block_v2/machine/program.rs',
    'lattica-prover-p3/src/block_v2/machine/program/proof_inputs.rs',
    'lattica-prover-p3/src/block_v2/machine/symbolic/lookup.rs',
    'lattica-prover-p3/src/block_v2/machine/symbolic/mod.rs',
    'lattica-prover-p3/src/block_v2/machine/symbolic/ringct_shake.rs',
    'lattica-prover-p3/src/block_v2/machine/symbolic/verifier.rs',
    'lattica-prover-p3/src/block_v2/machine/verifier/batch.rs',
    'lattica-prover-p3/src/block_v2/machine/verifier/batch/shape.rs',
    'lattica-prover-p3/src/block_v2/machine/verifier/batch/shape/OPAQUE_CAPS.md',
    'lattica-prover-p3/src/block_v2/machine/verifier/batch/shape/envelope.rs',
    'lattica-prover-p3/src/block_v2/machine/verifier/batch/shape/storage.rs',
    'lattica-prover-p3/src/block_v2/machine/verifier/batch/shape/tests.rs',
    'lattica-prover-p3/src/block_v2/machine/verifier/mod.rs',
    'lattica-prover-p3/src/block_v2/machine/verifier/template.rs',
    'lattica-prover-p3/src/block_v2/mod.rs',
    'lattica-prover-p3/src/block_v2/native_gpu.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/execution.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/quota_projection.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/quota_projection/tests.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/capacity.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/hashx.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/hashx/outer.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/hashx/outer/succession.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/hashx/tests.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/successor.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/retirement/successor/tests.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/tests/ACTIVE_HASHX_PREFLIGHT.md',
    'lattica-prover-p3/src/block_v2/native_gpu/research/owned_shake/tree_profile.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/shake_output.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/shake_output/storage.rs',
    'lattica-prover-p3/src/block_v2/native_gpu/research/shake_preparation.rs',
    'lattica-prover-p3/src/block_v2/native_shake_proof.rs',
    'lattica-prover-p3/src/block_v2/pcs_field.rs',
    'lattica-prover-p3/src/block_v2/profile.rs',
    'lattica-prover-p3/src/block_v2/profile/verification.rs',
    'lattica-prover-p3/src/block_v2/quotient_pcs.rs',
    'lattica-prover-p3/src/config.rs',
    'lattica-prover-p3/src/lib.rs',
    'lattica-prover-p3/src/proving.rs',
    'lattica-prover-p3/src/proving/proof_storage/native_shake_ocl.rs',
    'lattica-prover-p3/src/proving/proof_storage/outer_ocl.rs',
    'lattica-prover-p3/src/ringct_research_quota.rs',
    'lattica-prover-p3/src/ringct_research_quota/reunite.rs',
    'lattica-prover-p3/src/ringct_research_quota/reunite/tests.rs',
    'lattica-prover-p3/src/ringct_research_quota/tests.rs',
    'lattica-prover-p3/vendor/p3-field/src/extension/cubic_extension.rs',
    'lattica-prover-p3/vendor/p3-field/src/extension/mod.rs',
    'lattica-prover-p3/vendor/p3-lookup/src/bus.rs',
    'lattica-prover-p3/vendor/p3-lookup/src/logup.rs',
    'lattica-prover-p3/vendor/p3-lookup/src/symbolic.rs',
    'lattica-prover-p3/vendor/p3-lookup/src/types.rs',
    'lattica-prover-p3/vendor/p3-symmetric/src/hash.rs',
    'research/pq-direct-spend/Cargo.lock',
    'research/pq-direct-spend/Cargo.toml',
    'research/pq-direct-spend/src/ring_circuit.rs',
    'research/pq-direct-spend/src/ring_circuit/artifact.rs',
    'research/pq-direct-spend/src/ring_circuit/proving.rs',
    'research/pq-direct-spend/src/ring_circuit/recursion.rs',
    'research/pq-direct-spend/src/ring_circuit/recursion/BOUNDS.md',
    'research/pq-direct-spend/src/ring_circuit/recursion/outer.rs',
    'research/pq-direct-spend/src/ring_circuit/recursion/outer/tests.rs',
    'research/pq-direct-spend/src/ring_circuit/verification.rs',
    'research/pq-direct-spend/src/ring_circuit/verification/lifecycle.rs',
    'research/pq-direct-spend/src/ring_circuit/verification/lifecycle/tests.rs',
    'research/pq-direct-spend/src/ring_circuit/verification/mutation.rs',
    'research/pq-direct-spend/src/ring_circuit/verification/reconstruction.rs',
    'research/pq-direct-spend/src/ring_circuit/verification/recursive_child.rs',
    'research/pq-ringct/Cargo.lock',
    'research/pq-ringct/Cargo.toml',
    'research/pq-ringct/src/bin/pq_ringct_opencl_probe.rs',
    'research/pq-ringct/src/component_tree.rs',
    'research/pq-ringct/src/component_tree/classified_verification.rs',
    'research/pq-ringct/src/component_tree/classified_verification/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/hashx_leaf.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/hashx_leaf/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/hashx_leaf/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/outer_continuation.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/outer_continuation/authenticated.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/outer_continuation/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/sequence.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/preissued/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/refusal.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/outer_producer/production/tests/qualification.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output/authenticated.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output/authenticated/parent.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output/parent_production.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output/preissued.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output/preissued/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/output/preissued/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/output/tests/genuine.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/hashx.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/hashx/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/hashx/qualification.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/bank.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/bank/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/bank/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/bank/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/children.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/qualification.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/qualification/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/qualification/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/qualification/transport.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/qualification/transport/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/qualification/transport/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/qualification/transport/claims/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/qualification/transport/claims/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/refusal.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/refusal/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_recheck.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_recheck/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_recheck/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_recheck/opening.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_recheck/opening/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_recheck/opening/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_recheck/opening/mutation.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_recheck/opening/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_recheck/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/admission.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/admission/API.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/admission/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/admission/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/admission/codec_frames.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/admission/source.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/admission/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/header.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/header/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/header/probes.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/root_transport/header/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/production/sequence/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/parent/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/capture/acceptance/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/framing.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/source/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/request_merge/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/source_shape.rs',
    'research/pq-ringct/src/component_tree/owned_shake/source_shape/tests.rs',
    'research/pq-ringct/src/component_tree/owned_shake/transport_shape.rs',
    'research/pq-ringct/src/component_tree/owned_shake/transport_shape/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/transport_shape/differential.rs',
    'research/pq-ringct/src/component_tree/owned_shake/transport_shape/differential/BOUNDS.md',
    'research/pq-ringct/src/component_tree/owned_shake/transport_shape/differential/census.rs',
    'research/pq-ringct/src/component_tree/owned_shake/transport_shape/differential/claims.rs',
    'research/pq-ringct/src/component_tree/owned_shake/transport_shape/differential/fixture.rs',
    'research/pq-ringct/src/component_tree/owned_shake/transport_shape/layout.rs',
    'research/pq-ringct/src/component_tree/owned_shake/transport_shape/tests.rs',
    'research/pq-ringct/src/component_tree/shake_verification_memory.rs',
    'research/pq-ringct/src/execution.rs',
    'research/pq-ringct/src/execution/phase_report.rs',
    'research/pq-ringct/src/execution/phase_report/BOUNDS.md',
    'research/pq-ringct/src/execution/phase_report/reclamation.rs',
    'research/pq-ringct/src/execution/phase_report/reclamation/BOUNDS.md',
    'research/pq-ringct/src/execution/phase_report/reclamation/tests.rs',
    'research/pq-ringct/src/execution/phase_report/tests.rs',
    'research/pq-ringct/src/execution/pre_session_outer.rs',
    'research/pq-ringct/src/execution/retained_resources.rs',
    'research/pq-ringct/src/graph_crypto.rs',
    'research/pq-ringct/src/graph_crypto/request_owner.rs',
    'research/pq-ringct/src/graph_crypto/request_owner/active_policy.rs',
    'research/pq-ringct/src/graph_crypto/request_owner/active_policy/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/payload.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/attachment.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/attachment/preissued.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/attachment/preissued/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/attachment/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/continuity.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/continuity/capacity.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/continuity/rejection.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/continuity/successor.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/continuity/successor/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/continuity/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/host.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/host/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/BOUNDS.md',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/attachment.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/capacity.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/outer.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/outer/succession.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/outer/succession/BOUNDS.md',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/outer/succession/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/outer/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/quota_projection.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/quota_projection/BOUNDS.md',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/quota_projection/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/production/workspace/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/recording.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/recording/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/preparation/tests.rs',
    'research/pq-ringct/src/graph_crypto/retention/owned/tests.rs',
    'research/pq-ringct/src/graph_crypto/shake_wrappers.rs',
    'research/pq-ringct/src/lib.rs',
    'research/pq-ringct/src/opencl.rs',
    'research/pq-ringct/src/opencl/aes_component.rs',
    'research/pq-ringct/src/opencl/mutation.rs',
    'research/pq-ringct/src/opencl/mutation/BOUNDS.md',
    'research/pq-ringct/src/opencl/mutation/tests.rs',
    'research/pq-ringct/src/opencl/session.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime/continuity.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime/continuity/hashx.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime/continuity/hashx/outer.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime/continuity/native_successor.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime/continuity/outer_startup.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime/continuity/tests.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime/quota_projection.rs',
    'research/pq-ringct/src/opencl/session/retained_runtime/tests.rs',
    'research/pq-ringct/src/shake_air.rs',
    'research/pq-ringct/src/shake_air/lane/batch/partition.rs',
    'research/pq-ringct/tools/hashx_first_leaf_guard.py',
    'research/pq-ringct/tools/hashx_root_public_capacity_guard.py',
    'research/pq-ringct/tools/hashx_root_public_gpu_guard.py',
    'research/pq-ringct/tools/hashx_root_transport_gpu_guard.py',
    'research/pq-ringct/tools/hashx_sequence_capacity_guard.py',
    'research/pq-ringct/tools/hashx_sequence_preissue_guard.py',
    'research/pq-ringct/tools/hashx_sequence_refusal_guard.py',
    'research/pq-ringct/tools/native_hashx_scratch_guard.py',
    'research/pq-ringct/tools/native_sequence_report.py',
    'research/pq-ringct/tools/native_sequence_source_pins.json',
    'research/pq-ringct/tools/note_startup_environment.py',
    'research/pq-ringct/tools/opencl_private_spend_validate.py',
    'research/pq-ringct/tools/opencl_qualify.py',
    'research/pq-ringct/tools/test_hashx_root_public_capacity_guard.py',
    'research/pq-ringct/tools/test_hashx_root_public_gpu_guard.py',
    'research/pq-ringct/tools/test_hashx_root_transport_gpu_guard.py',
    'research/pq-ringct/tools/test_hashx_root_transport_gpu_runner.py',
    'research/pq-ringct/tools/test_hashx_root_transport_reciprocal_guards.py',
    'research/pq-ringct/tools/test_hashx_sequence_capacity_guard.py',
    'research/pq-ringct/tools/test_hashx_sequence_preissue_guard.py',
    'research/pq-ringct/tools/test_hashx_sequence_preissue_runner.py',
    'research/pq-ringct/tools/test_source_shape_guard.py',
)

ROOT_CLAIMS = 'ringct_hashx_root_transport_claims'
SOURCE_CLAIMS = 'ringct_hashx_sequence_source_claims'
LEAF = 'ringct_hashx_sequence_leaf'
PARENT = 'ringct_hashx_sequence_parent'
ACCEPTANCE = 'ringct_hashx_sequence_acceptance_scope'
DECODE = 'bounded_decoded_proof_storage'
ROOT_SCOPE = 'ringct_hashx_root_transport_scope'
COMPLETE = 'ringct_hashx_root_transport_complete'
TERMINAL = 'ringct_hashx_sequence_terminal'
MARKERS = (ROOT_CLAIMS, SOURCE_CLAIMS, LEAF, PARENT, ACCEPTANCE, ROOT_SCOPE, COMPLETE, TERMINAL)
LEAF_SPANS = ((0, 32), (32, 32), (64, 32), (96, 24), (120, 2))
PARENT_SPANS = ((0, 64, 1), (64, 56, 1), (0, 120, 2), (0, 122, 3))
ORDER = (('leaf', 0), ('leaf', 1), ('parent', 0), ('leaf', 2), ('leaf', 3),
         ('parent', 1), ('parent', 2), ('leaf', 4), ('parent', 3))
ENTRIES = ('ringct_owned_native_shake',) * 10 + ('block_v2_preprocessing', 'block_v2_registered_program') * 9
PACKET_LIMIT, DECODE_LIMIT, HEADER_BYTES = 2 << 20, 64 << 20, 2480
OBSERVER_EVENT_LIMIT = 4096
OBSERVER_HOST_LIMIT = 1 << 20
ROOT_FIXED = {'cpu_heights': '18', 'codec_heights': '18', 'mode': 'root-transport', 'actual_root_transports': '0', 'native_dispatch_started': 'false', 'complete_ringct_workflow': 'false'}
ROOT_NUMBERS = ('fixed_host_bytes', 'packet_and_decoder_host_bytes', 'verifier_host_bytes', 'additional_host_bytes', 'packet_limit_bytes', 'decoder_limit_bytes', 'max_inner_bytes', 'max_packet_bytes', 'max_packet_and_probe_bytes', 'max_decoder_cumulative_bytes', 'caller_host_bytes', 'total_host_bytes')
SOURCE_FIXED = dict(native_outputs='10', native_attachments='10', retained_leaf_sources='5',
                    retained_parent_sources='4', original_compiler_bank='1', leaf_output_claims='5',
                    parent_output_claims='4', source_acceptance_claims='9', original_outer_sequence='true',
                    mode='root-transport', native_dispatch_started='false', complete_ringct_workflow='false')
PROVISIONAL = dict(source_key_authenticated='true', transaction_context_authenticated='false',
                   provisional='true', terminal_cleanup_complete='false', complete_ringct_workflow='false')
COUNTS = {'cpu_heights': '18', 'codec_heights': '18', 'numerical_positive_checks': '2', 'header_positive_checks': '2', 'bounded_decode_successes': '1', 'header_syntax_rejections': '24', 'header_public_rejections': '46', 'header_cap_rejections': '256', 'header_height_rejections': '1', 'header_canonical_rejections': '302', 'typed_header_refusals': '629'}
NO_WIDER_CHECKS = {'raw_proof_mutation_checks_complete': 'false', 'interior_mutation_checks_complete': 'false', 'mutation_checks_complete': 'false', 'artifact_roundtrip_complete': 'false', 'complete_ringct_workflow': 'false', 'decoder_failures_classified': 'false', 'disk_artifact_roundtrip_complete': 'false'}
OBSERVER_FIXED = {'terminal_observer_scope': 'process-audit-only', 'released_claims_cover_terminal_observer': 'false', 'process_engine_device_audit_complete': 'false'}
ROOT_SCOPE_FIXED = {'cpu_heights': '18', 'codec_heights': '18', 'numerical_positive_checks': '2', 'header_positive_checks': '2', 'bounded_decode_successes': '1', 'header_syntax_rejections': '24', 'header_public_rejections': '46', 'header_cap_rejections': '256', 'header_height_rejections': '1', 'header_canonical_rejections': '302', 'typed_header_refusals': '629', 'raw_proof_mutation_checks_complete': 'false', 'interior_mutation_checks_complete': 'false', 'mutation_checks_complete': 'false', 'artifact_roundtrip_complete': 'false', 'complete_ringct_workflow': 'false', 'decoder_failures_classified': 'false', 'disk_artifact_roundtrip_complete': 'false', 'provisional': 'true', 'terminal_cleanup_complete': 'false', 'retained_output_immutable': 'true', 'source_key_authenticated': 'true', 'transaction_context_authenticated': 'false', 'transport_scope': 'single-root-in-memory'}
COMPLETE_FIXED = {'cpu_heights': '18', 'codec_heights': '18', 'numerical_positive_checks': '2', 'header_positive_checks': '2', 'bounded_decode_successes': '1', 'header_syntax_rejections': '24', 'header_public_rejections': '46', 'header_cap_rejections': '256', 'header_height_rejections': '1', 'header_canonical_rejections': '302', 'typed_header_refusals': '629', 'raw_proof_mutation_checks_complete': 'false', 'interior_mutation_checks_complete': 'false', 'mutation_checks_complete': 'false', 'artifact_roundtrip_complete': 'false', 'complete_ringct_workflow': 'false', 'decoder_failures_classified': 'false', 'disk_artifact_roundtrip_complete': 'false', 'terminal_observer_scope': 'process-audit-only', 'released_claims_cover_terminal_observer': 'false', 'process_engine_device_audit_complete': 'false', 'native_proofs': '10', 'recursive_proofs': '9', 'compiler_reclamations': '9', 'first_unit': '0', 'units': '122', 'level': '3', 'retained_output_immutable': 'true', 'source_key_authenticated': 'true', 'transaction_context_authenticated': 'false', 'original_quota_released': 'true', 'owner_quota_cleanup_complete': 'true', 'recursive_leaf_proofs': '5', 'recursive_parent_proofs': '4', 'transport_scope': 'single-root-in-memory', 'root_transport_roundtrip_complete': 'true'}
TERMINAL_FIXED = {'terminal_observer_scope': 'process-audit-only', 'released_claims_cover_terminal_observer': 'false', 'process_engine_device_audit_complete': 'false', 'original_quota_released': 'true', 'current_host_bytes': '0', 'current_device_bytes': '0', 'component_success': 'true', 'mode': 'root-transport', 'mutation_checks_complete': 'false', 'artifact_roundtrip_complete': 'false', 'complete_ringct_workflow': 'false'}
SCOPE_NUMBERS = ('packet_bytes', 'inner_bytes', 'original_verification_ns', 'encoding_ns', 'header_checks_ns', 'decoding_ns', 'decoded_verification_ns', 'reencoding_ns', 'transport_action_ns')
DECODE_NUMBERS = ('vector_bytes', 'canonical_bytes', 'admitted_bytes', 'allocations', 'limit_bytes')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def exact(actual, expected):
    """Boolean authority flags must never compare equal to integer receipts."""
    if type(actual) is not type(expected):
        return False
    if type(actual) is dict:
        return actual.keys() == expected.keys() and all(exact(actual[k], expected[k]) for k in actual)
    if type(actual) is list:
        return len(actual) == len(expected) and all(exact(a, b) for a, b in zip(actual, expected))
    return actual == expected


def helper(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('root_transport_gpu_' + name, path)
    require(spec is not None and spec.loader is not None, 'missing maintained root-transport helper')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def absolute(value):
    return (type(value) is str and '\0' not in value and PurePosixPath(value).is_absolute()
            and '..' not in PurePosixPath(value).parts and str(PurePosixPath(value)) == value)


def expected_environment(root, uuid):
    environment = helper('hashx_sequence_preissue_guard').expected_environment(root, uuid)
    require(environment.get('LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION') == '1',
            'maintained full sequence environment changed')
    environment[FLAG] = '1'
    return environment


def receipt(environment):
    require(type(environment) is dict and all(type(k) is str and type(v) is str and k
            and '=' not in k and '\0' not in k + v for k, v in environment.items()),
            'malformed root-transport GPU environment')
    encoded = b''.join((key + '=' + environment[key] + '\0').encode() for key in sorted(environment))
    require(len(environment) <= 64 and len(encoded) <= 8192, 'root-transport GPU environment bound')
    return dict(schema='ringct-root-transport-gpu-environment-v1', mode='root-transport', selector=SELECTOR,
                entry_count=len(environment), serialized_bytes=len(encoded),
                sha256_sorted_name_equals_value_nul=sha256(encoded).hexdigest(),
                requires_env_clear_before_exec=True, requires_immutable_environment_after_exec=True,
                dispatch_authority=False, complete_ringct_workflow=False, performance_qualified=False)


def exact_command(command):
    require(type(command) is list and len(command) == 6 and absolute(command[0])
            and PurePosixPath(command[0]).name.startswith('lattica_pq_ringct_research-')
            and command[1:] == [SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'root-transport GPU requires its exact recorded isolated test')


def build_environment(args, base, root, kernel, tree_storage):
    require(getattr(args, 'owned_hashx_root_transport_test', None) == 'gpu', 'unknown root-transport GPU mode')
    command = list(args.command)
    if command[:1] == ['--']:
        command.pop(0)
    exact_command(command)
    require(args.profile == 'full' and args.expect_tests is True and args.build_label,
            'root-transport GPU requires recorded full profile')
    require(not any(bool(getattr(args, key, False)) for key in EXCLUSIVE), 'root-transport GPU mode is exclusive')
    require(kernel == 'baseline' and tree_storage == 'host', 'root-transport GPU hash/tree mode changed')
    environment = expected_environment(root, getattr(args, 'device_uuid', None))
    expected_base = dict(environment)
    for flag in (FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION', 'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'):
        expected_base.pop(flag)
    expected_base['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    require(base == expected_base, 'root-transport GPU fixed startup base changed')
    return environment, receipt(environment)


def bind_execution(plan, sources, executable, root):
    require(absolute(root), 'root-transport GPU source root is not absolute')
    exact_command(plan.get('command'))
    environment = plan.get('environment')
    require(type(environment) is dict, 'root-transport GPU environment absent')
    expected = expected_environment(root, environment.get('LATTICA_GPU_DEVICE_UUID'))
    require(environment == expected and exact(plan.get(ENV_KEY), receipt(expected)),
            'root-transport GPU environment or receipt changed')
    require(all(plan.get(key) is None for key in FOREIGN_RECEIPTS), 'foreign root-transport qualification mode')
    resources = dict(memory_max_bytes=47 * GIB, memory_high_bytes=45 * GIB, fresh_memavailable_required_bytes=49 * GIB)
    require(all(type(plan.get(key)) is int and plan[key] == value for key, value in resources.items())
            and plan.get('profile') == 'full' and plan.get('expect_tests') is True
            and plan.get('cpu_quota') == '800%' and plan.get('benchmark') is False
            and plan.get('performance_qualified') is False and plan.get('comparison_baseline') is False
            and plan.get('public_hash_kernel') == 'baseline' and plan.get('expect_result') is False
            and plan.get('expect_direct_result') is False and plan.get('correctness_label') is None
            and plan.get('record_artifacts') == [], 'root-transport GPU resource/profile contract changed')
    require(type(plan.get('runtime_seconds')) is int and 1 <= plan['runtime_seconds'] <= 86400,
            'root-transport GPU runtime bound changed')
    require(type(sources) is dict and all(path in sources for path in REQUIRED_SOURCES),
            'root-transport GPU source manifest incomplete')
    require(all(type(path) is str and path and '\0' not in path and not PurePosixPath(path).is_absolute()
                and '..' not in PurePosixPath(path).parts and str(PurePosixPath(path)) == path and digest(value) for path, value in sources.items()),
            'malformed root-transport GPU source manifest')
    label = plan.get('build_label')
    require(type(label) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label),
            'root-transport GPU recorded build absent')
    require(type(executable) is dict and executable.get('path') == plan['command'][0]
            and absolute(executable.get('resolved_path')) and digest(executable.get('sha256'))
            and executable.get('build_record') == root + '/.tools/pq-opencl-opt/runs/' + label + '.json'
            and digest(executable.get('build_record_sha256')), 'root-transport GPU executable binding differs')
    return dict(schema='ringct-root-transport-gpu-binding-v1', mode='root-transport', selector=SELECTOR, source_root=root,
                resolved_executable=executable['resolved_path'],
                source_manifest_sha256=sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
                executable_sha256=executable['sha256'], build_record_sha256=executable['build_record_sha256'],
                environment_sha256=plan[ENV_KEY]['sha256_sorted_name_equals_value_nul'],
                selected_physical_device_uuid=environment['LATTICA_GPU_DEVICE_UUID'],
                requires_terminal_reaping_and_unchanged_sources=True, requires_independent_physical_device_audit=True,
                dispatch_authority=False, complete_ringct_workflow=False, performance_qualified=False)


def fields(body, fixed, numbers):
    require(type(body) is str and len(body) <= 8192, 'root-transport event serialized bound')
    pairs = body.split(' ')
    require(all(re.fullmatch(r'[a-z_]+=[a-z0-9-]+', item) for item in pairs), 'malformed root-transport fields')
    found = dict(item.split('=') for item in pairs)
    require(len(found) == len(pairs) and set(found) == set(fixed) | set(numbers),
            'duplicate, missing or extra root-transport fields')
    require(all(found[key] == value for key, value in fixed.items()), 'root-transport fixed flags/counts differ')
    values = {}
    for key in numbers:
        require(re.fullmatch(r'0|[1-9][0-9]{0,38}', found[key]), 'noncanonical root-transport number')
        value = int(found[key])
        require(value <= (U128_MAX if key.endswith('_ns') else U64_MAX), 'root-transport integer overflow')
        values[key] = value
    return values


def valid_header_payload(payload):
    if payload == '' or payload.startswith(ROOT_CLAIMS + ' '):
        return True
    number = r'(0|[1-9][0-9]{0,19})'
    growth = re.fullmatch(r'bounded_proof_input_growth old_values=' + number + r' new_values=' + number
                         + r' live_bytes=' + number + r' value_limit=' + number, payload)
    if growth is None:
        return False
    old, new, live, limit = map(int, growth.groups())
    return (0 < limit <= 1 << 20 and 0 <= old < new <= limit
            and new == min(max(old * 2, 4), limit) and live == (old + new) * 8)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate root-transport receipt JSON key')
        result[key] = value
    return result


def reject_json_number(_):
    raise ValueError('root-transport receipt requires finite integer numbers')


def decode_report(body):
    require(len(body) <= 65536, 'root-transport receipt serialized bound')
    report = json.loads(body, object_pairs_hook=unique, parse_float=reject_json_number,
                        parse_constant=reject_json_number)
    require(type(report) is dict and set(report) == set('schema entry_point policy capabilities elapsed_ns '
            'succeeded stage_coverage_complete completion_rejected observation_errors observations components'.split()),
            'root-transport receipt report schema differs')
    caps = report['capabilities']
    require(type(caps) is dict and set(caps) == {'scope', 'profile', 'max_log_fri_arity', 'stages'},
            'root-transport receipt capability schema differs')
    require(type(caps['stages']) is list and all(type(item) is dict and set(item) == {'stage', 'backend'}
            and type(item['stage']) is str and type(item['backend']) is str
            for item in caps['stages']), 'root-transport receipt stage schema differs')
    require(type(report['observations']) is list and all(type(item) is dict and set(item) == set(
            'stage backend calls completed_calls device_calls inclusive_ns device_ns'.split())
            and type(item['stage']) is str and type(item['backend']) is str
            for item in report['observations']), 'root-transport receipt observation schema differs')
    for item in report['observations']:
        require(all(type(item[key]) is int and 0 <= item[key] <= U64_MAX
                    for key in ('calls', 'completed_calls', 'device_calls')), 'root-transport receipt counter overflow')
    return report


def geometry(record):
    active, padded = record['active_rows'], record['padded_rows']
    require(0 < active <= padded <= 1 << 20 and padded >= 8 and padded & (padded - 1) == 0,
            'root-transport compiler row geometry differs')
    require(0 < record['wires'] <= 1 << 26 and 0 < record['input_values'] <= 1 << 20,
            'root-transport compiler wire/input bound differs')
    require(record['compiler_ns'] > 0 and record['source_cpu_verification_ns'] > 0,
            'root-transport compiler/source-verifier timing absent')


def validate_log(content, plan):
    binding = plan.get(BINDING_KEY)
    require(type(binding) is dict and absolute(binding.get('source_root')), 'root-transport GPU binding absent')
    require(exact(binding, bind_execution(plan, plan.get('input_sha256'), plan.get('executable_provenance'),
                                         binding['source_root'])), 'root-transport GPU original binding changed')
    observation = plan.get('observation_before_validation_ns')
    require(type(observation) is int and 0 < observation <= U128_MAX, 'root-transport runner observation absent')
    require(type(content) is str and len(content) <= 16 << 20, 'root-transport log text/bound differs')
    require(not any(token in content for token in ('panicked at', 'FAILED', 'OPENCL_OPT_RESULT',
            'DIRECT_SPEND_RESULT', 'DIRECT_RING_RESULT', 'NATIVE_EXECUTION_RECEIPT', 'PUBLIC_HASH_EXECUTION',
            'fallback=true', 'retry=true', 'transport_schema_case')),
            'root-transport log contains foreign, synthetic or failed evidence')
    headers = list(re.finditer(r'^test (\S+) \.\.\. ([^\n]*)$', content, re.M))
    completions = list(re.finditer(r'^ok$', content, re.M))
    footers = list(re.finditer(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; '
                             r'(?:0|[1-9][0-9]*) filtered out; finished in [0-9]+\.[0-9]+s$', content, re.M))
    require(len(headers) == len(completions) == len(footers) == 1 and headers[0].group(1) == SELECTOR
            and valid_header_payload(headers[0].group(2)) and content.count('test result:') == 1,
            'root-transport requires its exact passing isolated test/footer')
    header_prefix = 'test ' + SELECTOR + ' ... '
    require(content.count(header_prefix) == 1, 'duplicate root-transport invocation')
    events = []
    observer_bytes = 0
    for line_number, line in enumerate(content.splitlines()):
        if line.startswith(header_prefix):
            line = line[len(header_prefix):]
        if line.startswith('proving_stage_report '):
            events.append(('receipt', decode_report(line.removeprefix('proving_stage_report ')), line_number))
            continue
        require('proving_stage_report' not in line, 'misplaced root-transport receipt')
        if line.startswith(DECODE + ' '):
            events.append((DECODE, line.removeprefix(DECODE + ' '), line_number))
            continue
        require(DECODE not in line, 'misplaced root-transport bounded decode event')
        names = re.findall(r'\bringct_[A-Za-z0-9_]+', line)
        if names or 'ringct_' in line:
            require(len(names) == 1 and names[0] in MARKERS and line.startswith(names[0] + ' '),
                    'foreign or malformed root-transport marker')
            name, body = line.split(' ', 1)
            if name in (COMPLETE, TERMINAL):
                require(line.isascii(), 'root-transport observer event must be ASCII')
                observer_bytes += len(line) + 1
            events.append((name, body, line_number))
    expected_order = [ROOT_CLAIMS, SOURCE_CLAIMS] + ['receipt'] * 28 + [LEAF] * 5 + [PARENT] * 4
    expected_order += [ACCEPTANCE, DECODE, ROOT_SCOPE, COMPLETE, TERMINAL]
    require([name for name, _, _ in events] == expected_order,
            'missing, duplicate or reordered root-transport events')
    require(observer_bytes <= OBSERVER_EVENT_LIMIT, 'root-transport terminal observer event bound')
    header_line = content[:headers[0].start()].count('\n')
    completion_line = content[:completions[0].start()].count('\n')
    require(header_line <= events[0][2] and events[-1][2] < completion_line
            and completions[0].start() < footers[0].start(), 'root-transport events outside invocation/completion')

    root = fields(events[0][1], ROOT_FIXED, ROOT_NUMBERS)
    source = fields(events[1][1], SOURCE_FIXED, ('host_bytes', 'device_bytes'))
    require(0 < source['host_bytes'] <= HOST and source['device_bytes'] == 0,
            'root-transport original source claims differ')
    require(root['fixed_host_bytes'] > 0 and root['verifier_host_bytes'] > 0
            and root['caller_host_bytes'] > (64 << 10)
            and root['packet_and_decoder_host_bytes'] == DECODE_LIMIT + 2 * PACKET_LIMIT
            and root['additional_host_bytes'] == (root['fixed_host_bytes']
                + root['packet_and_decoder_host_bytes'] + root['verifier_host_bytes'])
            and root['total_host_bytes'] == root['additional_host_bytes'] + root['caller_host_bytes']
            and root['total_host_bytes'] <= source['host_bytes'],
            'root-transport transport-plus-driver preclaim incomplete or unbacked')
    require(root['packet_limit_bytes'] == PACKET_LIMIT and root['decoder_limit_bytes'] == DECODE_LIMIT
            and root['max_inner_bytes'] > 8
            and root['max_packet_bytes'] == root['max_inner_bytes'] + HEADER_BYTES
            and root['max_packet_and_probe_bytes'] == root['max_packet_bytes'] + 1 <= PACKET_LIMIT
            and root['max_inner_bytes'] - 8 < root['max_decoder_cumulative_bytes'] <= DECODE_LIMIT,
            'root-transport all-height packet/decoder envelope differs')

    receipt_check = helper('native_sequence_report').receipt
    elapsed = [receipt_check(event[1], entry) for event, entry in zip(events[2:30], ENTRIES)]
    metrics = ('active_rows', 'padded_rows', 'wires', 'input_values', 'compiler_ns', 'source_cpu_verification_ns')
    leaves, parents = [], []
    for ordinal, (first, units) in enumerate(LEAF_SPANS):
        fixed = dict(PROVISIONAL, ordinal=str(ordinal), first_segment=str(2 * ordinal), segment_count='2',
                     first_unit=str(first), units=str(units))
        record = fields(events[30 + ordinal][1], fixed, metrics)
        geometry(record)
        leaves.append(dict(record, ordinal=ordinal, first_segment=2 * ordinal, segment_count=2,
                           first_unit=first, units=units))
    for ordinal, (first, units, level) in enumerate(PARENT_SPANS):
        fixed = dict(PROVISIONAL, ordinal=str(ordinal), first_unit=str(first), units=str(units), level=str(level))
        record = fields(events[35 + ordinal][1], fixed, metrics)
        geometry(record)
        parents.append(dict(record, ordinal=ordinal, first_unit=first, units=units, level=level))
    acceptance = fields(events[39][1], dict(PROVISIONAL, first_unit='0', units='122', level='3',
                        mutation_checks_complete='false', artifact_roundtrip_complete='false'),
                        ('preparation_through_acceptance_ns',))
    decoded = fields(events[40][1], {'rejected': 'false'}, DECODE_NUMBERS)
    transport = fields(events[41][1], ROOT_SCOPE_FIXED, SCOPE_NUMBERS)
    complete = fields(events[42][1], COMPLETE_FIXED,
                      ('component_through_destruction_ns', 'terminal_observer_fixed_host_bytes'))
    terminal = fields(events[43][1], TERMINAL_FIXED,
                      ('peak_host_bytes', 'peak_device_bytes', 'component_through_destruction_ns',
                       'terminal_observer_fixed_host_bytes'))
    require(8 < transport['inner_bytes'] <= root['max_inner_bytes']
            and transport['packet_bytes'] == transport['inner_bytes'] + HEADER_BYTES <= root['max_packet_bytes']
            and transport['packet_bytes'] + 1 <= PACKET_LIMIT,
            'root-transport actual packet exceeds original all-height admission')
    require(decoded['limit_bytes'] == DECODE_LIMIT and decoded['vector_bytes'] > 0
            and 0 < decoded['allocations'] <= decoded['vector_bytes']
            and decoded['canonical_bytes'] == transport['inner_bytes'] - 8
            and decoded['admitted_bytes'] == decoded['vector_bytes'] + decoded['canonical_bytes']
            and decoded['admitted_bytes'] <= root['max_decoder_cumulative_bytes'],
            'root-transport actual bounded decode accounting differs')
    require(source['host_bytes'] + DEVICE <= terminal['peak_host_bytes'] <= HOST
            and terminal['peak_device_bytes'] == DEVICE, 'root-transport terminal memory peaks disagree')
    require(0 < complete['terminal_observer_fixed_host_bytes']
            == terminal['terminal_observer_fixed_host_bytes'] <= OBSERVER_HOST_LIMIT,
            'root-transport process-only terminal observer census differs')
    intervals = ('original_verification_ns', 'encoding_ns', 'header_checks_ns', 'decoding_ns',
                 'decoded_verification_ns', 'reencoding_ns')
    require(all(transport[key] > 0 for key in intervals)
            and sum(transport[key] for key in intervals) <= transport['transport_action_ns'],
            'root-transport numerical/codec/header intervals exceed enclosing action')
    preparation = acceptance['preparation_through_acceptance_ns']
    # These pinned phases are serialized. Nested device and inclusive timings
    # are never summed. The transport action excludes preparation/destruction.
    serialized = sum(elapsed) + sum(item['compiler_ns'] + item['source_cpu_verification_ns']
                                  for item in leaves + parents)
    require(preparation >= serialized and complete['component_through_destruction_ns']
            == terminal['component_through_destruction_ns'] <= observation
            and terminal['component_through_destruction_ns'] >= preparation + transport['transport_action_ns'],
            'root-transport timers do not enclose serialized work and destruction')
    # JSON receipts do not carry cryptographic ordinals. Only pinned driver
    # order maps these positions to the nine recursive phase summaries.
    phases = [dict((leaves if kind == 'leaf' else parents)[ordinal], kind=kind,
                   setup_ns=elapsed[10 + 2 * position], proving_ns=elapsed[11 + 2 * position])
              for position, (kind, ordinal) in enumerate(ORDER)]
    return dict(schema='ringct-root-transport-gpu-qualification-v1', scope='single-root-in-memory',
                native_proofs=10, recursive_proofs=9, recursive_leaf_proofs=5, recursive_parent_proofs=4,
                stage_receipts=28, cpu_heights=18, codec_heights=18,
                numerical_positive_checks=2, header_positive_checks=2, bounded_decode_successes=1,
                header_syntax_rejections=24, header_public_rejections=46, header_cap_rejections=256,
                header_height_rejections=1, header_canonical_rejections=302, typed_header_refusals=629,
                root_transport_claims=root, source_claims=source, native_receipt_elapsed_ns=elapsed[:10],
                recursive_phases=phases, acceptance=acceptance, bounded_decode=decoded,
                root_transport=transport, terminal=terminal,
                root_transport_roundtrip_complete=True, retained_output_immutable=True, source_key_authenticated=True,
                original_quota_released=True, owner_quota_cleanup_complete=True, fresh_only=True, gpu_required=True,
                original_startup_pcs_reused=True, fresh_native_proof_receipts=10,
                fresh_outer_preprocessing_receipts=9, fresh_outer_proof_receipts=9,
                receipt_phase_identity='pinned-source-order-only',
                terminal_observer_scope='process-audit-only', terminal_observer_event_bytes=observer_bytes,
                released_claims_cover_terminal_observer=False, terminal_observer_census_is_physical_measurement=False,
                process_engine_device_audit_complete=False, transaction_context_authenticated=False,
                decoder_failures_classified=False, raw_proof_mutation_checks_complete=False,
                interior_mutation_checks_complete=False, mutation_checks_complete=False,
                disk_artifact_roundtrip_complete=False, artifact_roundtrip_complete=False,
                complete_ringct_workflow=False, performance_qualified=False)
