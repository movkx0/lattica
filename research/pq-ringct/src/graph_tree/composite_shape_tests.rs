//! Unproved composite-leaf geometry, using real registered request predicates.
//! Native and outer proof-shaped inputs are deliberately invalid. This avoids
//! producing hundreds of outer proofs but still registers every source cap in
//! the selected complete-request tree. It is not a proof/cache/acceptance path.
use super::*;
use crate::{
    component_tree::{
        self,
        shape_diagnostic::{invalid_native_template, RegisteredShape},
    },
    graph_auxiliary::{AuxiliaryArtifact, AuxiliaryFactory, AuxiliaryRequest, Kind, Role},
    graph_crypto::{self, Request, RequestDescriptor},
    graph_proofs::{GraphProofPlan, ResourceLimits},
    rust_verify::{committed_backend, Proof, Statement},
};
use lattica_prover_p3::block_v2::{
    machine::{
        analysis,
        verifier::{self, ProofInputs},
        MachineAir,
    },
    profile,
};
use p3_air::{symbolic::SymbolicAirBuilder, Air, BaseAir};
use std::{path::PathBuf, time::Instant};

fn report_geometry(stage: &str, operation: usize, ordinal: Option<usize>, geometry: &Geometry) {
    eprintln!(
        "COMPOSITE_SHAPE_GEOMETRY {}",
        serde_json::json!({
            "stage": stage, "operation": operation, "graph_ordinal": ordinal,
            "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
            "wires": geometry.wires, "main_width": geometry.main_width,
            "preprocessed_width": geometry.preprocessed_width,
            "permutation_width_base": geometry.permutation_width_base,
            "quotient_chunks": geometry.quotient_chunks, "constraints": geometry.constraints,
            "max_constraint_degree": geometry.max_constraint_degree,
            "fri_ali_bits": geometry.fri_ali_bits,
            "retained_lde_bytes": geometry.retained_lde_bytes,
            "proof_produced": false,
        })
    );
}

fn register_request_node(
    request: &Request,
    stage: &str,
    compiled: component_tree::CompiledNode,
    budget: u64,
    registrations: &mut usize,
) -> RegisteredShape {
    report_geometry(
        stage,
        request.operation_index(),
        None,
        &compiled.geometry().unwrap(),
    );
    let start = Instant::now();
    let registered = RegisteredShape::register(compiled, budget).unwrap();
    *registrations += 1;
    eprintln!(
        "COMPOSITE_SHAPE_REGISTER {}",
        serde_json::json!({
            "stage": stage, "operation": request.operation_index(),
            "request_index": request.request_index(), "seconds": start.elapsed().as_secs_f64(),
            "actual_registered_cap": true, "invalid_template_rejected": true,
        })
    );
    registered
}

pub(crate) fn complete_request_shape(
    request: &Request,
    context: &GraphContext,
    maximum_permutations: usize,
    native_budget: u64,
    outer_budget: u64,
    registrations: &mut usize,
) -> RegisteredShape {
    let contract = request.contract().unwrap();
    let endpoint = request.endpoint_context_hint(context);
    let root = match request.descriptor() {
        RequestDescriptor::Aes(descriptor) if descriptor.blocks() < 16 => {
            let partition = request.aes_partition().unwrap();
            assert_eq!(
                partition.segments().len(),
                1,
                "small request must be one admitted serial segment"
            );
            let air = &partition.segments()[0];
            let artifact = crate::aes_lane_air::join::AesLaneSegmentProof {
                public_values: [Val::ZERO; crate::aes_lane_air::PUBLIC_VALUES],
                proof: invalid_native_template(air, air.height),
            };
            let compiled = component_tree::compile_aes(
                &contract,
                0,
                descriptor.blocks() as u32,
                &endpoint,
                &artifact,
            )
            .unwrap();
            register_request_node(
                request,
                "aes-small-serial-leaf",
                compiled,
                outer_budget,
                registrations,
            )
        }
        RequestDescriptor::Aes(descriptor) => {
            let factory = request.wide_aes(native_budget).unwrap();
            let geometry = factory.geometry();
            eprintln!(
                "COMPOSITE_SHAPE_NATIVE_LAYOUT {}",
                serde_json::json!({
                    "operation": request.operation_index(), "request_index": request.request_index(),
                    "layout": "whole-wide-aes", "segments": 1,
                    "width": geometry.width, "height": geometry.height,
                    "retained_main_lde_bytes": geometry.retained_main_lde_bytes,
                    "uncalibrated_peak_estimate_bytes": geometry.uncalibrated_peak_estimate_bytes,
                })
            );
            let air = crate::aes_air::AesAir::new(descriptor).unwrap();
            let artifact = component_tree::WideAesProof {
                public_values: core::array::from_fn(|i| {
                    if i < 4 {
                        endpoint.input[i]
                    } else {
                        endpoint.output[i - 4]
                    }
                }),
                proof: invalid_native_template(&air, air.height),
            };
            let compiled =
                component_tree::compile_wide_aes(&contract, &endpoint, &artifact).unwrap();
            register_request_node(request, "aes-leaf", compiled, outer_budget, registrations)
        }
        RequestDescriptor::Shake(_) => {
            let factory = request
                .wide_shake(maximum_permutations, native_budget)
                .unwrap();
            // Exactly the binary carry schedule in RequestProver::prove_wide:
            // merge occupied slots on insertion, then low slots into the right
            // remainder on completion. No source cap or subtree is fabricated.
            let mut slots: Vec<Option<RegisteredShape>> = Vec::new();
            for (index, air) in factory.segments().iter().enumerate() {
                let geometry = factory.geometry(index).unwrap();
                eprintln!(
                    "COMPOSITE_SHAPE_NATIVE_LAYOUT {}",
                    serde_json::json!({
                        "operation": request.operation_index(), "request_index": request.request_index(),
                        "layout": "segmented-wide-shake", "segments": factory.segment_count(),
                        "segment_index": index, "first": air.first_permutation, "units": air.permutations,
                        "width": geometry.width, "height": geometry.height,
                        "retained_main_lde_bytes": geometry.retained_main_lde_bytes,
                        "uncalibrated_peak_estimate_bytes": geometry.uncalibrated_peak_estimate_bytes,
                    })
                );
                let artifact = crate::crypto_join::ShakeSegmentProof {
                    public_values: [Val::ZERO; crate::shake_air::PUBLIC_VALUES],
                    proof: invalid_native_template(air, air.height),
                };
                let compiled = component_tree::compile_wide_shake(
                    &contract,
                    air.first_permutation as u32,
                    air.permutations as u32,
                    &endpoint,
                    &artifact,
                )
                .unwrap();
                let mut value = register_request_node(
                    request,
                    "shake-leaf",
                    compiled,
                    outer_budget,
                    registrations,
                );
                let mut level = 0;
                loop {
                    if level == slots.len() {
                        slots.push(None);
                    }
                    match slots[level].take() {
                        None => {
                            slots[level] = Some(value);
                            break;
                        }
                        Some(left) => {
                            let parent = left.compile_parent(&value).unwrap();
                            value = register_request_node(
                                request,
                                "shake-parent",
                                parent,
                                outer_budget,
                                registrations,
                            );
                            level += 1;
                        }
                    }
                }
            }
            let mut right = None;
            for left in slots.into_iter().flatten() {
                right = Some(match right {
                    None => left,
                    Some(right) => {
                        let compiled = left.compile_parent(&right).unwrap();
                        register_request_node(
                            request,
                            "shake-parent-remainder",
                            compiled,
                            outer_budget,
                            registrations,
                        )
                    }
                });
            }
            right.unwrap()
        }
    };
    root.key.manifest_shape().unwrap(); // Rejects incomplete registered spans.
    assert!(root
        .key
        .verify_request(&root.invalid_proof, &endpoint)
        .is_err());
    report_geometry(
        "complete-request-root",
        request.operation_index(),
        None,
        &root.geometry,
    );
    root
}

pub(crate) fn auxiliary_template(request: &AuxiliaryRequest) -> AuxiliaryArtifact {
    let public_values = request.expected_public_values();
    let artifact = match request.kind() {
        Kind::Uniform(kind) => {
            let air = crate::uniform_air::UniformAir::new(kind);
            let proof = invalid_native_template(&air, air.height());
            report_native_verifier_geometry(request, &air, air.height(), &proof);
            AuxiliaryArtifact::Uniform(crate::uniform_air::join::UniformArtifact {
                public_values,
                proof,
            })
        }
        Kind::Sparse(kind) => {
            let air = crate::sparse_air::SparseAir::new(kind);
            let proof = invalid_native_template(&air, crate::sparse_air::HEIGHT);
            report_native_verifier_geometry(request, &air, crate::sparse_air::HEIGHT, &proof);
            AuxiliaryArtifact::Sparse(crate::sparse_air::join::SparseArtifact {
                public_values,
                proof,
            })
        }
        Kind::Transcript => {
            let air = request.transcript_air().unwrap();
            let proof = invalid_native_template(air, air.height());
            report_native_verifier_geometry(request, air, air.height(), &proof);
            AuxiliaryArtifact::Transcript(crate::transcript_air::join::TranscriptArtifact {
                public_values,
                proof,
            })
        }
    };
    assert!(request.verify(&artifact).is_err());
    artifact
}

/// Isolate the exact native verifier, excluding the consumer's graph root
/// joins. Composite geometry below includes those joins through production
/// SourceBinding and is authoritative for graph-leaf admission.
fn report_native_verifier_geometry<A>(
    request: &AuxiliaryRequest,
    air: &A,
    height: usize,
    proof: &p3_uni_stark::Proof<profile::Config>,
) where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    let mut builder = ProgramBuilder::new(air.num_public_values()).unwrap();
    let public: Vec<_> = (0..air.num_public_values())
        .map(|i| builder.public(i).unwrap())
        .collect();
    let mut inputs = ProofInputs::default();
    verifier::uni::verify(&mut builder, &mut inputs, air, height, &public, proof).unwrap();
    let program = builder.finish(None).unwrap();
    let machine = MachineAir::new(program);
    let report = analysis::analyze(&machine).unwrap();
    let geometry = Geometry {
        active_rows: machine.program().active_rows(),
        padded_rows: machine.program().height(),
        wires: machine.program().wire_count(),
        main_width: report.main_width,
        preprocessed_width: report.preprocessed_width,
        permutation_width_base: report.permutation_width_base,
        quotient_chunks: report.quotient_chunks,
        constraints: report.constraints,
        max_constraint_degree: report.max_constraint_degree,
        fri_ali_bits: report.fri_ali_bits,
        retained_lde_bytes: report.retained_lde_bytes,
    };
    report_geometry(
        &format!("auxiliary-verifier-{:?}", request.role()),
        request.operation_index(),
        None,
        &geometry,
    );
    assert!(machine
        .trace(&request.expected_public_values(), &inputs.values)
        .is_err());
}

#[test]
#[ignore = "trusted source-cap registration only, no proofs; coordinate a guarded memory window"]
fn exact_composite_graph_leaves_with_invalid_complete_request_templates() {
    let start = Instant::now();
    let archive = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit persisted public graph fixture required"),
    );
    let fixture = crate::native_test_fixture::load_or_create(
        &archive,
        [71; 32],
        [29; 32],
        3,
        crate::native::FixtureAmounts {
            input: [17, 23],
            output: [29, 11],
        },
        false,
    )
    .unwrap();
    let graph = committed_backend::lower_unproved(
        fixture.setup_seed,
        &fixture.context,
        &Statement::decode(&fixture.statement).unwrap(),
        &Proof::decode(&fixture.proof).unwrap(),
    )
    .unwrap();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&registered, &graph, ResourceLimits::default()).unwrap();
    let plan = Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = GraphContext {
        context: fixture.context,
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            plan.label(),
            fixture.context,
            &fixture.statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: plan.node_manifest_hint(&graph).unwrap(),
    };
    let maximum_permutations = std::env::var("LATTICA_COMPOSITE_SHAPE_SHAKE_MAX")
        .map(|v| v.parse::<usize>().unwrap())
        .unwrap_or(128);
    let native_gib = std::env::var("LATTICA_COMPOSITE_SHAPE_NATIVE_GIB")
        .map(|v| {
            v.parse::<u64>()
                .expect("native admission GiB must be an integer")
        })
        .unwrap_or(16);
    assert!(
        matches!(native_gib, 8 | 16 | 32 | 64),
        "explicit native estimate allowance must be 8, 16, 32 or 64 GiB"
    );
    let native_budget = native_gib.checked_mul(1u64 << 30).unwrap();
    // Registration retains only the preprocessing source material. Its hard
    // process guard is imposed by the external runner; this admission value
    // is not permission to prove a request or a claim that its prover fits.
    let registration_gib = std::env::var("LATTICA_COMPOSITE_SHAPE_REGISTER_GIB")
        .map(|v| {
            v.parse::<u64>()
                .expect("registration GiB must be an integer")
        })
        .unwrap_or(32);
    assert!(
        matches!(registration_gib, 32 | 64),
        "explicit registration allowance must be 32 or 64 GiB"
    );
    let outer_budget = registration_gib.checked_mul(1u64 << 30).unwrap();
    let local_retained_reference = 32u64 << 30;
    let local_process_reference = 48u64 << 30;
    eprintln!(
        "COMPOSITE_SHAPE_OPTIONS {}",
        serde_json::json!({
            "request_registration_retained_budget_bytes": outer_budget,
            "local_retained_reference_bytes": local_retained_reference,
            "local_process_reference_bytes": local_process_reference,
            "maximum_shake_permutations": maximum_permutations,
            "native_estimate_budget_bytes": native_budget,
            "hard_process_guard": "external runner, not this admission setting",
        })
    );
    let crypto = graph_crypto::Plan::new(
        &plan,
        &graph,
        graph_crypto::Policy {
            child_memory_budget_bytes: native_budget,
            ..graph_crypto::Policy::default()
        },
    )
    .unwrap();
    let auxiliary = AuxiliaryFactory::new(&plan, &graph, &context, native_budget).unwrap();
    let selected_operation = std::env::var("LATTICA_COMPOSITE_SHAPE_OPERATION")
        .ok()
        .map(|v| v.parse::<usize>().unwrap());
    let mut registrations = 0;
    let mut measured = 0;
    let mut graph_nodes_over_budget = 0;
    let mut graph_nodes_above_local_process_lower_bound = 0;
    let mut selected_leaves: Vec<_> = plan
        .leaves()
        .iter()
        .enumerate()
        .filter(|(_, leaf)| {
            matches!(
                leaf.kind(),
                LeafKind::Operations(
                    OperationFamily::SampleG
                        | OperationFamily::ExpandAlpha
                        | OperationFamily::HashAlpha
                        | OperationFamily::HashX
                )
            )
        })
        .collect();
    selected_leaves.sort_by_key(|(_, leaf)| match leaf.kind() {
        LeafKind::Operations(OperationFamily::SampleG) => 0,
        LeafKind::Operations(OperationFamily::ExpandAlpha) => 1,
        LeafKind::Operations(OperationFamily::HashX) => 2,
        LeafKind::Operations(OperationFamily::HashAlpha) => 3,
        _ => unreachable!(),
    });
    for (ordinal, leaf) in selected_leaves {
        let LeafKind::Operations(family) = leaf.kind() else {
            continue;
        };
        if !matches!(
            family,
            OperationFamily::SampleG
                | OperationFamily::ExpandAlpha
                | OperationFamily::HashAlpha
                | OperationFamily::HashX
        ) {
            continue;
        }
        let operation = leaf.operation_indices()[0];
        if selected_operation.is_some_and(|selected| selected != operation) {
            continue;
        }
        let request = |subrequest| {
            crypto
                .requests()
                .iter()
                .find(|r| r.operation_index() == operation && r.subrequest() == subrequest)
                .unwrap()
        };
        let first = complete_request_shape(
            request(0),
            &context,
            maximum_permutations,
            native_budget,
            outer_budget,
            &mut registrations,
        );
        let aes = || AesProof::Tree {
            key: &first.key,
            proof: &first.invalid_proof,
        };
        let shake = || ShakeProof::Tree {
            key: &first.key,
            proof: &first.invalid_proof,
        };
        let compiled = match family {
            OperationFamily::SampleG => {
                let sampler =
                    auxiliary_template(auxiliary.request(operation, Role::SampleGUniform).unwrap());
                compile_leaf(
                    &plan,
                    &graph,
                    ordinal,
                    &context,
                    LeafArtifact::SampleG {
                        aes: aes(),
                        sampler: sampler.uniform().unwrap(),
                    },
                )
                .unwrap()
            }
            OperationFamily::ExpandAlpha => {
                let second = complete_request_shape(
                    request(1),
                    &context,
                    maximum_permutations,
                    native_budget,
                    outer_budget,
                    &mut registrations,
                );
                let uniform =
                    auxiliary_template(auxiliary.request(operation, Role::AlphaUniform).unwrap());
                let sparse =
                    auxiliary_template(auxiliary.request(operation, Role::AlphaSparse).unwrap());
                compile_leaf(
                    &plan,
                    &graph,
                    ordinal,
                    &context,
                    LeafArtifact::ExpandAlpha {
                        uniform_aes: aes(),
                        uniform: uniform.uniform().unwrap(),
                        sparse_aes: AesProof::Tree {
                            key: &second.key,
                            proof: &second.invalid_proof,
                        },
                        sparse: sparse.sparse().unwrap(),
                    },
                )
                .unwrap()
            }
            OperationFamily::HashAlpha => {
                let transcript = auxiliary_template(
                    auxiliary
                        .request(operation, Role::HashAlphaTranscript)
                        .unwrap(),
                );
                compile_leaf(
                    &plan,
                    &graph,
                    ordinal,
                    &context,
                    LeafArtifact::HashAlpha {
                        transcript: transcript.transcript().unwrap(),
                        shake: shake(),
                    },
                )
                .unwrap()
            }
            OperationFamily::HashX => {
                let transcript = auxiliary_template(
                    auxiliary.request(operation, Role::HashXTranscript).unwrap(),
                );
                let sampler =
                    auxiliary_template(auxiliary.request(operation, Role::HashXSparse).unwrap());
                compile_leaf(
                    &plan,
                    &graph,
                    ordinal,
                    &context,
                    LeafArtifact::HashX {
                        transcript: transcript.transcript().unwrap(),
                        shake: shake(),
                        sampler: sampler.sparse().unwrap(),
                    },
                )
                .unwrap()
            }
            _ => unreachable!(),
        };
        let geometry = compiled.geometry().unwrap();
        report_geometry(
            &format!("graph-{family:?}"),
            operation,
            Some(ordinal),
            &geometry,
        );
        graph_nodes_over_budget +=
            usize::from(geometry.retained_lde_bytes > local_retained_reference);
        graph_nodes_above_local_process_lower_bound +=
            usize::from(geometry.retained_lde_bytes > local_process_reference);
        // Compilation is not validity. The invalid child proof witnesses must
        // also fail the graph predicate's actual constraint evaluation.
        assert!(compiled.evaluate().is_err());
        measured += 1;
    }
    assert!(
        measured > 0,
        "no selected composite operation exists in this fixture"
    );
    eprintln!(
        "COMPOSITE_SHAPE_RESULT {}",
        serde_json::json!({
            "graph_leaves_measured": measured, "registered_request_nodes": registrations,
            "registered_schedule_entries": plan.leaves().len(), "graph_nodes_over_32gib_retained_reference": graph_nodes_over_budget,
            "graph_nodes_above_48gib_process_lower_bound": graph_nodes_above_local_process_lower_bound,
            "maximum_shake_permutations": maximum_permutations, "native_estimate_budget_bytes": native_budget,
            "request_registration_retained_budget_bytes": outer_budget,
            "local_retained_reference_bytes": local_retained_reference,
            "local_process_reference_bytes": local_process_reference,
            "seconds": start.elapsed().as_secs_f64(),
            "native_proofs_produced": 0, "outer_proofs_produced": 0, "complete_graph_proved": false,
            "scope": "Only exact geometry from actual registered request caps and explicitly invalid native/outer proof-shaped inputs. No proof validity, source coverage, transaction or block acceptance is claimed.",
        })
    );
}
