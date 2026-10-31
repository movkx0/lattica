//! Geometry screening of exact native AIRs, never accepted proofs. These tests
//! compile deliberately invalid proof-shaped inputs without native generation
//! or program registration. First, interior and final intervals are sampled;
//! neither the other intervals nor a complete request tree are qualified.
use super::*;
use crate::{
    graph_crypto::{self, Admission, Policy, Request},
    graph_proofs::{GraphProofPlan, ResourceLimits},
    graph_tree::{self, GraphContext},
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape, Operation},
        Proof, Statement,
    },
};
use shape_diagnostic::invalid_native_template;
use std::{path::PathBuf, time::Instant};

fn sampled_indices(count: usize) -> Vec<usize> {
    assert!(count > 0);
    let mut indices = vec![0, 1.min(count - 1), count - 1];
    indices.sort_unstable();
    indices.dedup();
    indices
}

fn report(
    layout: &str,
    maximum: usize,
    request: &Request,
    index: usize,
    segments: usize,
    interval: [usize; 2],
    native: [u64; 3],
    compiled: CompiledNode,
) -> bool {
    let geometry = compiled.geometry().unwrap();
    // This is only rejection of an intentionally invalid template. It is not
    // a mutation test with an accepted native or recursive proof baseline.
    assert!(compiled.evaluate().is_err());
    let fits_row_tier = geometry.padded_rows <= 262_144;
    eprintln!(
        "CRYPTO_SEGMENT_SHAPE {}",
        serde_json::json!({
            "layout": layout, "maximum_units": maximum,
            "operation": request.operation_index(), "subrequest": request.subrequest(),
            "request_index": request.request_index(), "descriptor": format!("{:?}", request.descriptor()),
            "sampled_segment_index": index, "complete_partition_segments": segments,
            "first_unit": interval[0], "units": interval[1],
            "native_width": native[0], "native_height": native[1],
            "uncalibrated_native_peak_estimate_bytes": native[2],
            "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
            "wires": geometry.wires, "main_width": geometry.main_width,
            "preprocessed_width": geometry.preprocessed_width,
            "permutation_width_base": geometry.permutation_width_base,
            "quotient_chunks": geometry.quotient_chunks,
            "retained_lde_bytes": geometry.retained_lde_bytes,
            "fits_262144_row_tier": fits_row_tier,
            "invalid_template_rejected": true, "native_trace_generated": false,
            "native_proof_generated": false, "program_registered": false,
            "outer_proof_generated": false, "complete_request_qualified": false,
        })
    );
    fits_row_tier
}

#[test]
#[ignore = "geometry only: invalid native templates, no registration/proofs; coordinate an8GiB process guard"]
fn exact_crypto_segment_wrappers_geometry_without_registration() {
    assert_eq!(
        std::env::var("LATTICA_CRYPTO_SEGMENT_SHAPE_OPT_IN").as_deref(),
        Ok("1"),
        "explicit guarded geometry opt-in required"
    );
    let family =
        std::env::var("LATTICA_CRYPTO_SEGMENT_SHAPE_FAMILY").unwrap_or_else(|_| "all".into());
    assert!(matches!(
        family.as_str(),
        "all" | "wide-shake" | "serial-aes" | "serial-shake"
    ));
    let started = Instant::now();
    let archive = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit existing public graph fixture required"),
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
    let shape = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&shape, &graph, ResourceLimits::default()).unwrap();
    let tree = graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = GraphContext {
        context: fixture.context,
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            tree.label(),
            fixture.context,
            &fixture.statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: tree.node_manifest_hint(&graph).unwrap(),
    };
    let mut rows = 0;
    let mut within_tier = 0;
    if matches!(family.as_str(), "all" | "wide-shake") {
        let plan = graph_crypto::Plan::new(&tree, &graph, Policy::default()).unwrap();
        let request = plan
            .requests()
            .iter()
            .find(|r| {
                matches!(
                    graph.operations()[r.operation_index()],
                    Operation::HashAlpha { .. }
                )
            })
            .unwrap();
        assert_eq!(request.operation_index(), 622);
        let contract = request.contract().unwrap();
        let endpoint = request.endpoint_context_hint(&context);
        for maximum in [16, 32, 64, 128] {
            let factory = request.wide_shake(maximum, 16 << 30).unwrap();
            for index in sampled_indices(factory.segment_count()) {
                let air = &factory.segments()[index];
                let native = factory.geometry(index).unwrap();
                let artifact = crate::crypto_join::ShakeSegmentProof {
                    public_values: [Val::ZERO; shake_air::PUBLIC_VALUES],
                    proof: invalid_native_template(air, air.height),
                };
                let compiled = compile_wide_shake(
                    &contract,
                    air.first_permutation as u32,
                    air.permutations as u32,
                    &endpoint,
                    &artifact,
                )
                .unwrap();
                within_tier += usize::from(report(
                    "wide-shake",
                    maximum,
                    request,
                    index,
                    factory.segment_count(),
                    [air.first_permutation, air.permutations],
                    [
                        native.width as u64,
                        native.height as u64,
                        native.uncalibrated_peak_estimate_bytes,
                    ],
                    compiled,
                ));
                rows += 1;
            }
        }
    }
    if matches!(family.as_str(), "all" | "serial-aes") {
        for maximum in [8, 16, 32, 64] {
            let plan = graph_crypto::Plan::new(
                &tree,
                &graph,
                Policy {
                    maximum_aes_blocks: maximum,
                    maximum_shake_permutations: 8,
                    // Planning admission only: no native trace/proof is generated.
                    child_memory_budget_bytes: 64 << 30,
                    admission: Admission::Estimated,
                },
            )
            .unwrap();
            for operation in [624, 1017] {
                let request = plan
                    .requests()
                    .iter()
                    .find(|r| r.operation_index() == operation && r.subrequest() == 0)
                    .unwrap();
                let partition = request.aes_partition().unwrap();
                let contract = request.contract().unwrap();
                let endpoint = request.endpoint_context_hint(&context);
                for index in sampled_indices(partition.segments().len()) {
                    let air = &partition.segments()[index];
                    let native = &request.segments()[index];
                    let artifact = aes_lane_air::join::AesLaneSegmentProof {
                        public_values: [Val::ZERO; aes_lane_air::PUBLIC_VALUES],
                        proof: invalid_native_template(air, air.height),
                    };
                    let compiled = compile_aes(
                        &contract,
                        air.first_block as u32,
                        air.blocks as u32,
                        &endpoint,
                        &artifact,
                    )
                    .unwrap();
                    within_tier += usize::from(report(
                        "serial-aes",
                        maximum,
                        request,
                        index,
                        partition.segments().len(),
                        [air.first_block, air.blocks],
                        [
                            native.width as u64,
                            native.height as u64,
                            native.estimated_peak_bytes,
                        ],
                        compiled,
                    ));
                    rows += 1;
                }
            }
        }
    }
    if matches!(family.as_str(), "all" | "serial-shake") {
        for maximum in [8, 16, 32] {
            let plan = graph_crypto::Plan::new(
                &tree,
                &graph,
                Policy {
                    maximum_aes_blocks: 8,
                    maximum_shake_permutations: maximum,
                    child_memory_budget_bytes: 64 << 30,
                    admission: Admission::Estimated,
                },
            )
            .unwrap();
            let request = plan
                .requests()
                .iter()
                .find(|r| r.operation_index() == 622)
                .unwrap();
            let partition = request.shake_partition().unwrap();
            let contract = request.contract().unwrap();
            let endpoint = request.endpoint_context_hint(&context);
            for index in sampled_indices(partition.segments().len()) {
                let air = &partition.segments()[index];
                let native = &request.segments()[index];
                let artifact = shake_air::lane::LaneShakeProof {
                    public_values: [Val::ZERO; shake_air::PUBLIC_VALUES],
                    proof: invalid_native_template(air, air.height()),
                };
                let compiled = compile_shake_batch(
                    &contract,
                    air.first_permutation() as u32,
                    air.permutations() as u32,
                    &endpoint,
                    &artifact,
                )
                .unwrap();
                within_tier += usize::from(report(
                    "serial-shake",
                    maximum,
                    request,
                    index,
                    partition.segments().len(),
                    [air.first_permutation(), air.permutations()],
                    [
                        native.width as u64,
                        native.height as u64,
                        native.estimated_peak_bytes,
                    ],
                    compiled,
                ));
                rows += 1;
            }
        }
    }
    eprintln!(
        "CRYPTO_SEGMENT_SHAPE_SUMMARY {}",
        serde_json::json!({
            "family": family, "sampled_wrappers": rows, "within_262144_row_tier": within_tier,
            "seconds": started.elapsed().as_secs_f64(),
            "all_partition_intervals_checked": false, "request_parent_geometry_measured": false,
            "native_proofs_generated": 0, "registered_programs": 0, "outer_proofs_generated": 0,
            "source_fingerprint": crate::graph_proofs::compiled_source_fingerprint(),
        })
    );
}
