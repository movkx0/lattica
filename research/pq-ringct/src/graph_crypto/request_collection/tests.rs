use super::*;
use crate::{
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{
        Admission, NativeProductionPlan, Payload, RequestDescriptor, ShakeWrapperLayout,
    },
    rust_verify::{
        committed_backend::{CommittedBackend, Source},
        generic::{Backend, GStatement},
    },
};
use std::panic::{catch_unwind, AssertUnwindSafe};

const PROFILE: [u8; 32] = [71; 32];

#[derive(Clone, Copy)]
enum Shape {
    Complete,
    MissingPp,
    MissingAlpha,
    MissingX,
    RepeatedPp,
    RepeatedAlpha,
    ReorderedX,
    TooManyParts,
}

// Builds only immutable graph hints, never a native proof. The transcript
// lengths match the full reference profile while repeated fixed polynomials
// keep this source fixture small. It is not a valid transaction statement.
fn graph(shape: Shape, seed_byte: u8) -> UnprovedRelationGraph {
    let setup = [seed_byte; 32];
    let mut backend = CommittedBackend::new(setup);
    let seed = backend.import_bytes(setup, Source::StatementSeed);
    let context = backend.import_bytes([17; 32], Source::Context);
    let pp = if matches!(shape, Shape::MissingPp) {
        context
    } else {
        backend.parameters(&seed, &context).unwrap().pp
    };
    if matches!(shape, Shape::RepeatedPp) {
        backend.parameters(&seed, &context).unwrap();
    }
    let q = [backend.constant(23, Q); D];
    let qhat = [backend.constant(QHAT - 1, QHAT); D];
    let statement = GStatement {
        seed,
        ring: Vec::new(),
        recipients: vec![vec![
            q;
            if matches!(shape, Shape::TooManyParts) {
                256
            } else {
                222
            }
        ]],
        coins: Vec::new(),
        serials: [context, seed],
    };
    if matches!(shape, Shape::ReorderedX) {
        backend
            .hash_x(&pp, &q, &q, &[qhat; 4], &[qhat; 4], &[q; 6])
            .unwrap();
    }
    let alpha = if matches!(shape, Shape::MissingAlpha) {
        pp
    } else {
        backend.hash_alpha(&pp, &statement, &[], &[], &[], &q, &q, &q, &[], &[])
    };
    if matches!(shape, Shape::RepeatedAlpha) {
        backend.hash_alpha(&pp, &statement, &[], &[], &[], &q, &q, &q, &[], &[]);
    }
    if !matches!(shape, Shape::MissingX) {
        backend
            .hash_x(&alpha, &q, &q, &[qhat; 4], &[qhat; 4], &[q; 6])
            .unwrap();
    }
    backend.into_unproved_graph()
}

fn ledger(host: u64) -> Ledger {
    Ledger::new(WorkerAllowance { host, device: 0 })
}

fn plan(graph: &UnprovedRelationGraph, maximum: usize) -> GraphShakeCollectionPlan<'_> {
    GraphShakeCollectionPlan::new(
        PROFILE,
        graph,
        Policy {
            maximum_shake_permutations: maximum,
            admission: Admission::Estimated,
            ..Policy::default()
        },
    )
    .unwrap()
}

fn reference_bytes(graph: &UnprovedRelationGraph, operation: usize) -> Vec<u8> {
    match &graph.operations()[operation] {
        Operation::ParametersPp {
            setup_seed,
            context,
            ..
        } => crate::transcript_bridge::pp_input_bytes(
            setup_seed,
            &graph.byte_string(*context).values,
        ),
        operation => {
            let (air, values, _) =
                crate::transcript_air::TranscriptAir::from_graph_operation(graph, operation)
                    .unwrap();
            air.serialize(&values).unwrap()
        }
    }
}

#[test]
fn all_three_requests_match_reference_serialization_identity_and_partition() {
    for seed in [29, 31] {
        let graph = graph(Shape::Complete, seed);
        for maximum in [1, 8, 64] {
            let plan = plan(&graph, maximum);
            let entries = plan.entries;
            let policy = plan.policy;
            let bounds = plan.bounds();
            assert_eq!(bounds.input_bytes, [PP_INPUT_BYTES, 230496, 16416]);
            assert_eq!(bounds.serialization_buffer_bytes, 230496);
            if maximum == 8 {
                assert_eq!(bounds.native_segments.iter().sum::<usize>(), 232);
            }
            let ledger = ledger(bounds.admitted_bytes);
            let token = ledger.admit_phase(plan.requirements()).unwrap();
            let retained = plan.retained_requirements();
            let collection = plan.construct(token, &ledger).unwrap();
            assert_eq!(collection.bounds(), bounds);
            assert!(collection.belongs_to(&ledger));
            assert_eq!(ledger.snapshot().current, retained.total().unwrap());
            assert_eq!(ledger.snapshot().peak.host, bounds.admitted_bytes);
            assert_eq!(
                bounds.admitted_bytes - bounds.retained_bytes,
                bounds.serialization_temporary_bytes as u64
            );
            for entry in entries {
                let bytes = reference_bytes(&graph, entry.operation);
                let expected = Request::new(
                    PROFILE,
                    entry.operation,
                    0,
                    RequestDescriptor::Shake(crate::shake_air::Descriptor {
                        input_len: bytes.len(),
                        output_len: entry.kind.output_len(),
                    }),
                    Payload::Shake(bytes),
                    policy,
                )
                .unwrap();
                let request = collection.request_for(&graph, PROFILE, entry.kind).unwrap();
                let (Payload::Shake(actual), Payload::Shake(expected_bytes)) =
                    (&request.payload, &expected.payload)
                else {
                    panic!("closed SHAKE payloads");
                };
                assert_eq!(actual, expected_bytes);
                assert_eq!(request.profile, PROFILE);
                assert_eq!(request.operation_index(), entry.operation);
                assert_eq!(request.subrequest(), 0);
                assert_eq!(request.request_index(), expected.request_index());
                assert_eq!(request.descriptor(), expected.descriptor());
                assert_eq!(request.segments(), expected.segments());
                assert_eq!(
                    request.cache_key(0).unwrap(),
                    expected.cache_key(0).unwrap()
                );
                assert_eq!(
                    request.cache_key(request.segments().len() - 1).unwrap(),
                    expected.cache_key(expected.segments().len() - 1).unwrap()
                );
            }
            drop(collection);
            assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        }
    }
}

#[test]
fn missing_repeated_reordered_and_oversized_transcripts_refuse_during_planning() {
    for (shape, expected) in [
        (Shape::MissingPp, Error::RequestOrder),
        (Shape::MissingAlpha, Error::RequestOrder),
        (Shape::MissingX, Error::MissingRequest),
        (Shape::RepeatedPp, Error::RequestOrder),
        (Shape::RepeatedAlpha, Error::RequestOrder),
        (Shape::ReorderedX, Error::RequestOrder),
        (Shape::TooManyParts, Error::TranscriptParts),
    ] {
        let graph = graph(shape, 29);
        assert_eq!(
            GraphShakeCollectionPlan::new(PROFILE, &graph, Policy::default()).err(),
            Some(expected)
        );
    }
    let empty = CommittedBackend::new([29; 32]).into_unproved_graph();
    assert_eq!(
        GraphShakeCollectionPlan::new(PROFILE, &empty, Policy::default()).err(),
        Some(Error::MissingRequest)
    );
}

#[test]
fn canonicality_setup_operation_and_arithmetic_failures_are_fixed_errors() {
    let bad = PolynomialValues::Canonical([Q; D]);
    assert_eq!(
        canonical_values(PolynomialKind::Canonical { modulus: Q }, &bad).err(),
        Some(Error::Noncanonical)
    );
    let too_wide = PolynomialValues::Canonical([u64::MAX; D]);
    assert_eq!(
        canonical_values(PolynomialKind::Canonical { modulus: QHAT }, &too_wide).err(),
        Some(Error::Noncanonical)
    );
    let signed = PolynomialValues::Signed([0; D]);
    assert_eq!(
        canonical_values(PolynomialKind::Canonical { modulus: Q }, &signed).err(),
        Some(Error::PolynomialKind)
    );
    assert_eq!(
        canonical_values(PolynomialKind::Signed { bound: 1 }, &signed).err(),
        Some(Error::PolynomialKind)
    );
    assert_eq!(
        canonical_values(PolynomialKind::Canonical { modulus: 1 }, &bad).err(),
        Some(Error::PolynomialKind)
    );
    assert_eq!(add(usize::MAX, 1), Err(Error::Overflow));
    let mut huge = Requirements::single(
        Category::CompilerInputs,
        Bytes {
            host: u64::MAX,
            device: 0,
        },
    );
    assert_eq!(
        combine(
            &mut huge,
            Requirements::single(Category::RegisteredMetadata, Bytes { host: 1, device: 0 })
        ),
        Err(Error::Overflow)
    );

    let graph = graph(Shape::Complete, 29);
    let plan = plan(&graph, 8);
    let Operation::ParametersPp {
        context, output, ..
    } = &graph.operations()[plan.entries[0].operation]
    else {
        unreachable!()
    };
    let changed = Operation::ParametersPp {
        setup_seed: [1; 32],
        context: *context,
        output: *output,
    };
    assert_eq!(source_length(&graph, &changed), Err(Error::SetupIdentity));
    let mut entry = plan.entries[1];
    entry.operation = plan.entries[0].operation;
    let mut output = Vec::with_capacity(entry.input_len);
    assert_eq!(
        serialize(&graph, entry, &mut output),
        Err(Error::SourceChanged)
    );
    assert!(output.is_empty());
}

#[test]
fn exact_tokens_and_query_bindings_preserve_complete_collection_charge() {
    let graph = graph(Shape::Complete, 29);
    let foreign_graph = CommittedBackend::new([29; 32]).into_unproved_graph();
    let bytes = plan(&graph, 8).bounds().admitted_bytes;
    let insufficient = ledger(bytes - 1);
    assert!(insufficient
        .admit_phase(plan(&graph, 8).requirements())
        .is_err());
    assert_eq!(insufficient.snapshot().current, Bytes::ZERO);
    let ledger = ledger(bytes + 1);
    let foreign = self::ledger(bytes + 1);
    for variant in 0..3 {
        let plan = plan(&graph, 8);
        let token = match variant {
            0 => foreign.admit_phase(plan.requirements()).unwrap(),
            1 => ledger
                .reserve(Category::CompilerInputs, Bytes { host: 1, device: 0 })
                .unwrap(),
            _ => {
                let mut required = plan.requirements();
                required
                    .add(Category::CompilerInputs, Bytes { host: 1, device: 0 })
                    .unwrap();
                ledger.admit_phase(required).unwrap()
            }
        };
        assert_eq!(
            plan.construct(token, &ledger).err(),
            Some(if variant == 0 {
                Error::WrongLedger
            } else {
                Error::WrongReservation
            })
        );
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    }
    for allowance in [
        WorkerAllowance {
            host: (32 << 30) + 1,
            device: 0,
        },
        WorkerAllowance {
            host: 8 << 30,
            device: (8 << 30) + 1,
        },
    ] {
        let oversized = Ledger::new(allowance);
        let plan = plan(&graph, 8);
        let token = oversized.admit_phase(plan.requirements()).unwrap();
        assert_eq!(
            plan.construct(token, &oversized).err(),
            Some(Error::WrongReservation)
        );
        assert_eq!(oversized.snapshot().current, Bytes::ZERO);
    }
    let plan = plan(&graph, 8);
    let retained = plan.retained_requirements().total().unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    let collection = plan.construct(token, &ledger).unwrap();
    assert_eq!(
        collection
            .request_for(&foreign_graph, PROFILE, Kind::HashAlpha)
            .err(),
        Some(Error::SourceIdentity)
    );
    assert_eq!(
        collection
            .request_for(&graph, [72; 32], Kind::HashAlpha)
            .err(),
        Some(Error::ProfileIdentity)
    );
    assert_eq!(ledger.snapshot().current, retained);
    drop(collection);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn partial_construction_failure_and_unwind_destroy_requests_before_release() {
    let graph = graph(Shape::Complete, 29);
    let ledger = ledger(8 << 30);
    for failure in 0..2 {
        let mut plan = plan(&graph, 8);
        let bytes = plan.bounds().admitted_bytes;
        let token = ledger.admit_phase(plan.requirements()).unwrap();
        // Test-only corruption forces refusal after the ParametersPp request
        // already exists. No production callback or unchecked constructor.
        if failure == 0 {
            plan.entries[1].input_len -= 1;
        } else {
            plan.entries[1].operation = plan.entries[0].operation;
        }
        assert_eq!(
            plan.construct(token, &ledger).err(),
            Some(Error::SourceChanged)
        );
        assert_eq!(ledger.snapshot().peak.host, bytes);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    let failed = catch_unwind(AssertUnwindSafe(|| {
        let plan = plan(&graph, 8);
        let token = ledger.admit_phase(plan.requirements()).unwrap();
        let _collection = plan.construct(token, &ledger).unwrap();
        panic!("injected owner abandonment");
    }));
    assert!(failed.is_err());
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn native_and_compiler_borrows_remain_tied_to_the_collection() {
    let graph = graph(Shape::Complete, 29);
    let ledger = ledger(8 << 30);
    let plan = plan(&graph, 1);
    let retained = plan.retained_requirements().total().unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    let collection = plan.construct(token, &ledger).unwrap();
    let request = collection
        .request_for(&graph, PROFILE, Kind::HashX)
        .unwrap();
    let production = NativeProductionPlan::new(request, 0).unwrap();
    let token = ledger.admit_phase(production.requirement()).unwrap();
    let pending = production.claim_for(request, 0, token, &ledger).unwrap();
    let compiler = crate::component_tree::owned_shake::GroupCompilePlan::new(
        request,
        ShakeWrapperLayout::PairedV1,
        0,
        crate::component_tree::EndpointContext {
            context: [0; 32],
            statement: Default::default(),
            input: Default::default(),
            output: Default::default(),
        },
    )
    .unwrap();
    let compile_charge = ledger.admit_phase(compiler.requirements()).unwrap();
    assert!(ledger.snapshot().current.host > retained.host);
    drop(compile_charge);
    drop(compiler);
    drop(pending);
    assert_eq!(ledger.snapshot().current, retained);
    drop(collection);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[cfg(feature = "native-verification-allocation-audit")]
#[test]
#[ignore = "process-wide allocation observer; serialized guarded qualification required"]
fn collection_allocation_requests_fit_preceding_bound_and_failure_cleanup() {
    use crate::component_tree::shake_verification_memory::observe_planner_allocations;
    assert_eq!(
        std::env::var("LATTICA_SHAKE_COLLECTION_QUALIFICATION").as_deref(),
        Ok("1")
    );
    let graph = graph(Shape::Complete, 29);
    let foreign_graph = CommittedBackend::new([29; 32]).into_unproved_graph();
    let ledger = ledger(8 << 30);
    for maximum in [1, 8, 64] {
        let plan = observe_planner_allocations(0, || plan(&graph, maximum));
        let bounds = plan.bounds();
        let token = ledger.admit_phase(plan.requirements()).unwrap();
        let collection = observe_planner_allocations(bounds.admitted_bytes as usize, || {
            plan.construct(token, &ledger)
        })
        .unwrap();
        assert_eq!(ledger.snapshot().current.host, bounds.retained_bytes);
        observe_planner_allocations(0, || {
            assert_eq!(
                collection
                    .request_for(&foreign_graph, PROFILE, Kind::HashX)
                    .err(),
                Some(Error::SourceIdentity)
            );
            assert_eq!(
                collection.request_for(&graph, [72; 32], Kind::HashX).err(),
                Some(Error::ProfileIdentity)
            );
        });
        drop(collection);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    let mut plan = self::plan(&graph, 8);
    let bound = plan.bounds().admitted_bytes as usize;
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    plan.entries[1].input_len -= 1;
    let failed = observe_planner_allocations(bound, || plan.construct(token, &ledger));
    assert_eq!(failed.err(), Some(Error::SourceChanged));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    let plan = self::plan(&graph, 8);
    let token = ledger
        .reserve(Category::CompilerInputs, Bytes { host: 1, device: 0 })
        .unwrap();
    let failed = observe_planner_allocations(0, || plan.construct(token, &ledger));
    assert_eq!(failed.err(), Some(Error::WrongReservation));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[cfg(feature = "native-matrict")]
#[test]
#[ignore = "full graph fixture and unchanged reference Plan; serialized process guard required"]
fn full_graph_collection_matches_unchanged_seven_request_plan() {
    assert_eq!(
        std::env::var("LATTICA_SHAKE_COLLECTION_QUALIFICATION").as_deref(),
        Ok("1")
    );
    // Existing shared fixture honors the archived-public-fixture environment.
    // Graph construction, source verification and the reference Plan are
    // independently process guarded, outside the collection's admitted scope.
    let (graph, tree, _) = crate::graph_crypto::tests::fixture();
    let reference = crate::graph_crypto::Plan::new(&tree, &graph, Policy::default()).unwrap();
    assert_eq!(reference.requests().len(), 7);
    let references = reference
        .requests()
        .iter()
        .filter(|request| matches!(request.descriptor(), RequestDescriptor::Shake(_)));
    assert_eq!(references.clone().count(), COUNT);
    let plan = GraphShakeCollectionPlan::new(tree.label(), &graph, Policy::default()).unwrap();
    assert_eq!(plan.bounds().input_bytes, [PP_INPUT_BYTES, 230496, 16416]);
    let reference_segments = references
        .clone()
        .map(|request| request.segments().len())
        .sum::<usize>();
    assert_eq!(
        plan.bounds().native_segments.iter().sum::<usize>(),
        reference_segments
    );
    eprintln!(
        "graph_shake_collection_reference requests=3 input_bytes={:?} native_segment_counts={:?} native_segments={} maximum_shake_permutations={} source_and_reference_external=true outer_proofs_started=false gpu_work=false",
        plan.bounds().input_bytes, plan.bounds().native_segments, reference_segments,
        Policy::default().maximum_shake_permutations,
    );
    let ledger = ledger(8 << 30);
    let retained = plan.retained_requirements().total().unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    let collection = plan.construct(token, &ledger).unwrap();
    for (kind, expected) in Kind::ALL.into_iter().zip(references) {
        let actual = collection.request_for(&graph, tree.label(), kind).unwrap();
        assert_eq!(actual.profile, expected.profile);
        assert_eq!(actual.operation_index(), expected.operation_index());
        assert_eq!(actual.subrequest(), expected.subrequest());
        assert_eq!(actual.request_index(), expected.request_index());
        assert_eq!(actual.descriptor(), expected.descriptor());
        assert_eq!(actual.segments(), expected.segments());
        let (Payload::Shake(actual_bytes), Payload::Shake(expected_bytes)) =
            (&actual.payload, &expected.payload)
        else {
            panic!("selected SHAKE requests");
        };
        assert_eq!(actual_bytes, expected_bytes);
        for index in 0..actual.segments().len() {
            assert_eq!(
                actual.cache_key(index).unwrap(),
                expected.cache_key(index).unwrap()
            );
        }
    }
    assert_eq!(ledger.snapshot().current, retained);
    drop(collection);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
