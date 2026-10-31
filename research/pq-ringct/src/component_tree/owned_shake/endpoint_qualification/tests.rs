use super::*;
use crate::{
    component_tree::{
        owned_shake::{GroupCompilePlan, Summary},
        EndpointContext, CONTEXT, EXPECTED_INPUT, EXPECTED_OUTPUT, HEADER, STATEMENT,
    },
    execution::{phase_lifecycle::Status, retained_resources::WorkerAllowance, ProvingContext},
    graph_crypto::{
        NativeProductionPlan, Policy, ShakeRequestPlan, ShakeWrapperLayout,
    },
    shake_air::{self, PUBLIC_VALUES},
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256, Shake256Reader,
};

struct Fixture {
    input: [u8; 137],
    output: [u8; 137],
    endpoints: EndpointContext,
    _reservation: Reservation,
}

impl Fixture {
    fn requirements() -> super::super::Requirements {
        // Stack-backed source, XOF state, commitments and the two captured
        // native public arrays (including copy/move overlap). No input/output
        // Vec is allocated. The exact copied request has its separate owner.
        let bytes = size_of::<Self>()
            + 2 * size_of::<Shake256>()
            + 2 * size_of::<Shake256Reader>()
            + 2 * size_of::<[u8; 137]>()
            + 4 * size_of::<[Val; PUBLIC_VALUES]>()
            + 2 * size_of::<[usize; 3]>()
            + POSEIDON_BYTES;
        requirement(Category::PhaseScratch, bytes).unwrap()
    }

    fn new(ledger: &Ledger) -> Self {
        let reservation = ledger.admit_phase(Self::requirements()).unwrap();
        let input = [31; 137];
        let mut output = [0; 137];
        let mut xof = Shake256::default();
        xof.update(&input);
        xof.finalize_xof().read(&mut output);
        let endpoints = EndpointContext {
            // Context/statement are explicit framing placeholders. Only the
            // request byte roots below are derived/authenticated in this test.
            context: [17; 32],
            statement: [Val::from_u64(19); 4],
            input: shake_air::commit_bytes(shake_air::SHAKE_INPUT_DOMAIN, &input),
            output: shake_air::commit_bytes(shake_air::SHAKE_OUTPUT_DOMAIN, &output),
        };
        Self {
            input,
            output,
            endpoints,
            _reservation: reservation,
        }
    }
}

fn rejected(result: Result<(), Error>) {
    assert_eq!(result, Err(Error::Execution(ExecutionError::Unsatisfied)));
}

#[test]
fn evaluation_geometry_refuses_unsupported_rows_wires_and_overflow() {
    let scratch = Scratch::for_geometry(3_004_067, 262_144).unwrap();
    assert_eq!(scratch.wire_bytes, 3_004_067 * size_of::<Val>());
    assert_eq!(scratch.trace_bytes, 262_144 * WIDTH * size_of::<Val>());
    assert_eq!(
        scratch.total_bytes,
        scratch.wire_bytes + scratch.trace_bytes + scratch.helper_bytes
    );
    for (wires, rows) in [
        (0, 0),
        (1, 7),
        (1, 9),
        (1, MAX_ROWS * 2),
        (MAX_WIRES + 1, 8),
        (usize::MAX, 8),
        (1, usize::MAX),
    ] {
        assert_eq!(Scratch::for_geometry(wires, rows), Err(Error::Geometry));
    }
    assert!(
        Scratch::for_geometry(MAX_WIRES, MAX_ROWS)
            .unwrap()
            .total_bytes
            < 32usize << 30
    );
}

#[test]
fn source_roots_come_from_reserved_exact_immutable_bytes() {
    let ledger = Ledger::new(WorkerAllowance {
        host: 1 << 20,
        device: 0,
    });
    let fixture = Fixture::new(&ledger);
    assert_eq!(
        fixture.endpoints.input,
        shake_air::commit_bytes(shake_air::SHAKE_INPUT_DOMAIN, &fixture.input)
    );
    assert_eq!(
        fixture.endpoints.output,
        shake_air::commit_bytes(shake_air::SHAKE_OUTPUT_DOMAIN, &fixture.output)
    );
    assert_eq!(
        ledger.snapshot().current,
        Fixture::requirements().total().unwrap()
    );
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

fn check_admission(output: &mut OwnedCompiledShake<'_>, ledger: &Ledger) {
    let before = ledger.snapshot().current;
    let foreign = Ledger::new(WorkerAllowance {
        host: 8 << 30,
        device: 0,
    });
    assert!(matches!(
        Evaluator::new(output, &foreign),
        Err(Error::Authority)
    ));
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    let scratch = Scratch::for_geometry(
        output.compiled.program.wire_count(),
        output.compiled.program.height(),
    )
    .unwrap();
    let remaining = ledger.snapshot().allowance.host - before.host;
    let blocker = ledger
        .admit_phase(
            requirement(
                Category::RegisteredMetadata,
                remaining as usize - scratch.total_bytes + 1,
            )
            .unwrap(),
        )
        .unwrap();
    let blocked = ledger.snapshot().current;
    assert!(matches!(
        Evaluator::new(output, ledger),
        Err(Error::Admission)
    ));
    assert_eq!(ledger.snapshot().current, blocked);
    drop(blocker);
    // Exact remaining admission succeeds, including retained output/source
    // storage. No separate evaluation allowance is added to this worker.
    let blocker = ledger
        .admit_phase(
            requirement(
                Category::RegisteredMetadata,
                remaining as usize - scratch.total_bytes,
            )
            .unwrap(),
        )
        .unwrap();
    let mut evaluator = Evaluator::new(output, ledger).unwrap();
    assert_eq!(
        ledger.snapshot().current.host,
        ledger.snapshot().allowance.host
    );
    assert_eq!(evaluator.run(), Ok(()));
    rejected(evaluator.changed_public(0));
    drop(evaluator);
    drop(blocker);
    assert_eq!(ledger.snapshot().current, before);
}

fn check_header(evaluator: &mut Evaluator<'_, '_>) -> usize {
    // Every profile word, pinned descriptor/interval field and compressed
    // endpoint root is constrained in each singleton/pair/tail wrapper.
    let mut mutations = 0;
    for index in (0..8).chain(28..HEADER + 8) {
        rejected(evaluator.changed_public(index));
        mutations += 1;
    }
    let spec = &evaluator.output.compiled.spec;
    let final_boundary = spec.end() == spec.contract.total;
    if final_boundary {
        for index in EXPECTED_INPUT..EXPECTED_OUTPUT + 4 {
            rejected(evaluator.changed_public(index));
            mutations += 1;
        }
    } else {
        // A nonfinal group makes no claim about final roots. They are joined
        // through the complete request tree, whose final node enforces them.
        assert_eq!(evaluator.changed_public(EXPECTED_INPUT), Ok(()));
        assert_eq!(evaluator.changed_public(EXPECTED_OUTPUT), Ok(()));
    }
    // This component alone does not authenticate transaction context/statement.
    assert_eq!(evaluator.changed_public(CONTEXT), Ok(()));
    assert_eq!(evaluator.changed_public(STATEMENT), Ok(()));
    mutations
}

fn check_boundary(evaluator: &mut Evaluator<'_, '_>, input_offset: usize, start: bool) -> usize {
    let offsets = if start {
        [
            (shake_air::START_STATE, 100),
            (shake_air::INPUT_START, 4),
            (shake_air::OUTPUT_START, 4),
        ]
    } else {
        [
            (shake_air::END_STATE, 100),
            (shake_air::INPUT_END, 4),
            (shake_air::OUTPUT_END, 4),
        ]
    };
    let mut mutations = 0;
    for (offset, width) in offsets {
        for index in offset..offset + width {
            rejected(evaluator.changed_witness(input_offset + index));
            mutations += 1;
        }
    }
    assert_eq!(mutations, 108);
    mutations
}

#[test]
#[ignore = "six fresh native CPU proofs plus compiled constraint/mutation evaluation; serialized process guard required"]
fn valid_source_singletons_pair_and_odd_tail_satisfy_constraints_and_reject_mutations() {
    assert_eq!(
        std::env::var("LATTICA_SHAKE_ENDPOINT_QUALIFICATION").as_deref(),
        Ok("1"),
        "requires explicit serialized process-guarded endpoint correctness qualification"
    );
    let context = ProvingContext::cpu(8 << 30).unwrap();
    let mut capability = context.endpoint_qualification_capability().unwrap();
    let ledger = capability.ledger().clone();
    let fixture = Fixture::new(&ledger);
    let fixture_bytes = Fixture::requirements().total().unwrap();
    let request_plan = ShakeRequestPlan::new(
        [7; 32],
        0,
        0,
        &fixture.input,
        fixture.output.len(),
        Policy {
            maximum_shake_permutations: 1,
            ..Policy::default()
        },
    )
    .unwrap();
    let request_requirements = request_plan.requirements();
    let token = ledger.admit_phase(request_requirements).unwrap();
    let request_owner = request_plan.construct(token, &ledger).unwrap();
    assert!(request_owner.belongs_to(&ledger));
    let request = request_owner.request();
    assert_eq!(request.segments().len(), 3);
    let mut singleton_inputs = [0; 3];
    let mut fresh_native_proofs = 0;
    for (layout, ordinal) in [
        (ShakeWrapperLayout::Singleton, 0),
        (ShakeWrapperLayout::Singleton, 1),
        (ShakeWrapperLayout::Singleton, 2),
        (ShakeWrapperLayout::PairedV1, 0),
        (ShakeWrapperLayout::PairedV1, 1),
    ] {
        let plan =
            GroupCompilePlan::new(request, layout, ordinal, fixture.endpoints.clone()).unwrap();
        let span = plan.span();
        let requirements = plan.requirements();
        let children: [Option<crate::graph_crypto::ReservedNativeChild<'_>>; 2] =
            core::array::from_fn(|offset| {
                if offset >= span.segment_count {
                    return None;
                }
                let index = span.first_segment + offset;
                let native = NativeProductionPlan::new(request, index).unwrap();
                let token = ledger.admit_phase(native.requirement()).unwrap();
                fresh_native_proofs += 1;
                Some(
                    native
                        .claim_for(request, index, token, &ledger)
                        .unwrap()
                        .produce_cpu_fixture()
                        .unwrap(),
                )
            });
        // Fixed copied public values identify the exact native-input offsets
        // without rebuilding/retaining a second compiler or cloning a proof.
        let child_public: [[Val; PUBLIC_VALUES]; 2] =
            core::array::from_fn(
                |index| match children[index].as_ref().map(|c| c.shake_artifact()) {
                    Some(proof) => proof.public_values,
                    None => [Val::ZERO; PUBLIC_VALUES],
                },
            );
        let mut output = capability
            .compile_shake_endpoint_qualification(plan, children)
            .unwrap();
        let summary: Summary = output.summary();
        assert_eq!(summary.independent_native_verifications, span.segment_count);
        assert_eq!(capability.status(), Status::Ready);
        let retained = ledger.snapshot().current;
        assert_eq!(
            retained.host,
            fixture_bytes.host
                + request_requirements.total().unwrap().host
                + requirements.get(Category::SymbolicCompiler).host
                + requirements.get(Category::CompilerInputs).host
                + requirements.get(Category::Report).host
        );
        for category in [Category::NativeProof, Category::IndependentVerifier] {
            assert_eq!(
                ledger.snapshot().categories[category as usize].current,
                Bytes::ZERO
            );
        }
        assert_eq!(
            ledger.snapshot().categories[Category::PhaseScratch as usize].current,
            fixture_bytes
        );
        if layout == ShakeWrapperLayout::Singleton {
            singleton_inputs[ordinal] = summary.input_values;
        }
        if layout == ShakeWrapperLayout::Singleton && ordinal == 0 {
            check_admission(&mut output, &ledger);
        }
        let mut evaluator = Evaluator::new(&mut output, &ledger).unwrap();
        assert_eq!(
            ledger.snapshot().current.host,
            retained.host + evaluator.scratch.total_bytes as u64
        );
        assert_eq!(
            evaluator.run(),
            Ok(()),
            "valid source layout={layout:?} ordinal={ordinal}"
        );
        let header_mutations = check_header(&mut evaluator);
        assert_eq!(
            evaluator.output.compiled.witness[..PUBLIC_VALUES],
            child_public[0]
        );
        rejected(evaluator.changed_witness(PUBLIC_VALUES));
        assert_eq!(
            evaluator.run_witness_prefix(summary.input_values - 1),
            Err(Error::Execution(ExecutionError::WitnessCount))
        );
        let mut boundary_mutations = 0;
        if span.segment_count == 2 {
            assert_eq!(singleton_inputs[0], singleton_inputs[1]);
            let second = singleton_inputs[0];
            assert_eq!(summary.input_values, second + singleton_inputs[1]);
            assert_eq!(
                evaluator.output.compiled.witness[second..second + PUBLIC_VALUES],
                child_public[1]
            );
            rejected(evaluator.changed_witness(second + PUBLIC_VALUES));
            assert_eq!(
                evaluator.run_witness_prefix(second),
                Err(Error::Execution(ExecutionError::WitnessCount))
            );
            rejected(evaluator.reordered_pair(second));
            boundary_mutations += check_boundary(&mut evaluator, 0, false);
            boundary_mutations += check_boundary(&mut evaluator, second, true);
        } else if layout == ShakeWrapperLayout::PairedV1 {
            assert_eq!(summary.input_values, singleton_inputs[2]);
            // The odd tail starts with the padding segment's final state and
            // crosses the squeezing transition. Check all 108 start fields.
            boundary_mutations += check_boundary(&mut evaluator, 0, true);
        }
        assert_eq!(evaluator.run(), Ok(()), "every temporary mutation restored");
        eprintln!("shake_endpoint_constraints layout={layout:?} ordinal={ordinal} members={} active_rows={} padded_rows={} wires={} inputs={} retained_program_bytes={} retained_input_bytes={} evaluation_wire_bytes={} evaluation_trace_bytes={} evaluation_helper_bytes={} evaluation_required_bytes={} rejected_header_mutations={header_mutations} rejected_boundary_mutations={boundary_mutations} actual_compiler_phase_cleanup=true constraints_satisfied=true outer_proofs_started=false gpu_work=false transaction_context_authenticated=false",
            span.segment_count, summary.active_rows, summary.padded_rows, summary.wires, summary.input_values,
            evaluator.retained_program_bytes, evaluator.retained_input_bytes, evaluator.scratch.wire_bytes,
            evaluator.scratch.trace_bytes, evaluator.scratch.helper_bytes, evaluator.scratch.total_bytes);
        drop(evaluator);
        assert_eq!(ledger.snapshot().current, retained);
        drop(output);
        assert_eq!(
            ledger.snapshot().current.host,
            fixture_bytes.host + request_requirements.total().unwrap().host
        );
    }
    assert_eq!(fresh_native_proofs, 6);
    drop(request_owner);
    assert_eq!(ledger.snapshot().current, fixture_bytes);
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    capability.retire().unwrap();
    assert_eq!(capability.status(), Status::Retired);
    eprintln!("shake_endpoint_constraints_complete fresh_native_proofs={fresh_native_proofs} compiled_wrappers=5 full_ledger_cleanup=true recursive_proofs=0 gpu_work=false");
}

#[cfg(all(feature = "recursive-wide", not(feature = "opencl")))]
mod recursive_preflight;

#[cfg(all(
    feature = "native-verification-allocation-audit",
    not(feature = "opencl")
))]
mod exact_retention;
