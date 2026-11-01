//! Compiler equivalence only: a registered public-only shell and deliberately
//! invalid proof template never establish request or transaction acceptance.
use super::*;
use lattica_prover_p3::{block_v2::machine::verifier::batch::shape::OperationCounts,
    proving::{Policy, Request as BackendRequest}};

fn template_key(input_len: usize) -> (NodeKey, NodeProof) {
    let contract = Contract::shake([7; 32], 3, shake_air::Descriptor { input_len, output_len: 32 }).unwrap();
    let spec = contract.span(0, contract.total).unwrap();
    let program = ProgramBuilder::new(source::PUBLICS).unwrap().finish(Some(64)).unwrap();
    let registered = RegisteredProgram::new_with_cpu_identity(
MachineAir::new(program),
512 << 20,
BackendRequest { policy: Policy::CpuRequired, emit_report: false },
).unwrap();
    let key = NodeKey { spec, height: 64, cap: registered.preprocessing_cap().roots().to_vec(),
        verifier: Arc::new(registered.verifier()) };
    let endpoints = EndpointContext { context: [11; 32], statement: [Val::ONE; 4],
        input: [Val::from_u64(13); 4], output: [Val::from_u64(17); 4] };
    let proof = NodeProof { public: header(&key.spec, &endpoints).unwrap(),
        proof: verifier::template::batch(&key.air().unwrap()).unwrap() };
    (key, proof)
}

fn compile(key: &NodeKey, proof: &NodeProof, bounded: bool) -> (Program, Vec<Val>) {
    let mut builder = ProgramBuilder::new_with_construction_limits(20, source::construction()).unwrap();
    let context = crate::obligation_manifest::ContextWires {
        profile: core::array::from_fn(|i| builder.public(i).unwrap()),
        context: core::array::from_fn(|i| builder.public(8 + i).unwrap()),
        statement: core::array::from_fn(|i| builder.public(16 + i).unwrap()),
    };
    let mut inputs = ProofInputs::default();
    let roots = if bounded {
        key.compile_manifest_record_bounded(&mut builder, &mut inputs, proof, &context)
    } else {
        key.compile_manifest_record(&mut builder, &mut inputs, proof, &context)
    }.unwrap();
    // Keep both authenticated roots live using the same consumer framing.
    for (left, right) in roots[0].into_iter().zip(roots[1]) { builder.assert_equal(left, right); }
    (builder.finish(None).unwrap(), inputs.values)
}

#[test]
fn bounded_request_manifest_verifier_matches_legacy_shape_and_inputs() {
    let (key, proof) = template_key(0);
    let (legacy, legacy_inputs) = compile(&key, &proof, false);
    let (bounded, bounded_inputs) = compile(&key, &proof, true);
    assert_eq!(OperationCounts::from_program(&legacy), OperationCounts::from_program(&bounded));
    assert_eq!(legacy.active_rows(), bounded.active_rows());
    assert_eq!(legacy.height(), bounded.height());
    assert_eq!(legacy.wire_count(), bounded.wire_count());
    assert_eq!(legacy.witness_values(), bounded.witness_values());
    assert_eq!(legacy_inputs, bounded_inputs);
    // Invalid templates are not evaluated, proven, returned as verified data,
    // or counted as native/recursive proof production by this source test.
}

#[test]
fn bounded_request_manifest_rejects_incomplete_span_before_emission() {
    let (mut key, proof) = template_key(shake_air::RATE);
    assert!(key.spec.count > 1);
    key.spec.count -= 1;
    let mut builder = ProgramBuilder::new_with_construction_limits(20, source::construction()).unwrap();
    let context = crate::obligation_manifest::ContextWires {
        profile: core::array::from_fn(|i| builder.public(i).unwrap()),
        context: core::array::from_fn(|i| builder.public(8 + i).unwrap()),
        statement: core::array::from_fn(|i| builder.public(16 + i).unwrap()),
    };
    let mut inputs = ProofInputs::default();
    assert!(key.compile_manifest_record_bounded(&mut builder, &mut inputs, &proof, &context).is_err());
    assert!(inputs.values.is_empty());
}
