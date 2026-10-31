//! A pair of byte proofs followed by an aggregate-plus-byte merge. This diagnostic
//! exercises real recursion but never constructs a MatRiCT graph key.
use super::{event, persist, read, require, Result, FILE_LIMIT};
use lattica_pq_ringct_research::opencl::{strict_request, Limits, Session};
use lattica_prover_p3::block_v2::{
    machine::{
        backend::{RegisteredProgram, RegisteredVerifier},
        pq_bytes::Byte,
        program::Val,
        verifier::{self, ProofInputs},
        ExecutionError, MachineAir, Program, ProgramBuilder, WIDTH,
    },
    profile::{Challenge, Config},
};
use p3_batch_stark::BatchProof;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use serde_json::{json, Value};
use std::{path::Path, time::Instant};

struct Node {
    height: usize,
    cap: Vec<[Val; 4]>,
    key: RegisteredVerifier,
    public: Vec<Val>,
    proof: BatchProof<Config>,
}
fn opening(proof: &mut BatchProof<Config>) -> Result<&mut Challenge> {
    proof
        .opened_values
        .instances
        .first_mut()
        .and_then(|i| i.base_opened_values.trace_local.first_mut())
        .ok_or_else(|| "diagnostic proof lacks trace opening".into())
}
fn prove(
    session: &Session,
    program: Program,
    public: Vec<Val>,
    witness: Vec<Val>,
    depth: usize,
) -> Result<(Node, Value)> {
    let rows = program.height();
    session.check_rows(rows)?;
    let started = Instant::now();
    let registered = RegisteredProgram::new_with_request(
        MachineAir::new(program),
        session.limits().host_bytes,
        strict_request(),
    )
    .map_err(|e| format!("diagnostic registration failed: {e:?}"))?;
    let mut proof = registered
        .prove_with_request(&public, &witness, strict_request())
        .map_err(|e| format!("diagnostic proving failed: {e:?}"))?;
    let key = registered.verifier();
    let cap = registered.preprocessing_cap().roots().to_vec();
    drop(registered);
    key.verify(&proof, &public)?;
    for index in 0..public.len() {
        let mut wrong = public.clone();
        wrong[index] += Val::ONE;
        require(
            key.verify(&proof, &wrong).is_err(),
            "changed diagnostic public value accepted",
        )?;
    }
    let old = *opening(&mut proof)?;
    *opening(&mut proof)? += Challenge::ONE;
    let rejected = key.verify(&proof, &public).is_err();
    *opening(&mut proof)? = old;
    require(rejected, "changed diagnostic proof opening accepted")?;
    key.verify(&proof, &public)?;
    let report = json!({"depth":depth,"rows":rows,"seconds":started.elapsed().as_secs_f64(),
        "strict_gpu_request":true,"actual_stark_proof":true,"cpu_verification":true,
        "changed_public_rejected":true,"changed_public_rejected_count":public.len(),"changed_proof_rejected":true,
        "prepared_proving_state_dropped":true});
    event("diagnostic_layer_verified", report.clone());
    Ok((
        Node {
            height: rows,
            cap,
            key,
            public,
            proof,
        },
        report,
    ))
}
fn pair(
    children: [&Node; 2],
    check_aggregate_witness: bool,
) -> Result<(Program, Vec<Val>, Vec<Val>, Option<Value>)> {
    for child in children {
        child.key.verify(&child.proof, &child.public)?;
    }
    let public: Vec<Val> = children
        .iter()
        .flat_map(|child| child.public.iter().copied())
        .collect();
    let mut b = ProgramBuilder::new(public.len()).map_err(|e| format!("{e:?}"))?;
    let mut inputs = ProofInputs::default();
    let mut output_index = 0;
    let mut witness_target = None;
    for (child_index, child) in children.into_iter().enumerate() {
        let fields = inputs
            .bases(&mut b, &child.public)
            .map_err(|e| format!("{e:?}"))?;
        for field in &fields {
            let outer = b.public(output_index).map_err(|e| format!("{e:?}"))?;
            b.assert_equal(*field, outer);
            output_index += 1;
        }
        let proof_start = inputs.values.len();
        let cap: Vec<_> = child
            .cap
            .iter()
            .map(|root| root.map(|v| b.constant(v)))
            .collect();
        // Same shape-only verifier construction used by registered batch keys.
        // The actual preprocessing roots are constants from local registration.
        let shape = MachineAir::new(
            ProgramBuilder::new(child.public.len())
                .map_err(|e| format!("{e:?}"))?
                .finish(Some(child.height))
                .map_err(|e| format!("{e:?}"))?,
        );
        verifier::batch::verify(&mut b, &mut inputs, &shape, &fields, &cap, &child.proof)
            .map_err(|e| format!("{e:?}"))?;
        if check_aggregate_witness && child_index == 0 {
            // Locate the actual emitted first trace opening, not a public value
            // or header field. Match the complete prefix before using an index.
            let proof = &child.proof;
            let random = proof
                .commitments
                .random
                .as_ref()
                .ok_or("missing random cap")?;
            let permutation = proof
                .commitments
                .permutation
                .as_ref()
                .ok_or("missing permutation cap")?;
            let terminal = proof
                .lookup_terminals
                .first()
                .and_then(Option::as_ref)
                .ok_or("missing lookup terminal")?;
            let opening = proof
                .opened_values
                .instances
                .first()
                .and_then(|i| i.base_opened_values.trace_local.first())
                .ok_or("missing trace opening")?;
            let mut prefix = Vec::new();
            for cap in [
                &proof.commitments.main,
                &proof.commitments.quotient_chunks,
                random,
                permutation,
            ] {
                prefix.extend(cap.roots().iter().flatten().copied());
            }
            prefix.extend_from_slice(terminal.0.as_basis_coefficients_slice());
            let target = proof_start
                .checked_add(prefix.len())
                .ok_or("opening offset overflow")?;
            prefix.extend_from_slice(opening.as_basis_coefficients_slice());
            let end = proof_start
                .checked_add(prefix.len())
                .ok_or("opening prefix overflow")?;
            require(
                inputs.values.get(proof_start..end) == Some(prefix.as_slice()),
                "emitted child verifier prefix mismatch",
            )?;
            witness_target = Some(target);
        }
    }
    let program = b.finish(None).map_err(|e| format!("{e:?}"))?;
    let check = if let Some(index) = witness_target {
        let bytes = program
            .height()
            .checked_mul(WIDTH)
            .and_then(|n| n.checked_add(program.wire_count()))
            .and_then(|n| n.checked_mul(core::mem::size_of::<Val>()))
            .ok_or("diagnostic temporary buffer size overflow")?;
        require(
            bytes <= 1 << 30,
            "diagnostic witness evaluation exceeds 1 GiB principal-buffer cap",
        )?;
        let original = inputs.values[index];
        inputs.values[index] += Val::ONE;
        let started = Instant::now();
        let evaluated = MachineAir::new(program.clone()).trace(&public, &inputs.values);
        inputs.values[index] = original;
        require(
            matches!(evaluated, Err(ExecutionError::Unsatisfied)),
            "corrupted aggregate child did not return Unsatisfied",
        )?;
        Some(
            json!({"child_index":0,"mutated_field":"trace_local[0].basis[0]",
            "execution_error":"Unsatisfied","original_witness_restored":true,
            "same_compiled_program":true,"public_values_unchanged":true,
            "principal_buffer_bound_bytes":bytes,"evaluation_budget_bytes":1_u64<<30,
            "evaluation_seconds":started.elapsed().as_secs_f64(),
            "negative_stark_proof_generated":false}),
        )
    } else {
        None
    };
    Ok((program, public, inputs.values, check))
}
pub(super) fn run(limits: Limits, output: &Path) -> Result<Value> {
    let session = Session::start(limits)?;
    let mut b = ProgramBuilder::new(1).map_err(|e| format!("{e:?}"))?;
    let left = Byte::input(&mut b);
    let right = Byte::input(&mut b);
    let xor = left.xor(&mut b, right).to_wire(&mut b);
    let expected = b.public(0).map_err(|e| format!("{e:?}"))?;
    b.assert_equal(xor, expected);
    let program = b.finish(None).map_err(|e| format!("{e:?}"))?;
    let (leaf, first) = prove(
        &session,
        program,
        vec![Val::from_u64(173 ^ 91)],
        vec![Val::from_u64(173), Val::from_u64(91)],
        0,
    )?;
    let mut layers = vec![first];
    let (program, public, witness, _) = pair([&leaf, &leaf], false)?;
    let (aggregate, second) = prove(&session, program, public, witness, 1)?;
    layers.push(second);
    let (program, public, witness, mut recursive_check) = pair([&aggregate, &leaf], true)?;
    drop(leaf);
    drop(aggregate);
    let (child, third) = prove(&session, program, public, witness, 2)?;
    layers.push(third);
    if let Some(check) = &mut recursive_check {
        check["valid_parent_positive_control"] = json!(true);
    }
    let bytes = postcard::to_allocvec(&(&child.public, &child.proof))?;
    let mut artifact = persist(output, &bytes)?;
    let stored = read(output, FILE_LIMIT)?;
    let ((public, proof), tail): ((Vec<Val>, BatchProof<Config>), &[u8]) =
        postcard::take_from_bytes(&stored)?;
    require(
        tail.is_empty() && public == child.public,
        "decoded diagnostic artifact public mismatch or trailing bytes",
    )?;
    let observation = session.finish()?;
    child.key.verify(&proof, &public)?;
    artifact["decoded_payload_reverified"] = json!(true);
    Ok(
        json!({"schema":lattica_pq_ringct_batch::opencl::SCHEMA,"mode":"diagnostic","passed":true,
        "proof_count":3,"recursive_depth":2,"layers":layers,"session":observation,"artifact":artifact,
        "recursive_witness_checks":[recursive_check.ok_or("missing recursive witness check")?],
        "decoded_verification_after_gpu_shutdown":true,"ordered_public_value_count":3,
        "original_profile":true,"num_queries":128,"blowup":16,"extension":"Goldilocks cubic trinomial","hiding":true,
        "cpu_verification":true,"changed_public_rejected":true,"changed_proof_rejected":true,
        "strict_stage_reports_required":true,"complete_matrict_relation_qualified":false,
        "complete_ledger_transaction_qualified":false,"relation_kind":"repeated byte relation binary recursive aggregation diagnostic",
        "claims":"Actual binary pair and aggregate-plus-leaf verifiers over a repeated byte proof; no MatRiCT graph, transaction, block, speedup or cross-vendor qualification"}),
    )
}
