//! Constrained verifier for the candidate's one-AIR, one-bus hiding batch-STARK.
//! The preprocessing cap is supplied by the enclosing registered-program logic,
//! NOT accepted from a child proof as an arbitrary verification key.
use super::super::circuit::Extension;
use super::super::merkle::Digest;
use super::super::program::Val;
use super::super::transcript::Transcript;
use super::super::{MachineAir, ProgramBuilder, Wire};
use super::expressions::{self, Evaluation, Lowerer};
use super::pcs::{Point, Round};
use super::{ext_base, observe_cap, CompileError, ProofInputs};
use crate::block_v2::profile::{self, Config};
use p3_air::{symbolic::AirLayout, BaseAir};
use p3_batch_stark::{symbolic, BatchProof};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_lookup::{Kind, LogUpGadget, Lookups};

fn observe_usize(t: &mut Transcript, b: &mut ProgramBuilder, value: usize) {
    // BatchTranscript pads structural values to extension-field coefficients.
    let value = b.constant(Val::from_usize(value));
    let value = ext_base(b, value);
    t.observe_slice(b, &value);
}

fn recompose(b: &mut ProgramBuilder, flat: &[Extension]) -> Vec<Extension> {
    let basis = [
        b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]),
        b.ext_constant([Val::ZERO, Val::ONE, Val::ZERO]),
        b.ext_constant([Val::ZERO, Val::ZERO, Val::ONE]),
    ];
    flat.chunks_exact(3)
        .map(|coefficients| {
            let mut value = b.ext_constant([Val::ZERO; 3]);
            for i in 0..3 {
                let term = b.ext_mul(coefficients[i], basis[i]);
                value = b.ext_add(value, term);
            }
            value
        })
        .collect()
}

pub fn verify(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    air: &MachineAir,
    public: &[Wire],
    preprocessing_cap: &[Digest],
    proof: &BatchProof<Config>,
) -> Result<(), CompileError> {
    let height = air.program().height();
    let log_height = height.ilog2() as usize;
    let ext_db = log_height + 1;
    let layout = AirLayout::from_air::<Val>(air);
    let gadget = LogUpGadget::new();
    let unpacked = Lookups::<Val>::from_air::<profile::Challenge, _>(air);
    let log_chunks = symbolic::get_log_num_quotient_chunks::<Val, profile::Challenge, _, _>(
        air, layout, &unpacked, 1, &gadget,
    );
    if log_chunks > profile::LOG_BLOWUP {
        return Err(CompileError::Shape("batch quotient degree"));
    }
    let lookups = unpacked.pack_same_bus(&gadget, 1 << log_chunks);
    let expected_bus = match lookups.first().map(|x| &x.kind) {
        Some(Kind::Global(name)) => name,
        _ => return Err(CompileError::Unsupported("single global bus required")),
    };
    if lookups.iter().any(|l| {
        l.kind != Kind::Global(expected_bus.clone()) || l.elements.iter().any(|e| e.len() != 2)
    }) {
        return Err(CompileError::Unsupported(
            "single width-two lookup bus required",
        ));
    }
    let chunks = 1 << (log_chunks + 1);
    let perm_width = (lookups.len() + 1) * 3;
    if public.len() != air.num_public_values()
        || proof.degree_bits != [ext_db]
        || proof.opened_values.instances.len() != 1
        || proof.lookup_terminals.len() != 1
        || proof.lookup_terminals[0].is_none()
        || proof.commitments.permutation.is_none()
        || proof.commitments.random.is_none()
        || !air.main_next_row_columns().is_empty()
        || !air.preprocessed_next_row_columns().is_empty()
    {
        return Err(CompileError::Shape("single-table batch proof"));
    }
    let inst = &proof.opened_values.instances[0];
    let opened = &inst.base_opened_values;
    if opened.trace_local.len() != air.width()
        || opened.trace_next.is_some()
        || opened
            .preprocessed_local
            .as_ref()
            .is_none_or(|v| v.len() != air.preprocessed_width())
        || opened.preprocessed_next.is_some()
        || opened.random.as_ref().is_none_or(|v| v.len() != 3)
        || opened.quotient_chunks.len() != chunks
        || opened.quotient_chunks.iter().any(|v| v.len() != 3)
        || inst.permutation_local.len() != perm_width
        || inst.permutation_next.len() != perm_width
    {
        return Err(CompileError::Shape("batch opened values"));
    }
    let log_lde = ext_db + profile::LOG_BLOWUP;
    if preprocessing_cap.len() != 1 << log_lde.min(profile::CAP_HEIGHT) {
        return Err(CompileError::Shape("registered preprocessing cap"));
    }
    let main_cap = inputs.cap(b, &proof.commitments.main, log_lde)?;
    let quotient_cap = inputs.cap(b, &proof.commitments.quotient_chunks, log_lde)?;
    let random_cap = inputs.cap(b, proof.commitments.random.as_ref().unwrap(), log_lde)?;
    let perm_cap = inputs.cap(b, proof.commitments.permutation.as_ref().unwrap(), log_lde)?;
    let terminal = inputs.extension(b, proof.lookup_terminals[0].as_ref().unwrap().0);
    let zero = b.ext_constant([Val::ZERO; 3]);
    b.ext_assert_equal(terminal, zero);
    let local = inputs.extensions(b, &opened.trace_local);
    let pre = inputs.extensions(b, opened.preprocessed_local.as_ref().unwrap());
    let random = inputs.extensions(b, opened.random.as_ref().unwrap());
    let quotient_chunks: Vec<_> = opened
        .quotient_chunks
        .iter()
        .map(|v| inputs.extensions(b, v))
        .collect();
    let perm_local = inputs.extensions(b, &inst.permutation_local);
    let perm_next = inputs.extensions(b, &inst.permutation_next);
    let mut transcript = Transcript::new(b);
    for value in [1, ext_db, log_height, air.width(), chunks] {
        observe_usize(&mut transcript, b, value);
    }
    observe_cap(&mut transcript, b, &main_cap);
    transcript.observe_slice(b, public);
    observe_usize(&mut transcript, b, air.preprocessed_width());
    observe_cap(&mut transcript, b, preprocessing_cap);
    let lookup_alpha = transcript.sample_ext(b);
    let lookup_beta = transcript.sample_ext(b);
    let gamma = b.ext_mul(lookup_beta, lookup_beta);
    let prefix = b.ext_add(lookup_alpha, gamma);
    let challenges: Vec<_> = (0..lookups.len())
        .flat_map(|_| [prefix, lookup_beta])
        .collect();
    observe_cap(&mut transcript, b, &perm_cap);
    transcript.observe_slice(b, &terminal);
    let alpha = transcript.sample_ext(b);
    observe_cap(&mut transcript, b, &quotient_cap);
    observe_cap(&mut transcript, b, &random_cap);
    let zeta = transcript.sample_ext(b);
    let rotation = b.constant(Val::two_adic_generator(log_height));
    let zeta_next = b.ext_scale(zeta, rotation);
    let rounds = vec![
        Round {
            commitment: random_cap,
            log_domain: ext_db,
            matrices: vec![vec![Point {
                point: zeta,
                values: random,
            }]],
            preprocessing: false,
        },
        Round {
            commitment: main_cap,
            log_domain: ext_db,
            matrices: vec![vec![Point {
                point: zeta,
                values: local.clone(),
            }]],
            preprocessing: false,
        },
        Round {
            commitment: quotient_cap,
            log_domain: ext_db,
            matrices: quotient_chunks
                .iter()
                .map(|v| {
                    vec![Point {
                        point: zeta,
                        values: v.clone(),
                    }]
                })
                .collect(),
            preprocessing: false,
        },
        Round {
            commitment: preprocessing_cap.to_vec(),
            log_domain: ext_db,
            matrices: vec![vec![Point {
                point: zeta,
                values: pre.clone(),
            }]],
            preprocessing: true,
        },
        Round {
            commitment: perm_cap,
            log_domain: ext_db,
            matrices: vec![vec![
                Point {
                    point: zeta,
                    values: perm_local.clone(),
                },
                Point {
                    point: zeta_next,
                    values: perm_next.clone(),
                },
            ]],
            preprocessing: false,
        },
    ];
    super::pcs::verify(b, inputs, &mut transcript, rounds, &proof.opening_proof)?;
    let (first, last, transition, inv_vanishing) = expressions::selectors(b, zeta, log_height);
    let periodic = expressions::periodic_values(b, &air.periodic_columns(), zeta, log_height)?;
    let quotient = expressions::quotient(b, &quotient_chunks, zeta, log_height)?;
    let perm_local = recompose(b, &perm_local);
    let perm_next = recompose(b, &perm_next);
    let values = Evaluation {
        main: [local, vec![zero; air.width()]],
        preprocessed: [pre, vec![zero; air.preprocessed_width()]],
        periodic,
        public: public.to_vec(),
        permutation: [perm_local, perm_next],
        challenges,
        terminals: vec![terminal],
        first,
        last,
        transition,
    };
    let (base, extension) = symbolic::get_symbolic_constraints::<Val, profile::Challenge, _, _>(
        air, layout, &lookups, &gadget,
    );
    let order = symbolic::get_constraint_layout::<Val, profile::Challenge, _, _>(
        air, layout, &lookups, &gadget,
    );
    let mut lowerer = Lowerer::new(b, values);
    let mut constraints = vec![None; order.total_constraints()];
    for (e, &index) in base.iter().zip(&order.base_indices) {
        constraints[index] = Some(lowerer.base(e)?);
    }
    for (e, &index) in extension.iter().zip(&order.ext_indices) {
        constraints[index] = Some(lowerer.extension(e)?);
    }
    let mut folded = zero;
    for value in constraints {
        let value = value.ok_or(CompileError::Shape("constraint emission order"))?;
        folded = lowerer.b.ext_mul(folded, alpha);
        folded = lowerer.b.ext_add(folded, value);
    }
    let lhs = lowerer.b.ext_mul(folded, inv_vanishing);
    lowerer.b.ext_assert_equal(lhs, quotient);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::super::{backend::RegisteredProgram, Program};
    use super::*;

    fn compile(registered: &RegisteredProgram, proof: &BatchProof<Config>) -> (Program, Vec<Val>) {
        let mut b = ProgramBuilder::new(1).unwrap();
        let public = b.public(0).unwrap();
        let cap: Vec<_> = registered
            .preprocessing_cap()
            .roots()
            .iter()
            .map(|root| root.map(|v| b.constant(v)))
            .collect();
        let mut inputs = ProofInputs::default();
        verify(
            &mut b,
            &mut inputs,
            registered.air(),
            &[public],
            &cap,
            proof,
        )
        .unwrap();
        (b.finish(None).unwrap(), inputs.values)
    }

    #[test]
    fn full_strength_batch_verifier_accepts_and_rejects_real_proofs() {
        let mut b = ProgramBuilder::new(1).unwrap();
        let input = b.input();
        let seven = b.constant(Val::from_u64(7));
        let value = b.add(input, seven);
        let public = b.public(0).unwrap();
        b.assert_equal(value, public);
        let registered = RegisteredProgram::new(MachineAir::new(b.finish(None).unwrap())).unwrap();
        let public = [Val::from_u64(12)];
        let proof = registered.prove(&public, &[Val::from_u64(5)]).unwrap();
        registered.verify(&proof, &public).unwrap();
        let (program, witness) = compile(&registered, &proof);
        eprintln!(
            "batch-verifier rows={} height={} wires={} inputs={}",
            program.active_rows(),
            program.height(),
            program.wire_count(),
            witness.len()
        );
        program.evaluate(&public, &witness).unwrap();
        assert!(program.evaluate(&[Val::from_u64(13)], &witness).is_err());
        let manifest = program.manifest_fields();
        drop(program);
        let encoded = postcard::to_allocvec(&proof).unwrap();
        for mutation in 0..12 {
            let mut proof: BatchProof<Config> = postcard::from_bytes(&encoded).unwrap();
            let opened = &mut proof.opened_values.instances[0];
            match mutation {
                0 => opened.permutation_local[0] += profile::Challenge::ONE,
                1 => opened.permutation_next[0] += profile::Challenge::ONE,
                2 => opened.base_opened_values.trace_local[0] += profile::Challenge::ONE,
                3 => {
                    opened
                        .base_opened_values
                        .preprocessed_local
                        .as_mut()
                        .unwrap()[0] += profile::Challenge::ONE
                }
                4 => opened.base_opened_values.quotient_chunks[0][0] += profile::Challenge::ONE,
                5 => {
                    opened.base_opened_values.random.as_mut().unwrap()[0] += profile::Challenge::ONE
                }
                6 => proof.opening_proof.0[0][0][0][0] += profile::Challenge::ONE,
                7 => proof.opening_proof.1.final_poly[0] += profile::Challenge::ONE,
                8 => {
                    proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].sibling_values
                        [0] += profile::Challenge::ONE
                }
                9 => {
                    proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0][0] +=
                        Val::ONE
                }
                10 => {
                    proof.opening_proof.1.query_proofs[0].input_proof[0]
                        .opening_proof
                        .1[0][0] += Val::ONE
                }
                11 => proof.lookup_terminals[0].as_mut().unwrap().0 += profile::Challenge::ONE,
                _ => unreachable!(),
            }
            assert!(
                registered.verify(&proof, &public).is_err(),
                "native mutation {mutation}"
            );
            let (bad, bad_witness) = compile(&registered, &proof);
            assert_eq!(
                manifest,
                bad.manifest_fields(),
                "mutation {mutation} altered program"
            );
            assert!(
                bad.evaluate(&public, &bad_witness).is_err(),
                "circuit accepted mutation {mutation}"
            );
        }
    }
}
