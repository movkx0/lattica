//! Full constrained verifier for candidate hiding uni-STARK transaction proofs.
use super::super::program::Val;
use super::super::transcript::Transcript;
use super::super::{ProgramBuilder, Wire};
use super::expressions::{self, Evaluation, Lowerer};
use super::pcs::{Point, Round};
use super::{observe_cap, CompileError, ProofInputs};
use crate::block_v2::profile::{self, Config};
use p3_air::{
    symbolic::{AirLayout, SymbolicAirBuilder},
    Air, BaseAir,
};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_uni_stark::{get_log_num_quotient_chunks, Proof};

pub fn verify<A>(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    air: &A,
    height: usize,
    public: &[Wire],
    proof: &Proof<Config>,
) -> Result<(), CompileError>
where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    if !height.is_power_of_two()
        || height < 8
        || height.ilog2() as usize + 1 + profile::LOG_BLOWUP > 32
    {
        return Err(CompileError::Shape("uni trace height"));
    }
    if air.preprocessed_width() != 0 {
        return Err(CompileError::Unsupported("uni preprocessing"));
    }
    let log_height = height.ilog2() as usize;
    let ext_db = log_height + 1;
    let layout = AirLayout::from_air::<Val>(air);
    let log_chunks = get_log_num_quotient_chunks::<Val, A>(air, layout, 1);
    if log_chunks > profile::LOG_BLOWUP {
        return Err(CompileError::Shape("quotient degree"));
    }
    let chunks = 1 << (log_chunks + 1);
    let main_next = !air.main_next_row_columns().is_empty();
    let opened = &proof.opened_values;
    if public.len() != air.num_public_values()
        || proof.degree_bits != ext_db
        || opened.trace_local.len() != air.width()
        || opened.trace_next.is_some() != main_next
        || opened
            .trace_next
            .as_ref()
            .is_some_and(|v| v.len() != air.width())
        || opened.preprocessed_local.is_some()
        || opened.preprocessed_next.is_some()
        || opened.quotient_chunks.len() != chunks
        || opened.quotient_chunks.iter().any(|v| v.len() != 3)
        || opened.random.as_ref().is_none_or(|v| v.len() != 3)
        || proof.commitments.random.is_none()
    {
        return Err(CompileError::Shape("uni proof shape"));
    }
    let log_lde = ext_db + profile::LOG_BLOWUP;
    let trace_cap = inputs.cap(b, &proof.commitments.trace, log_lde)?;
    let quotient_cap = inputs.cap(b, &proof.commitments.quotient_chunks, log_lde)?;
    let random_cap = inputs.cap(b, proof.commitments.random.as_ref().unwrap(), log_lde)?;
    let local = inputs.extensions(b, &opened.trace_local);
    let next = opened.trace_next.as_ref().map(|v| inputs.extensions(b, v));
    let random = inputs.extensions(b, opened.random.as_ref().unwrap());
    let quotient_chunks: Vec<_> = opened
        .quotient_chunks
        .iter()
        .map(|v| inputs.extensions(b, v))
        .collect();
    let mut transcript = Transcript::new(b);
    for n in [ext_db, log_height, 0] {
        let v = b.constant(Val::from_usize(n));
        transcript.observe(b, v);
    }
    observe_cap(&mut transcript, b, &trace_cap);
    transcript.observe_slice(b, public);
    let alpha = transcript.sample_ext(b);
    observe_cap(&mut transcript, b, &quotient_cap);
    observe_cap(&mut transcript, b, &random_cap);
    let zeta = transcript.sample_ext(b);
    let rotation = b.constant(Val::two_adic_generator(log_height));
    let zeta_next = b.ext_scale(zeta, rotation);
    let mut trace_points = vec![Point {
        point: zeta,
        values: local.clone(),
    }];
    if let Some(next) = &next {
        trace_points.push(Point {
            point: zeta_next,
            values: next.clone(),
        });
    }
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
            commitment: trace_cap,
            log_domain: ext_db,
            matrices: vec![trace_points],
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
    ];
    super::pcs::verify(b, inputs, &mut transcript, rounds, &proof.opening_proof)?;
    let (first, last, transition, inv_vanishing) = expressions::selectors(b, zeta, log_height);
    let periodic = expressions::periodic_values(b, &air.periodic_columns(), zeta, log_height)?;
    let quotient = expressions::quotient(b, &quotient_chunks, zeta, log_height)?;
    let zero = b.ext_constant([Val::ZERO; 3]);
    let values = Evaluation {
        main: [local, next.unwrap_or_else(|| vec![zero; air.width()])],
        preprocessed: [vec![], vec![]],
        periodic,
        public: public.to_vec(),
        permutation: [vec![], vec![]],
        challenges: vec![],
        terminals: vec![],
        first,
        last,
        transition,
    };
    let constraints = p3_air::symbolic::get_symbolic_constraints::<Val, A>(air, layout);
    let mut lowerer = Lowerer::new(b, values);
    let mut folded = zero;
    for constraint in &constraints {
        let value = lowerer.base(constraint)?;
        folded = lowerer.b.ext_mul(folded, alpha);
        folded = lowerer.b.ext_add(folded, value);
    }
    let lhs = lowerer.b.ext_mul(folded, inv_vanishing);
    lowerer.b.ext_assert_equal(lhs, quotient);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::super::Program;
    use super::*;
    use p3_air::{AirBuilder, WindowAccess};
    use p3_matrix::dense::RowMajorMatrix;

    #[derive(Clone)]
    struct Counter;
    impl BaseAir<Val> for Counter {
        fn width(&self) -> usize {
            1
        }
        fn num_public_values(&self) -> usize {
            1
        }
    }
    impl<AB: AirBuilder<F = Val>> Air<AB> for Counter {
        fn eval(&self, b: &mut AB) {
            let main = b.main();
            let local: AB::Expr = main.current_slice()[0].into();
            let next: AB::Expr = main.next_slice()[0].into();
            let public: AB::Expr = b.public_values()[0].into();
            b.when_first_row().assert_zero(local.clone() - public);
            b.when_transition()
                .assert_zero(next - local - AB::Expr::ONE);
        }
    }

    fn compile(proof: &Proof<Config>) -> (Program, Vec<Val>) {
        let mut b = ProgramBuilder::new(1).unwrap();
        let public = b.public(0).unwrap();
        let mut inputs = ProofInputs::default();
        verify(&mut b, &mut inputs, &Counter, 8, &[public], proof).unwrap();
        (b.finish(None).unwrap(), inputs.values)
    }

    #[test]
    fn full_strength_uni_verifier_accepts_and_rejects_real_proofs() {
        let public = [Val::from_u64(37)];
        let trace = RowMajorMatrix::new((37..45).map(Val::from_u64).collect(), 1);
        let config = profile::make_config();
        let proof = p3_uni_stark::prove(&config, &Counter, trace, &public);
        p3_uni_stark::verify(&config, &Counter, &proof, &public).unwrap();
        let (program, witness) = compile(&proof);
        eprintln!(
            "uni-verifier rows={} height={} wires={} inputs={}",
            program.active_rows(),
            program.height(),
            program.wire_count(),
            witness.len()
        );
        program.evaluate(&public, &witness).unwrap();
        assert!(program.evaluate(&[Val::from_u64(38)], &witness).is_err());
        let manifest = program.manifest_fields();
        drop(program);
        let encoded = postcard::to_allocvec(&proof).unwrap();
        for mutation in 0..10 {
            let mut proof: Proof<Config> = postcard::from_bytes(&encoded).unwrap();
            match mutation {
                0 => proof.opened_values.trace_local[0] += profile::Challenge::ONE,
                1 => proof.opened_values.trace_next.as_mut().unwrap()[0] += profile::Challenge::ONE,
                2 => proof.opened_values.quotient_chunks[0][0] += profile::Challenge::ONE,
                3 => proof.opened_values.random.as_mut().unwrap()[0] += profile::Challenge::ONE,
                4 => proof.opening_proof.0[0][0][0][0] += profile::Challenge::ONE,
                5 => proof.opening_proof.1.final_poly[0] += profile::Challenge::ONE,
                6 => {
                    proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].sibling_values
                        [0] += profile::Challenge::ONE
                }
                7 => {
                    proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0][0] +=
                        Val::ONE
                }
                8 => {
                    proof.opening_proof.1.query_proofs[0].input_proof[0]
                        .opening_proof
                        .1[0][0] += Val::ONE
                }
                9 => {
                    let mut roots = proof.commitments.trace.roots().to_vec();
                    roots[0][0] += Val::ONE;
                    proof.commitments.trace = p3_symmetric::MerkleCap::new(roots);
                }
                _ => unreachable!(),
            }
            assert!(
                p3_uni_stark::verify(&config, &Counter, &proof, &public).is_err(),
                "native mutation {mutation}"
            );
            let (bad_program, bad_witness) = compile(&proof);
            assert_eq!(
                manifest,
                bad_program.manifest_fields(),
                "mutation {mutation} altered program"
            );
            assert!(
                bad_program.evaluate(&public, &bad_witness).is_err(),
                "circuit accepted mutation {mutation}"
            );
        }
    }

    #[test]
    fn real_wallet_verifier_program_is_satisfied() {
        use crate::{
            block_v2::{commitment::Context, leaf::ContextJoinSplitAir},
            joinsplit_air as js,
        };
        let wallet = js::demo_witness();
        let context = Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: [19; 32],
        };
        let mut public = js::public_values(&wallet);
        public.extend(context.to_fields().map(Val::from_u64));
        let config = profile::make_config();
        let proof = p3_uni_stark::prove(
            &config,
            &ContextJoinSplitAir,
            js::build_trace(&wallet),
            &public,
        );
        p3_uni_stark::verify(&config, &ContextJoinSplitAir, &proof, &public).unwrap();
        let mut b = ProgramBuilder::new(public.len()).unwrap();
        let public_wires: Vec<_> = (0..public.len()).map(|i| b.public(i).unwrap()).collect();
        let mut inputs = ProofInputs::default();
        verify(
            &mut b,
            &mut inputs,
            &ContextJoinSplitAir,
            js::HEIGHT,
            &public_wires,
            &proof,
        )
        .unwrap();
        let program = b.finish(None).unwrap();
        eprintln!(
            "wallet-verifier rows={} height={} wires={} inputs={}",
            program.active_rows(),
            program.height(),
            program.wire_count(),
            inputs.values.len()
        );
        program.evaluate(&public, &inputs.values).unwrap();
        let mut wrong_public = public;
        wrong_public[js::PI_FEE] += Val::ONE;
        assert!(program.evaluate(&wrong_public, &inputs.values).is_err());
    }
}
