//! Full constrained verifier for candidate hiding uni-STARK transaction proofs.
use super::super::compiler_constants::Constants;
use super::super::program::ScopedProgramBuilder as ProgramBuilder;
use super::super::program::Val;
use super::super::transcript::Transcript;
use super::super::Wire;
use super::expressions::{self, Evaluation, Lowerer, Values};
use super::pcs::{Point, Round, MAX_MATRICES};
use super::{observe_cap, CompileError, ProofInputs};
use crate::block_v2::profile::{self, Config};
use p3_air::{symbolic::SymbolicAirBuilder, Air, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;

pub mod shape;

/// AIRs generic over `AirBuilder` can use this bounded recording implementation.
pub use super::super::symbolic::Builder as BoundedSymbolicBuilder;

/// Separate simultaneous reservations for bounded symbolic preparation and the
/// normalized graph owned during lowering. These exclude caller AIR callbacks,
/// periodic tables, ProofInputs, returned wire arrays and the program builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedSymbolicAllowance {
    pub workspace_bytes: usize,
    pub retained_graph_bytes: usize,
}
impl BoundedSymbolicAllowance {
    pub const REQUIRED: Self = Self {
        workspace_bytes: super::super::symbolic::HOST_BYTES as usize,
        retained_graph_bytes: super::super::symbolic::UNI_RETAINED_HOST_BYTES,
    };

    fn check(self) -> Result<(), CompileError> {
        if self.workspace_bytes < Self::REQUIRED.workspace_bytes
            || self.retained_graph_bytes < Self::REQUIRED.retained_graph_bytes
        {
            return Err(CompileError::Shape("bounded uni symbolic allowance"));
        }
        Ok(())
    }
}

/// Inspect quotient geometry through the same bounded recorder/normalizer used
/// by `verify_bounded`, dropping its graph before returning. This returns only
/// geometry, never a template, program, proof or acceptance/admission token.
///
/// The caller must reserve both symbolic components and separately bound the
/// trusted AIR callbacks' own allocations before entry. No periodic table is
/// requested. An arbitrary caller-provided AIR is not resource-admitted here.
pub fn quotient_chunks_bounded<A>(
    air: &A,
    height: usize,
    allowance: BoundedSymbolicAllowance,
) -> Result<usize, CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    validate_geometry(air, height)?;
    allowance.check()?;
    let (_, log_chunks) = super::super::symbolic::prepare_uni_bounded(air, Constants::cpu())?;
    if log_chunks > profile::LOG_BLOWUP {
        return Err(CompileError::Shape("quotient degree"));
    }
    Ok(1 << (log_chunks + 1))
}

/// Compile the same uni-STARK relation through bounded CPU symbolic recording.
/// The caller must reserve both symbolic allowances before entry and separately
/// admit its AIR-owned allocations and already-owned periodic table. This API
/// never invokes `air.periodic_columns()` or retries the unbounded reference.
/// Recording/normalization scratch drops before lowering; the at-most-64 MiB
/// returned graph drops when `verify_prepared` returns. Its reservation must
/// remain live throughout lowering, including overlap with compiler storage.
pub fn verify_bounded<A>(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    air: &A,
    height: usize,
    public: &[Wire],
    proof: &Proof<Config>,
    columns: &[Vec<Val>],
    allowance: BoundedSymbolicAllowance,
) -> Result<(), CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    validate_geometry(air, height)?;
    if columns.len() != air.num_periodic_columns()
        || columns.iter().any(|c| !c.len().is_power_of_two() || c.len() > height)
    {
        return Err(CompileError::Shape("bounded uni periodic geometry"));
    }
    allowance.check()?;
    let prepared = super::super::symbolic::prepare_uni_bounded(air, Constants::cpu())?;
    verify_prepared(
        b, inputs, air, height, public, proof, Constants::cpu(), prepared,
        &super::periodic::Borrowed(columns),
    )
}

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
    validate_geometry(air, height)?;
    let columns = air.periodic_columns();
    verify_prepared(
        b,
        inputs,
        air,
        height,
        public,
        proof,
        Constants::cpu(),
        super::super::symbolic::native_uni(air),
        &super::periodic::Borrowed(&columns),
    )
}

pub(crate) fn verify_with_constants<A>(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    air: &A,
    height: usize,
    public: &[Wire],
    proof: &Proof<Config>,
    constants: Constants<'_>,
) -> Result<(), CompileError>
where
    A: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + Air<super::super::symbolic::Builder>
        + super::periodic::Source,
{
    validate_geometry(air, height)?;
    let prepared = super::super::symbolic::prepare_uni(air, constants)?;
    verify_prepared(
        b, inputs, air, height, public, proof, constants, prepared, air,
    )
}

fn validate_geometry<A: BaseAir<Val>>(air: &A, height: usize) -> Result<(), CompileError> {
    if !height.is_power_of_two()
        || height < 8
        || height.ilog2() as usize + 1 + profile::LOG_BLOWUP > 32
    {
        return Err(CompileError::Shape("uni trace height"));
    }
    if air.preprocessed_width() != 0 {
        return Err(CompileError::Unsupported("uni preprocessing"));
    }
    Ok(())
}

fn verify_prepared<A: BaseAir<Val>>(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    air: &A,
    height: usize,
    public: &[Wire],
    proof: &Proof<Config>,
    constants: Constants<'_>,
    prepared: (Vec<p3_air::symbolic::SymbolicExpression<Val>>, usize),
    periodic_source: &dyn super::periodic::Source,
) -> Result<(), CompileError> {
    validate_geometry(air, height)?;
    if periodic_source.count() != air.num_periodic_columns() {
        return Err(CompileError::Shape("periodic source count"));
    }
    let log_height = height.ilog2() as usize;
    let ext_db = log_height + 1;
    let (constraints, log_chunks) = prepared;
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
    let local = inputs.extensions(b, &opened.trace_local)?;
    let next = opened
        .trace_next
        .as_ref()
        .map(|v| inputs.extensions(b, v))
        .transpose()?;
    let random = inputs.extensions(b, opened.random.as_ref().unwrap())?;
    let quotient_chunks: Vec<_> = opened
        .quotient_chunks
        .iter()
        .map(|v| inputs.extensions(b, v))
        .collect::<Result<_, _>>()?;
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
    let rotation = b.constant(Val::TWO_ADIC_GENERATORS[log_height]);
    let zeta_next = b.ext_scale(zeta, rotation);
    let trace_points = [
        Point {
            point: zeta,
            values: &local,
        },
        Point {
            point: zeta_next,
            values: next.as_deref().unwrap_or(&[]),
        },
    ];
    let quotient_points: [[Point<'_>; 1]; MAX_MATRICES] = core::array::from_fn(|i| {
        [Point {
            point: zeta,
            values: quotient_chunks.get(i).map_or(&[], Vec::as_slice),
        }]
    });
    let quotient_matrices: [&[Point<'_>]; MAX_MATRICES] =
        core::array::from_fn(|i| quotient_points[i].as_slice());
    let rounds = [
        Round {
            commitment: &random_cap,
            log_domain: ext_db,
            matrices: &[&[Point {
                point: zeta,
                values: &random,
            }]],
            preprocessing: false,
        },
        Round {
            commitment: &trace_cap,
            log_domain: ext_db,
            matrices: &[&trace_points[..1 + usize::from(next.is_some())]],
            preprocessing: false,
        },
        Round {
            commitment: &quotient_cap,
            log_domain: ext_db,
            matrices: &quotient_matrices[..quotient_chunks.len()],
            preprocessing: false,
        },
    ];
    super::pcs::verify(b, inputs, &mut transcript, &rounds, &proof.opening_proof)?;
    let (first, last, transition, inv_vanishing) =
        expressions::selectors_with_constants(b, zeta, log_height, constants)?;
    b.with_compiler_scratch(
        "evaluation",
        periodic_source.count(),
        [Wire(0); 3],
        |b, periodic| {
            super::periodic::values_into(
                b,
                periodic_source,
                zeta,
                log_height,
                constants,
                periodic,
            )?;
            let quotient = expressions::quotient_with_constants(
                b,
                &quotient_chunks,
                zeta,
                log_height,
                constants,
            )?;
            let zero = b.ext_constant([Val::ZERO; 3]);
            let zeros = [zero];
            let next = match &next {
                Some(values) => Values::Slice(values),
                None => Values::repeat(&zeros, air.width())?,
            };
            let values = Evaluation {
                main: [Values::Slice(&local), next],
                preprocessed: [Values::Slice(&[]); 2],
                periodic,
                public,
                permutation: [&[]; 2],
                challenges: Values::Slice(&[]),
                terminals: &[],
                first,
                last,
                transition,
            };
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
        },
    )
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

    fn compile_bounded(proof: &Proof<Config>) -> (Program, Vec<Val>) {
        use super::super::super::program::{ConstructionLimits, MAX_WIRES};
        let mut b = ProgramBuilder::new_with_construction_limits(1, ConstructionLimits {
            max_requested_program_bytes: 1 << 30,
            max_wires: MAX_WIRES,
            max_input_values: 1 << 20,
        }).unwrap();
        let public = b.public(0).unwrap();
        let mut inputs = ProofInputs::default();
        verify_bounded(&mut b, &mut inputs, &Counter, 8, &[public], proof, &[],
            BoundedSymbolicAllowance::REQUIRED).unwrap();
        (b.finish(None).unwrap(), inputs.values)
    }

    #[test]
    fn bounded_uni_matches_reference_program_order_and_rejects_mutations() {
        let public = [Val::from_u64(37)];
        let trace = RowMajorMatrix::new((37..45).map(Val::from_u64).collect(), 1);
        let config = profile::make_config();
        let mut proof = p3_uni_stark::prove(&config, &Counter, trace, &public);
        p3_uni_stark::verify(&config, &Counter, &proof, &public).unwrap();
        let (reference, values) = compile(&proof);
        let manifest = reference.manifest_fields();
        drop(reference);
        let (bounded, bounded_values) = compile_bounded(&proof);
        assert_eq!(manifest, bounded.manifest_fields());
        assert_eq!(values, bounded_values);
        bounded.evaluate(&public, &bounded_values).unwrap();
        assert!(bounded.evaluate(&[Val::from_u64(38)], &bounded_values).is_err());
        drop(bounded);
        proof.opened_values.trace_local[0] += profile::Challenge::ONE;
        let (mutated, mutated_values) = compile_bounded(&proof);
        assert_eq!(manifest, mutated.manifest_fields());
        assert!(mutated.evaluate(&public, &mutated_values).is_err());
    }

    #[test]
    fn bounded_uni_symbolic_components_are_admitted_separately() {
        let required = BoundedSymbolicAllowance::REQUIRED;
        assert_eq!(required.workspace_bytes, 192 << 20);
        assert_eq!(required.retained_graph_bytes, 64 << 20);
        required.check().unwrap();
        for allowance in [
            BoundedSymbolicAllowance { workspace_bytes: required.workspace_bytes - 1, ..required },
            BoundedSymbolicAllowance { retained_graph_bytes: required.retained_graph_bytes - 1, ..required },
        ] {
            assert_eq!(allowance.check(), Err(CompileError::Shape("bounded uni symbolic allowance")));
        }
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
