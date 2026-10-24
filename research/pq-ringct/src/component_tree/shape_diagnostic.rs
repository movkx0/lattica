//! Test-only geometry inputs. Every key is registered from an actual compiled
//! predicate; every returned proof object is deliberately invalid. Nothing in
//! this module proves a statement, accepts a request, or enters production.
use super::*;
use lattica_prover_p3::block_v2::profile;
use p3_air::{
    symbolic::{AirLayout, SymbolicAirBuilder},
    Air, BaseAir,
};

/// Match the exact hiding native verifier shape without generating a trace or
/// proof. The batch template supplies the shared PCS/FRI structure; its rounds
/// are reduced to the native verifier's random, main, and quotient openings.
pub(crate) fn invalid_native_template<A>(air: &A, height: usize) -> p3_uni_stark::Proof<Config>
where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    assert_eq!(air.preprocessed_width(), 0);
    assert!(height.is_power_of_two() && height >= 8);
    let shape_air = MachineAir::new(
        ProgramBuilder::new(0)
            .unwrap()
            .finish(Some(height))
            .unwrap(),
    );
    let mut skeleton = verifier::template::batch(&shape_air).unwrap();
    let chunks = 1usize
        << (1 + p3_uni_stark::get_log_num_quotient_chunks::<Val, A>(
            air,
            AirLayout::from_air::<Val>(air),
            1,
        ));
    let next = !air.main_next_row_columns().is_empty();
    let random_columns = profile::NUM_RANDOM_CODEWORDS;
    let opening = &mut skeleton.opening_proof;
    opening.0.truncate(3);
    opening.0[1] = vec![vec![
        vec![profile::Challenge::ZERO; random_columns];
        1 + usize::from(next)
    ]];
    opening.0[2] = vec![vec![vec![profile::Challenge::ZERO; random_columns]]; chunks];
    for query in &mut opening.1.query_proofs {
        query.input_proof.truncate(3);
        query.input_proof[1].opened_values = vec![vec![Val::ZERO; air.width() + random_columns]];
        query.input_proof[2].opened_values = vec![vec![Val::ZERO; 3 + random_columns]; chunks];
        query.input_proof[2].opening_proof.0 = vec![vec![Val::ZERO; 4]; chunks];
    }
    p3_uni_stark::Proof {
        commitments: p3_uni_stark::Commitments {
            trace: skeleton.commitments.main,
            quotient_chunks: skeleton.commitments.quotient_chunks,
            random: skeleton.commitments.random,
        },
        opened_values: p3_uni_stark::OpenedValues {
            trace_local: vec![profile::Challenge::ZERO; air.width()],
            trace_next: next.then(|| vec![profile::Challenge::ZERO; air.width()]),
            preprocessed_local: None,
            preprocessed_next: None,
            quotient_chunks: vec![vec![profile::Challenge::ZERO; 3]; chunks],
            random: Some(vec![profile::Challenge::ZERO; 3]),
        },
        opening_proof: skeleton.opening_proof,
        degree_bits: height.ilog2() as usize + 1,
    }
}

/// Keeps a real registered source cap separate from its invalid proof-shaped
/// input. Construction is possible only from the closed production compiler.
pub(crate) struct RegisteredShape {
    pub(crate) key: NodeKey,
    pub(crate) invalid_proof: NodeProof,
    pub(crate) geometry: Geometry,
}

impl RegisteredShape {
    pub(crate) fn register(compiled: CompiledNode, retained_budget: u64) -> Result<Self> {
        let geometry = compiled.geometry()?;
        let public = compiled.public_values().to_vec();
        let prepared = compiled.prepare(retained_budget)?;
        let key = prepared.key();
        drop(prepared);
        let invalid_proof = NodeProof {
            public,
            proof: verifier::template::batch(&key.air()?).map_err(err)?,
        };
        require(
            key.verify(&invalid_proof).is_err(),
            "shape template unexpectedly verified",
        )?;
        Ok(Self {
            key,
            invalid_proof,
            geometry,
        })
    }

    /// The same parent predicate as production, with intentionally invalid
    /// witnesses. This is private test scaffolding, never native acceptance.
    pub(crate) fn compile_parent(&self, right: &Self) -> Result<CompiledNode> {
        merge_impl(
            &self.key,
            &right.key,
            [&self.invalid_proof, &right.invalid_proof],
        )
    }
}

#[test]
fn native_shape_templates_remain_invalid_for_exact_registered_airs() {
    let air = crate::uniform_air::UniformAir::new(crate::uniform_air::Kind::ExpandAlpha2);
    let proof = invalid_native_template(&air, air.height());
    assert_eq!(proof.degree_bits, air.height().ilog2() as usize + 1);
    assert!(p3_uni_stark::verify(&profile::make_config(), &air, &proof, &[Val::ZERO; 8]).is_err());
    // Native rejection alone would also accept malformed templates as a test
    // outcome. Require the recursive verifier to accept their exact shape,
    // then reject their invalid witness through its emitted constraints.
    let mut builder = ProgramBuilder::new(8).unwrap();
    let public: Vec<_> = (0..8).map(|index| builder.public(index).unwrap()).collect();
    let mut inputs = verifier::ProofInputs::default();
    verifier::uni::verify(
        &mut builder,
        &mut inputs,
        &air,
        air.height(),
        &public,
        &proof,
    )
    .unwrap();
    let machine = MachineAir::new(builder.finish(None).unwrap());
    assert!(machine.trace(&[Val::ZERO; 8], &inputs.values).is_err());
}
