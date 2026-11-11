//! Bound a constrained parent to the exact trusted child template and cap.
use super::super::{
    program::{ConstructionLimits, ProofInputs},
    ProgramBuilder,
};
use super::*;
use crate::block_v2::profile;

pub struct CompiledRecursionVerifier {
    program: Arc<Program>,
    witness: Vec<Val>,
}
impl CompiledRecursionVerifier {
    pub fn program(&self) -> &Arc<Program> {
        &self.program
    }
    pub fn witness(&self) -> &[Val] {
        &self.witness
    }
    pub fn evaluate(&self, public: &[Val]) -> Result<(), ExecutionError> {
        self.program.evaluate(public, &self.witness).map(|_| ())
    }
}

pub(super) fn compile(
    template: &RecursionTemplate,
    cap: &p3_batch_stark::Commitment<profile::Config>,
    proof: &RecursionExecutionProof,
    limits: ConstructionLimits,
) -> Result<CompiledRecursionVerifier, String> {
    let mut builder =
        ProgramBuilder::new_with_construction_limits(template.program.public_values(), limits)
            .map_err(|e| format!("parent construction: {e:?}"))?;
    let public = (0..template.program.public_values())
        .map(|i| builder.public(i))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parent publics: {e:?}"))?;
    let mut inputs = ProofInputs::default();
    RecursionVerifier::new(template.clone(), cap.clone()).constrain(
        &mut builder,
        &mut inputs,
        &public,
        proof,
    )?;
    let program = builder
        .finish(None)
        .map_err(|e| format!("parent program: {e:?}"))?;
    Ok(CompiledRecursionVerifier {
        program: Arc::new(program),
        witness: inputs.values,
    })
}

/// Trusted, host-only verifier key. It can outlive GPU preprocessing buffers.
/// Construction is restricted to an owner that generated the pinned public cap.
pub struct RecursionVerifier {
    source: std::sync::Weak<Program>,
    id: [u8; 32],
    publics: usize,
    airs: Vec<air::VerifierAir>,
    cap: p3_batch_stark::Commitment<profile::Config>,
}
impl RecursionVerifier {
    pub(super) fn new(
        template: RecursionTemplate,
        cap: p3_batch_stark::Commitment<profile::Config>,
    ) -> Self {
        Self {
            source: Arc::downgrade(&template.program),
            id: template.id,
            publics: template.program.publics,
            airs: template
                .airs()
                .iter()
                .map(air::TableAir::verifier_air)
                .collect(),
            cap,
        }
    }
    pub fn matches_program(&self, program: &Arc<Program>) -> bool {
        self.source.ptr_eq(&Arc::downgrade(program))
    }
    pub fn identity(&self) -> [u8; 32] {
        self.id
    }
    /// Verification after releasing the source program and all GPU allocations.
    /// Neither this descriptor nor its public cap can be supplied by a proof.
    pub fn verify(&self, proof: &RecursionExecutionProof, public: &[Val]) -> Result<(), String> {
        use p3_air::{symbolic::AirLayout, BaseAir};
        use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
        use p3_lookup::{LogUpGadget, Lookups};
        if public.len() != self.publics
            || proof.inner.degree_bits
                != self
                    .airs
                    .iter()
                    .map(|a| a.height.ilog2() as usize + 1)
                    .collect::<Vec<_>>()
        {
            return Err("compact recursion trusted shape mismatch".into());
        }
        let gadget = LogUpGadget::new();
        let lookups = self
            .airs
            .iter()
            .map(|air| {
                let lookups = Lookups::<Val>::from_air::<profile::Challenge, _>(air);
                let log_chunks =
                    p3_batch_stark::symbolic::get_log_num_quotient_chunks::<
                        Val,
                        profile::Challenge,
                        _,
                        _,
                    >(air, AirLayout::from_air(air), &lookups, 1, &gadget);
                lookups.pack_same_bus(&gadget, 1 << log_chunks)
            })
            .collect();
        let instances = self
            .airs
            .iter()
            .enumerate()
            .map(|(matrix_index, air)| {
                Some(PreprocessedInstanceMeta {
                    matrix_index,
                    width: air.preprocessed_width(),
                    degree_bits: air.height.ilog2() as usize + 1,
                })
            })
            .collect();
        let common = p3_batch_stark::CommonData {
            preprocessed: Some(GlobalPreprocessed {
                commitment: self.cap.clone(),
                instances,
                matrix_to_instance: (0..self.airs.len()).collect(),
            }),
            lookups,
        };
        let publics = self
            .airs
            .iter()
            .map(|a| if a.kind == 3 { public.to_vec() } else { vec![] })
            .collect::<Vec<_>>();
        p3_batch_stark::verify_batch(
            &profile::make_cpu_config(),
            &self.airs,
            &proof.inner,
            &publics,
            &common,
        )
        .map_err(|e| format!("compact recursion CPU verification: {e:?}"))
    }
    pub fn constrain(
        &self,
        builder: &mut super::super::program::ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        public: &[super::super::Wire],
        proof: &RecursionExecutionProof,
    ) -> Result<(), String> {
        constrain(
            self.publics,
            &self.airs,
            &self.cap,
            builder,
            inputs,
            public,
            proof,
        )
    }
}

fn constrain(
    num_publics: usize,
    airs: &[air::VerifierAir],
    cap: &p3_batch_stark::Commitment<profile::Config>,
    builder: &mut super::super::program::ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    public: &[super::super::Wire],
    proof: &RecursionExecutionProof,
) -> Result<(), String> {
    if public.len() != num_publics {
        return Err("trusted child public width".into());
    }
    let cap = cap
        .roots()
        .iter()
        .map(|root| root.map(|v| builder.constant(v)))
        .collect::<Vec<_>>();
    let log_heights = airs
        .iter()
        .map(|a| a.height.ilog2() as usize)
        .collect::<Vec<_>>();
    let publics = airs
        .iter()
        .map(|a| {
            if a.kind == 3 {
                public.to_vec()
            } else {
                Vec::new()
            }
        })
        .collect::<Vec<_>>();
    super::super::verifier::batch::mixed::verify(
        builder,
        inputs,
        airs,
        &log_heights,
        &publics,
        &cap,
        &proof.inner,
    )
    .map_err(|e| format!("constrained recursion verifier: {e:?}"))
}
