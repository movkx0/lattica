//! Compact typed graph proofs. Only checked graph compilation can create a
//! node; parents constrain every child and the exact registered schedule span.
use super::*;
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, ScopedProgramBuilder},
    recursion::{
        GpuProofMeasurement, GpuRecursionCache, GpuTemplateLimits, RecursionExecutionProof,
        RecursionTemplate, RecursionVerifier,
    },
};

pub(crate) struct ProvenNode {
    spec: Spec,
    public: Vec<Val>,
    key: RecursionVerifier,
    proof: RecursionExecutionProof,
}
impl ProvenNode {
    pub(crate) fn prove_gpu(
        node: CompiledNode,
        cache: &mut GpuRecursionCache,
        limits: GpuTemplateLimits,
        source_released: impl FnOnce(),
    ) -> Result<(Self, f64, GpuProofMeasurement)> {
        let started = std::time::Instant::now();
        let template = RecursionTemplate::new(
            Arc::clone(&node.program),
            crate::graph_proofs::compiled_source_fingerprint(),
        )
        .map_err(err)?;
        let template_seconds = started.elapsed().as_secs_f64();
        let (node, setup_seconds, measurement) =
            Self::prove_prepared_gpu(node, template, cache, limits, source_released)?;
        Ok((node, template_seconds + setup_seconds, measurement))
    }
    pub(crate) fn prove_prepared_gpu(
        node: CompiledNode,
        template: RecursionTemplate,
        cache: &mut GpuRecursionCache,
        limits: GpuTemplateLimits,
        source_released: impl FnOnce(),
    ) -> Result<(Self, f64, GpuProofMeasurement)> {
        Self::prove_prepared_witness_gpu(node, template, None, cache, limits, source_released)
    }
    pub(crate) fn prove_prepared_witness_gpu(
        node: CompiledNode,
        template: RecursionTemplate,
        ready: Option<lattica_prover_p3::block_v2::machine::recursion::PreparedRecursionWitness>,
        cache: &mut GpuRecursionCache,
        limits: GpuTemplateLimits,
        source_released: impl FnOnce(),
    ) -> Result<(Self, f64, GpuProofMeasurement)> {
        require(
            template.matches_program(&node.program),
            "prepared graph source ownership",
        )?;
        let started = std::time::Instant::now();
        let owner = cache.prepare(template, limits).map_err(err)?;
        let setup_seconds = started.elapsed().as_secs_f64();
        let key = owner.verifier();
        require(
            key.matches_program(&node.program),
            "typed graph source ownership",
        )?;
        let CompiledNode {
            spec,
            program,
            public,
            witness,
        } = node;
        drop(program);
        let (proof, measurement) = match ready {
            Some(ready) => {
                drop(witness);
                owner.into_prove_prepared(&public, ready, source_released)
            }
            None => owner.into_prove(&public, &witness, source_released),
        }
        .map_err(err)?;
        Ok((
            Self {
                spec,
                public,
                key,
                proof,
            },
            setup_seconds,
            measurement,
        ))
    }
    pub(crate) fn profile_label(&self) -> [u8; 32] {
        self.spec.plan.label
    }
    pub(crate) fn span(&self) -> (usize, usize) {
        (self.spec.first as usize, self.spec.count as usize)
    }
    pub(crate) fn verify(&self, plan: &Plan, context: &GraphContext) -> Result<()> {
        require(
            Arc::ptr_eq(&self.spec.plan, &plan.0),
            "typed graph registration mismatch",
        )?;
        self.verify_context(context)
    }
    fn verify_context(&self, context: &GraphContext) -> Result<()> {
        require(
            self.public == header(&self.spec, context),
            "typed graph context or coverage mismatch",
        )?;
        self.key.verify(&self.proof, &self.public).map_err(err)
    }
    pub(crate) fn verify_complete(&self, context: &GraphContext) -> Result<()> {
        require(self.spec.complete(), "incomplete typed graph")?;
        self.verify_context(context)
    }
    pub(crate) fn compile_complete(
        &self,
        b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        expected: &ContextWires,
    ) -> Result<()> {
        require(self.spec.complete(), "incomplete typed graph consumer")?;
        let public = inputs.bases(b, &self.public).map_err(err)?;
        self.key
            .constrain(b, inputs, &public, &self.proof)
            .map_err(err)?;
        bind_context(b, &public, expected);
        Ok(())
    }
    pub(crate) fn rejects_altered_public(&self) -> bool {
        let mut wrong = self.public.clone();
        wrong[STATEMENT] += Val::ONE;
        self.key.verify(&self.proof, &wrong).is_err()
    }
    pub(crate) fn retained_bytes(&self, maximum: usize) -> Result<usize> {
        let fixed = (64 << 10) + self.public.capacity() * core::mem::size_of::<Val>();
        let remaining = maximum
            .checked_sub(fixed)
            .ok_or_else(|| err("typed graph retained limit"))?;
        self.proof
            .retained_backing_bytes(remaining)
            .map_err(err)?
            .checked_add(fixed)
            .ok_or_else(|| err("typed graph retained overflow"))
    }
}

pub(crate) fn compile_merge(
    children: &[&ProvenNode],
    limits: ConstructionLimits,
) -> Result<CompiledNode> {
    require(
        (2..=8).contains(&children.len()),
        "typed graph parent fan-in",
    )?;
    let mut spec = children[0].spec.clone();
    for child in &children[1..] {
        spec = Spec::merge(&spec, &child.spec)?;
    }
    spec.level = children
        .iter()
        .map(|c| c.spec.level)
        .max()
        .unwrap()
        .checked_add(1)
        .ok_or_else(|| err("typed graph level overflow"))?;
    let mut public = children[0].public.clone();
    public[FIRST] = Val::from_u32(spec.first);
    public[COUNT] = Val::from_u32(spec.count);
    public[LEVEL] = Val::from_u32(spec.level);
    let mut b = ProgramBuilder::new_with_construction_limits(PUBLIC_VALUES, limits).map_err(err)?;
    let outer = public_wires(&mut b, &spec)?;
    let mut inputs = ProofInputs::default();
    let mut next = outer[FIRST];
    for child in children {
        require(
            child.public.len() == PUBLIC_VALUES,
            "typed graph child width",
        )?;
        let wires = inputs.bases(&mut b, &child.public).map_err(err)?;
        child
            .key
            .constrain(&mut b, &mut inputs, &wires, &child.proof)
            .map_err(err)?;
        for i in 0..PUBLIC_VALUES {
            if ![FIRST, COUNT, LEVEL].contains(&i) {
                b.assert_equal(wires[i], outer[i]);
            }
        }
        b.assert_equal(wires[FIRST], next);
        next = b.add(next, wires[COUNT]);
    }
    let end = b.add(outer[FIRST], outer[COUNT]);
    b.assert_equal(next, end);
    Ok(CompiledNode {
        spec,
        program: Arc::new(b.finish(None).map_err(err)?),
        public,
        witness: inputs.values,
    })
}

#[cfg(test)]
mod tests;
