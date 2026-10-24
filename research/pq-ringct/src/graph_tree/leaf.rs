use super::*;
use crate::{
    affine_air::AffineBatchProof,
    g_bound_air::join::GBoundArtifact,
    linear_map_air::LinearMapProof,
    ntt_air::NttBatchProof,
    obligation_manifest::ContextWires,
    permutation_air::PermutationProof,
    poly_air::MulBatchProof,
    proof_air::join::ProofArtifact,
    request_bridge::{AesRequest, ShakeRequest, TreeArtifacts},
    rust_verify::committed_backend::source_binding::SourceBinding,
    sampler_bridge::AesArtifacts,
    sparse_air::join::SparseArtifact,
    statement_air::bundle::StatementProof,
    transcript_air::join::TranscriptArtifact,
    transcript_bridge::ShakeArtifacts,
    uniform_air::join::UniformArtifact,
};
use lattica_prover_p3::block_v2::machine::verifier::ProofInputs;

/// The request index and expected context are deliberately absent. The closed
/// leaf dispatcher derives them from the registered graph and public header.
pub enum AesProof<'a> {
    Direct(AesArtifacts<'a>),
    Tree {
        key: &'a crate::component_tree::NodeKey,
        proof: &'a crate::component_tree::NodeProof,
    },
}
pub enum ShakeProof<'a> {
    Direct(ShakeArtifacts<'a>),
    Tree {
        key: &'a crate::component_tree::NodeKey,
        proof: &'a crate::component_tree::NodeProof,
    },
}
impl<'a> From<AesArtifacts<'a>> for AesProof<'a> {
    fn from(value: AesArtifacts<'a>) -> Self {
        Self::Direct(value)
    }
}
impl<'a> From<ShakeArtifacts<'a>> for ShakeProof<'a> {
    fn from(value: ShakeArtifacts<'a>) -> Self {
        Self::Direct(value)
    }
}
impl<'a> AesProof<'a> {
    fn request<'b>(self, context: &'b ContextWires, index: u32) -> AesRequest<'b>
    where
        'a: 'b,
    {
        match self {
            Self::Direct(value) => AesRequest::Direct(value),
            Self::Tree { key, proof } => AesRequest::Tree(TreeArtifacts {
                key,
                proof,
                context,
                index,
            }),
        }
    }
}
impl<'a> ShakeProof<'a> {
    fn request<'b>(self, context: &'b ContextWires, index: u32) -> ShakeRequest<'b>
    where
        'a: 'b,
    {
        match self {
            Self::Direct(value) => ShakeRequest::Direct(value),
            Self::Tree { key, proof } => ShakeRequest::Tree(TreeArtifacts {
                key,
                proof,
                context,
                index,
            }),
        }
    }
}
pub enum LeafArtifact<'a> {
    FixedSources,
    Statement(&'a StatementProof),
    PrivateProof(&'a ProofArtifact),
    Affine(&'a AffineBatchProof),
    Ntt(&'a NttBatchProof),
    Mul(&'a MulBatchProof),
    GBound(&'a GBoundArtifact),
    Permutation(&'a PermutationProof),
    LinearMap(&'a LinearMapProof),
    Equality,
    ParametersPp(ShakeProof<'a>),
    SampleG {
        aes: AesProof<'a>,
        sampler: &'a UniformArtifact,
    },
    ExpandAlpha {
        uniform_aes: AesProof<'a>,
        uniform: &'a UniformArtifact,
        sparse_aes: AesProof<'a>,
        sparse: &'a SparseArtifact,
    },
    ExpandAlphaBranches {
        uniform: crate::producer_branch::Artifact<'a>,
        sparse: crate::producer_branch::Artifact<'a>,
    },
    HashAlpha {
        transcript: &'a TranscriptArtifact,
        shake: ShakeProof<'a>,
    },
    HashX {
        transcript: &'a TranscriptArtifact,
        shake: ShakeProof<'a>,
        sampler: &'a SparseArtifact,
    },
    HashXBranch {
        branch: crate::producer_branch::Artifact<'a>,
        sampler: &'a SparseArtifact,
    },
}
fn emit(
    session: &mut SourceBinding<'_, '_, '_>,
    plan: &LeafPlan,
    context: &ContextWires,
    node_manifest: &[Wire; 4],
    artifact: LeafArtifact<'_>,
) -> Result<()> {
    use LeafArtifact as A;
    use LeafKind as K;
    use OperationFamily as F;
    let indices = &plan.operations;
    let index = indices.first().copied().unwrap_or(0);
    let request = u32::try_from(index)
        .map_err(err)?
        .checked_mul(2)
        .ok_or_else(|| Error("graph request index overflow".into()))?;
    match (&plan.kind, artifact) {
        (K::FixedSources, A::FixedSources) => session.constrain_fixed_sources(),
        (K::Statement, A::Statement(proof)) => session.verify_statement(proof),
        (K::PrivateProof, A::PrivateProof(proof)) => session.verify_private_proof(proof),
        (K::Operations(F::Affine { .. }), A::Affine(proof)) => {
            session.verify_affine_batch(indices, proof)
        }
        (K::Operations(F::Ntt { .. }), A::Ntt(proof)) => session.verify_ntt_batch(indices, proof),
        (K::Operations(F::Mul { .. }), A::Mul(proof)) => session.verify_mul_batch(indices, proof),
        (K::Operations(F::GBound), A::GBound(proof)) => session.verify_g_bound(index, proof),
        (K::Operations(F::Permutation), A::Permutation(proof)) => {
            session.verify_permutation(index, proof)
        }
        (K::Operations(F::LinearMap), A::LinearMap(proof)) => {
            session.verify_linear_map(index, proof)
        }
        (K::Operations(F::Equality), A::Equality) => session.constrain_equality(index),
        (K::Operations(F::ParametersPp), A::ParametersPp(shake)) => {
            session.verify_parameters_pp(index, shake.request(context, request))
        }
        (K::Operations(F::SampleG), A::SampleG { aes, sampler }) => {
            session.verify_sample_g(index, aes.request(context, request), sampler)
        }
        (
            K::Operations(F::ExpandAlpha),
            A::ExpandAlpha {
                uniform_aes,
                uniform,
                sparse_aes,
                sparse,
            },
        ) => session.verify_expand_alpha(
            index,
            uniform_aes.request(context, request),
            uniform,
            sparse_aes.request(context, request + 1),
            sparse,
        ),
        (K::Operations(F::ExpandAlpha), A::ExpandAlphaBranches { uniform, sparse }) => {
            session.verify_expand_alpha_branches(index, context, node_manifest, uniform, sparse)
        }
        (K::Operations(F::HashAlpha), A::HashAlpha { transcript, shake }) => {
            session.verify_hash_alpha(index, transcript, shake.request(context, request))
        }
        (
            K::Operations(F::HashX),
            A::HashX {
                transcript,
                shake,
                sampler,
            },
        ) => session.verify_hash_x(index, transcript, shake.request(context, request), sampler),
        (K::Operations(F::HashX), A::HashXBranch { branch, sampler }) => {
            session.verify_hash_x_branch(index, context, node_manifest, branch, sampler)
        }
        _ => {
            return Err(Error(
                "artifact does not match the registered graph leaf predicate".into(),
            ))
        }
    }
    .map_err(err)
}
/// Compile a fixed registered leaf. There is no generic callback, caller-chosen
/// coverage bitmap, native acceptance Boolean, or externally supplied root wire.
/// The private compiled-node constructor is reached only after exact coverage.
pub fn compile_leaf(
    plan: &Plan,
    graph: &UnprovedRelationGraph,
    ordinal: usize,
    context: &GraphContext,
    artifact: LeafArtifact<'_>,
) -> Result<CompiledNode> {
    compile_group(plan, graph, ordinal, context, vec![artifact])
}

/// Exact union of a contiguous registered schedule span. Only the implicit
/// context/setup-seed bindings may appear in more than one constituent leaf.
pub(super) fn group_coverage(
    graph: &UnprovedRelationGraph,
    leaves: &[LeafPlan],
) -> Result<(Vec<usize>, Vec<usize>, Vec<usize>)> {
    use crate::rust_verify::committed_backend::Source;
    let mut polynomials = vec![false; graph.polynomials().len()];
    let mut bytes = vec![false; graph.bytes().len()];
    let mut operations = vec![false; graph.operations().len()];
    for leaf in leaves {
        for (indices, seen) in [
            (&leaf.polynomials, &mut polynomials),
            (&leaf.operations, &mut operations),
        ] {
            require(
                indices.windows(2).all(|v| v[0] < v[1]),
                "unordered registered group coverage",
            )?;
            for &index in indices {
                let covered = seen
                    .get_mut(index)
                    .ok_or_else(|| Error("group coverage index".into()))?;
                require(
                    !*covered,
                    "overlapping group polynomial or operation coverage",
                )?;
                *covered = true;
            }
        }
        require(
            leaf.bytes.windows(2).all(|v| v[0] < v[1]),
            "unordered registered byte coverage",
        )?;
        for &index in &leaf.bytes {
            let covered = bytes
                .get_mut(index)
                .ok_or_else(|| Error("group byte coverage index".into()))?;
            let implicit = matches!(
                graph.bytes()[index].source,
                Source::Context | Source::StatementSeed
            );
            require(
                !*covered || implicit,
                "overlapping group byte producer coverage",
            )?;
            *covered = true;
        }
    }
    let indices = |flags: Vec<bool>| {
        flags
            .into_iter()
            .enumerate()
            .filter_map(|(i, bound)| bound.then_some(i))
            .collect()
    };
    Ok((indices(polynomials), indices(bytes), indices(operations)))
}

/// Emit multiple native component/source verifiers in one wrapper while
/// preserving the existing registered schedule and profile. The covered span
/// is contiguous in that schedule; operation IDs inside a leaf may be sparse.
/// No intermediate recursive parent proof is required within this group.
pub fn compile_group(
    plan: &Plan,
    graph: &UnprovedRelationGraph,
    first: usize,
    context: &GraphContext,
    artifacts: Vec<LeafArtifact<'_>>,
) -> Result<CompiledNode> {
    require(
        plan.0.shape.matches(graph),
        "graph shape differs from full tree registration",
    )?;
    require(!artifacts.is_empty(), "empty graph leaf group")?;
    let end = first
        .checked_add(artifacts.len())
        .ok_or_else(|| Error("graph group span overflow".into()))?;
    require(
        end <= plan.0.leaves.len(),
        "graph group outside registered schedule",
    )?;
    let leaves = &plan.0.leaves[first..end];
    let (polynomials, bytes, operations) = group_coverage(graph, leaves)?;
    let spec = Spec {
        plan: plan.0.clone(),
        first: u32::try_from(first).map_err(err)?,
        count: u32::try_from(artifacts.len()).map_err(err)?,
        level: 0,
    };
    let mut builder = ProgramBuilder::new(PUBLIC_VALUES).map_err(err)?;
    let public = public_wires(&mut builder, &spec)?;
    let context_wires = ContextWires {
        profile: public[..8].try_into().unwrap(),
        context: public[CONTEXT..CONTEXT + 8].try_into().unwrap(),
        statement: public[STATEMENT..STATEMENT + 4].try_into().unwrap(),
    };
    let mut inputs = ProofInputs::default();
    let node_manifest = public[NODE_MANIFEST..NODE_MANIFEST + 4].try_into().unwrap();
    let mut session = SourceBinding::new(
        &plan.0.shape,
        graph,
        &mut builder,
        &mut inputs,
        context_wires.context,
        context_wires.statement,
        public[NODE_MANIFEST..NODE_MANIFEST + 4].try_into().unwrap(),
    )
    .map_err(err)?;
    for (leaf, artifact) in leaves.iter().zip(artifacts) {
        emit(&mut session, leaf, &context_wires, &node_manifest, artifact)?;
    }
    session
        .require_exact_coverage(&polynomials, &bytes, &operations)
        .map_err(err)?;
    let public = header(&spec, context);
    Ok(CompiledNode {
        spec,
        program: Arc::new(builder.finish(None).map_err(err)?),
        public,
        witness: inputs.values,
    })
}
