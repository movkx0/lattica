//! The public leaf enum carries this opaque borrowed view. Only retained
//! originals with exact named source plans can construct its private payload.
use super::*;
use crate::{execution::workflow_resources::ExecutionAccess,
    graph_tree::owned_parent::{AuxiliaryGraphSources, AuxiliaryGraphOutputs},
    transcript_air::TranscriptAir};
use lattica_prover_p3::block_v2::{native_uniform_proof::NativeUniformProof,
    native_sparse_proof::NativeSparseProof, native_transcript_proof::NativeTranscriptProof};

pub struct BoundedAuxiliaryLeaf<'a> { artifact: Artifact<'a> }
enum Artifact<'a> {
    SampleG { aes: AesProof<'a>, uniform: &'a NativeUniformProof },
    ExpandAlpha { uniform_aes: AesProof<'a>, uniform: &'a NativeUniformProof,
        sparse_aes: AesProof<'a>, sparse: &'a NativeSparseProof },
    HashAlpha { shake: ShakeProof<'a>, air: &'a TranscriptAir, transcript: &'a NativeTranscriptProof },
    HashX { shake: ShakeProof<'a>, air: &'a TranscriptAir, transcript: &'a NativeTranscriptProof,
        sparse: &'a NativeSparseProof },
}
impl<'a> BoundedAuxiliaryLeaf<'a> {
    pub(crate) fn from_owned(outputs: &'a AuxiliaryGraphOutputs<'_>, sources: AuxiliaryGraphSources<'_, '_>,
        context: &GraphContext, execution: &ExecutionAccess<'_>) -> Result<Self> {
        outputs.check_source(sources, execution).map_err(err)?;
        use AuxiliaryGraphOutputs as O;
        use AuxiliaryGraphSources as S;
        use crate::graph_tree::owned_components::{aes_artifact, shake_artifact};
        let artifact = match (outputs, sources) {
            (O::SampleG { aes, uniform }, S::SampleG { aes: a, .. }) => Artifact::SampleG {
                aes: aes_artifact(aes, a, context, execution)?, uniform: uniform.get().artifact() },
            (O::ExpandAlpha { uniform_aes, uniform, sparse_aes, sparse },
                S::ExpandAlpha { uniform_aes: a, sparse_aes: b, .. }) => Artifact::ExpandAlpha {
                    uniform_aes: aes_artifact(uniform_aes, a, context, execution)?, uniform: uniform.get().artifact(),
                    sparse_aes: aes_artifact(sparse_aes, b, context, execution)?, sparse: sparse.get().artifact() },
            (O::HashAlpha { shake, transcript }, S::HashAlpha { shake: s, .. }) => Artifact::HashAlpha {
                shake: shake_artifact(shake, s, context, execution)?, air: transcript.get().source().air(),
                transcript: transcript.get().artifact() },
            (O::HashX { shake, transcript, sparse }, S::HashX { shake: s, .. }) => Artifact::HashX {
                shake: shake_artifact(shake, s, context, execution)?, air: transcript.get().source().air(),
                transcript: transcript.get().artifact(), sparse: sparse.get().artifact() },
            _ => return Err(Error("owned auxiliary source family mismatch".into())),
        };
        Ok(Self { artifact })
    }
    pub(super) fn emit(self, session: &mut SourceBinding<'_, '_, '_>, family: &LeafKind,
        index: usize, context: &ContextWires, request: u32) -> Result<()> {
        use OperationFamily as F;
        use Artifact as A;
        match (family, self.artifact) {
            (LeafKind::Operations(F::SampleG), A::SampleG { aes, uniform }) =>
                session.verify_sample_g_owned(index, aes.request(context, request), uniform),
            (LeafKind::Operations(F::ExpandAlpha), A::ExpandAlpha { uniform_aes, uniform, sparse_aes, sparse }) => {
                let sparse_request = request.checked_add(1).ok_or_else(|| Error("owned auxiliary request overflow".into()))?;
                session.verify_expand_alpha_owned(index, uniform_aes.request(context, request), uniform,
                    sparse_aes.request(context, sparse_request), sparse)
            }
            (LeafKind::Operations(F::HashAlpha), A::HashAlpha { shake, air, transcript }) =>
                session.verify_hash_alpha_owned(index, air, transcript, shake.request(context, request)),
            (LeafKind::Operations(F::HashX), A::HashX { shake, air, transcript, sparse }) =>
                session.verify_hash_x_owned(index, air, transcript, shake.request(context, request), sparse),
            _ => return Err(Error("owned auxiliary registered leaf mismatch".into())),
        }.map_err(err)
    }
}
