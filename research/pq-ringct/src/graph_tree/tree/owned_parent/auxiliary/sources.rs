use super::*;
use crate::component_tree::native_shape::NativeDescriptor;
use lattica_prover_p3::block_v2::native_gpu::{uniform_preparation::UniformKind,
    sparse_preparation::SparseKind};

#[derive(Clone, Copy)]
pub(super) enum RequestSource<'s, 'a> { Aes(&'s OwnedAesRequestPlan<'a>), Shake(&'s PairedRequestPlan<'a>) }
impl<'s, 'a> RequestSource<'s, 'a> {
    pub(super) fn request(self) -> &'a crate::graph_crypto::Request {
        match self { Self::Aes(p) => p.request(), Self::Shake(p) => p.request() }
    }
    pub(super) fn root(self) -> crate::component_tree::paired_runtime::ComponentSourceFacts {
        match self { Self::Aes(p) => p.root_source(), Self::Shake(p) => p.root_source() }
    }
    pub(super) fn fingerprint(self) -> [u8; 32] {
        match self { Self::Aes(p) => p.source_fingerprint(), Self::Shake(p) => p.source_fingerprint() }
    }
    fn belongs_to(self, ledger: &Ledger) -> bool {
        match self { Self::Aes(p) => p.belongs_to(ledger), Self::Shake(p) => p.belongs_to(ledger) }
    }
    fn validate(self, prepared: &SourceRetained<PreparedWorkflowSources<'_>>) -> OwnedResult<()> {
        let (context, compiled) = match self {
            Self::Aes(p) => (p.graph_context(), p.compiled_source_fingerprint()),
            Self::Shake(p) => (p.graph_context(), p.compiled_source_fingerprint()),
        };
        if context != prepared.get().context() || compiled != prepared.compiled_source_fingerprint() {
            return Err(GraphParentFailure::Authority);
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub(super) enum NativeSource<'s, 'a> {
    Uniform(&'s UniformNativeOperationPlan<'a>), Sparse(&'s SparseNativeOperationPlan<'a>),
    Transcript(&'s TranscriptNativeOperationPlan<'a>),
}
impl<'s, 'a> NativeSource<'s, 'a> {
    pub(super) fn descriptor(self) -> NativeDescriptor<'a> {
        match self {
            Self::Uniform(p) => NativeDescriptor::Uniform(match p.kind() {
                UniformKind::SampleG4 => crate::uniform_air::Kind::SampleG4,
                UniformKind::ExpandAlpha2 => crate::uniform_air::Kind::ExpandAlpha2 }),
            Self::Sparse(p) => NativeDescriptor::Sparse(match p.kind() {
                SparseKind::AlphaPrime39 => crate::sparse_air::Kind::AlphaPrime39,
                SparseKind::ChallengeX44 => crate::sparse_air::Kind::ChallengeX44 }),
            Self::Transcript(p) => NativeDescriptor::Transcript(p.source().air().parts()),
        }
    }
    pub(super) fn fingerprint(self) -> [u8; 32] {
        match self { Self::Uniform(p) => p.source_fingerprint(), Self::Sparse(p) => p.source_fingerprint(),
            Self::Transcript(p) => p.source_fingerprint() }
    }
    fn belongs_to(self, ledger: &Ledger) -> bool {
        match self { Self::Uniform(p) => p.belongs_to(ledger), Self::Sparse(p) => p.belongs_to(ledger),
            Self::Transcript(p) => p.belongs_to(ledger) }
    }
    fn validate(self, prepared: &SourceRetained<PreparedWorkflowSources<'_>>,
        context: &ProvingContext, operation: usize, role: Role) -> OwnedResult<()> {
        macro_rules! check {
            ($p:expr) => {{
                let p = $p;
                if !core::ptr::eq(p.sources(), prepared) || !core::ptr::eq(p.source().sources(), prepared)
                    || !core::ptr::eq(p.context(), context) || p.policy() != ProofCachePolicy::FreshOnly
                    || p.operation_index() != operation || p.role() != role
                    || p.workflow_source_fingerprint() != prepared.source_fingerprint()
                    || p.compiled_source_fingerprint() != prepared.compiled_source_fingerprint()
                    || !prepared.get().auxiliary_factory().requests().iter().any(|known| core::ptr::eq(known, p.request()))
                { return Err(GraphParentFailure::Authority); }
            }};
        }
        match self { Self::Uniform(p) => check!(p), Self::Sparse(p) => check!(p), Self::Transcript(p) => check!(p) }
        Ok(())
    }
}
impl AuxiliaryGraphKind {
    pub(super) fn family(self) -> OperationFamily {
        match self { Self::SampleG => OperationFamily::SampleG, Self::ExpandAlpha => OperationFamily::ExpandAlpha,
            Self::HashAlpha => OperationFamily::HashAlpha, Self::HashX => OperationFamily::HashX }
    }
    pub(super) fn tag(self) -> u8 { match self { Self::SampleG => 0, Self::ExpandAlpha => 1, Self::HashAlpha => 2, Self::HashX => 3 } }
    pub(crate) fn input_count(self) -> usize {
        match self { Self::SampleG | Self::HashAlpha => 3, Self::ExpandAlpha => 6, Self::HashX => 4 }
    }
}
impl<'s, 'a> AuxiliaryGraphSources<'s, 'a> {
    pub(crate) fn kind(self) -> AuxiliaryGraphKind {
        match self { Self::SampleG { .. } => AuxiliaryGraphKind::SampleG, Self::ExpandAlpha { .. } => AuxiliaryGraphKind::ExpandAlpha,
            Self::HashAlpha { .. } => AuxiliaryGraphKind::HashAlpha, Self::HashX { .. } => AuxiliaryGraphKind::HashX }
    }
    pub(super) fn operation_index(self) -> usize {
        match self { Self::SampleG { uniform, .. } | Self::ExpandAlpha { uniform, .. } => uniform.operation_index(),
            Self::HashAlpha { transcript, .. } | Self::HashX { transcript, .. } => transcript.operation_index() }
    }
    pub(super) fn requests(self) -> [Option<RequestSource<'s, 'a>>; 2] {
        match self {
            Self::SampleG { aes, .. } => [Some(RequestSource::Aes(aes)), None],
            Self::ExpandAlpha { uniform_aes, sparse_aes, .. } => [Some(RequestSource::Aes(uniform_aes)), Some(RequestSource::Aes(sparse_aes))],
            Self::HashAlpha { shake, .. } | Self::HashX { shake, .. } => [Some(RequestSource::Shake(shake)), None],
        }
    }
    pub(super) fn natives(self) -> [Option<NativeSource<'s, 'a>>; 2] {
        match self {
            Self::SampleG { uniform, .. } => [Some(NativeSource::Uniform(uniform)), None],
            Self::ExpandAlpha { uniform, sparse, .. } => [Some(NativeSource::Uniform(uniform)), Some(NativeSource::Sparse(sparse))],
            Self::HashAlpha { transcript, .. } => [Some(NativeSource::Transcript(transcript)), None],
            Self::HashX { transcript, sparse, .. } => [Some(NativeSource::Transcript(transcript)), Some(NativeSource::Sparse(sparse))],
        }
    }
    pub(super) fn transcript_parts(self) -> usize {
        match self { Self::HashAlpha { transcript, .. } | Self::HashX { transcript, .. } => transcript.source().air().parts().len(), _ => 0 }
    }
    pub(super) fn belongs_to(self, ledger: &Ledger) -> bool {
        self.requests().into_iter().flatten().all(|p| p.belongs_to(ledger))
            && self.natives().into_iter().flatten().all(|p| p.belongs_to(ledger))
    }
    pub(super) fn validate(self, prepared: &SourceRetained<PreparedWorkflowSources<'_>>,
        context: &ProvingContext, ordinal: usize) -> OwnedResult<()> {
        let operation = self.operation_index(); let graph = prepared.get().graph();
        validate_leaf(prepared.get().plan(), graph, self.kind(), operation, ordinal)?;
        for request in self.requests().into_iter().flatten() { request.validate(prepared)?; }
        let request = |p: &crate::graph_crypto::Request, sub, descriptor| {
            validate_request(prepared.get().crypto(), p, operation, sub, descriptor)
        };
        let aes = |domain, start_counter, output_len| RequestDescriptor::Aes(crate::aes_air::Descriptor { domain, start_counter, output_len });
        let shake = |input_len, output_len| RequestDescriptor::Shake(crate::shake_air::Descriptor { input_len, output_len });
        match self {
            Self::SampleG { aes: a, uniform } => {
                NativeSource::Uniform(uniform).validate(prepared, context, operation, Role::SampleGUniform)?;
                if uniform.kind() != UniformKind::SampleG4 { return Err(GraphParentFailure::Source); }
                request(a.request(), 0, aes(0, 0, 1197 * 4))?;
            }
            Self::ExpandAlpha { uniform_aes, uniform, sparse_aes, sparse } => {
                NativeSource::Uniform(uniform).validate(prepared, context, operation, Role::AlphaUniform)?;
                NativeSource::Sparse(sparse).validate(prepared, context, operation, Role::AlphaSparse)?;
                if uniform.kind() != UniformKind::ExpandAlpha2 || sparse.kind() != SparseKind::AlphaPrime39 {
                    return Err(GraphParentFailure::Source);
                }
                request(uniform_aes.request(), 0, aes(0x4368, 0, 2572))?;
                request(sparse_aes.request(), 1, aes(0x4368, 161, 127))?;
            }
            Self::HashAlpha { shake: s, transcript } => {
                NativeSource::Transcript(transcript).validate(prepared, context, operation, Role::HashAlphaTranscript)?;
                request(s.request(), 0, shake(transcript.source().air().byte_len(), 32))?;
            }
            Self::HashX { shake: s, transcript, sparse } => {
                NativeSource::Transcript(transcript).validate(prepared, context, operation, Role::HashXTranscript)?;
                NativeSource::Sparse(sparse).validate(prepared, context, operation, Role::HashXSparse)?;
                if sparse.kind() != SparseKind::ChallengeX44 { return Err(GraphParentFailure::Source); }
                request(s.request(), 0, shake(transcript.source().air().byte_len(), 137))?;
            }
        }
        Ok(())
    }
}
pub(super) fn validate_request(crypto: &crate::graph_crypto::Plan, actual: &crate::graph_crypto::Request,
    operation: usize, subrequest: u32, descriptor: RequestDescriptor) -> OwnedResult<()> {
    let expected_index = u32::try_from(operation).ok().and_then(|n| n.checked_mul(2)).and_then(|n| n.checked_add(subrequest));
    if !crypto.requests().iter().any(|known| core::ptr::eq(known, actual))
        || actual.operation_index() != operation || actual.subrequest() != subrequest
        || Some(actual.request_index()) != expected_index || actual.descriptor() != descriptor {
        return Err(GraphParentFailure::Coverage);
    }
    Ok(())
}
pub(super) fn validate_leaf(tree: &Plan, graph: &UnprovedRelationGraph, kind: AuxiliaryGraphKind,
    operation: usize, ordinal: usize) -> OwnedResult<()> {
    let leaf = tree.leaves().get(ordinal).ok_or(GraphParentFailure::Coverage)?;
    let family_matches = matches!((kind, graph.operations().get(operation)),
        (AuxiliaryGraphKind::SampleG, Some(Operation::SampleG { .. }))
        | (AuxiliaryGraphKind::ExpandAlpha, Some(Operation::ExpandAlpha { .. }))
        | (AuxiliaryGraphKind::HashAlpha, Some(Operation::HashAlpha { .. }))
        | (AuxiliaryGraphKind::HashX, Some(Operation::HashX { .. })));
    if !family_matches || leaf.kind() != &LeafKind::Operations(kind.family())
        || leaf.operation_indices() != [operation]
        || !leaf.polynomial_indices().iter().copied().eq(graph.polynomials().iter().enumerate().filter_map(|(i, node)|
            matches!(node.source, Source::Derived { operation: owner } if owner == operation).then_some(i)))
        || !leaf.byte_indices().iter().copied().eq(graph.bytes().iter().enumerate().filter_map(|(i, node)|
            (matches!(node.source, Source::Context | Source::StatementSeed)
                || matches!(node.source, Source::Derived { operation: owner } if owner == operation)).then_some(i))) {
        return Err(GraphParentFailure::Coverage);
    }
    Ok(())
}

#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod tests;
