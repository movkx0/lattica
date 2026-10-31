//! Allocation-free auxiliary construction inventory from the original member.
//! It carries exact requests and descriptors, never proof/phase authority.
use super::*;
use crate::{component_tree::native_shape::NativeDescriptor,
    graph_auxiliary::{AuxiliaryRequest, Kind}, graph_crypto::Request};

#[derive(Clone, Copy)]
pub(crate) struct AuxiliaryPreparedInventory<'a> {
    prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    kind: AuxiliaryGraphKind,
    ordinal: usize,
    operation: usize,
    requests: [Option<&'a Request>; 2],
    natives: [Option<&'a AuxiliaryRequest>; 2],
}

impl<'a> AuxiliaryPreparedInventory<'a> {
    /// Bootstrap reserves these fixed inspection/forwarding frames before
    /// calling the allocation-free selector or construction-bound query.
    pub(crate) fn inspection_requirements() -> OwnedResult<Requirements> {
        requirement(Category::PhaseScratch, bounds::frames()?)
    }
    pub(crate) fn new(prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
        ordinal: usize) -> OwnedResult<Self>
    {
        let member = prepared.get();
        let leaf = member.plan().leaves().get(ordinal).ok_or(GraphParentFailure::Coverage)?;
        let [operation] = leaf.operation_indices() else { return Err(GraphParentFailure::Coverage); };
        let operation = *operation;
        let kind = match leaf.kind() {
            LeafKind::Operations(OperationFamily::SampleG) => AuxiliaryGraphKind::SampleG,
            LeafKind::Operations(OperationFamily::ExpandAlpha) => AuxiliaryGraphKind::ExpandAlpha,
            LeafKind::Operations(OperationFamily::HashAlpha) => AuxiliaryGraphKind::HashAlpha,
            LeafKind::Operations(OperationFamily::HashX) => AuxiliaryGraphKind::HashX,
            _ => return Err(GraphParentFailure::Coverage),
        };
        sources::validate_leaf(member.plan(), member.graph(), kind, operation, ordinal)?;
        if prepared.compiled_source_fingerprint() != crate::graph_proofs::compiled_source_fingerprint() {
            return Err(GraphParentFailure::Source);
        }
        let native = |role: Role, expected: Kind| -> OwnedResult<&'a AuxiliaryRequest> {
            let mut found = member.auxiliary_factory().requests().iter()
                .filter(|request| request.operation_index() == operation && request.role() == role);
            let result = found.next().ok_or(GraphParentFailure::Coverage)?;
            if found.next().is_some() || result.kind() != expected {
                return Err(GraphParentFailure::Coverage);
            }
            Ok(result)
        };
        let crypto = |subrequest, descriptor| -> OwnedResult<&'a Request> {
            let mut found = member.crypto().requests().iter()
                .filter(|request| request.operation_index() == operation && request.subrequest() == subrequest);
            let result = found.next().ok_or(GraphParentFailure::Coverage)?;
            if found.next().is_some() { return Err(GraphParentFailure::Coverage); }
            sources::validate_request(member.crypto(), result, operation, subrequest, descriptor)?;
            Ok(result)
        };
        let aes = |domain, start_counter, output_len| RequestDescriptor::Aes(crate::aes_air::Descriptor {
            domain, start_counter, output_len,
        });
        let shake = |input_len, output_len| RequestDescriptor::Shake(crate::shake_air::Descriptor { input_len, output_len });
        let (requests, natives) = match kind {
            AuxiliaryGraphKind::SampleG => (
                [Some(crypto(0, aes(0, 0, 1197 * 4))?), None],
                [Some(native(Role::SampleGUniform, Kind::Uniform(crate::uniform_air::Kind::SampleG4))?), None]),
            AuxiliaryGraphKind::ExpandAlpha => (
                [Some(crypto(0, aes(0x4368, 0, 2572))?), Some(crypto(1, aes(0x4368, 161, 127))?)],
                [Some(native(Role::AlphaUniform, Kind::Uniform(crate::uniform_air::Kind::ExpandAlpha2))?),
                 Some(native(Role::AlphaSparse, Kind::Sparse(crate::sparse_air::Kind::AlphaPrime39))?)]),
            AuxiliaryGraphKind::HashAlpha => {
                let transcript = native(Role::HashAlphaTranscript, Kind::Transcript)?;
                let air = transcript.transcript_air().ok_or(GraphParentFailure::Source)?;
                ([Some(crypto(0, shake(air.byte_len(), 32))?), None], [Some(transcript), None])
            }
            AuxiliaryGraphKind::HashX => {
                let transcript = native(Role::HashXTranscript, Kind::Transcript)?;
                let air = transcript.transcript_air().ok_or(GraphParentFailure::Source)?;
                ([Some(crypto(0, shake(air.byte_len(), 137))?), None],
                 [Some(transcript), Some(native(Role::HashXSparse, Kind::Sparse(crate::sparse_air::Kind::ChallengeX44))?)])
            }
        };
        if member.crypto().requests().iter().filter(|r| r.operation_index() == operation).count()
                != requests.iter().flatten().count()
            || member.auxiliary_factory().requests().iter().filter(|r| r.operation_index() == operation).count()
                != natives.iter().flatten().count()
        { return Err(GraphParentFailure::Coverage); }
        let result = Self { prepared, kind, ordinal, operation, requests, natives };
        // Pure geometry validates transcript parts and every closed descriptor.
        for descriptor in result.descriptors()?.into_iter().flatten() {
            descriptor.geometry().map_err(|_| GraphParentFailure::Source)?;
        }
        Ok(result)
    }

    pub(crate) fn prepared(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.prepared }
    pub(crate) fn kind(self) -> AuxiliaryGraphKind { self.kind }
    pub(crate) fn ordinal(self) -> usize { self.ordinal }
    pub(crate) fn operation_index(self) -> usize { self.operation }
    pub(super) fn requests(self) -> [Option<&'a Request>; 2] { self.requests }
    pub(super) fn descriptors(self) -> OwnedResult<[Option<NativeDescriptor<'a>>; 2]> {
        let mut descriptors = [None; 2];
        for (out, request) in descriptors.iter_mut().zip(self.natives) {
            *out = match request {
                None => None,
                Some(request) => Some(match request.kind() {
                    Kind::Uniform(kind) => NativeDescriptor::Uniform(kind),
                    Kind::Sparse(kind) => NativeDescriptor::Sparse(kind),
                    Kind::Transcript => NativeDescriptor::Transcript(request.transcript_air()
                        .ok_or(GraphParentFailure::Source)?.parts()),
                }),
            };
        }
        Ok(descriptors)
    }
    pub(crate) fn planning_scratch_requirements(self) -> OwnedResult<Requirements> {
        bounds::prepared_planning_scratch_requirements(self)
    }
    /// Full-plan binding compares exact original request owners as well as the
    /// operation family and ordinal; matching request counts is insufficient.
    pub(crate) fn validate_plans(self, sources: AuxiliaryGraphSources<'_, 'a>,
        context: &ProvingContext) -> OwnedResult<()> {
        sources.validate(self.prepared, context, self.ordinal)?;
        if sources.kind() != self.kind || sources.operation_index() != self.operation {
            return Err(GraphParentFailure::Source);
        }
        for (actual, expected) in sources.requests().into_iter().zip(self.requests) {
            match (actual, expected) {
                (None, None) => (),
                (Some(actual), Some(expected)) if core::ptr::eq(actual.request(), expected) => (),
                _ => return Err(GraphParentFailure::Source),
            }
        }
        for (actual, expected) in sources.natives().into_iter().zip(self.natives) {
            let actual = actual.map(|source| match source {
                sources::NativeSource::Uniform(p) => p.request(),
                sources::NativeSource::Sparse(p) => p.request(),
                sources::NativeSource::Transcript(p) => p.request(),
            });
            match (actual, expected) {
                (None, None) => (),
                (Some(actual), Some(expected)) if core::ptr::eq(actual, expected) => (),
                _ => return Err(GraphParentFailure::Source),
            }
        }
        Ok(())
    }
}
