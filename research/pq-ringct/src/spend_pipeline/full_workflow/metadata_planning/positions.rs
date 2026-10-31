//! Dense construction order derived from exact immutable member inventories.
use super::*;

fn positions(member: &PreparedWorkflowSources<'_>, family: ProducerFamily,
    selected: Option<usize>, reverse: bool) -> Result<(usize, Option<usize>)>
{
    let mut count = 0;
    let mut found = None;
    macro_rules! include {
        ($ordinal:expr, $belongs:expr) => {
            if $belongs {
                if reverse {
                    if selected == Some(count) { found = Some($ordinal); }
                } else if selected == Some($ordinal) { found = Some(count); }
                count = add(count, 1)?;
            }
        };
    }
    match family {
        ProducerFamily::Source => { include!(0, true); include!(1, true); }
        ProducerFamily::Fixed => { include!(0, true); }
        ProducerFamily::Uniform | ProducerFamily::Sparse | ProducerFamily::Transcript => {
            for (ordinal, request) in member.auxiliary_factory().requests().iter().enumerate() {
                include!(ordinal, matches!((family, request.kind()),
                    (ProducerFamily::Uniform, crate::graph_auxiliary::Kind::Uniform(_))
                    | (ProducerFamily::Sparse, crate::graph_auxiliary::Kind::Sparse(_))
                    | (ProducerFamily::Transcript, crate::graph_auxiliary::Kind::Transcript)));
            }
        }
        ProducerFamily::Affine | ProducerFamily::Ntt | ProducerFamily::Mul | ProducerFamily::GBound
        | ProducerFamily::Permutation | ProducerFamily::LinearMap => {
            for (ordinal, batch) in member.algebra().batches().iter().enumerate() {
                include!(ordinal, matches!((family, batch.kind()),
                    (ProducerFamily::Affine, ComponentKind::Affine { .. })
                    | (ProducerFamily::Ntt, ComponentKind::Ntt { .. })
                    | (ProducerFamily::Mul, ComponentKind::Mul { .. })
                    | (ProducerFamily::GBound, ComponentKind::GBound { .. })
                    | (ProducerFamily::Permutation, ComponentKind::Permutation { .. })
                    | (ProducerFamily::LinearMap, ComponentKind::LinearMap { .. })));
            }
        }
        ProducerFamily::Shake | ProducerFamily::Aes => {
            for (ordinal, request) in member.crypto().requests().iter().enumerate() {
                include!(ordinal, matches!((family, request.descriptor()),
                    (ProducerFamily::Shake, RequestDescriptor::Shake(_))
                    | (ProducerFamily::Aes, RequestDescriptor::Aes(_))));
            }
        }
        ProducerFamily::Equality | ProducerFamily::Parameters | ProducerFamily::Auxiliary => {
            for (ordinal, leaf) in member.plan().leaves().iter().enumerate() {
                include!(ordinal, matches!((family, leaf.kind()),
                    (ProducerFamily::Equality, LeafKind::Operations(OperationFamily::Equality))
                    | (ProducerFamily::Parameters, LeafKind::Operations(OperationFamily::ParametersPp))
                    | (ProducerFamily::Auxiliary, LeafKind::Operations(OperationFamily::SampleG
                        | OperationFamily::ExpandAlpha | OperationFamily::HashAlpha | OperationFamily::HashX))));
            }
        }
    }
    Ok((count, found))
}

impl<'a> SourceMetadataPlanningPlan<'a> {
    pub(crate) fn source_position(&self, member: MetadataMember<'_, 'a>,
        family: ProducerFamily, ordinal: usize) -> Result<usize>
    {
        if !member.belongs_to(self) { return Err(ClosureError::Identity); }
        let mut preceding = 0;
        for prior in &self.members[..member.ordinal] {
            preceding = add(preceding, positions(prior.get(), family, None, false)?.0)?;
        }
        let local = positions(member.prepared.get(), family, Some(ordinal), false)?.1
            .ok_or(ClosureError::Coverage)?;
        let position = add(preceding, local)?;
        if position >= self.counts.family(family) { return Err(ClosureError::Coverage); }
        Ok(position)
    }
}

impl SourceMetadataPlanningPlan<'_> {
    /// Diagnostic reverse lookup in the existing immutable dense family order.
    /// The source ordinal retains its original per-family semantics; this pair
    /// does not replace a PhaseBinding or confer member/operation authority.
    pub(crate) fn verification_source_position(&self, family: ProducerFamily, position: usize)
        -> Result<(usize, usize)>
    {
        if position >= self.counts.family(family) { return Err(ClosureError::Coverage); }
        let mut remaining = position;
        for (member, owner) in self.members.iter().enumerate() {
            let (count, source) = positions(owner.get(), family, Some(remaining), true)?;
            if remaining < count {
                return Ok((member, source.ok_or(ClosureError::Coverage)?));
            }
            remaining = remaining.checked_sub(count).ok_or(ClosureError::Overflow)?;
        }
        Err(ClosureError::Coverage)
    }

    pub(crate) fn verification_position_frame_bytes() -> Result<usize> {
        // Source/position counting shares positions()'s allocation-free match.
        // Include both its enumerated source slice iterator and caller member
        // iterator, references, scalar/index/Option/match frames and returned pair.
        [size_of::<Self>(), size_of::<ProducerFamily>(),
            size_of::<Result<(usize, Option<usize>)>>(), size_of::<Result<(usize, usize)>>(),
            size_of::<[usize; 32]>(), size_of::<[Option<usize>; 8]>(),
            size_of::<[&(); 16]>(), size_of::<[bool; 8]>(),
            size_of::<[core::iter::Enumerate<core::slice::Iter<'static, ()>>; 4]>()]
            .into_iter().try_fold(0usize, add)
    }
}
