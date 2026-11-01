//! Dense construction order derived from exact immutable member inventories.
use super::*;

fn visit_sources(
    member: &PreparedWorkflowSources<'_>,
    family: ProducerFamily,
    mut visit: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    macro_rules! include {
        ($ordinal:expr, $belongs:expr) => {
            if $belongs {
                visit($ordinal)?;
            }
        };
    }
    match family {
        ProducerFamily::Source => {
            include!(0, true);
            include!(1, true);
        }
        ProducerFamily::Fixed => {
            include!(0, true);
        }
        ProducerFamily::Uniform | ProducerFamily::Sparse | ProducerFamily::Transcript => {
            for (ordinal, request) in member.auxiliary_factory().requests().iter().enumerate() {
                include!(
                    ordinal,
                    matches!(
                        (family, request.kind()),
                        (
                            ProducerFamily::Uniform,
                            crate::graph_auxiliary::Kind::Uniform(_)
                        ) | (
                            ProducerFamily::Sparse,
                            crate::graph_auxiliary::Kind::Sparse(_)
                        ) | (
                            ProducerFamily::Transcript,
                            crate::graph_auxiliary::Kind::Transcript
                        )
                    )
                );
            }
        }
        ProducerFamily::Affine
        | ProducerFamily::Ntt
        | ProducerFamily::Mul
        | ProducerFamily::GBound
        | ProducerFamily::Permutation
        | ProducerFamily::LinearMap => {
            for (ordinal, batch) in member.algebra().batches().iter().enumerate() {
                include!(
                    ordinal,
                    matches!(
                        (family, batch.kind()),
                        (ProducerFamily::Affine, ComponentKind::Affine { .. })
                            | (ProducerFamily::Ntt, ComponentKind::Ntt { .. })
                            | (ProducerFamily::Mul, ComponentKind::Mul { .. })
                            | (ProducerFamily::GBound, ComponentKind::GBound { .. })
                            | (
                                ProducerFamily::Permutation,
                                ComponentKind::Permutation { .. }
                            )
                            | (ProducerFamily::LinearMap, ComponentKind::LinearMap { .. })
                    )
                );
            }
        }
        ProducerFamily::Shake | ProducerFamily::Aes => {
            for (ordinal, request) in member.crypto().requests().iter().enumerate() {
                include!(
                    ordinal,
                    matches!(
                        (family, request.descriptor()),
                        (ProducerFamily::Shake, RequestDescriptor::Shake(_))
                            | (ProducerFamily::Aes, RequestDescriptor::Aes(_))
                    )
                );
            }
        }
        ProducerFamily::Equality | ProducerFamily::Parameters | ProducerFamily::Auxiliary => {
            for (ordinal, leaf) in member.plan().leaves().iter().enumerate() {
                include!(
                    ordinal,
                    matches!(
                        (family, leaf.kind()),
                        (
                            ProducerFamily::Equality,
                            LeafKind::Operations(OperationFamily::Equality)
                        ) | (
                            ProducerFamily::Parameters,
                            LeafKind::Operations(OperationFamily::ParametersPp)
                        ) | (
                            ProducerFamily::Auxiliary,
                            LeafKind::Operations(
                                OperationFamily::SampleG
                                    | OperationFamily::ExpandAlpha
                                    | OperationFamily::HashAlpha
                                    | OperationFamily::HashX
                            )
                        )
                    )
                );
            }
        }
    }
    Ok(())
}

const FAMILIES_IN_ORDER: [ProducerFamily; FAMILIES] = [
    ProducerFamily::Source,
    ProducerFamily::Uniform,
    ProducerFamily::Sparse,
    ProducerFamily::Transcript,
    ProducerFamily::Affine,
    ProducerFamily::Ntt,
    ProducerFamily::Mul,
    ProducerFamily::GBound,
    ProducerFamily::Permutation,
    ProducerFamily::LinearMap,
    ProducerFamily::Fixed,
    ProducerFamily::Parameters,
    ProducerFamily::Auxiliary,
    ProducerFamily::Equality,
    ProducerFamily::Shake,
    ProducerFamily::Aes,
];

/// Pure positions only. The original outlives all vector backings, including
/// partial construction on refusal. No source or execution authority is stored.
pub(super) struct SourcePositions {
    families: [Vec<(usize, usize)>; FAMILIES],
    _original: Reservation,
}
impl SourcePositions {
    fn requirements(counts: ProducerCounts) -> Result<Requirements> {
        let count = counts.families.into_iter().try_fold(0, add)?;
        // Exact reservations are requested; retain room for a rounded capacity
        // and reject any capacity beyond that envelope before populating it.
        let backing = mul(mul(count, 2)?, size_of::<(usize, usize)>())?;
        Ok(Requirements::single(
            Category::RegisteredMetadata,
            host(backing)?,
        ))
    }
    fn allocate(counts: ProducerCounts, original: Reservation, ledger: &Ledger) -> Result<Self> {
        if !original.belongs_to(ledger) || original.requirements() != Self::requirements(counts)? {
            return Err(ClosureError::Resource);
        }
        let mut result = Self {
            families: core::array::from_fn(|_| Vec::new()),
            _original: original,
        };
        for (entries, count) in result.families.iter_mut().zip(counts.families) {
            entries
                .try_reserve_exact(count)
                .map_err(|_| ClosureError::Resource)?;
            if entries.capacity() > mul(count, 2)? {
                return Err(ClosureError::Resource);
            }
        }
        Ok(result)
    }
    fn push(
        &mut self,
        counts: ProducerCounts,
        family: ProducerFamily,
        entry: (usize, usize),
    ) -> Result<()> {
        let entries = &mut self.families[family as usize];
        if entries.len() >= counts.family(family)
            || entries.last().is_some_and(|previous| *previous >= entry)
        {
            return Err(ClosureError::Coverage);
        }
        entries.push(entry);
        Ok(())
    }
    fn complete(&self, counts: ProducerCounts) -> Result<()> {
        if self
            .families
            .iter()
            .zip(counts.families)
            .any(|(v, n)| v.len() != n)
        {
            return Err(ClosureError::Coverage);
        }
        Ok(())
    }
    fn forward(&self, family: ProducerFamily, entry: (usize, usize)) -> Result<usize> {
        self.families[family as usize]
            .binary_search(&entry)
            .map_err(|_| ClosureError::Coverage)
    }
    fn reverse(&self, family: ProducerFamily, position: usize) -> Result<(usize, usize)> {
        self.families[family as usize]
            .get(position)
            .copied()
            .ok_or(ClosureError::Coverage)
    }
}

impl<'a> SourceMetadataPlanningPlan<'a> {
    pub(crate) fn position_requirements(&self) -> Result<Requirements> {
        SourcePositions::requirements(self.counts)
    }
    /// Called only after the complete construction envelope has been admitted.
    pub(crate) fn initialize_positions(&self, original: Reservation) -> Result<()> {
        if self.positions.get().is_some() {
            return Err(ClosureError::Order);
        }
        let mut index = SourcePositions::allocate(self.counts, original, &self.ledger)?;
        for (member, owner) in self.members.iter().enumerate() {
            for family in FAMILIES_IN_ORDER {
                visit_sources(owner.get(), family, |source| {
                    index.push(self.counts, family, (member, source))
                })?;
            }
        }
        index.complete(self.counts)?;
        self.positions.set(index).map_err(|_| ClosureError::Order)
    }
    pub(crate) fn source_position(
        &self,
        member: MetadataMember<'_, 'a>,
        family: ProducerFamily,
        ordinal: usize,
    ) -> Result<usize> {
        if !member.belongs_to(self) {
            return Err(ClosureError::Identity);
        }
        self.positions
            .get()
            .ok_or(ClosureError::Order)?
            .forward(family, (member.ordinal, ordinal))
    }
    /// Diagnostic numeric lookup; member authentication remains in the caller.
    pub(crate) fn verification_source_position(
        &self,
        family: ProducerFamily,
        position: usize,
    ) -> Result<(usize, usize)> {
        self.positions
            .get()
            .ok_or(ClosureError::Order)?
            .reverse(family, position)
    }
    pub(crate) fn verification_position_frame_bytes() -> Result<usize> {
        [
            size_of::<Self>(),
            size_of::<ProducerFamily>(),
            size_of::<SourcePositions>(),
            size_of::<Result<(usize, usize)>>(),
            size_of::<[usize; 32]>(),
            size_of::<[Option<usize>; 8]>(),
            size_of::<[&(); 16]>(),
            size_of::<[bool; 8]>(),
        ]
        .into_iter()
        .try_fold(0usize, add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;
    #[test]
    fn partial_index_refusal_releases_backing_and_rejects_wrong_ledger() {
        let ledger = Ledger::new(WorkerAllowance {
            host: 1 << 20,
            device: 0,
        });
        let other = Ledger::new(WorkerAllowance {
            host: 1 << 20,
            device: 0,
        });
        let mut counts = ProducerCounts::default();
        counts.add(ProducerFamily::Aes, 2).unwrap();
        let requirements = SourcePositions::requirements(counts).unwrap();
        assert!(SourcePositions::allocate(
            counts,
            ledger.admit_phase(requirements).unwrap(),
            &other
        )
        .is_err());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        let mut index =
            SourcePositions::allocate(counts, ledger.admit_phase(requirements).unwrap(), &ledger)
                .unwrap();
        index.push(counts, ProducerFamily::Aes, (1, 3)).unwrap();
        assert!(index.push(counts, ProducerFamily::Aes, (1, 3)).is_err());
        assert!(index.push(counts, ProducerFamily::Aes, (0, 4)).is_err());
        assert!(index.complete(counts).is_err());
        drop(index);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    #[test]
    fn index_preserves_dense_family_order_and_releases_its_original() {
        let ledger = Ledger::new(WorkerAllowance {
            host: 1 << 20,
            device: 0,
        });
        let mut counts = ProducerCounts::default();
        counts.add(ProducerFamily::Ntt, 3).unwrap();
        counts.add(ProducerFamily::Mul, 1).unwrap();
        let requirements = SourcePositions::requirements(counts).unwrap();
        let original = ledger.admit_phase(requirements).unwrap();
        let mut index = SourcePositions::allocate(counts, original, &ledger).unwrap();
        for entry in [(0, 2), (0, 7), (2, 1)] {
            index.push(counts, ProducerFamily::Ntt, entry).unwrap();
        }
        assert!(index.complete(counts).is_err());
        index.push(counts, ProducerFamily::Mul, (1, 3)).unwrap();
        index.complete(counts).unwrap();
        for (position, entry) in [(0, 2), (0, 7), (2, 1)].into_iter().enumerate() {
            assert_eq!(index.forward(ProducerFamily::Ntt, entry).unwrap(), position);
            assert_eq!(index.reverse(ProducerFamily::Ntt, position).unwrap(), entry);
        }
        assert!(index.forward(ProducerFamily::Ntt, (1, 3)).is_err());
        assert!(index.reverse(ProducerFamily::Ntt, 3).is_err());
        assert!(index.push(counts, ProducerFamily::Mul, (1, 3)).is_err());
        drop(index);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
