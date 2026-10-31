//! Sealed accepted child owners. Parent owners are constructed only by the
//! actual source-captured parent producer, never by a numerical ordinal/cap.
use super::*;

pub(in crate::component_tree::owned_shake) enum AcceptedChild<'bound, 'source, 'request> {
    Leaf(AcceptedLeaf<'bound, 'source, 'request>),
    Parent(AcceptedParent<'bound, 'source, 'request>),
}

#[derive(Clone, Copy, Debug)]
pub(in crate::component_tree::owned_shake) struct ParentAcceptanceReport {
    pub(in crate::component_tree::owned_shake) parent: usize,
    pub(in crate::component_tree::owned_shake) height: usize,
    pub(in crate::component_tree::owned_shake) cpu_heights_admitted: usize,
    pub(in crate::component_tree::owned_shake) independent_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) retirement: Retirement,
    pub(in crate::component_tree::owned_shake) source_key_authenticated: bool,
    pub(in crate::component_tree::owned_shake) transaction_context_authenticated: bool,
    pub(in crate::component_tree::owned_shake) workflow_admitted: bool,
}

/// No raw constructor, cap/key/proof getter, Clone or compiler borrow. Actual
/// source acceptance must destroy its independent verifier before retaining
/// the original metadata claim in this owner.
pub(in crate::component_tree::owned_shake) struct AcceptedParent<'bound, 'source, 'request> {
    output: RetainedNodeOutput<'request>,
    source: &'bound Source<'source, 'request>,
    ordinal: usize,
    height: usize,
    cap: [[Val; 4]; ROOTS],
    report: ParentAcceptanceReport,
    original: Reservation,
}

pub(in crate::component_tree::owned_shake) struct PreissuedParentAcceptance<
    'bound,
    'source,
    'request,
> {
    source: &'bound Source<'source, 'request>,
    ordinal: usize,
    cpu: CpuEnvelope,
    original: Reservation,
}

pub(in crate::component_tree::owned_shake) struct CapturedParentAcceptance<
    'compiled,
    'bound,
    'source,
    'request,
> {
    compiled: &'compiled CompiledLeafParent<'bound, 'source, 'request>,
    verifier: RegisteredVerifier,
    cap: [[Val; 4]; ROOTS],
    source: &'bound Source<'source, 'request>,
    ordinal: usize,
    cpu: CpuEnvelope,
    original: Reservation,
}

pub(super) fn additional_host_bytes() -> Result<usize> {
    let parts = [
        frames::<AcceptedChild<'static, 'static, 'static>>(8)?,
        frames::<AcceptedParent<'static, 'static, 'static>>(8)?,
        frames::<Result<AcceptedParent<'static, 'static, 'static>>>(8)?,
        frames::<PreissuedParentAcceptance<'static, 'static, 'static>>(8)?,
        frames::<CapturedParentAcceptance<'static, 'static, 'static, 'static>>(8)?,
        frames::<Result<PreissuedParentAcceptance<'static, 'static, 'static>>>(8)?,
        frames::<Result<CapturedParentAcceptance<'static, 'static, 'static, 'static>>>(8)?,
        frames::<RegisteredVerifier>(8)?,
        frames::<CpuEnvelope>(8)?,
        frames::<Result<CpuEnvelope>>(8)?,
        frames::<&RegisteredProgram>(8)?,
        frames::<&CompiledLeafParent<'static, 'static, 'static>>(8)?,
        frames::<std::time::Instant>(8)?,
        frames::<core::result::Result<(), String>>(8)?,
        frames::<Result<u128>>(8)?,
        frames::<Retirement>(8)?,
        frames::<ParentAcceptanceReport>(8)?,
        frames::<SourceNode>(16)?,
        frames::<[[Val; 4]; ROOTS]>(8)?,
        frames::<&RetainedNodeOutput<'static>>(8)?,
        frames::<&Source<'static, 'static>>(8)?,
        frames::<&[[Val; 4]; ROOTS]>(8)?,
        frames::<&AcceptedChild<'static, 'static, 'static>>(8)?,
        frames::<Result<()>>(8)?,
        frames::<Requirements>(8)?,
        frames::<Reservation>(8)?,
        frames::<usize>(32)?,
        frames::<bool>(8)?,
        64 << 10,
    ];
    let helper = super::super::super::super::times(8, size_of_val(&parts))?;
    parts
        .into_iter()
        .try_fold(helper, super::super::super::super::add)
}

pub(super) fn retained_requirement() -> Result<Requirements> {
    super::super::super::super::requirement(Category::RegisteredMetadata, additional_host_bytes()?)
}

pub(super) fn acceptance_requirement(cpu: CpuEnvelope) -> Result<Requirements> {
    let mut whole = retained_requirement()?;
    whole
        .add(
            Category::IndependentVerifier,
            Bytes {
                host: u64::try_from(cpu.bytes).map_err(|_| Error::Overflow)?,
                device: 0,
            },
        )
        .map_err(|_| Error::Overflow)?;
    Ok(whole)
}

impl<'source, 'request> ParentSourceBound<'source, 'request> {
    pub(in crate::component_tree::owned_shake) fn preissue_parent_acceptance<'bound>(
        &'bound self,
        ordinal: usize,
        ledger: &Ledger,
    ) -> Result<PreissuedParentAcceptance<'bound, 'source, 'request>> {
        if !self.is_for(self.request, ledger) {
            return Err(Error::Authority);
        }
        specs(self, ordinal)?;
        let cpu = CpuEnvelope::source()?;
        let original = ledger
            .admit_phase(acceptance_requirement(cpu)?)
            .map_err(|_| Error::Capacity)?;
        Ok(PreissuedParentAcceptance {
            source: self,
            ordinal,
            cpu,
            original,
        })
    }
}

impl<'bound, 'source, 'request> PreissuedParentAcceptance<'bound, 'source, 'request> {
    pub(in crate::component_tree::owned_shake) fn check_compiled(
        &self,
        compiled: &CompiledLeafParent<'bound, 'source, 'request>,
        ledger: &Ledger,
    ) -> Result<()> {
        if !self.original.belongs_to(ledger)
            || self.original.requirements() != acceptance_requirement(self.cpu)?
            || !core::ptr::eq(self.source, compiled.source)
            || self.ordinal != compiled.report.ordinal
            || !self.source.is_for(self.source.request, ledger)
            || !compiled.original.belongs_to(ledger)
            || compiled.original.requirements() != Storage::source()?.complete
        {
            return Err(Error::Authority);
        }
        let (_, expected) = specs(self.source, self.ordinal)?;
        let node = &compiled.payload.0;
        if node.spec != expected[2]
            || compiled.report.independently_authenticated_children != 2
            || compiled.report.parent_proof_generated
            || compiled.report.workflow_admitted
            || node.program.height() != compiled.report.padded_rows
            || node.program.public_values() != PUBLICS
            || node.public.len() != PUBLICS
            || node.witness.len() != node.program.witness_values()
        {
            return Err(Error::Source);
        }
        super::super::super::super::shape(node.program.height())?;
        Ok(())
    }

    pub(in crate::component_tree::owned_shake) fn capture<'compiled>(
        self,
        compiled: &'compiled CompiledLeafParent<'bound, 'source, 'request>,
        registered: &RegisteredProgram,
        ledger: &Ledger,
    ) -> Result<CapturedParentAcceptance<'compiled, 'bound, 'source, 'request>> {
        self.check_compiled(compiled, ledger)?;
        if !super::super::super::same_program(
            &compiled.payload.0.program,
            registered.air().program(),
        ) {
            return Err(Error::Source);
        }
        let commitment = registered.preprocessing_cap();
        if commitment.roots().len() != ROOTS || commitment.root_capacity() != ROOTS {
            return Err(Error::Source);
        }
        let mut cap = [[Val::ZERO; 4]; ROOTS];
        cap.copy_from_slice(commitment.roots());
        Ok(CapturedParentAcceptance {
            compiled,
            verifier: registered.verifier(),
            cap,
            source: self.source,
            ordinal: self.ordinal,
            cpu: self.cpu,
            original: self.original,
        })
    }
}

impl CapturedParentAcceptance<'_, '_, '_, '_> {
    pub(in crate::component_tree::owned_shake) fn verify_original_output(
        &self,
        key: &NodeKey,
        proof: &NodeProof,
        request: &crate::graph_crypto::ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<u128> {
        if !self.original.belongs_to(ledger)
            || self.original.requirements() != acceptance_requirement(self.cpu)?
            || !self.source.is_for(self.source.request, ledger)
            || !core::ptr::eq(request, self.source.request.owner)
            || !core::ptr::eq(self.compiled.source, self.source)
            || self.compiled.report.ordinal != self.ordinal
        {
            return Err(Error::Authority);
        }
        let node = &self.compiled.payload.0;
        if !exact_binding(
            &node.spec,
            node.program.height(),
            &node.public,
            &self.cap,
            &key.spec,
            key.height,
            &proof.public,
            &key.cap,
            key.cap.capacity(),
        ) {
            return Err(Error::Source);
        }
        let started = std::time::Instant::now();
        self.verifier
            .verify(&proof.proof, &proof.public)
            .map_err(|_| Error::Source)?;
        Ok(started.elapsed().as_nanos())
    }
}

impl AcceptedChild<'_, '_, '_> {
    #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn recheck_interior_opening(
        &mut self,
        action: &crate::component_tree::owned_shake::request_merge::InteriorOpeningAction<'_, '_, '_, '_>,
    ) -> Result<crate::component_tree::owned_shake::request_merge::InteriorOpeningMeasurements> {
        match self {
            Self::Leaf(child) => child.output.recheck_interior_opening(action),
            Self::Parent(_) => Err(Error::Source),
        }
    }

    #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn recheck_root_opening(
        &mut self,
        action: &crate::component_tree::owned_shake::request_merge::RootOpeningRecheckAction<'_, '_, '_, '_>,
    ) -> Result<crate::component_tree::owned_shake::request_merge::RootOpeningMeasurements> {
        match self {
            Self::Parent(child) => child.output.recheck_root_opening(action),
            Self::Leaf(_) => Err(Error::Source),
        }
    }

    pub(super) fn check_original(
        &self,
        source: &Source<'_, '_>,
        expected: SourceNode,
        ledger: &Ledger,
    ) -> Result<()> {
        match (self, expected) {
            (Self::Leaf(child), SourceNode::Leaf(index)) => {
                original_leaf(child, source, index, ledger)
            }
            (Self::Parent(child), SourceNode::Parent(index)) => {
                if !core::ptr::eq(child.source, source)
                    || child.ordinal != index
                    || !child.original.belongs_to(ledger)
                    || child.original.requirements() != retained_requirement()?
                    || !child.output.belongs_to(ledger)
                    || !child.output.report().independent_verification_complete
                    || !child.output.report().authenticated_source_key
                    || child.output.report().transaction_context_authenticated
                    || child.output.report().workflow_admitted
                    || child.report.parent != index
                    || child.report.height != child.height
                    || child.report.cpu_heights_admitted != 18
                    || !child.report.source_key_authenticated
                    || child.report.transaction_context_authenticated
                    || child.report.workflow_admitted
                {
                    return Err(Error::Authority);
                }
                super::super::super::super::shape(child.height)?;
                Ok(())
            }
            _ => Err(Error::Source),
        }
    }

    pub(super) fn output(&self) -> &RetainedNodeOutput<'_> {
        match self {
            Self::Leaf(v) => &v.output,
            Self::Parent(v) => &v.output,
        }
    }
    pub(super) fn source(&self) -> &Source<'_, '_> {
        match self {
            Self::Leaf(v) => v.source,
            Self::Parent(v) => v.source,
        }
    }
    pub(super) fn height(&self) -> usize {
        match self {
            Self::Leaf(v) => v.height,
            Self::Parent(v) => v.height,
        }
    }
    pub(super) fn cap(&self) -> &[[Val; 4]; ROOTS] {
        match self {
            Self::Leaf(v) => &v.cap,
            Self::Parent(v) => &v.cap,
        }
    }
}

impl AcceptedParent<'_, '_, '_> {
    pub(in crate::component_tree::owned_shake) fn report(&self) -> ParentAcceptanceReport {
        self.report
    }
}

impl<'bound, 'source, 'request> CapturedParentAcceptance<'_, 'bound, 'source, 'request> {
    /// Only the closed producer calls this after finishing its actual session.
    /// The original A continuation is checked against this exact source request;
    /// a numerical retirement or cap is never accepted as authority.
    pub(in crate::component_tree::owned_shake) fn accept_retired(
        self,
        mut output: RetainedNodeOutput<'request>,
        originals: &crate::graph_crypto::RetiredHashxOuterOriginals<'request>,
        ledger: &Ledger,
    ) -> Result<AcceptedParent<'bound, 'source, 'request>> {
        use crate::graph_crypto::HashxOuterStep;
        let expected = match self.ordinal {
            0 => HashxOuterStep::Parent0,
            1 => HashxOuterStep::Parent1,
            2 => HashxOuterStep::Parent2,
            3 => HashxOuterStep::Parent3,
            _ => return Err(Error::Source),
        };
        let retirement = originals
            .check(self.source.request.owner, ledger)
            .map_err(|_| Error::Authority)?;
        if originals.outer_step().map_err(|_| Error::Authority)? != expected {
            return Err(Error::Source);
        }
        let elapsed = output
            .authenticate_parent_source(&self, ledger)
            .map_err(|_| Error::Source)?;
        let Self {
            compiled,
            verifier,
            cap,
            source,
            ordinal,
            cpu,
            mut original,
        } = self;
        let height = compiled.payload.0.program.height();
        // Destroy the actual independent verifier before returning its scratch.
        drop(verifier);
        let retained = original
            .split(retained_requirement()?)
            .map_err(|_| Error::Authority)?;
        drop(original);
        Ok(AcceptedParent {
            output,
            source,
            ordinal,
            height,
            cap,
            report: ParentAcceptanceReport {
                parent: ordinal,
                height,
                cpu_heights_admitted: cpu.heights,
                independent_verification_ns: elapsed,
                retirement,
                source_key_authenticated: true,
                transaction_context_authenticated: false,
                workflow_admitted: false,
            },
            original: retained,
        })
    }
}
