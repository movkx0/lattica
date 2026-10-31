//! Source-authenticated leaf acceptance after the same actual outer retirement.
//! Only the closed producer's opaque RetiredLeafAttempt can reach acceptance.
use super::*;
use crate::component_tree::{
    owned_shake::{
        outer_producer::{RetiredLeafAttempt, RetiredOuterOriginals},
        output::RetainedNodeOutput,
    },
    NodeKey, NodeProof, RegisteredVerifier, Spec, HEADER,
};
use lattica_prover_p3::block_v2::gpu_hash::device::ringct_runtime::Retirement;

mod parent;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use parent::{
    InteriorOpeningAction, InteriorOpeningMeasurements,
    RootOpeningRecheckAction, RootOpeningMeasurements,
    RootTransportAction, RootTransportMeasurements,
    RootPublicRecheckAction, RootPublicRecheckReport,
};
pub(in crate::component_tree::owned_shake) use parent::{
    CompiledLeafParent, EmittedParentChild, LeafParentCompilationReport, ParentChildEmission,
    PreissuedLeafParentCompiler,
};

mod hashx;
pub(in crate::component_tree::owned_shake) use hashx::{
    authenticate_retired_hashx_leaf, AcceptedHashxLeafCompletion,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuEnvelope {
    bytes: usize,
    heights: usize,
}

impl CpuEnvelope {
    fn source() -> Result<Self> {
        let mut bytes = 0;
        let mut heights = 0;
        for log in 3..=crate::component_tree::owned_shake::MAX_ROWS.ilog2() {
            let child = shape(1 << log)?;
            if child.public_values != HEADER + 8 || child.preprocessing_cap_roots != ROOTS {
                return Err(Error::Source);
            }
            bytes = bytes.max(
                RegisteredVerifier::host_reservation_bytes(
                    child.public_values,
                    child.height,
                    ROOTS,
                    ROOTS,
                )
                .map_err(|_| Error::Source)?,
            );
            heights += 1;
        }
        Ok(Self { bytes, heights })
    }
}

pub(in crate::component_tree::owned_shake) struct PreissuedLeafAcceptance<'bound, 'source, 'request>
{
    cap: PreissuedLeafCap<'bound, 'source, 'request>,
    cpu: CpuEnvelope,
    original: Reservation,
}

/// The second independent verifier is reconstructed from this same actual
/// registration's cap, before registration consumption. Its whole lifecycle
/// remains precharged alongside the output's independently retained key.
pub(in crate::component_tree::owned_shake) struct CapturedLeafAcceptance<
    'compiled,
    'bound,
    'source,
    'request,
> {
    cap: CapturedLeafCap<'compiled, 'bound, 'source, 'request>,
    verifier: RegisteredVerifier,
    cpu: CpuEnvelope,
    original: Reservation,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::component_tree::owned_shake) struct LeafAcceptanceReport {
    pub(in crate::component_tree::owned_shake) leaf: usize,
    pub(in crate::component_tree::owned_shake) height: usize,
    pub(in crate::component_tree::owned_shake) cpu_heights_admitted: usize,
    pub(in crate::component_tree::owned_shake) cpu_reserved_bytes: usize,
    pub(in crate::component_tree::owned_shake) independent_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) retirement: Retirement,
    pub(in crate::component_tree::owned_shake) source_key_authenticated: bool,
    pub(in crate::component_tree::owned_shake) transaction_context_authenticated: bool,
    pub(in crate::component_tree::owned_shake) workflow_admitted: bool,
}

/// No compiler/program/witness borrow survives numerical acceptance. Original
/// proof/key/report and fixed cap claims remain owned; no raw getters exist.
/// This authenticates one request-local component, not the transaction context.
pub(in crate::component_tree::owned_shake) struct AcceptedLeaf<'bound, 'source, 'request> {
    output: RetainedNodeOutput<'request>,
    source: &'bound ParentSourceBound<'source, 'request>,
    index: usize,
    height: usize,
    cap: [[Val; 4]; ROOTS],
    report: LeafAcceptanceReport,
    cap_original: Reservation,
    original: Reservation,
}

pub(in crate::component_tree::owned_shake) struct AcceptedLeafCompletion<'bound, 'source, 'request>
{
    leaf: AcceptedLeaf<'bound, 'source, 'request>,
    originals: RetiredOuterOriginals<'request>,
}

fn metadata_requirement() -> Result<Requirements> {
    let parts = [
        8 * size_of::<PreissuedLeafAcceptance<'static, 'static, 'static>>(),
        8 * size_of::<Result<PreissuedLeafAcceptance<'static, 'static, 'static>>>(),
        8 * size_of::<CapturedLeafAcceptance<'static, 'static, 'static, 'static>>(),
        8 * size_of::<Result<CapturedLeafAcceptance<'static, 'static, 'static, 'static>>>(),
        8 * size_of::<AcceptedLeaf<'static, 'static, 'static>>(),
        8 * size_of::<Result<AcceptedLeaf<'static, 'static, 'static>>>(),
        8 * size_of::<AcceptedLeafCompletion<'static, 'static, 'static>>(),
        8 * size_of::<Result<AcceptedLeafCompletion<'static, 'static, 'static>>>(),
        8 * size_of::<RetiredLeafAttempt<'static, 'static, 'static, 'static>>(),
        8 * size_of::<Result<RetiredLeafAttempt<'static, 'static, 'static, 'static>>>(),
        8 * size_of::<(
            CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
            RetainedNodeOutput<'static>,
            RetiredOuterOriginals<'static>,
            Ledger,
        )>(),
        8 * size_of::<(
            CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
            RetainedNodeOutput<'static>,
            Retirement,
            &Ledger,
        )>(),
        8 * size_of::<
            Result<(
                RetainedNodeOutput<'static>,
                CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
            )>,
        >(),
        8 * size_of::<RegisteredVerifier>(),
        8 * size_of::<Spec>(),
        8 * size_of::<LeafAcceptanceReport>(),
        8 * size_of::<Retirement>(),
        8 * size_of::<CpuEnvelope>(),
        8 * size_of::<Result<CpuEnvelope>>(),
        8 * size_of::<Requirements>(),
        8 * size_of::<Reservation>(),
        8 * size_of::<Result<Requirements>>(),
        8 * size_of::<Result<u128>>(),
        8 * size_of::<std::time::Instant>(),
        8 * size_of::<core::result::Result<(), String>>(),
        8 * size_of::<[Val; HEADER + 8]>(),
        // Concrete producer forwarding/destructure/return, iterator and
        // bounded diagnostic frames are additive to the existing producer.
        64 << 10,
        RetiredLeafAttempt::additional_host_bytes().ok_or(Error::Overflow)?,
    ];
    let helper = super::super::times(8, size_of_val(&parts))?;
    let bytes = parts.into_iter().try_fold(helper, super::super::add)?;
    super::super::requirement(Category::RegisteredMetadata, bytes)
}

fn whole_requirement(cpu: CpuEnvelope) -> Result<Requirements> {
    let mut whole = metadata_requirement()?;
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
    pub(in crate::component_tree::owned_shake) fn preissue_leaf_acceptance<'bound>(
        &'bound self,
        index: usize,
        ledger: &Ledger,
    ) -> Result<PreissuedLeafAcceptance<'bound, 'source, 'request>> {
        if !self.is_for(self.request, ledger) {
            return Err(Error::Authority);
        }
        let cap = self.preissue_leaf_cap(index, ledger)?;
        let cpu = CpuEnvelope::source()?;
        let original = ledger
            .admit_phase(whole_requirement(cpu)?)
            .map_err(|_| Error::Capacity)?;
        Ok(PreissuedLeafAcceptance { cap, cpu, original })
    }
}

impl<'bound, 'source, 'request> PreissuedLeafAcceptance<'bound, 'source, 'request> {
    pub(in crate::component_tree::owned_shake) fn check_compiled(
        &self,
        compiled: &OwnedCompiledShake<'request>,
        request: &crate::graph_crypto::ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<()> {
        if !self.original.belongs_to(ledger)
            || self.original.requirements() != whole_requirement(self.cpu)?
            || !self.cap.source.is_for(self.cap.source.request, ledger)
            || !core::ptr::eq(self.cap.source.request.owner, request)
        {
            return Err(Error::Authority);
        }
        self.cap
            .source
            .request
            .sources
            .get(self.cap.index)
            .and_then(Option::as_ref)
            .ok_or(Error::Source)?
            .check_compiled(compiled, ledger)
            .map_err(|_| Error::Source)
    }

    pub(in crate::component_tree::owned_shake) fn capture<'compiled>(
        self,
        compiled: &'compiled OwnedCompiledShake<'request>,
        registered: &RegisteredProgram,
        ledger: &Ledger,
    ) -> Result<CapturedLeafAcceptance<'compiled, 'bound, 'source, 'request>> {
        self.check_compiled(compiled, self.cap.source.request.owner, ledger)?;
        let cap = self.cap.capture(compiled, registered, ledger)?;
        // capture proved the same original Program allocation, canonical cap
        // geometry and original request source. The immutable registration is
        // still borrowed here; no output/caller-supplied verifier enters.
        let verifier = registered.verifier();
        Ok(CapturedLeafAcceptance {
            cap,
            verifier,
            cpu: self.cpu,
            original: self.original,
        })
    }
}

fn exact_binding(
    expected_spec: &Spec,
    expected_height: usize,
    expected_public: &[Val],
    expected_cap: &[[Val; 4]; ROOTS],
    actual_spec: &Spec,
    actual_height: usize,
    actual_public: &[Val],
    actual_cap: &[[Val; 4]],
    actual_capacity: usize,
) -> bool {
    expected_spec == actual_spec
        && expected_height == actual_height
        && expected_public.len() == HEADER + 8
        && expected_public == actual_public
        && actual_cap == &expected_cap[..]
        && actual_capacity == ROOTS
}

impl CapturedLeafAcceptance<'_, '_, '_, '_> {
    pub(in crate::component_tree::owned_shake) fn verify_original_output(
        &self,
        key: &NodeKey,
        proof: &NodeProof,
        request: &crate::graph_crypto::ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<u128> {
        if !self.original.belongs_to(ledger)
            || self.original.requirements() != whole_requirement(self.cpu)?
            || !self.cap.original.belongs_to(ledger)
            || self.cap.original.requirements() != super::requirements()?
            || !self.cap.source.is_for(self.cap.source.request, ledger)
            || !core::ptr::eq(self.cap.source.request.owner, request)
        {
            return Err(Error::Authority);
        }
        let compiled = &self.cap.compiled.compiled;
        if !exact_binding(
            &compiled.spec,
            compiled.program.height(),
            &compiled.public,
            &self.cap.cap,
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

/// A raw output and a numerically similar retirement cannot call this entry.
/// Only the actual producer constructs the opaque input with these exact owners.
pub(in crate::component_tree::owned_shake) fn authenticate_retired_leaf<
    'bound,
    'source,
    'request,
>(
    attempt: RetiredLeafAttempt<'_, 'bound, 'source, 'request>,
) -> Result<AcceptedLeafCompletion<'bound, 'source, 'request>> {
    let (captured, output, originals, ledger) = attempt.into_original_parts();
    let retirement = originals
        .source_authentication_retirement(&ledger)
        .map_err(|_| Error::Source)?;
    let leaf = finish_source_acceptance(captured, output, retirement, &ledger)?;
    Ok(AcceptedLeafCompletion { leaf, originals })
}

// Private common implementation. Its two callers first consume different
// opaque producer-created attempts and check their actual retained originals.
// No caller outside this acceptance module can substitute a numeric receipt.
fn finish_source_acceptance<'bound, 'source, 'request>(
    captured: CapturedLeafAcceptance<'_, 'bound, 'source, 'request>,
    mut output: RetainedNodeOutput<'request>,
    retirement: Retirement,
    ledger: &Ledger,
) -> Result<AcceptedLeaf<'bound, 'source, 'request>> {
    let elapsed = output
        .authenticate_captured_source(&captured, ledger)
        .map_err(|_| Error::Source)?;
    let CapturedLeafAcceptance {
        cap,
        verifier,
        cpu,
        mut original,
    } = captured;
    // Actual independently reconstructed verifier/configuration payloads end
    // before their original scratch claim is released. No compiler borrow or
    // registered Program allocation survives in the accepted child.
    drop(verifier);
    let CapturedLeafCap {
        compiled,
        source,
        index,
        cap,
        original: cap_original,
    } = cap;
    let height = compiled.compiled.program.height();
    let retained = original
        .split(metadata_requirement()?)
        .map_err(|_| Error::Authority)?;
    drop(original);
    Ok(AcceptedLeaf {
        output,
        source,
        index,
        height,
        cap,
        report: LeafAcceptanceReport {
            leaf: index,
            height,
            cpu_heights_admitted: cpu.heights,
            cpu_reserved_bytes: cpu.bytes,
            independent_verification_ns: elapsed,
            retirement,
            source_key_authenticated: true,
            transaction_context_authenticated: false,
            workflow_admitted: false,
        },
        cap_original,
        original: retained,
    })
}

impl<'bound, 'source, 'request> AcceptedLeafCompletion<'bound, 'source, 'request> {
    pub(in crate::component_tree::owned_shake) fn into_parts(
        self,
    ) -> (
        AcceptedLeaf<'bound, 'source, 'request>,
        RetiredOuterOriginals<'request>,
    ) {
        (self.leaf, self.originals)
    }
}

impl AcceptedLeaf<'_, '_, '_> {
    pub(in crate::component_tree::owned_shake) fn report(&self) -> LeafAcceptanceReport {
        self.report
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(in crate::component_tree::owned_shake) use parent::{AcceptedChild, AcceptedParent, CapturedParentAcceptance, ParentAcceptanceReport, PreissuedParentAcceptance};
