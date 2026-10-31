//! Closed test-only preclaims and move-only recursive output ownership.
//!
//! The fixed outer producer runs while this claim is live. Retaining its result
//! transfers already-held category reservations; it never admits new storage.
//! Independent proof verification is recorded separately from key and complete
//! transaction context authentication.
use super::{OwnedCompiledShake, HEADER};
use crate::{
    component_tree::{NodeKey, NodeProof, RegisteredVerifier, Val},
    execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    graph_crypto::ReservedShakeRequest,
};
use core::mem::{align_of, size_of};
use lattica_prover_p3::block_v2::machine::{
    backend::retained_proof_capacity_bytes, inspect_registered_gpu_output,
    RegisteredGpuOutputFootprint,
};

#[cfg(all(feature = "owned-native-shake", target_os = "linux"))]
mod preissued;
#[cfg(all(feature = "owned-native-shake", target_os = "linux"))]
pub(super) use preissued::{OutputRecheck, PreissuedOutput};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Authority,
    Source,
    Profile,
    Overflow,
    Admission,
    Capacity,
    Identity,
    Verification,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Report {
    pub(super) footprint: RegisteredGpuOutputFootprint,
    pub(super) public_output_backing_ceiling: u64,
    pub(super) recursive_output_host_bytes: u64,
    pub(super) registered_key_host_bytes: u64,
    pub(super) independent_verifier_host_bytes: u64,
    pub(super) report_host_bytes: u64,
    pub(super) total_claimed_host_bytes: u64,
    pub(super) actual_recursive_host_bytes: Option<u64>,
    pub(super) actual_key_host_bytes: Option<u64>,
    pub(super) setup_elapsed_ns: Option<u128>,
    pub(super) proving_elapsed_ns: Option<u128>,
    pub(super) cpu_verification_elapsed_ns: Option<u128>,
    pub(super) independent_verification_complete: bool,
    pub(super) authenticated_source_key: bool,
    pub(super) transaction_context_authenticated: bool,
    pub(super) native_production_admitted: bool,
    pub(super) workflow_admitted: bool,
}

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn bytes<T>(count: usize) -> Result<u64, Error> {
    count
        .checked_mul(size_of::<T>())
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Error::Overflow)
}

#[derive(Clone, Copy, Debug)]
struct Storage {
    report: Report,
    requirements: Requirements,
}
impl Storage {
    fn new(footprint: RegisteredGpuOutputFootprint, public_capacity: usize) -> Result<Self, Error> {
        if footprint.public_values != (HEADER + 8) as u64
            || !footprint.producer_backing_bound_complete
            || footprint.enclosing_ownership_bound_complete
            || footprint.dispatch_authority
            || public_capacity < HEADER + 8
        {
            return Err(Error::Profile);
        }
        let public = bytes::<Val>(public_capacity)?;
        // Both raw NodeProof and the final enclosing owner/header remain
        // charged even though the proof normally moves between stack slots.
        let recursive = add(
            add(footprint.proof_backing_ceiling_host_bytes, public)?,
            add(
                bytes::<NodeProof>(1)?,
                bytes::<RetainedNodeOutput<'static>>(1)?,
            )?,
        )?;
        // The core metadata bound includes the complete independent public-only
        // Program/Arc and lookup graph referents, not just Arc headers. The
        // separate key cap and caller Arc allocation are additional owners.
        let key_arc = add(bytes::<usize>(2)?, align_of::<RegisteredVerifier>() as u64)?;
        let key = add(
            add(
                footprint.verifier_metadata_retained_host_bytes,
                footprint.copied_key_cap_host_bytes,
            )?,
            add(key_arc, bytes::<NodeKey>(1)?)?,
        )?;
        let verifier = footprint.verifier_lifecycle_peak_host_bytes;
        if verifier < footprint.verifier_construction_peak_host_bytes
            || verifier < footprint.verifier_verification_peak_host_bytes
            || verifier < footprint.verifier_metadata_retained_host_bytes
        {
            return Err(Error::Profile);
        }
        // Keep the full independent lifecycle in addition to proof/key claims;
        // no credit is taken for its internal 64 MiB already-owned input cap.
        let report = bytes::<Report>(1)?;
        let mut requirements = Requirements::default();
        for (category, host) in [
            (Category::RecursiveProof, recursive),
            (Category::RegisteredMetadata, key),
            (Category::IndependentVerifier, verifier),
            (Category::Report, report),
        ] {
            requirements
                .add(category, Bytes { host, device: 0 })
                .map_err(|_| Error::Overflow)?;
        }
        let total = requirements.total().map_err(|_| Error::Overflow)?.host;
        Ok(Self {
            report: Report {
                footprint,
                public_output_backing_ceiling: public,
                recursive_output_host_bytes: recursive,
                registered_key_host_bytes: key,
                independent_verifier_host_bytes: verifier,
                report_host_bytes: report,
                total_claimed_host_bytes: total,
                actual_recursive_host_bytes: None,
                actual_key_host_bytes: None,
                setup_elapsed_ns: None,
                proving_elapsed_ns: None,
                cpu_verification_elapsed_ns: None,
                independent_verification_complete: false,
                authenticated_source_key: false,
                transaction_context_authenticated: false,
                native_production_admitted: false,
                workflow_admitted: false,
            },
            requirements,
        })
    }

    fn proof_bytes(&self, proof: &NodeProof) -> Result<u64, Error> {
        let public = bytes::<Val>(proof.public.capacity())?;
        if public > self.report.public_output_backing_ceiling {
            return Err(Error::Capacity);
        }
        let backing = add(
            retained_proof_capacity_bytes(
                &proof.proof,
                usize::try_from(self.report.footprint.proof_backing_ceiling_host_bytes)
                    .map_err(|_| Error::Overflow)?,
            )
            .map_err(|_| Error::Capacity)? as u64,
            public,
        )?;
        let actual = add(
            backing,
            add(
                bytes::<NodeProof>(1)?,
                bytes::<RetainedNodeOutput<'static>>(1)?,
            )?,
        )?;
        if actual > self.report.recursive_output_host_bytes {
            return Err(Error::Capacity);
        }
        Ok(actual)
    }

    fn key_bytes(&self, key: &NodeKey) -> Result<u64, Error> {
        if key.cap.len() as u64 != self.report.footprint.cap_roots
            || key.cap.capacity() as u64 != self.report.footprint.cap_roots
        {
            return Err(Error::Capacity);
        }
        let actual = add(
            key.retained_reservation_bytes()
                .map_err(|_| Error::Capacity)? as u64,
            bytes::<NodeKey>(1)?,
        )?;
        if actual > self.report.registered_key_host_bytes {
            return Err(Error::Capacity);
        }
        Ok(actual)
    }
}

pub(super) struct OutputClaim<'compiled, 'owner, 'request> {
    compiled: &'compiled OwnedCompiledShake<'request>,
    request: &'owner ReservedShakeRequest,
    storage: Storage,
    token: Reservation,
}
impl<'compiled, 'owner, 'request> OutputClaim<'compiled, 'owner, 'request> {
    pub(super) fn reserve(
        compiled: &'compiled OwnedCompiledShake<'request>,
        request: &'owner ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<Self, Error> {
        if !request.belongs_to(ledger)
            || !compiled.is_for(request.request())
            || !compiled._program.belongs_to(ledger)
            || !compiled._inputs.belongs_to(ledger)
            || !compiled.report.belongs_to(ledger)
        {
            return Err(Error::Authority);
        }
        let node = &compiled.compiled;
        if node.public.len() != HEADER + 8
            || node.program.public_values() != HEADER + 8
            || node.witness.len() != node.program.witness_values()
        {
            return Err(Error::Source);
        }
        let footprint = inspect_registered_gpu_output(&node.program).map_err(|_| Error::Profile)?;
        let storage = Storage::new(footprint, node.public.capacity())?;
        let token = ledger
            .admit_phase(storage.requirements)
            .map_err(|_| Error::Admission)?;
        Ok(Self {
            compiled,
            request,
            storage,
            token,
        })
    }

    pub(super) fn report(&self) -> Report {
        self.storage.report
    }

    /// Only the fixed producer calls this while the original backend/output
    /// claims and borrowed runtime owner are still live. Capacity checks are
    /// drift checks of that preceding source bound, not fresh admission.
    pub(super) fn verify_and_retain(
        self,
        key: NodeKey,
        proof: NodeProof,
        setup_elapsed_ns: u128,
        proving_elapsed_ns: u128,
    ) -> Result<RetainedNodeOutput<'owner>, Error> {
        if key.spec != self.compiled.compiled.spec
            || key.height != self.compiled.compiled.program.height()
            || proof.public != self.compiled.compiled.public
        {
            return Err(Error::Identity);
        }
        self.storage.proof_bytes(&proof)?;
        self.storage.key_bytes(&key)?;
        // This uses the independent CPU verifier derived from the actual
        // freshly created registration; no caller-supplied verifier is used.
        let started = std::time::Instant::now();
        key.verifier
            .verify(&proof.proof, &proof.public)
            .map_err(|_| Error::Verification)?;
        let verification_elapsed_ns = started.elapsed().as_nanos();
        let mut retained = self.retain(key, proof)?;
        retained.report.independent_verification_complete = true;
        retained.report.setup_elapsed_ns = Some(setup_elapsed_ns);
        retained.report.proving_elapsed_ns = Some(proving_elapsed_ns);
        retained.report.cpu_verification_elapsed_ns = Some(verification_elapsed_ns);
        Ok(retained)
    }

    /// Private ownership handoff only; no proof/key access escapes the returned
    /// owner. The fixed producer verifies before calling it. Structural tests
    /// may retain without verification and cannot set the verification flag.
    fn retain(
        mut self,
        key: NodeKey,
        proof: NodeProof,
    ) -> Result<RetainedNodeOutput<'owner>, Error> {
        if key.spec != self.compiled.compiled.spec
            || key.height != self.compiled.compiled.program.height()
            || proof.public != self.compiled.compiled.public
        {
            return Err(Error::Identity);
        }
        let actual_proof = self.storage.proof_bytes(&proof)?;
        let actual_key = self.storage.key_bytes(&key)?;
        let retained = retain_claims(
            &mut self.token,
            actual_proof,
            actual_key,
            self.storage.report.report_host_bytes,
        )?;
        let mut report = self.storage.report;
        report.actual_recursive_host_bytes = Some(actual_proof);
        report.actual_key_host_bytes = Some(actual_key);
        // The original token releases only unused ceilings and verifier
        // scratch. Actual proof/key/report backing stays with the payload.
        Ok(RetainedNodeOutput {
            key,
            proof,
            request: self.request,
            report,
            retained,
        })
    }
}

fn retain_claims(
    token: &mut Reservation,
    proof: u64,
    key: u64,
    report: u64,
) -> Result<Reservation, Error> {
    let mut keep = Requirements::default();
    for (category, host) in [
        (Category::RecursiveProof, proof),
        (Category::RegisteredMetadata, key),
        (Category::Report, report),
    ] {
        keep.add(category, Bytes { host, device: 0 })
            .map_err(|_| Error::Overflow)?;
    }
    token.split(keep).map_err(|_| Error::Capacity)
}

/// Payload fields precede their reservation, including during unwinding.
/// No Clone, raw-key/proof getters, extraction, proof or merge methods exist.
/// Every key charges the entire Arc referent even if a test shares an Arc.
pub(super) struct RetainedNodeOutput<'owner> {
    key: NodeKey,
    proof: NodeProof,
    request: &'owner ReservedShakeRequest,
    report: Report,
    retained: Reservation,
}

impl RetainedNodeOutput<'_> {
    pub(super) fn report(&self) -> Report {
        self.report
    }

    pub(super) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.retained.belongs_to(ledger) && self.request.belongs_to(ledger)
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod authenticated;

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod parent_production;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(super) use parent_production::PreissuedParentOutput;
