//! Original-ledger ownership of one fixed native AES proof and its report.
//! A claim is empty until the closed producer consumes it. No public method
//! attaches reservations to a supplied proof or extracts an owned payload.
use super::aes_preparation::{AesPreparationGeometry, AesPreparationPlan};
use crate::block_v2::native_aes_proof::NativeAesProof;
use crate::proving::{FixedProofReportStorage, Report};
use crate::ringct_research_quota::{Bytes, Category, Ledger, Requirements, Reservation};
use core::mem::size_of;

mod report;
mod storage;

pub const PROOF_BACKING_CEILING: usize = 64 << 20;
pub(super) const ENTRY_POINT: &str = "ringct_owned_native_aes";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Geometry,
    Overflow,
    Capacity,
    Authority,
    Report,
}
type Result<T> = core::result::Result<T, Error>;

/// Pure preallocation inventory. Numbers carry no reservation or dispatch
/// authority; the original output/report claims must be transferred below.
#[derive(Clone, Copy, Debug)]
pub struct AesOutputPlan {
    preparation: AesPreparationPlan,
    storage: storage::Census,
    source_proof_host_bytes: usize,
    report_host_bytes: usize,
}

impl AesOutputPlan {
    pub fn new(preparation: AesPreparationPlan) -> Result<Self> {
        let storage = storage::Census::new(preparation.geometry())?;
        // The source inventory includes every permitted nested capacity.
        // Charge overlapping inline owners and public readback without move
        // credits. Research request/key/retained-child headers are separately
        // checked inside the same fixed proof ceiling before this claim moves.
        let source_proof_host_bytes = storage
            .heap_bound()?
            .checked_add(size_of::<NativeAesProof>())
            .and_then(|n| n.checked_add(2 * size_of::<OwnedAesProof>()))
            .and_then(|n| n.checked_add(2 * size_of::<PendingAesOutput>()))
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .and_then(|n| n.checked_add(size_of::<core::result::Result<OwnedAesProof, (Error, PendingAesOutput)>>()))
            .and_then(|n| n.checked_add(2 * size_of::<&mut Option<PendingAesOutput>>()))
            .and_then(|n| n.checked_add(2 * 12 * size_of::<crate::config::Val>()))
            .and_then(|n| n.checked_add(2 * size_of::<Vec<u64>>()))
            .ok_or(Error::Overflow)?;
        if source_proof_host_bytes > PROOF_BACKING_CEILING {
            return Err(Error::Capacity);
        }
        let report_host_bytes = FixedProofReportStorage::fixed()
            .map_err(|_| Error::Report)?
            .required_host_bytes();
        Ok(Self {
            preparation,
            storage,
            source_proof_host_bytes,
            report_host_bytes,
        })
    }

    pub fn source_proof_host_bytes(self) -> usize {
        self.source_proof_host_bytes
    }

    pub fn proof_requirement(self) -> Requirements {
        Requirements::single(
            Category::NativeProof,
            Bytes {
                host: PROOF_BACKING_CEILING as u64,
                device: 0,
            },
        )
    }

    pub fn report_requirement(self) -> Requirements {
        Requirements::single(
            Category::Report,
            Bytes {
                host: self.report_host_bytes as u64,
                device: 0,
            },
        )
    }

    /// Move the original claims before the producer can create a Run or proof.
    /// Neither a second ledger nor copied byte receipts can satisfy identity.
    pub fn claim(
        self,
        proof: Reservation,
        report: Reservation,
        ledger: &Ledger,
    ) -> Result<PendingAesOutput> {
        self.claim_preserving(proof, report, ledger)
            .map_err(|(error, _proof, _report)| error)
    }

    /// Preserve both original claims on validation refusal. The complete
    /// workflow issuer must restore or poison its existing slot; it must never
    /// replace these tokens by admitting fresh credit after a failed phase.
    pub fn claim_preserving(
        self,
        proof: Reservation,
        report: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<PendingAesOutput, (Error, Reservation, Reservation)> {
        let allowance = ledger.snapshot().allowance;
        if allowance.host == 0
            || allowance.host > 32 << 30
            || allowance.device == 0
            || allowance.device > 8 << 30
            || !proof.belongs_to(ledger)
            || !report.belongs_to(ledger)
            || proof.requirements() != self.proof_requirement()
            || report.requirements() != self.report_requirement()
        {
            return Err((Error::Authority, proof, report));
        }
        Ok(PendingAesOutput {
            plan: self,
            ledger: ledger.clone(),
            proof,
            report,
        })
    }
}

/// No constructor accepts a proof. All data remain empty until the fixed core
/// producer runs; the claims cannot be split, cloned or extracted by a caller.
pub struct PendingAesOutput {
    plan: AesOutputPlan,
    ledger: Ledger,
    proof: Reservation,
    report: Reservation,
}

impl PendingAesOutput {
    pub(super) fn check(&self, preparation: AesPreparationPlan, ledger: &Ledger) -> Result<()> {
        if self.plan.preparation != preparation
            || !self.proof.belongs_to(ledger)
            || !self.report.belongs_to(ledger)
            || !self.proof.belongs_to(&self.ledger)
            || self.proof.requirements() != self.plan.proof_requirement()
            || self.report.requirements() != self.plan.report_requirement()
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    /// An unfilled slot owns no proof or report payload. Return its exact
    /// originals for restoration to the same enclosing source slot pool.
    pub fn into_originals(self) -> (Reservation, Reservation) {
        let Self { plan: _, ledger, proof, report } = self;
        drop(ledger);
        (proof, report)
    }

    // This method is private to native_gpu::research. It is never a public
    // proof-attachment API and must only follow the closed kernel/PCS path.
    pub(super) fn finish_retaining(
        slot: &mut Option<Self>,
        artifact: NativeAesProof,
        report: Report,
    ) -> Result<OwnedAesProof> {
        let pending = slot.as_ref().ok_or(Error::Authority)?;
        let checked = pending.check(pending.plan.preparation, &pending.ledger)
            .and_then(|()| pending.plan.storage.audit(&artifact.proof))
            .and_then(|()| report::validate(&report));
        if let Err(error) = checked {
            // Payload death precedes return of the original empty claims.
            drop(artifact);
            drop(report);
            return Err(error);
        }
        let pending = slot.take().ok_or(Error::Authority)?;
        Ok(OwnedAesProof {
            artifact,
            report,
            geometry: pending.plan.preparation.geometry(),
            proof: pending.proof,
            report_owner: pending.report,
        })
    }
}

/// Immutable producer output. Rust destroys artifact/report before their
/// original non-cloneable reservations; only borrowed access is exposed.
pub struct OwnedAesProof {
    artifact: NativeAesProof,
    report: Report,
    geometry: AesPreparationGeometry,
    proof: Reservation,
    report_owner: Reservation,
}

impl OwnedAesProof {
    /// Destroy both retained payloads before returning their original claims.
    /// No raw proof or report can escape this operation.
    pub fn into_originals(self) -> (Reservation, Reservation) {
        let Self { artifact, report, geometry: _, proof, report_owner } = self;
        drop(artifact);
        drop(report);
        (proof, report_owner)
    }

    pub fn artifact(&self) -> &NativeAesProof {
        &self.artifact
    }

    pub fn report(&self) -> &Report {
        &self.report
    }

    pub fn geometry(&self) -> AesPreparationGeometry {
        self.geometry
    }

    pub fn proof_reservation(&self) -> &Reservation {
        &self.proof
    }

    pub fn report_reservation(&self) -> &Reservation {
        &self.report_owner
    }

    pub fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.proof.belongs_to(ledger) && self.report_owner.belongs_to(ledger)
    }
}

#[cfg(test)]
mod tests;
