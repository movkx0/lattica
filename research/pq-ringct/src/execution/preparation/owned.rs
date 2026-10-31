//! Closed raw graph preparation for a source-owned reserved Session.
//!
//! This research-only boundary takes no callback, byte allowance or constructed
//! graph. It does not instantiate the legacy registry or JSON diagnostics. The
//! runtime and graph claims must belong to the original worker ledger before
//! entering native_gpu::with_operations. No proof acceptance is conferred.
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation};
use crate::opencl::Session;
use crate::rust_verify::committed_backend::source_graph::{Construction, OwnedGraph};
use lattica_prover_p3::{
    block_v2::native_gpu,
    proving::{operation_storage::RawPreparationReportStorage, Policy, Request},
};

type Result<T> = core::result::Result<T, &'static str>;

struct ReportClaim {
    // Payload/plan fields, if added, must precede this original reservation.
    reservation: Reservation,
}
impl ReportClaim {
    fn reserve(ledger: &Ledger) -> Result<Self> {
        let footprint = RawPreparationReportStorage::new()
            .map_err(|_| "raw preparation report source census refused")?;
        let host = u64::try_from(
            footprint
                .required_host_bytes
                .checked_add(core::mem::size_of::<Self>())
                .ok_or("raw preparation claim layout overflow")?,
        )
        .map_err(|_| "raw preparation report source census overflow")?;
        let reservation = ledger
            .admit_phase(Requirements::single(
                Category::Report,
                Bytes { host, device: 0 },
            ))
            .map_err(|_| "raw preparation report reservation refused")?;
        Ok(Self { reservation })
    }
}

fn check_source(source: &Construction, ledger: &Ledger) -> Result<()> {
    if !source.belongs_to(ledger) {
        return Err("raw graph source belongs to another worker ledger");
    }
    Ok(())
}

/// Original decoded inputs/graph/raw backing, exact runtime, and additive report
/// backing remain charged through their respective destruction. Native driver
/// errors belong to the reserved runtime; report/error formatting belongs to the
/// separate ReportClaim. All dynamic errors are destroyed inside these owners.
///
/// Test-only until the source graph, native/outer producers and complete graph
/// authentication have qualified together. This function alone is no complete
/// workflow admission and never turns an operation report into a proof receipt.
pub(crate) fn prepare_owned_graph(
    session: &Session,
    source: Construction,
    ledger: &Ledger,
) -> Result<OwnedGraph> {
    check_source(&source, ledger)?;
    let runtime = session
        .check_reserved_runtime(ledger)
        .map_err(|_| "raw preparation requires its original reserved runtime")?;
    let report_claim = ReportClaim::reserve(ledger)?;
    // Derive from the actual opaque Construction, after its original token and
    // runtime identity checks. The caller cannot select this numeric allowance.
    let allowance = source.operation_host_allowance();
    let result = native_gpu::with_operations(
        allowance,
        Request {
            policy: Policy::GpuRequired,
            emit_report: true,
        },
        move |operation| source.lower_on_gpu(operation).map_err(str::to_owned),
    );
    let output = match result {
        Ok((pending, report)) => {
            let accepted = super::validate_preparation_report(&report).is_ok();
            // Drop report/error backing before releasing callback growth. A
            // refused report destroys the graph while all owner claims remain.
            drop(report);
            if accepted {
                Ok(pending.after_callback())
            } else {
                drop(pending);
                Err("owned raw graph preparation report was incomplete")
            }
        }
        Err(error) => {
            drop(error);
            Err("owned raw graph preparation failed")
        }
    };
    drop(report_claim);
    drop(runtime);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;
    use crate::native_packet::{PROOF_BYTES, STATEMENT_BYTES};

    fn ledger(host: u64) -> Ledger {
        Ledger::new(WorkerAllowance {
            host,
            device: 8 << 30,
        })
    }

    #[test]
    fn report_claim_is_additive_atomic_and_releases_in_original_ledger() {
        let footprint = RawPreparationReportStorage::new().unwrap();
        let bytes = (footprint.required_host_bytes + core::mem::size_of::<ReportClaim>()) as u64;
        let small = ledger(bytes - 1);
        assert!(ReportClaim::reserve(&small).is_err());
        assert_eq!(small.snapshot().current, Bytes::ZERO);
        let owner = ledger(bytes + 1);
        let sibling = ledger(bytes + 1);
        let preceding = owner
            .admit_phase(Requirements::single(
                Category::CompilerInputs,
                Bytes { host: 1, device: 0 },
            ))
            .unwrap();
        let claim = ReportClaim::reserve(&owner).unwrap();
        assert!(claim.reservation.belongs_to(&owner));
        assert!(!claim.reservation.belongs_to(&sibling));
        assert_eq!(owner.snapshot().current.host, bytes + 1);
        assert!(ReportClaim::reserve(&owner).is_err());
        assert_eq!(owner.snapshot().current.host, bytes + 1);
        drop(claim);
        assert_eq!(owner.snapshot().current.host, 1);
        drop(preceding);
        assert_eq!(owner.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn source_identity_refusal_precedes_report_or_runtime_entry() {
        let owner = ledger(32 << 30);
        let sibling = ledger(32 << 30);
        let mut statement = vec![0; STATEMENT_BYTES];
        statement[STATEMENT_BYTES - 32] = 1;
        let proof = vec![0; PROOF_BYTES];
        let source = Construction::new([1; 32], [2; 32], &statement, &proof, &owner).unwrap();
        let before = owner.snapshot();
        assert!(check_source(&source, &sibling).is_err());
        assert_eq!(owner.snapshot(), before);
        assert_eq!(sibling.snapshot().current, Bytes::ZERO);
        assert!(check_source(&source, &owner).is_ok());
        drop(source);
        assert_eq!(owner.snapshot().current, Bytes::ZERO);
    }
}

mod gpu_tests;
