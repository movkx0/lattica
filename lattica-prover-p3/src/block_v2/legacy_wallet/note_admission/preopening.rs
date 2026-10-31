//! Outer source-owned payload census before the fixed note's PCS opening.
//! Public compiler/periodic source, configuration/runtime, reports and opening
//! proof storage retain their separate cumulative charges. This component is
//! not a complete lifetime token, allocator bound or driver-storage model.
#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]

use super::{add, mul, Error, Geometry};
use crate::block_v2::gpu_hash::{
    device::{
        note_payload, DeviceMatrix, DomainSpec, EvaluationInput, MatrixSpec, QuotientCommitInput,
        QuotientCommitShape, TraceCommitInput, TraceCommitShape,
    },
    engine::{lde_execute::note_storage, lde_plan::InputShape},
};
use crate::config::Val;
use core::mem::size_of;

fn vector<T>(count: usize) -> Result<usize, Error> {
    note_storage::vector_backing::<T>(count).map_err(|_| Error::Overflow)
}
fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts.iter().try_fold(0, |n, &part| add(n, part))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct PreopeningHostResources {
    wallet_staging_bytes: usize,
    public_handoff_bytes: usize,
    trace_adapter_bytes: usize,
    quotient_adapter_bytes: usize,
    randomization_adapter_bytes: usize,
    salt_preflight_adapter_bytes: usize,
    quotient_partition_adapter_bytes: usize,
    transform_constant_and_schedule_bytes: usize,
    transcript_cap_copy_bytes: usize,
    device_wrappers: note_payload::Resources,
    lde_adapters: note_storage::NoteLdeHostResources,
    inline_owner_bytes: usize,
    requested_payload_bytes: usize,
    complete_lifetime_admitted: bool,
}

impl PreopeningHostResources {
    /// Allocation-free fixed geometry census. The caller must own this charge
    /// before normalization/witness/proving work and retain it with returned
    /// proof payload. A numeric result alone cannot authorize those operations.
    pub(crate) fn new() -> Result<Self, Error> {
        let g = Geometry::pinned()?;
        if g.quotient_chunks != 16
            || g.extension_degree != 2
            || g.public_values != 26
            || g.width != 19
            || g.rows != 4096
            || g.random_codewords != 4
        {
            return Err(Error::Geometry);
        }
        let wallet = crate::gpu_wallet::Plan::new(32 << 30).map_err(|_| Error::Geometry)?;
        let wallet_staging_bytes = wallet.staging_bytes().map_err(|_| Error::Overflow)?;
        if wallet_staging_bytes != (364 + 28 + 1) * 8 {
            return Err(Error::Geometry);
        }
        // DeviceSession::read's exact public readback plus a conservative
        // separate canonical Val conversion. Expected publics are retained by
        // PreparedNote; the witness is borrowed under its preparation charge.
        let public_handoff_bytes = add(vector::<u64>(26)?, vector::<Val>(26)?)?;
        // uni -> commit_main_device -> commit_trace_device. Count both the
        // original and converted domain vectors, even if collect reuses one.
        let trace_adapter_bytes = sum(&[
            mul(2, vector::<(DomainSpec, DeviceMatrix)>(1)?)?,
            vector::<TraceCommitShape>(1)?,
            vector::<usize>(2)?, // pending: random + normalization
            vector::<InputShape>(1)?,
            mul(2, vector::<usize>(1)?)?, // RNG request + parameter requests
            vector::<TraceCommitInput>(1)?,
        ])?;
        // One AIR group produces exactly sixteen native quotient chunks. The
        // group/shape/prepared vectors remain one element; LDE shapes expand.
        let quotient_adapter_bytes = sum(&[
            vector::<(DomainSpec, &DeviceMatrix, usize)>(1)?,
            vector::<DeviceMatrix>(1)?,
            vector::<QuotientCommitShape>(1)?,
            vector::<InputShape>(16)?,
            vector::<usize>(3)?, // random, masks, per-chunk parameters
            vector::<usize>(2)?, // random + mask sampling requests
            vector::<usize>(1)?, // parameter allocation request
            vector::<QuotientCommitInput>(1)?,
            vector::<&QuotientCommitInput>(1)?,
        ])?;
        // randomization_device takes one stack-array domain, collects it,
        // derives shape/spec/pending requests and prepares one evaluation.
        let randomization_adapter_bytes = sum(&[
            vector::<DomainSpec>(1)?,
            vector::<InputShape>(1)?,
            vector::<MatrixSpec>(1)?,
            vector::<usize>(2)?,
            mul(2, vector::<usize>(1)?)?,
            vector::<EvaluationInput>(1)?,
        ])?;
        // preflight_private_salts copies pending and pushes replay workspace.
        // Charge the maximum final count with old/new backing coexistence.
        // Its replay request Vec and prepare_salt_replay's second request Vec
        // are independent; recipes and their streams are in the LDE census.
        let mut salt_preflight_adapter_bytes = 0;
        for (pending, matrices) in [(2usize, 1usize), (3, 16), (2, 1)] {
            salt_preflight_adapter_bytes = add(
                salt_preflight_adapter_bytes,
                add(
                    vector::<usize>(pending + 1)?,
                    mul(2, vector::<usize>(matrices)?)?,
                )?,
            )?;
        }
        // owned_quotient has 26 public parameters and two alpha coefficients.
        // partitioned evaluation uses main + periodic input; no lookup/permutation
        // matrix exists. Domain output and GPU shift readback are separate Vecs.
        // Sixteen domains is a safe fixed-profile upper bound, not a relaxation
        // of the exact normalized quotient degree checked before witness work.
        let quotient_partition_adapter_bytes = sum(&[
            vector::<u64>(26)?,
            vector::<u64>(2)?,
            vector::<&DeviceMatrix>(2)?,
            vector::<MatrixSpec>(2)?,
            vector::<DomainSpec>(16)?,
            vector::<u64>(16)?,
            vector::<u64>(1)?, // initial disjoint_domain scalar readback
        ])?;
        // Each device transform owns inverse+forward root vectors. Their logs
        // are <=17; ntt_groups has <=3 tuples. Charge all potential transforms
        // together instead of relying on scratch reuse between sequential calls.
        let transform_constant_and_schedule_bytes = mul(
            note_payload::TRANSFORMS,
            add(
                mul(2, vector::<u64>(17)?)?,
                mul(2, vector::<(usize, usize, usize)>(3)?)?,
            )?,
        )?;
        // uni observes clones of each public commitment cap. Those copies are
        // in addition to raw/converted/returned caps counted by the LDE census.
        let transcript_cap_copy_bytes = mul(3, vector::<[Val; 4]>(1 << g.cap_height)?)?;
        let device_wrappers = note_payload::Resources::new().map_err(|_| Error::Overflow)?;
        let lde_adapters =
            note_storage::NoteLdeHostResources::new().map_err(|_| Error::Geometry)?;
        let inline_owner_bytes = size_of::<Self>();
        let requested_payload_bytes = sum(&[
            wallet_staging_bytes,
            public_handoff_bytes,
            trace_adapter_bytes,
            quotient_adapter_bytes,
            randomization_adapter_bytes,
            salt_preflight_adapter_bytes,
            quotient_partition_adapter_bytes,
            transform_constant_and_schedule_bytes,
            transcript_cap_copy_bytes,
            device_wrappers.requested_payload_bytes(),
            lde_adapters.requested_payload_bytes(),
            inline_owner_bytes,
        ])?;
        Ok(Self {
            wallet_staging_bytes,
            public_handoff_bytes,
            trace_adapter_bytes,
            quotient_adapter_bytes,
            randomization_adapter_bytes,
            salt_preflight_adapter_bytes,
            quotient_partition_adapter_bytes,
            transform_constant_and_schedule_bytes,
            transcript_cap_copy_bytes,
            device_wrappers,
            lde_adapters,
            inline_owner_bytes,
            requested_payload_bytes,
            complete_lifetime_admitted: false,
        })
    }

    pub(crate) fn requested_payload_bytes(self) -> usize {
        self.requested_payload_bytes
    }
}

#[cfg(all(test, feature = "stream", not(debug_assertions)))]
mod tests {
    use super::*;
    use crate::block_v2::gpu_hash::device::{Extension, RowOrder};
    use crate::spill_alloc::allocation_requests::measure;

    #[test]
    fn outer_note_adapter_census_matches_actual_commit_geometry() {
        let g = Geometry::pinned().unwrap();
        let trace = TraceCommitShape::new(
            MatrixSpec::new(12, g.width, Extension::Base, RowOrder::Natural, 1).unwrap(),
            g.random_codewords,
        )
        .unwrap();
        assert_eq!((trace.height, trace.width), (8192, 23));
        assert_eq!(trace.allocation_bytes().len(), 2);
        let quotient = QuotientCommitShape::new(
            MatrixSpec::new(16, 1, Extension::Quadratic, RowOrder::Natural, 7).unwrap(),
            g.quotient_chunks,
            g.random_codewords,
        )
        .unwrap();
        assert_eq!(
            (quotient.chunks, quotient.height, quotient.width),
            (16, 4096, 6)
        );
        assert_eq!(quotient.allocation_words().len(), 3);
        assert_eq!(crate::gpu_wallet::INPUT_WORDS, 364);
        assert_eq!(crate::gpu_wallet::GEOMETRY_WORDS, 28);
    }

    #[test]
    fn outer_note_adapter_census_is_allocation_free_without_dispatch_authority() {
        let (report, request) = measure(|| PreopeningHostResources::new().unwrap());
        assert_eq!(
            (request.calls, request.bytes, request.overflow),
            (0, 0, false)
        );
        assert!(!report.complete_lifetime_admitted);
        assert!(report.requested_payload_bytes() > report.lde_adapters.requested_payload_bytes());
        assert_eq!(report.wallet_staging_bytes, 3144);
    }
}
