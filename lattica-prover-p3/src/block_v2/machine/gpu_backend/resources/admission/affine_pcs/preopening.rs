//! Native cubic affine adapter backing before PCS opening. The caller retains
//! its separate preparation/configuration/runtime/output/report reservations.
//! This pure census neither records an AIR nor issues a dispatch capability.
use super::{add, bytes, mul, sum, Geometry};
use crate::block_v2::gpu_hash::{
    device::{
        note_payload, DeviceMatrix, DomainSpec, EvaluationInput, MatrixSpec, QuotientCommitInput,
        QuotientCommitShape, TraceCommitInput, TraceCommitShape,
    },
    engine::{lde_execute::note_storage, lde_plan::InputShape},
};
use crate::config::Val;
use core::mem::size_of;
use p3_commit::Mmcs;

type Cap = <crate::block_v2::gpu_hash::CandidateMmcs as Mmcs<Val>>::Commitment;

fn vector<T>(count: usize) -> Result<usize, String> {
    note_storage::vector_backing::<T>(count).map_err(str::to_owned)
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(super) struct Preopening {
    pub host_bytes: usize,
    pub transform_count: usize,
    pub maximum_log_rows: usize,
    pub maximum_ntt_groups: usize,
    pub scaled_base_field_lde_backing: usize,
    pub scaled_device_wrapper_backing: usize,
    pub native_adapter_backing: usize,
}

impl Preopening {
    pub(super) fn new(g: Geometry) -> Result<Self, String> {
        g.check()?;
        // Only these two extension-independent wrapper inventories are reused.
        // Their fixed source dimensions dominate each term after multiplication
        // by two: [1,32,1] <= 2*[1,16,1], 5 NTT groups <= 2*3, and 66 transforms
        // <= 2*34. No quadratic scalar, opening, configuration or note witness
        // byte count is borrowed. Native owners have separate original claims.
        let transforms = add(2, mul(2, g.quotient_chunks)?)?;
        let log_rows = add(g.rows.ilog2() as usize, 1 + g.log_blowup)?;
        let groups = log_rows.div_ceil(10 - 4);
        let ordinary = add(5 + 3 + 1 + 2, mul(2, transforms)?)?;
        let direct = add(mul(3, transforms)?, 6 + 3)?;
        if note_payload::TRANSFORMS != 34
            || transforms > 2 * note_payload::TRANSFORMS
            || ordinary > 2 * (5 + 3 + 1 + 2 * 34 + 2)
            || direct > 2 * (3 * 34 + 6 + 3)
            || groups > 2 * 3
            || log_rows > 25
            || g.quotient_chunks > 32
        {
            return Err("native affine wrapper domination failed".into());
        }
        let scaled_base_field_lde_backing = mul(
            2,
            note_storage::NoteLdeHostResources::new()
                .map_err(str::to_owned)?
                .requested_payload_bytes(),
        )?;
        let scaled_device_wrapper_backing = mul(
            2,
            note_payload::Resources::new()
                .map_err(str::to_owned)?
                .requested_payload_bytes(),
        )?;
        let trace = sum(&[
            mul(2, vector::<(DomainSpec, DeviceMatrix)>(1)?)?,
            vector::<TraceCommitShape>(1)?,
            vector::<usize>(2)?,
            vector::<InputShape>(1)?,
            mul(2, vector::<usize>(1)?)?,
            vector::<TraceCommitInput>(1)?,
        ])?;
        let quotient = sum(&[
            vector::<(DomainSpec, &DeviceMatrix, usize)>(1)?,
            vector::<DeviceMatrix>(1)?,
            vector::<QuotientCommitShape>(1)?,
            vector::<InputShape>(g.quotient_chunks)?,
            vector::<usize>(3)?,
            vector::<usize>(2)?,
            vector::<usize>(1)?,
            vector::<QuotientCommitInput>(1)?,
            vector::<&QuotientCommitInput>(1)?,
        ])?;
        let randomization = sum(&[
            vector::<DomainSpec>(1)?,
            vector::<InputShape>(1)?,
            vector::<MatrixSpec>(1)?,
            vector::<usize>(2)?,
            mul(2, vector::<usize>(1)?)?,
            vector::<EvaluationInput>(1)?,
        ])?;
        let mut salt_preflight = 0;
        for (pending, matrices) in [(2, 1), (3, g.quotient_chunks), (2, 1)] {
            salt_preflight = add(
                salt_preflight,
                add(
                    vector::<usize>(pending + 1)?,
                    mul(2, vector::<usize>(matrices)?)?,
                )?,
            )?;
        }
        // Both fixed affine sources have eight public fields;
        // both have three alpha coefficients and main+periodic inputs.
        // inputs and no permutation. Count all maximum quotient domain words
        // and their scalar readbacks before normalization determines the count.
        let partition = sum(&[
            vector::<u64>(g.public_values)?,
            vector::<u64>(3)?,
            vector::<&DeviceMatrix>(2)?,
            vector::<MatrixSpec>(2)?,
            vector::<DomainSpec>(g.quotient_chunks)?,
            vector::<u64>(g.quotient_chunks)?,
            vector::<u64>(1)?,
        ])?;
        // Root tables and NTT schedules carry row counts, so these native
        // terms are derived separately rather than scaling a note scalar term.
        let transforms = mul(
            transforms,
            add(
                mul(2, vector::<u64>(log_rows)?)?,
                mul(2, vector::<(usize, usize, usize)>(groups)?)?,
            )?,
        )?;
        let cap_copies = mul(3, vector::<[Val; 4]>(1 << g.cap_height)?)?;
        // uni::prove's points, domains, scalar samples and outer returned
        // instance vector. Opened value and proof payloads have other owners.
        let uni_inline_and_adapters = sum(&[
            vector::<crate::block_v2::profile::Challenge>(2)?,
            // BaseAir's default next-row metadata builds 0..width before the
            // unchanged uni adapter checks whether any next opening is needed.
            vector::<usize>(g.main_width)?,
            bytes::<DomainSpec>(4)?,
            size_of::<p3_uni_stark::Commitments<Cap>>(),
            size_of::<Self>(),
        ])?;
        let native_adapter_backing = sum(&[
            trace,
            quotient,
            randomization,
            salt_preflight,
            partition,
            transforms,
            cap_copies,
            uni_inline_and_adapters,
        ])?;
        Ok(Self {
            host_bytes: sum(&[
                scaled_base_field_lde_backing,
                scaled_device_wrapper_backing,
                native_adapter_backing,
            ])?,
            transform_count: add(2, mul(2, g.quotient_chunks)?)?,
            maximum_log_rows: log_rows,
            maximum_ntt_groups: groups,
            scaled_base_field_lde_backing,
            scaled_device_wrapper_backing,
            native_adapter_backing,
        })
    }
}
