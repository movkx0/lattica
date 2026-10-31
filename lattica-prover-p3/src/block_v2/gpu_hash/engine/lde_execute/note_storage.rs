//! Requested Rust payload backing for the fixed private-note LDE adapters.
//!
//! This is a disconnected census, not admission or a dispatch capability. The
//! enclosing note producer must retain a real cumulative reservation, validate
//! its exact normalized profile and select device-only output before using it.
//! Allocator slack, compiled stack maxima and driver storage are not inferred
//! from these source-owned allocation requests.
#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]

use super::{CommitInput, LdeCommitOutput, SaltInput};
use crate::block_v2::gpu_hash::{
    device::{self, DeviceMatrix, MatrixSpec, ReplaySalts},
    engine::lde_plan::{InputShape, LdeCommitPlan},
    ProverData,
};
use crate::config::Val;
use core::mem::size_of;
use p3_matrix::{dense::RowMajorMatrix, Dimensions};

const MATRIX_COUNTS: [usize; 3] = [1, 16, 1];
const OUTPUT_LOG_ROWS: usize = 17;
const CAP_HEIGHT: usize = 6;
// ntt_groups permits tile_log2 >= 10 and max_column_bits <= 4. At log rows
// <= 17 the smallest stage capacity is 6 and at most ceil(17 / 6) = 3
// groups exist. Forward and inverse calls are sequential; charge both.
const NTT_GROUPS: usize = 3;

type Error = &'static str;
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or("note LDE host census overflow")
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or("note LDE host census overflow")
}
fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts.iter().try_fold(0, |n, &part| add(n, part))
}

/// Upper bound on requested Vec backing, including old/new growth overlap.
///
/// Source-pinned to Rust 1.96 alloc's RawVec::grow_amortized,
/// SpecFromIterNested and Vec::extend_desugared. Each audited iterator has a
/// truthful lower size hint no larger than its remaining fixed count. Exact
/// collect/to_vec allocate that count; fallible collect/push can start at
/// MIN_NON_ZERO_CAP and double. Capacity never exceeds max(minimum, 2 * count),
/// and charging two such capacities also covers a reallocation's old storage.
///
/// The caller must count an existing source Vec separately. This helper grants
/// no alias credit and does not bound arbitrary reserve requests, inherited
/// spare capacity, or an arbitrary iterator's excessive size hint.
pub(crate) fn vector_backing<T>(count: usize) -> Result<usize, Error> {
    let size = size_of::<T>();
    if count == 0 || size == 0 {
        return Ok(0);
    }
    let minimum = if size == 1 {
        8
    } else if size <= 1024 {
        4
    } else {
        1
    };
    let capacity = mul(count, 2)?.max(minimum);
    mul(mul(capacity, 2)?, size)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct NoteLdeHostResources {
    adapter_backing_bytes: usize,
    preflight_backing_bytes: usize,
    execution_backing_bytes: usize,
    simultaneous_plan_backing_bytes: usize,
    retained_output_backing_bytes: usize,
    salt_recipe_backing_bytes: usize,
    cap_construction_backing_bytes: usize,
    ntt_schedule_backing_bytes: usize,
    inline_owner_bytes: usize,
    requested_payload_bytes: usize,
    matrix_counts: [usize; 3],
    maximum_output_log_rows: usize,
    requires_device_only_output: bool,
    complete_preopening_admitted: bool,
}

impl NoteLdeHostResources {
    /// Three private commitments: main trace, sixteen quotient chunks and one
    /// randomization matrix. The public periodic preprocessing has a different
    /// retained owner and is deliberately outside this private-adapter census.
    /// This call reads neither environment nor device state and allocates none.
    pub(crate) fn new() -> Result<Self, Error> {
        if crate::block_v2::profile::LOG_BLOWUP != 4
            || crate::block_v2::profile::CAP_HEIGHT != CAP_HEIGHT
            || OUTPUT_LOG_ROWS.div_ceil(10 - 4) != NTT_GROUPS
        {
            return Err("note LDE host census profile changed");
        }
        let mut report = Self {
            adapter_backing_bytes: 0,
            preflight_backing_bytes: 0,
            execution_backing_bytes: 0,
            simultaneous_plan_backing_bytes: 0,
            retained_output_backing_bytes: 0,
            salt_recipe_backing_bytes: 0,
            cap_construction_backing_bytes: 0,
            ntt_schedule_backing_bytes: 0,
            inline_owner_bytes: size_of::<Self>(),
            requested_payload_bytes: 0,
            matrix_counts: MATRIX_COUNTS,
            maximum_output_log_rows: OUTPUT_LOG_ROWS,
            requires_device_only_output: true,
            complete_preopening_admitted: false,
        };
        for count in MATRIX_COUNTS {
            // salt_data borrows ReplaySalts into SaltInput. Each of the three
            // lde_execute adapters then constructs its separate CommitInput Vec.
            report.adapter_backing_bytes = add(
                report.adapter_backing_bytes,
                sum(&[
                    vector_backing::<SaltInput<'static>>(count)?,
                    vector_backing::<CommitInput<'static>>(count)?,
                ])?,
            )?;
            // engine::plan_lde_commit_storage retains its plan in the PCS
            // caller. Its capture-shape and capture-spec temporaries are charged
            // separately from commit_inputs_inner's second round of planning.
            report.preflight_backing_bytes = add(
                report.preflight_backing_bytes,
                sum(&[
                    vector_backing::<InputShape>(count)?,
                    vector_backing::<MatrixSpec>(count)?,
                ])?,
            )?;
            // shapes + capture_shapes, device_specs, and the independent
            // capture_specs allocation inside device_capture_bytes.
            report.execution_backing_bytes = add(
                report.execution_backing_bytes,
                mul(
                    2,
                    add(
                        vector_backing::<InputShape>(count)?,
                        vector_backing::<MatrixSpec>(count)?,
                    )?,
                )?,
            )?;
            // Both preflight and execution plans retain inputs and prefixes.
            report.simultaneous_plan_backing_bytes = add(
                report.simultaneous_plan_backing_bytes,
                mul(
                    2,
                    add(
                        vector_backing::<InputShape>(count)?,
                        vector_backing::<usize>(count)?,
                    )?,
                )?,
            )?;
            // DeviceMatrix collection moves into OwnedInputs; its dimensions
            // are a new Vec. The empty host matrix Vec still has count-sized
            // backing, because commit_inputs_inner calls with_capacity(count).
            // prefixes remains Vec::new() in the required DeviceOnly path.
            report.retained_output_backing_bytes = add(
                report.retained_output_backing_bytes,
                sum(&[
                    vector_backing::<DeviceMatrix>(count)?,
                    vector_backing::<Dimensions>(count)?,
                    vector_backing::<RowMajorMatrix<Val>>(count)?,
                    mul(count, device::matrix_host_backing(false))?,
                ])?,
            )?;
            // No alias credit: every retained salt recipe charges its stream
            // wrapper even though the actual recipes share the same stream.
            report.salt_recipe_backing_bytes = add(
                report.salt_recipe_backing_bytes,
                add(
                    vector_backing::<ReplaySalts>(count)?,
                    mul(count, device::retained_stream_host_backing())?,
                )?,
            )?;
            // finish_retained_layers' raw u64 download and converted cap, then
            // finish_salted_commit's public Commitment copy. Count all three.
            let cap = 1usize << CAP_HEIGHT;
            report.cap_construction_backing_bytes = add(
                report.cap_construction_backing_bytes,
                add(
                    vector_backing::<u64>(mul(cap, 4)?)?,
                    mul(2, vector_backing::<[Val; 4]>(cap)?)?,
                )?,
            )?;
            report.ntt_schedule_backing_bytes = add(
                report.ntt_schedule_backing_bytes,
                mul(2, vector_backing::<(usize, usize, usize)>(NTT_GROUPS)?)?,
            )?;
            // Count both sides of ownership moves. LdeCommitOutput embeds the
            // execution plan and tree; ProverData embeds OwnedInputs/SaltStore.
            // This is inline owner payload, not a compiled stack-size claim.
            report.inline_owner_bytes = add(
                report.inline_owner_bytes,
                sum(&[
                    size_of::<LdeCommitPlan>(),
                    size_of::<LdeCommitOutput>(),
                    size_of::<ProverData<RowMajorMatrix<Val>>>(),
                ])?,
            )?;
        }
        report.requested_payload_bytes = sum(&[
            report.adapter_backing_bytes,
            report.preflight_backing_bytes,
            report.execution_backing_bytes,
            report.simultaneous_plan_backing_bytes,
            report.retained_output_backing_bytes,
            report.salt_recipe_backing_bytes,
            report.cap_construction_backing_bytes,
            report.ntt_schedule_backing_bytes,
            report.inline_owner_bytes,
        ])?;
        Ok(report)
    }

    pub(crate) fn requested_payload_bytes(self) -> usize {
        self.requested_payload_bytes
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;
    use crate::spill_alloc::allocation_requests::measure;
    use core::mem::MaybeUninit;

    // Fallible collection deliberately has no useful lower size hint. This
    // exercises the generic Vec path instead of a known-length range fast path.
    struct NoHint<I>(I);
    impl<I: Iterator> Iterator for NoHint<I> {
        type Item = I::Item;
        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }

    fn check_vector<T: Copy>() {
        for count in [0usize, 1, 2, 3, 4, 5, 15, 16, 17, 64, 256] {
            let (exact, request) = measure(|| {
                (0..count)
                    .map(|_| MaybeUninit::<T>::uninit())
                    .collect::<Vec<_>>()
            });
            assert!(request.bytes <= vector_backing::<T>(count).unwrap());
            assert!(!request.overflow);
            assert_eq!(exact.len(), count);
            let (fallible, request) = measure(|| {
                NoHint(0..count)
                    .map(|_| Ok::<_, ()>(MaybeUninit::<T>::uninit()))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            });
            assert!(request.bytes <= vector_backing::<T>(count).unwrap());
            assert!(!request.overflow);
            assert_eq!(fallible.len(), count);
            drop((exact, fallible));
        }
    }

    #[test]
    fn pinned_vector_growth_covers_exact_and_fallible_allocation_requests() {
        check_vector::<u8>();
        check_vector::<usize>();
        check_vector::<InputShape>();
        check_vector::<[u8; 2048]>();
        assert_eq!(vector_backing::<()>(usize::MAX), Ok(0));
        assert!(vector_backing::<usize>(usize::MAX).is_err());
    }

    #[test]
    fn pending_copy_and_push_charge_old_and_new_backing() {
        for pending in [[0usize; 2].as_slice(), [0usize; 3].as_slice()] {
            let (values, request) = measure(|| {
                let mut values = pending.to_vec();
                values.push(1);
                values
            });
            assert!(request.bytes <= vector_backing::<usize>(values.len()).unwrap());
            assert!(!request.overflow);
            assert_eq!(values.len(), pending.len() + 1);
        }
    }

    #[test]
    fn fixed_private_lde_census_is_allocation_free_and_grants_no_admission() {
        let (report, request) = measure(|| NoteLdeHostResources::new().unwrap());
        assert_eq!(
            (request.calls, request.bytes, request.overflow),
            (0, 0, false)
        );
        assert_eq!(report.matrix_counts, [1, 16, 1]);
        assert!(report.requires_device_only_output);
        assert!(!report.complete_preopening_admitted);
        // Minimum independent live owners: two plans for all eighteen matrix
        // descriptors, retained private matrix and salt wrappers, and three
        // copies of each commitment's 64-element cap. The full model also
        // includes adapter scratch, growth overlap and output metadata.
        let minimum = 2 * 18 * (size_of::<InputShape>() + size_of::<usize>())
            + 18 * (device::matrix_host_backing(false) + device::retained_stream_host_backing())
            + 3 * 3 * 64 * size_of::<[Val; 4]>();
        assert!(report.requested_payload_bytes() > minimum);
    }
}
