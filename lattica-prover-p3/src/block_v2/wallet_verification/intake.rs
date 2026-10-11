//! Payload phases of one wallet verification through an already-approved context.
//!
//! Input bytes/registry/list owners are reserved by the caller. Registry approval,
//! stacks, allocator overhead and runtime control are separate. Concrete decoding
//! creates exact-capacity Vecs; a valid decoded proof uses the envelope maximum,
//! not the much larger allowance for arbitrary caller-owned proof capacities.

use super::decoded::{self, add};
use super::{profile, scratch, Val, MAX_DEGREE_BITS, MAX_PUBLIC};

const DIAGNOSTIC_BYTES: usize = 1024 + core::mem::size_of::<String>();

pub(crate) fn summary_requested_bytes() -> usize {
    // commitment::{statement_digest, leaf}, then streaming ArtifactRef hashing.
    // Each pinned x86_64 Poseidon2 constructor owns two four-round width-eight
    // constant vectors and 22 internal constants. Hashing uses stack state.
    3 * (2 * 4 * 8 + 22) * core::mem::size_of::<Val>() + MAX_PUBLIC * core::mem::size_of::<u64>()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    pub(crate) decoded_backing_bytes: usize,
    pub(crate) valid_decode_requested_bytes: usize,
    pub(crate) decoder_allowance_bytes: usize,
    pub(crate) numerical_peak_bytes: usize,
    pub(crate) summary_requested_bytes: usize,
    pub(crate) peak_bytes: usize,
    pub(crate) cumulative_requested_bytes: usize,
}

impl Plan {
    pub(crate) fn new(degree: usize, htlc: bool) -> Result<Self, &'static str> {
        let decoded_backing_bytes = decoded::backing_bytes(degree, htlc)?;
        let valid_decode_requested_bytes = add(decoded_backing_bytes, profile::MAX_PROOF_BYTES)?;
        let decoder_allowance_bytes = decoded::storage_limit()?;
        let numerical = scratch::Plan::new(degree, htlc)?;
        let summary_requested_bytes = summary_requested_bytes();
        // Canonical scratch is dropped before verification. The structural
        // envelope must pass before numerical allocation. Invalid decoder or
        // envelope paths retain at most the decoder allowance plus an error.
        let after_decode = add(
            decoded_backing_bytes,
            numerical.temporary_peak_bytes.max(summary_requested_bytes),
        )?;
        let peak_bytes = add(DIAGNOSTIC_BYTES, decoder_allowance_bytes.max(after_decode))?;
        let cumulative_requested_bytes = add(
            DIAGNOSTIC_BYTES,
            add(
                decoder_allowance_bytes,
                add(
                    numerical.cumulative_requested_bytes,
                    summary_requested_bytes,
                )?,
            )?,
        )?;
        Ok(Self {
            decoded_backing_bytes,
            valid_decode_requested_bytes,
            decoder_allowance_bytes,
            numerical_peak_bytes: numerical.temporary_peak_bytes,
            summary_requested_bytes,
            peak_bytes,
            cumulative_requested_bytes,
        })
    }

    pub(crate) fn maximum() -> Result<Self, &'static str> {
        let mut maximum = Self::new(1, false)?;
        for htlc in [false, true] {
            for degree in 1..=MAX_DEGREE_BITS {
                let plan = Self::new(degree, htlc)?;
                maximum.decoded_backing_bytes = maximum
                    .decoded_backing_bytes
                    .max(plan.decoded_backing_bytes);
                maximum.valid_decode_requested_bytes = maximum
                    .valid_decode_requested_bytes
                    .max(plan.valid_decode_requested_bytes);
                maximum.numerical_peak_bytes =
                    maximum.numerical_peak_bytes.max(plan.numerical_peak_bytes);
                maximum.peak_bytes = maximum.peak_bytes.max(plan.peak_bytes);
                maximum.cumulative_requested_bytes = maximum
                    .cumulative_requested_bytes
                    .max(plan.cumulative_requested_bytes);
            }
        }
        Ok(maximum)
    }
}
