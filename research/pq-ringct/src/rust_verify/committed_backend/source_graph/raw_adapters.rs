//! Pure fixed raw-adapter storage formulas, also used by test-only Construction.
//! This is source storage, not a driver or compiled-stack high-water bound.
use super::super::*;
use super::bounds::{add, backing, mul, Ceilings};
use core::mem::{align_of, size_of};

type Error = &'static str;
type RawPoly = [u64; D];

fn growing<T>(count: usize) -> Result<usize, Error> {
    backing::<T>(mul(3, count)?)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RawAdapterPlan {
    pub(super) framing: usize,
    pub(super) crypto_returns: usize,
    pub(super) sampled_polynomials: usize,
    pub(super) arithmetic: usize,
    pub(super) wrappers: usize,
    pub(super) host_bytes: usize,
    pub(super) device_bytes: usize,
    pub(super) operation_host_allowance: usize,
}

impl RawAdapterPlan {
    pub(super) fn fixed() -> Result<Self, Error> {
        // backend::{sample_g,expand_alpha} may reuse RawPoly backing for IDs.
        // With the pinned Vec in-place collector these exact layout relations
        // avoid a shrink/realloc. The whole source allocation is charged below,
        // never merely the resulting (much smaller) ID length.
        if align_of::<RawPoly>() != align_of::<PolyId>()
            || size_of::<RawPoly>() % size_of::<PolyId>() != 0
        {
            return Err("raw polynomial-to-ID collector layout changed");
        }
        let ceiling = Ceilings::fixed();
        let alpha_input = add(mul(ceiling.alpha_parts - 3, D * 4)?, 3 * 32)?;
        let x_input = add(mul(ceiling.x_parts - 1, D * 4)?, 32)?;
        let setup = 32 + 6 + 2 + 4 + 4 + 1;
        let binding = b"lattica/pq-ringct/matrict-plus-n10/fixture-v1".len() + 32 + 32;
        let framing = add(
            growing::<u8>(add(add(setup, binding)?, add(alpha_input, x_input)?)?)?,
            4 * size_of::<Vec<u8>>(),
        )?;

        // Every fixed crypto call is charged, conservatively ignoring early
        // drops. Readback pops its status word WITHOUT reducing capacity.
        // Byte conversion borrows RawWords, so word and byte backing coexist.
        let byte_outputs = [
            32,
            32,
            7648 * 4,
            3366 * 4,
            37232 * 5,
            1197 * 4,
            1197 * 4,
            643 * 4,
            127,
            32,
            137,
        ];
        let word_outputs = [
            7 * 4 * D,
            4 * 2 * D + 4 * 124 * 2,
            29 * 5 * D,
            4 * D,
            4 * D,
            2 * D,
            D,
            D,
        ];
        let mut crypto_returns = 0;
        for count in byte_outputs {
            crypto_returns = add(
                crypto_returns,
                add(backing::<u64>(add(count, 1)?)?, growing::<u8>(count)?)?,
            )?;
        }
        for count in word_outputs {
            crypto_returns = add(crypto_returns, backing::<u64>(add(count, 1)?)?)?;
        }
        crypto_returns = add(
            crypto_returns,
            (2 * byte_outputs.len() + word_outputs.len()) * size_of::<Vec<u64>>(),
        )?;

        // All three matrices, regrouping copies for mat1/mat3, both sample_g
        // outputs and alpha. Includes the original RawPoly allocation if its
        // later map to PolyId is in-place. Charge an additional ID allocation
        // too, so a collector choosing not to specialize remains covered.
        let sampled_polynomials = add(
            add(
                growing::<RawPoly>(185 + 173 + 4 + 4 + 2)?,
                growing::<Vec<RawPoly>>(7 + 4 + 29)?,
            )?,
            add(
                growing::<PolyId>(4 + 4 + 2)?,
                size_of::<primitives::Parameters>() + 7 * size_of::<Vec<RawPoly>>(),
            )?,
        )?;

        // Raw arithmetic is sequential and always a single polynomial. Sum
        // both public schedules, plus the largest metadata Vec growth (NTT),
        // input/output/status vectors and one shaped polynomial. vec growth
        // from 4 -> 3076 -> 6152 words is below 3 * final length 3140.
        let arithmetic = add(
            add(
                add(growing::<[u64; 4]>(768)?, growing::<[u64; 2]>(1024)?)?,
                // Four scope-owned public specs (NTT/product, Q/QHAT),
                // including allocator growth and their inline wrappers.
                add(growing::<u64>(2 * (3140 + 2052))?, 1024)?,
            )?,
            add(
                growing::<u64>(3140 + 512 + D + D)?,
                add(
                    growing::<RawPoly>(1)?,
                    6 * size_of::<Vec<u64>>()
                        + size_of::<[u64; 64]>()
                        + 3 * size_of::<RawPoly>()
                    // Batched signed subtraction: raw staging, both operands,
                    // returned values, bounds, and shaped reference copies.
                    + 6 * size_of::<RawPoly>()
                    + size_of::<[u32; D]>()
                    + 4 * size_of::<[SignedRef; D]>()
                        + size_of::<[bool; D]>()
                        + size_of::<crate::ntt_air::NttAir>()
                        + size_of::<crate::poly_air::MulAir>()
                        + size_of::<crate::permutation_air::PermutationAir>(),
                )?,
            )?,
        )?;

        #[cfg(all(feature = "opencl", target_os = "linux", target_arch = "x86_64"))]
        let wrappers = lattica_prover_p3::block_v2::native_gpu::RawGraphOperationStorage::fixed()?
            .requested_bytes();
        #[cfg(not(all(feature = "opencl", target_os = "linux", target_arch = "x86_64")))]
        let wrappers = 0;
        #[cfg(all(test, feature = "opencl"))]
        let wrappers = add(wrappers, super::super::gpu::profiling::FRAME_BYTES)?;
        #[cfg(feature = "opencl")]
        let wrappers = add(wrappers, super::super::gpu::commitments::FRAME_BYTES)?;
        #[cfg(feature = "opencl")]
        let wrappers = add(wrappers, super::super::vector_arithmetic::FRAME_BYTES)?;
        if cfg!(feature = "opencl") && !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err("owned raw graph requires Linux x86_64 OpenCL storage bounds");
        }

        // These are the core raw API's admission checks, not estimates of the
        // complete constructor. The largest is the mat3 AES byte generator.
        let operation_host_allowance = add(32, add(mul(16, 37232 * 5 + 1)?, 80 << 10)?)?;
        let workspace = lattica_prover_p3::block_v2::native_gpu::RawPreparationWorkspaceStorage::fixed();
        let operation_host_allowance = add(operation_host_allowance, workspace.host_bytes)?;
        // Each byte is one device u64. Operations scrub their used prefixes and
        // finish before returning. The separately charged scope workspace stays
        // live alongside transient operations that exceed its capacities. Hash
        // alpha dominates AES (32+5+256*66+186161 words), uniform mat3
        // (186160+5+1+37121), arithmetic and two-buffer node commitments.
        let device_bytes = if cfg!(feature = "opencl") {
            add(backing::<u64>(add(alpha_input, 5 + 1 + 32 + 1)?)?, workspace.device_bytes)?
        } else {
            0
        };
        let host_bytes = add(
            add(
                add(framing, crypto_returns)?,
                add(sampled_polynomials, arithmetic)?,
            )?,
            add(wrappers, size_of::<Self>())?,
        )?;
        if host_bytes < operation_host_allowance {
            return Err("raw graph storage cannot cover the operation admission allowance");
        }
        Ok(Self {
            framing,
            crypto_returns,
            sampled_polynomials,
            arithmetic,
            wrappers,
            host_bytes,
            device_bytes,
            operation_host_allowance,
        })
    }
}

#[cfg(test)]
mod tests;
