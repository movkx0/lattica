//! Explicit arithmetic for public compiler constants. Device sessions are
//! borrowed for one compilation and never enter a program or worker packet.
use super::{program::Val, verifier::CompileError};
use crate::proving::{Backend, Run, Stage};
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};

mod folding;
pub(crate) use folding::{FoldOperation, Folding};

#[derive(Clone, Copy)]
pub(crate) enum Constants<'a> {
    Cpu(Option<&'a Run>),
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    Device(
        &'a crate::block_v2::gpu_hash::device::DeviceSession,
        &'a Run,
    ),
}

pub(crate) fn selector_count(first: u64, last: u64) -> Result<usize, CompileError> {
    if first > last || last >= 0xffff_ffff_0000_0001 {
        return Err(CompileError::Shape("compiler selector range"));
    }
    usize::try_from(last - first + 1).map_err(|_| CompileError::Shape("compiler selector count"))
}

pub(crate) fn quotient_count(chunks: usize, log_height: usize) -> Result<usize, CompileError> {
    if !chunks.is_power_of_two() || log_height > 32 || log_height + chunks.ilog2() as usize > 32 {
        return Err(CompileError::Shape("compiler quotient domain"));
    }
    chunks
        .checked_mul(chunks)
        .and_then(|n| n.checked_add(chunks))
        .ok_or(CompileError::Shape("compiler quotient count"))
}

impl<'a> Constants<'a> {
    pub(crate) const fn cpu() -> Self {
        Self::Cpu(None)
    }

    pub(crate) fn cpu_reported(run: &'a Run) -> Self {
        Self::Cpu(Some(run))
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn device(
        session: &'a crate::block_v2::gpu_hash::device::DeviceSession,
        run: &'a Run,
    ) -> Self {
        Self::Device(session, run)
    }

    pub(crate) fn cpu_work<T>(
        run: Option<&Run>,
        body: impl FnOnce() -> T,
    ) -> Result<T, CompileError> {
        if let Some(run) = run {
            run.measure(Stage::Preprocessing, Backend::Cpu, body)
                .map_err(|e| CompileError::Backend(e.to_string()))
        } else {
            Ok(body())
        }
    }

    pub(crate) fn inverse_generator(self, log_height: usize) -> Result<Val, CompileError> {
        if log_height > 32 {
            return Err(CompileError::Shape("compiler subgroup height"));
        }
        match self {
            Self::Cpu(run) => Self::cpu_work(run, || Val::two_adic_generator(log_height).inverse()),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Self::Device(session, run) => session
                .compiler_inverse_generator(log_height, run)
                .map_err(CompileError::Backend),
        }
    }

    /// Fill storage admitted by the caller; no owned output or temporary copy.
    pub(crate) fn selectors_into(
        self,
        first: u64,
        last: u64,
        output: &mut [Val],
    ) -> Result<(), CompileError> {
        if output.len() != selector_count(first, last)? {
            return Err(CompileError::Shape("compiler selector output"));
        }
        match self {
            Self::Cpu(run) => Self::cpu_work(run, || {
                for (i, out) in (first..=last).zip(output) {
                    let mut denominator = Val::ONE;
                    for j in first..=last {
                        if i != j {
                            denominator *= Val::from_u64(i) - Val::from_u64(j);
                        }
                    }
                    *out = denominator.inverse();
                }
            }),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Self::Device(session, run) => session
                .compiler_selectors_into(first, last, output, run)
                .map_err(CompileError::Backend),
        }
    }

    pub(crate) fn periodic_into(
        self,
        column: &[Val],
        log_height: usize,
        output: &mut [Val],
    ) -> Result<(), CompileError> {
        let n = column.len();
        if log_height > 32 || !n.is_power_of_two() || n > 1usize << log_height || output.len() != n
        {
            return Err(CompileError::Shape("periodic column height"));
        }
        match self {
            Self::Cpu(run) => Self::cpu_work(run, || {
                let generator_inv = Val::two_adic_generator(n.ilog2() as usize).inverse();
                let inv_n = Val::from_usize(n).inverse();
                for (k, out) in output.iter_mut().enumerate() {
                    let step = generator_inv.exp_u64(k as u64);
                    let mut power = Val::ONE;
                    let mut sum = Val::ZERO;
                    for &value in column {
                        sum += power * value;
                        power *= step;
                    }
                    *out = sum * inv_n;
                }
            }),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Self::Device(session, run) => session
                .compiler_periodic_into(column, log_height, output, run)
                .map_err(CompileError::Backend),
        }
    }

    /// Inverse shifts followed by row-major normalization inverses (zero diagonal).
    pub(crate) fn quotient_into(
        self,
        chunks: usize,
        log_height: usize,
        output: &mut [Val],
    ) -> Result<(), CompileError> {
        if output.len() != quotient_count(chunks, log_height)? {
            return Err(CompileError::Shape("compiler quotient output"));
        }
        match self {
            Self::Cpu(run) => Self::cpu_work(run, || {
                let g = Val::two_adic_generator(log_height + chunks.ilog2() as usize);
                let (inverse_shifts, normalization) = output.split_at_mut(chunks);
                for i in 0..chunks {
                    let shift = Val::GENERATOR * g.exp_u64(i as u64);
                    inverse_shifts[i] = shift.inverse();
                    for j in 0..chunks {
                        normalization[i * chunks + j] = if i == j {
                            Val::ZERO
                        } else {
                            let other = Val::GENERATOR * g.exp_u64(j as u64);
                            ((shift / other).exp_u64(1 << log_height) - Val::ONE).inverse()
                        };
                    }
                }
            }),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Self::Device(session, run) => session
                .compiler_quotient_into(chunks, log_height, output, run)
                .map_err(CompileError::Backend),
        }
    }
}
