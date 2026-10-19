//! Storage contracts shared by FRI preflight and runtime. Live bytes include
//! borrowed inputs. Host allowances retain their existing output-only meaning;
//! temporary staging is reported separately, not reserved across caller lifetimes.
use crate::gpu_matrix::{Extension, MatrixSpec, RowOrder};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoragePlan {
    pub(crate) peak_bytes: usize,
    pub(crate) max_allocation_bytes: usize,
    pub(crate) host_output_bytes: usize,
    pub(crate) host_temporary_bytes: usize,
}

fn storage(
    allocations: &[usize],
    live: usize,
    limit: usize,
    max_alloc: usize,
    host_output_bytes: usize,
    host_temporary_bytes: usize,
    host_allowance: usize,
) -> Result<StoragePlan, String> {
    if host_output_bytes > host_allowance {
        return Err("FRI output exceeds host allowance".into());
    }
    let mut peak = live;
    let mut largest = 0;
    for &bytes in allocations {
        peak = peak.checked_add(bytes).ok_or("FRI storage overflow")?;
        if bytes > max_alloc || peak > limit {
            return Err("FRI storage exceeds managed/device allocation capacity".into());
        }
        largest = largest.max(bytes);
    }
    Ok(StoragePlan {
        peak_bytes: peak,
        max_allocation_bytes: largest,
        host_output_bytes,
        host_temporary_bytes,
    })
}

pub(crate) fn fold_output(input: MatrixSpec, log_arity: usize) -> Result<MatrixSpec, String> {
    vector(input)?;
    if !(1..=4).contains(&log_arity) || log_arity > input.log_rows as usize {
        return Err("FRI fold arity exceeds input or supported bound".into());
    }
    MatrixSpec::new(
        input.log_rows - log_arity as u32,
        1,
        input.extension,
        RowOrder::BitReversed,
        1,
    )
}

pub(crate) fn leaves(input: MatrixSpec, log_arity: usize) -> Result<MatrixSpec, String> {
    fold_output(input, log_arity)?;
    MatrixSpec::new(
        input.log_rows - log_arity as u32,
        1 << log_arity,
        input.extension,
        RowOrder::BitReversed,
        1,
    )
}

/// Folds and input mixes allocate one fresh extension vector. Shape/challenge
/// validation remains outside the allocation step; both runtime paths call this.
pub(crate) fn vector_output(
    output: MatrixSpec,
    live: usize,
    limit: usize,
    max_alloc: usize,
) -> Result<StoragePlan, String> {
    vector(output)?;
    storage(&[output.bytes()], live, limit, max_alloc, 0, 0, 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GatherShape {
    pub(crate) width: usize,
    pub(crate) queries: usize,
    pub(crate) words: usize,
}
impl GatherShape {
    pub(crate) fn new(
        input: MatrixSpec,
        queries: usize,
        host_allowance: usize,
    ) -> Result<Self, String> {
        let width = input
            .columns
            .checked_mul(input.extension.degree())
            .filter(|width| *width <= 16384)
            .ok_or("device gather width exceeds bound")?;
        if queries == 0 || queries > 4096 {
            return Err("device gather index count exceeds bound".into());
        }
        let words = queries
            .checked_mul(width)
            .ok_or("device gather size overflow")?;
        if words.checked_mul(8).is_none_or(|n| n > host_allowance) {
            return Err("device gather exceeds host allowance".into());
        }
        Ok(Self {
            width,
            queries,
            words,
        })
    }
    pub(crate) fn plan(
        self,
        live: usize,
        limit: usize,
        max_alloc: usize,
    ) -> Result<StoragePlan, String> {
        storage(
            &[self.words * 8, self.queries * 8],
            live,
            limit,
            max_alloc,
            self.words * 8,
            self.queries * 8,
            self.words * 8,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FinalShape {
    pub(crate) input: MatrixSpec,
    pub(crate) output: MatrixSpec,
}
impl FinalShape {
    pub(crate) fn new(
        input: MatrixSpec,
        log_blowup: usize,
        log_final_len: usize,
        host_allowance: usize,
    ) -> Result<Self, String> {
        vector(input)?;
        if log_final_len > 16
            || log_blowup.checked_add(log_final_len) != Some(input.log_rows as usize)
        {
            return Err("final polynomial domain or coefficient count exceeds its bound".into());
        }
        let output = MatrixSpec::new(
            log_final_len as u32,
            1,
            input.extension,
            RowOrder::Natural,
            1,
        )?;
        if output.bytes() > host_allowance {
            return Err("final polynomial exceeds host output allowance".into());
        }
        Ok(Self { input, output })
    }
    pub(crate) fn plan(
        self,
        live: usize,
        limit: usize,
        max_alloc: usize,
    ) -> Result<StoragePlan, String> {
        let log = self.output.log_rows as usize;
        if log == 0 {
            return GatherShape::new(self.input, 1, self.output.bytes())?
                .plan(live, limit, max_alloc);
        }
        storage(
            &[self.output.bytes(), self.output.bytes(), log * 8, 16],
            live,
            limit,
            max_alloc,
            self.output.bytes(),
            log * 8,
            self.output.bytes(),
        )
    }
}

pub(crate) fn vector(spec: MatrixSpec) -> Result<(), String> {
    if !matches!(spec.extension, Extension::Quadratic | Extension::Cubic)
        || spec.columns != 1
        || spec.log_rows > 25
        || spec.order != RowOrder::BitReversed
        || spec.shift != 1
    {
        return Err("FRI requires a quadratic/cubic bit-reversed subgroup vector".into());
    }
    Ok(())
}
