//! Backend-independent field matrix geometry and allocation planning.
//! This metadata contains no witness values or runtime handles.

mod domain;
pub(crate) mod query;
pub(crate) mod roots;
pub(crate) use domain::DomainSpec;

pub(crate) const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Extension {
    Base,
    Quadratic,
    Cubic,
}
impl Extension {
    pub fn degree(self) -> usize {
        match self {
            Self::Base => 1,
            Self::Quadratic => 2,
            Self::Cubic => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowOrder {
    Natural,
    BitReversed,
}

/// Contiguous row-major field elements, with adjacent extension coefficients.
/// `shift` is a canonical, nonzero Goldilocks coset multiplier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatrixSpec {
    pub(crate) log_rows: u32,
    pub(crate) columns: usize,
    pub(crate) extension: Extension,
    pub(crate) order: RowOrder,
    pub(crate) shift: u64,
    pub(crate) words: usize,
}

impl MatrixSpec {
    pub fn new(
        log_rows: u32,
        columns: usize,
        extension: Extension,
        order: RowOrder,
        shift: u64,
    ) -> Result<Self, String> {
        if log_rows > 32 || columns == 0 || columns > u32::MAX as usize {
            return Err("invalid device matrix dimensions".into());
        }
        if shift == 0 || shift >= GOLDILOCKS_MODULUS {
            return Err("device matrix coset shift must be canonical and nonzero".into());
        }
        let words = 1usize
            .checked_shl(log_rows)
            .and_then(|rows| rows.checked_mul(columns))
            .and_then(|elements| elements.checked_mul(extension.degree()))
            .filter(|words| words.checked_mul(8).is_some())
            .ok_or("device matrix storage overflow")?;
        Ok(Self {
            log_rows,
            columns,
            extension,
            order,
            shift,
            words,
        })
    }
    pub fn rows(self) -> usize {
        1usize << self.log_rows
    }
    pub fn columns(self) -> usize {
        self.columns
    }
    pub fn extension(self) -> Extension {
        self.extension
    }
    pub fn order(self) -> RowOrder {
        self.order
    }
    pub fn shift(self) -> u64 {
        self.shift
    }
    pub fn words(self) -> usize {
        self.words
    }
    pub fn bytes(self) -> usize {
        self.words * 8
    }

    pub(crate) fn cubic_fold_output(self) -> Result<Self, String> {
        if self.extension != Extension::Cubic
            || self.columns != 1
            || self.order != RowOrder::BitReversed
            || self.shift != 1
            || !(1..=25).contains(&self.log_rows)
        {
            return Err(
                "device FRI fold requires a bit-reversed cubic subgroup vector of 2..2^25 rows"
                    .into(),
            );
        }
        Self::new(self.log_rows - 1, 1, self.extension, self.order, 1)
    }
}

/// A snapshot, never a reservation. Execution replans under the engine lock;
/// allocation rechecks all live leases atomically, including retained trees.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct MemoryPlan {
    pub output_bytes: Vec<usize>,
    pub live_bytes: usize,
    pub peak_bytes: usize,
}
impl MemoryPlan {
    pub fn new(
        outputs: &[MatrixSpec],
        live_bytes: usize,
        managed_limit: usize,
        max_allocation: usize,
    ) -> Result<Self, String> {
        if outputs.is_empty() || outputs.len() > 256 || live_bytes > managed_limit {
            return Err("invalid device allocation plan".into());
        }
        let mut peak_bytes = live_bytes;
        let mut output_bytes = Vec::with_capacity(outputs.len());
        for output in outputs {
            let bytes = output.bytes();
            if bytes > max_allocation {
                return Err("device matrix exceeds per-allocation limit".into());
            }
            peak_bytes = peak_bytes
                .checked_add(bytes)
                .ok_or("device live-byte overflow")?;
            if peak_bytes > managed_limit {
                return Err("device matrix exceeds aggregate allocation budget".into());
            }
            output_bytes.push(bytes);
        }
        Ok(Self {
            output_bytes,
            live_bytes,
            peak_bytes,
        })
    }
}
