//! Shared static-periodic expansion geometry for all GPU backends.
use super::{Extension, MatrixSpec, MemoryPlan, RowOrder};

/// Storage geometry shared by request admission and runtime expansion. No
/// periodic field values or device allocations are needed to construct it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeriodicShape {
    pub(crate) output: MatrixSpec,
    pub(crate) input: MatrixSpec,
    pub(crate) metadata: MatrixSpec,
}

impl PeriodicShape {
    pub(crate) fn new(
        log_rows: u32,
        lengths: impl ExactSizeIterator<Item = usize>,
    ) -> Result<Self, String> {
        let count = lengths.len();
        let output = MatrixSpec::new(log_rows, count, Extension::Base, RowOrder::Natural, 1)?;
        let mut words = 0usize;
        for len in lengths {
            if !len.is_power_of_two() || len > output.rows() {
                return Err("invalid periodic column length".into());
            }
            words = words
                .checked_add(len)
                .ok_or("periodic source size overflow")?;
        }
        let metadata = count.checked_mul(2).ok_or("periodic metadata overflow")?;
        Ok(Self {
            output,
            input: MatrixSpec::new(0, words, Extension::Base, RowOrder::Natural, 1)?,
            metadata: MatrixSpec::new(0, metadata, Extension::Base, RowOrder::Natural, 1)?,
        })
    }

    pub(crate) fn input_words(self) -> usize {
        self.input.words()
    }
    pub(crate) fn metadata_words(self) -> usize {
        self.metadata.words()
    }
    pub(crate) fn allocation_bytes(self) -> [usize; 3] {
        [
            self.output.bytes(),
            self.input.bytes(),
            self.metadata.bytes(),
        ]
    }
    pub(crate) fn plan(
        self,
        live: usize,
        limit: usize,
        max_alloc: usize,
    ) -> Result<MemoryPlan, String> {
        MemoryPlan::new(
            &[self.output, self.input, self.metadata],
            live,
            limit,
            max_alloc,
        )
    }
}
