use super::*;
use crate::gpu_matrix::periodic::PeriodicShape;

impl Starks {
    pub(super) fn prepare_periodic(
        &self,
        source: &impl Source,
        log_rows: u32,
        host_bytes: usize,
    ) -> Result<Option<Matrix>> {
        let count = source.count();
        if count == 0 {
            return Ok(None);
        }
        let shape = PeriodicShape::new(log_rows, (0..count).map(|i| source.len(i).unwrap_or(0)))?;
        let host = shape
            .input_words()
            .checked_mul(16)
            .and_then(|n| n.checked_add(shape.metadata_words() * 8))
            .and_then(|n| n.checked_add(count * 8))
            .and_then(|n| n.checked_add(HOST_METADATA))
            .ok_or("CUDA periodic host storage overflow")?;
        if host > host_bytes {
            return Err("CUDA periodic tables exceed host allowance".into());
        }
        let limits = self.runtime.state.budget.limits;
        shape.plan(
            self.runtime.snapshot().live_bytes,
            limits.managed_bytes,
            limits.max_allocation_bytes,
        )?;
        let retained = self
            .runtime
            .snapshot()
            .live_bytes
            .checked_add(shape.output.bytes())
            .ok_or("CUDA periodic transform storage overflow")?;
        super::super::transform::storage_plan(shape.output, log_rows, retained, limits)?;
        let mut lengths = vector(count)?;
        for i in 0..count {
            lengths.push(source.len(i).ok_or("CUDA periodic source length changed")?);
        }
        if PeriodicShape::new(log_rows, lengths.iter().copied())? != shape {
            return Err("CUDA periodic source geometry changed".into());
        }
        let mut words = vector(shape.input_words())?;
        let mut metadata = vector(shape.metadata_words())?;
        let mut fields = vector(*lengths.iter().max().unwrap())?;
        for (index, &len) in lengths.iter().enumerate() {
            if source.count() != count || source.len(index) != Some(len) {
                return Err("CUDA periodic source geometry changed during construction".into());
            }
            fields.resize(len, Val::ZERO);
            source
                .fill(index, &mut fields)
                .map_err(super::super::error)?;
            metadata.extend([words.len() as u64, len as u64]);
            words.extend(fields.iter().map(PrimeField64::as_canonical_u64));
        }
        if words.len() != shape.input_words()
            || source.count() != count
            || lengths
                .iter()
                .enumerate()
                .any(|(i, &n)| source.len(i) != Some(n))
        {
            return Err("CUDA periodic source changed after construction".into());
        }
        let source = self.runtime.allocate(words.len())?;
        source.write(0, &words)?;
        let descriptors = self.runtime.allocate(metadata.len())?;
        descriptors.write(0, &metadata)?;
        let matrix = Matrix {
            spec: shape.output,
            buffer: self.runtime.allocate(shape.output.words())?,
        };
        // Periods and offsets cover the admitted source. Each lane owns one
        // output cell, with a power-of-two periodic index bounded by its column.
        unsafe {
            self.periodic_expand.launch(
                super::super::transform::linear_launch(shape.output.words())?,
                &[
                    super::super::Argument::Buffer(&source),
                    super::super::Argument::Buffer(&descriptors),
                    super::super::Argument::Buffer(&matrix.buffer),
                    super::super::Argument::U64(shape.output.rows() as u64),
                    super::super::Argument::U64(count as u64),
                ],
            )?
        }
        .finish()?;
        drop(source);
        drop(descriptors);
        self.transforms
            .lde(&matrix, log_rows, 7, RowOrder::BitReversed)
            .map(Some)
    }
}
