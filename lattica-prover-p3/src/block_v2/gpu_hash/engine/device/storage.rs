//! Immutable public preprocessing and explicit device copies. Private matrices
//! can only be aliased within one attempt; public promotion is crate-private
//! and reserved for the PCS's deterministic preprocessing branch.
use super::super::lde_plan::InputShape;
use super::*;
use p3_field::{Field, PrimeField64};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_capture_accounts_for_doubled_degree_and_checks_overflow() {
        use crate::block_v2::gpu_hash::engine::{device_capture_bytes, device_capture_shapes};
        let input = InputShape {
            height: 128,
            width: 7,
            added_bits: 5,
        };
        let shapes = device_capture_shapes(&[input], 1).unwrap();
        assert_eq!(shapes[0].height, 256);
        assert_eq!(shapes[0].added_bits, 4);
        assert_eq!(
            shapes[0].height << shapes[0].added_bits,
            input.height << input.added_bits
        );
        assert_eq!(
            device_capture_bytes(&shapes, 256 * 7 * 8).unwrap(),
            256 * 7 * 8
        );
        assert!(device_capture_bytes(&shapes, 128 * 7 * 8).is_err());
        assert!(device_capture_shapes(&[input], 2).is_err());
        assert!(device_capture_shapes(
            &[InputShape {
                added_bits: 0,
                ..input
            }],
            1
        )
        .is_err());
        assert!(device_capture_shapes(
            &[InputShape {
                height: 1 << 63,
                ..input
            }],
            1
        )
        .is_err());
    }

    #[test]
    fn captured_prefixes_use_degree_sized_storage_and_enforce_allocation_limits() {
        let inputs = [
            InputShape {
                height: 128,
                width: 200,
                added_bits: 4,
            },
            InputShape {
                height: 64,
                width: 98,
                added_bits: 5,
            },
        ];
        let specs = capture_specs(&inputs).unwrap();
        for (spec, shape) in specs.iter().zip(inputs) {
            assert_eq!(spec.rows(), shape.height);
            assert_eq!(spec.columns(), shape.width);
            assert_eq!(spec.bytes(), shape.height * shape.width * 8);
            assert_eq!(spec.extension, Extension::Base);
            assert_eq!(spec.order, RowOrder::BitReversed);
            assert_eq!(spec.shift(), Val::GENERATOR.as_canonical_u64());
        }
        let max_alloc = specs.iter().map(|spec| spec.bytes()).max().unwrap();
        let captured_bytes = crate::block_v2::gpu_hash::engine::device_capture_bytes;
        assert_eq!(
            captured_bytes(&inputs, max_alloc).unwrap(),
            128 * 200 * 8 + 64 * 98 * 8
        );
        assert!(captured_bytes(&inputs, max_alloc - 1).is_err());
        assert!(capture_specs(&[]).is_err());
        assert!(capture_specs(&vec![inputs[0]; 257]).is_err());
        for invalid in [
            InputShape {
                height: 0,
                ..inputs[0]
            },
            InputShape {
                height: 127,
                ..inputs[0]
            },
            InputShape {
                width: 0,
                ..inputs[0]
            },
            InputShape {
                added_bits: 32,
                ..inputs[0]
            },
        ] {
            assert!(capture_specs(&[invalid]).is_err());
        }
    }
}

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_copy_column_band(__global const ulong *source,
    __global ulong *target, uint source_width, uint source_row,
    uint rows, uint first, uint columns) {
    size_t i = get_global_id(0);
    if (i >= (size_t)rows * columns) return;
    target[i] = source[((size_t)source_row + i / columns) * source_width + first + i % columns];
}
__kernel void device_original_trace_rows(__global const ulong *source, __global ulong *target, uint rows, uint width) {
    size_t i = get_global_id(0);
    if (i >= (size_t)rows * width) return;
    target[i] = source[(i / width) * 2 * width + i % width];
}
__kernel void device_copy_columns(__global const ulong *source, __global ulong *target,
    uint source_width, uint target_width, uint source_first, uint target_first,
    uint columns, uint rows) {
    size_t i = get_global_id(0);
    if (i >= (size_t)rows * columns) return;
    size_t row = i / columns, column = i % columns;
    target[row * target_width + target_first + column] = source[row * source_width + source_first + column];
}
"#;

pub(crate) fn capture_specs(inputs: &[InputShape]) -> Result<Vec<MatrixSpec>, String> {
    if inputs.is_empty() || inputs.len() > 256 {
        return Err("device LDE capture matrix count exceeds its bound".into());
    }
    inputs
        .iter()
        .map(|shape| {
            if !shape.height.is_power_of_two() || shape.added_bits > 31 {
                return Err("invalid device LDE capture geometry".into());
            }
            // The caller supplies the effective polynomial degree, including
            // the doubled degree of a masked quotient commitment.
            let log_rows = shape.height.trailing_zeros();
            if log_rows > 31 {
                return Err("device LDE capture height overflow".into());
            }
            MatrixSpec::new(
                log_rows,
                shape.width,
                Extension::Base,
                RowOrder::BitReversed,
                Val::GENERATOR.as_canonical_u64(),
            )
        })
        .collect()
}

/// Only deterministic, public preprocessing may inhabit this type. No salt,
/// hiding column, witness or challenge is promoted by the PCS implementation.
#[derive(Clone)]
pub(crate) struct PublicMatrix {
    storage: Arc<Allocation>,
    context: Arc<JobLease>,
    spec: MatrixSpec,
}

impl PublicMatrix {
    pub(crate) fn cached_host_backing(&self) -> usize {
        crate::block_v2::gpu_hash::cache_metadata::arc_bytes::<Allocation>()
    }
}

impl DeviceMatrix {
    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        session.check_owner(self)
    }
    pub(in crate::block_v2::gpu_hash::engine) fn check_engine(
        &self,
        engine: &Engine,
    ) -> Result<(), String> {
        if !Arc::ptr_eq(&self.session.context, &engine._job_lease) {
            return Err("device matrix belongs to another context".into());
        }
        Ok(())
    }
    pub(in crate::block_v2::gpu_hash::engine) fn copy_column_band(
        &self,
        engine: &mut Engine,
        target: &compute::Buffer<u64>,
        row0: usize,
        rows: usize,
        first: usize,
        columns: usize,
    ) -> Result<(), String> {
        self.check_engine(engine)?;
        if self.spec.extension != Extension::Base
            || rows == 0
            || columns == 0
            || row0.checked_add(rows).is_none_or(|n| n > self.spec.rows())
            || first
                .checked_add(columns)
                .is_none_or(|n| n > self.spec.columns)
            || rows.checked_mul(columns).is_none_or(|n| n > target.len())
            || self.spec.rows() > u32::MAX as usize
        {
            return Err("invalid device column band".into());
        }
        #[cfg(not(feature = "gpu"))]
        {
            Err("device column bands are not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        {
            let mut event = compute::Event::empty();
            // SAFETY: source rows/columns and target capacity checked above.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_copy_column_band")
                    .arg(&self.storage.buffer)
                    .arg(target)
                    .arg(self.spec.columns as u32)
                    .arg(row0 as u32)
                    .arg(rows as u32)
                    .arg(first as u32)
                    .arg(columns as u32)
                    .global_work_size(rows * columns)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            engine.timeline.record("device_copy_column_band", &event)?;
            Ok(())
        }
    }

    pub(crate) fn into_public_preprocessing(self) -> PublicMatrix {
        assert!(
            self.private_random.is_none(),
            "private random data cannot become public preprocessing"
        );
        PublicMatrix {
            storage: self.storage,
            context: self.session.context.clone(),
            spec: self.spec,
        }
    }

    /// Called inside the engine lock, before its transform tile is reused.
    pub(in crate::block_v2::gpu_hash::engine) fn capture_columns(
        &self,
        engine: &mut Engine,
        source: &compute::Buffer<u64>,
        source_width: usize,
        first_column: usize,
    ) -> Result<(), String> {
        if !Arc::ptr_eq(&self.session.context, &engine._job_lease)
            || self.spec.extension != Extension::Base
            || first_column
                .checked_add(source_width)
                .is_none_or(|n| n > self.spec.columns)
            || self
                .spec
                .rows()
                .checked_mul(source_width)
                .is_none_or(|n| n > source.len())
        {
            return Err("invalid device LDE column capture".into());
        }
        copy_columns(
            engine,
            source,
            &self.storage.buffer,
            source_width,
            self.spec.columns,
            0,
            first_column,
            source_width,
            self.spec.rows(),
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn copy_columns(
    engine: &mut Engine,
    source: &compute::Buffer<u64>,
    target: &compute::Buffer<u64>,
    source_width: usize,
    target_width: usize,
    source_first: usize,
    target_first: usize,
    columns: usize,
    rows: usize,
) -> Result<(), String> {
    #[cfg(not(feature = "gpu"))]
    {
        let _ = (
            engine,
            source,
            target,
            source_width,
            target_width,
            source_first,
            target_first,
            columns,
            rows,
        );
        Err("owned LDE column capture is not implemented on Metal".into())
    }
    #[cfg(feature = "gpu")]
    {
        let mut event = compute::Event::empty();
        // SAFETY: callers bound both allocations, all column indices and rows;
        // the queue's caller-owned fence outlives the buffers.
        unsafe {
            engine
                .pq
                .kernel_builder("device_copy_columns")
                .arg(source)
                .arg(target)
                .arg(source_width as u32)
                .arg(target_width as u32)
                .arg(source_first as u32)
                .arg(target_first as u32)
                .arg(columns as u32)
                .arg(rows as u32)
                .global_work_size(rows * columns)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        engine.timeline.record("device_copy_columns", &event)?;
        Ok(())
    }
}

impl DeviceSession {
    /// Recover original rows from the resident PCS's doubled hiding domain.
    pub(crate) fn original_trace(
        &self,
        prefix: &DeviceMatrix,
        log_rows: u32,
        columns: usize,
    ) -> Result<DeviceMatrix, String> {
        self.check_owner(prefix)?;
        if log_rows >= 31 || prefix.spec.log_rows != log_rows + 1 {
            return Err("lookup trace prefix does not match doubled hiding domain".into());
        }
        let projected = self.quotient_input(
            prefix,
            log_rows + 1,
            prefix.spec.shift,
            columns,
            Extension::Base,
        )?;
        let subgroup = self.lde(&projected, log_rows + 1, 1, RowOrder::Natural)?;
        drop(projected);
        let spec = MatrixSpec::new(log_rows, columns, Extension::Base, RowOrder::Natural, 1)?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (subgroup, spec);
            Err("original trace recovery is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let output = self.allocate(engine, spec)?;
            let fence = engine.fence();
            let mut event = compute::Event::empty();
            // SAFETY: subgroup has exactly twice the output's rows and width.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_original_trace_rows")
                    .arg(&subgroup.storage.buffer)
                    .arg(&output.storage.buffer)
                    .arg(spec.rows() as u32)
                    .arg(columns as u32)
                    .global_work_size(spec.words())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            engine
                .timeline
                .record("device_original_trace_rows", &event)?;
            fence.finish()?;
            Ok(output)
        })
    }

    pub(crate) fn alias_private(&self, matrix: &DeviceMatrix) -> Result<DeviceMatrix, String> {
        self.check_owner(matrix)?;
        Ok(DeviceMatrix {
            storage: matrix.storage.clone(),
            private_random: matrix.private_random.clone(),
            session: self.session.clone(),
            spec: matrix.spec,
        })
    }

    pub(crate) fn import_preprocessing(
        &self,
        matrix: &PublicMatrix,
    ) -> Result<DeviceMatrix, String> {
        if !Arc::ptr_eq(&self.session.context, &matrix.context) {
            return Err("public preprocessing belongs to another GPU context".into());
        }
        Ok(DeviceMatrix {
            storage: matrix.storage.clone(),
            private_random: None,
            session: self.session.clone(),
            spec: matrix.spec,
        })
    }

    /// Select the AIR's columns and the bit-reversed prefix for its quotient
    /// domain. A short retained prefix is extended on GPU when necessary.
    pub(crate) fn quotient_input(
        &self,
        input: &DeviceMatrix,
        log_rows: u32,
        shift: u64,
        columns: usize,
        extension: Extension,
    ) -> Result<DeviceMatrix, String> {
        self.check_owner(input)?;
        let width = columns
            .checked_mul(extension.degree())
            .ok_or("quotient input width overflow")?;
        if input.spec.extension != Extension::Base
            || input.spec.order != RowOrder::BitReversed
            || input.spec.shift != shift
            || width == 0
            || width > input.spec.columns
            || log_rows > 31
        {
            return Err("device quotient projection has unsupported geometry".into());
        }
        let spec = MatrixSpec::new(
            input.spec.log_rows.min(log_rows),
            columns,
            extension,
            RowOrder::BitReversed,
            shift,
        )?;
        if spec == input.spec && log_rows == spec.log_rows {
            return self.alias_private(input);
        }
        let projected = self.with_engine(|engine| {
            let output = self.allocate(engine, spec)?;
            let fence = engine.fence();
            copy_columns(
                engine,
                &input.storage.buffer,
                &output.storage.buffer,
                input.spec.columns,
                width,
                0,
                0,
                width,
                spec.rows(),
            )?;
            fence.finish()?;
            Ok(output)
        })?;
        if spec.log_rows == log_rows {
            Ok(projected)
        } else {
            self.lde(&projected, log_rows, shift, RowOrder::BitReversed)
        }
    }
}
