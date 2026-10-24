//! Already-random subgroup/coset evaluations. Unlike trace hiding, this
//! interface neither interleaves rows nor appends random columns.
use super::*;
use p3_field::{Field, PrimeField64};

pub(in crate::block_v2::gpu_hash::engine) const KERNEL_SRC: &str = r#"
__kernel void device_evaluation_parameters(__global ulong *parameters,
    uint height, ulong shift, ulong generator) {
    parameters[0] = gl_inverse((ulong)height);
    parameters[1] = gl_mul(generator, gl_inverse(shift));
}
__kernel void device_evaluation_scale(__global ulong *coefficients,
    __global const ulong *parameters, uint height, uint columns) {
    size_t i = get_global_id(0);
    if (i >= (size_t)height * columns) return;
    coefficients[i] = gl_mul(gl_mul(coefficients[i], parameters[0]),
        gl_pow(parameters[1], (ulong)(i / columns)));
}
"#;

#[derive(Clone, Copy, Debug)]
pub(crate) struct EvaluationShape(MatrixSpec);

impl EvaluationShape {
    pub(crate) fn new(spec: MatrixSpec) -> Result<Self, String> {
        if spec.extension != Extension::Base
            || spec.order != RowOrder::Natural
            || !(1..=25).contains(&spec.log_rows)
            || spec.columns > 4096
        {
            return Err("device evaluations require bounded natural-order base columns".into());
        }
        Ok(Self(spec))
    }

    pub(crate) fn storage_plan(
        self,
        live: usize,
        managed: usize,
        max_allocation: usize,
    ) -> Result<CommitInputStorage, String> {
        CommitInputStorage::new(
            [0, 0],
            2,
            SampleLocation::Resident,
            live,
            managed,
            max_allocation,
        )
    }

    pub(crate) fn lde_shape(
        self,
        added_bits: usize,
    ) -> Result<super::super::lde_plan::InputShape, String> {
        if added_bits >= 32
            || self
                .0
                .rows()
                .checked_shl(added_bits as u32)
                .is_none_or(|n| n > 1 << 25)
        {
            return Err("device evaluation LDE exceeds supported height".into());
        }
        Ok(super::super::lde_plan::InputShape {
            height: self.0.rows(),
            width: self.0.columns,
            added_bits,
        })
    }
}

pub(crate) struct EvaluationInput {
    values: DeviceMatrix,
    parameters: Allocation,
}
impl DeviceSession {
    pub(crate) fn prepare_evaluations(
        &self,
        values: &DeviceMatrix,
    ) -> Result<EvaluationInput, String> {
        self.check_owner(values)?;
        let spec = values.spec();
        let shape = EvaluationShape::new(spec)?;
        #[cfg(not(feature = "gpu"))]
        {
            Err("device evaluation commitments are not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let live = engine.accounting.lock().unwrap().live;
            let _plan = shape.storage_plan(live, engine.limits.managed_bytes, engine.max_alloc)?;
            let mut parameters = allocation(
                &engine.pq,
                &engine.accounting,
                engine.limits,
                engine.max_alloc,
                2,
                compute::flags::MEM_READ_WRITE,
            )?;
            parameters._lease.mark_device()?;
            let input = EvaluationInput {
                values: self.alias_private(values)?,
                parameters,
            };
            let fence = engine.fence();
            let mut event = compute::Event::empty();
            // SAFETY: two parameters are allocated and the domain is validated.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_evaluation_parameters")
                    .arg(&input.parameters.buffer)
                    .arg(spec.rows() as u32)
                    .arg(spec.shift)
                    .arg(Val::GENERATOR.as_canonical_u64())
                    .global_work_size(1usize)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.session.record_event(
                engine,
                crate::proving::Stage::Transform,
                "device_evaluation_parameters",
                &event,
            )?;
            fence.finish()?;
            Ok(input)
        })
    }
}
impl EvaluationInput {
    pub(crate) fn shape(
        &self,
        added_bits: usize,
    ) -> Result<super::super::lde_plan::InputShape, String> {
        EvaluationShape::new(self.values.spec)?.lde_shape(added_bits)
    }
    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        session.check_owner(&self.values)
    }
    pub(in crate::block_v2::gpu_hash::engine) fn check_engine(
        &self,
        engine: &Engine,
    ) -> Result<(), String> {
        self.values.check_engine(engine)
    }
    pub(in crate::block_v2::gpu_hash::engine) fn load_columns(
        &self,
        engine: &mut Engine,
        output: &compute::Buffer<u64>,
        first: usize,
        columns: usize,
    ) -> Result<(), String> {
        self.values
            .copy_column_band(engine, output, 0, self.values.spec.rows(), first, columns)
    }
    pub(in crate::block_v2::gpu_hash::engine) fn scale_columns(
        &self,
        engine: &mut Engine,
        output: &compute::Buffer<u64>,
        columns: usize,
    ) -> Result<(), String> {
        self.check_engine(engine)?;
        let rows = self.values.spec.rows();
        if columns == 0
            || columns > self.values.spec.columns
            || rows.checked_mul(columns).is_none_or(|n| n > output.len())
        {
            return Err("invalid device evaluation coefficient tile".into());
        }
        #[cfg(not(feature = "gpu"))]
        {
            Err("device evaluation scale is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        {
            let mut event = compute::Event::empty();
            // SAFETY: parameters and coefficient tile dimensions checked above.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_evaluation_scale")
                    .arg(output)
                    .arg(&self.parameters.buffer)
                    .arg(rows as u32)
                    .arg(columns as u32)
                    .global_work_size(rows * columns)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.values.session.record_event(
                engine,
                crate::proving::Stage::Transform,
                "device_evaluation_scale",
                &event,
            )?;
            Ok(())
        }
    }
}
