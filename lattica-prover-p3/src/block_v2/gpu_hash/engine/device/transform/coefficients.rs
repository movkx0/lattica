//! Private, attempt-local interpolation shared by several output cosets.
use super::*;

/// Values are unnormalized inverse-DFT coefficients in natural row order.
/// The spec retains the source coset so evaluation applies its inverse shift
/// and row normalization exactly once. Never pass this matrix as evaluations.
pub(in super::super) struct DeviceCoefficients {
    pub(super) matrix: DeviceMatrix,
}

impl DeviceSession {
    pub(in super::super) fn interpolate_coefficients(
        &self,
        input: &DeviceMatrix,
    ) -> Result<DeviceCoefficients, String> {
        self.check_owner(input)?;
        let (_, width, _) = geometry(input.spec, input.spec.log_rows, 1, RowOrder::Natural)?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = width;
            Err("owned coefficient interpolation is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            self.observe_engine(engine, |engine| {
                engine.fence().finish()?;
                engine.lde_workspace = None;
                let live = engine.accounting.lock().unwrap().live;
                storage_plan(
                    input.spec,
                    input.spec.log_rows,
                    live,
                    engine.limits,
                    engine.max_alloc,
                )?;
                if input.spec.rows() == 1 {
                    return Ok(DeviceCoefficients {
                        matrix: self.alias_private(input)?,
                    });
                }
                let spec = MatrixSpec::new(
                    input.spec.log_rows,
                    input.spec.columns,
                    input.spec.extension,
                    RowOrder::Natural,
                    input.spec.shift,
                )?;
                let output = self.allocate(engine, spec)?;
                let reordered = if input.spec.order == RowOrder::BitReversed {
                    Some(self.allocate(engine, spec)?)
                } else {
                    None
                };
                let inverse = allocation(
                    &engine.pq,
                    &engine.accounting,
                    engine.limits,
                    engine.max_alloc,
                    input.spec.log_rows as usize,
                    compute::flags::MEM_READ_WRITE,
                )?;
                let roots = (1..=input.spec.log_rows)
                    .map(super::super::super::fri_fold::inverse_root)
                    .collect::<Vec<_>>();
                let fence = engine.fence();
                inverse
                    .buffer
                    .write(&roots)
                    .enq()
                    .map_err(|e| e.to_string())?;
                let mut device_ns = 0;
                let source = if let Some(reordered) = &reordered {
                    let mut event = compute::Event::empty();
                    // SAFETY: the checked matrix extent covers this bijection;
                    // the input and reorder destination have distinct owners.
                    unsafe {
                        engine
                            .pq
                            .kernel_builder("device_transform_order")
                            .arg(&input.storage.buffer)
                            .arg(&reordered.storage.buffer)
                            .arg(width as u32)
                            .arg(input.spec.rows() as u32)
                            .arg(input.spec.log_rows)
                            .global_work_size(input.spec.words)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    device_ns += self.session.record_event(
                        engine,
                        crate::proving::Stage::Transform,
                        "device_transform_order",
                        &event,
                    )?;
                    &reordered.storage.buffer
                } else {
                    &input.storage.buffer
                };
                let before = engine.stats.lde_transform_ns;
                // Natural output leaves the source immutable and the complete
                // unnormalized inverse transform in the destination.
                engine.lde_ntt(
                    source,
                    &output.storage.buffer,
                    &inverse.buffer,
                    true,
                    input.spec.rows(),
                    width,
                    1,
                    1,
                    false,
                    false,
                    false,
                    None,
                )?;
                fence.finish()?;
                device_ns += engine.stats.lde_transform_ns - before;
                let uploaded = (roots.len() * 8) as u64;
                engine.stats.uploaded_bytes += uploaded;
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.transforms += 1;
                stats.transform_device_ns += device_ns;
                Ok(DeviceCoefficients { matrix: output })
            })
        })
    }
}
