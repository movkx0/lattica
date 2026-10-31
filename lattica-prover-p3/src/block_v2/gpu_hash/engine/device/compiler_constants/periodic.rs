//! Linear bounded storage and O(n log n) public periodic interpolation.
use super::*;

pub(crate) const PERIODIC_MAX_ALLOCATION_BYTES: u64 = MAX_PERIOD as u64 * 8;
pub(crate) const PERIODIC_WORKSPACE_BYTES: u64 =
    (MAX_PERIOD as u64 + MAX_PERIOD as u64 / 2 + 2) * 8;
const _: () = assert!(PERIODIC_WORKSPACE_BYTES <= 2 << 20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeriodicPlan {
    n: usize,
    log_n: usize,
    table_words: usize,
}
impl PeriodicPlan {
    fn new(n: usize, log_height: usize, output: usize) -> Result<Self, String> {
        if log_height > 32
            || !n.is_power_of_two()
            || n > MAX_PERIOD
            || n.ilog2() as usize > log_height
        {
            return Err("GPU compiler periodic column exceeds admission".into());
        }
        if output != n {
            return Err("GPU compiler periodic output length".into());
        }
        Ok(Self {
            n,
            log_n: n.ilog2() as usize,
            table_words: n / 2 + 2,
        })
    }

    fn specs(self) -> Result<[MatrixSpec; 2], String> {
        Ok([
            MatrixSpec::new(0, self.n, Extension::Base, RowOrder::Natural, 1)?,
            MatrixSpec::new(0, self.table_words, Extension::Base, RowOrder::Natural, 1)?,
        ])
    }
}

impl DeviceSession {
    pub(crate) fn compiler_periodic_into(
        &self,
        column: &[Val],
        log_height: usize,
        coefficients: &mut [Val],
        run: &Run,
    ) -> Result<(), String> {
        // Geometry must fail before device selection, allocation or receipt creation.
        let plan = PeriodicPlan::new(column.len(), log_height, coefficients.len())?;
        run.check_device_stage(Stage::Preprocessing, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = plan;
            Err("GPU compiler constants are not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            use super::super::event_batch::EventBatch;
            let specs = plan.specs()?;
            // The compiler workspace is separate from the public-hash tile.
            // Admission includes current live buffers and precedes both allocations.
            let _admitted = Self::plan(engine, &specs)?;
            let values = self.allocate(engine, specs[0])?;
            let table = self.allocate(engine, specs[1])?;
            let fence = engine.fence();
            let mut staging = [0u64; PERIOD_TILE];
            for start in (0..plan.n).step_by(PERIOD_TILE) {
                let count = PERIOD_TILE.min(plan.n - start);
                for (dst, src) in staging.iter_mut().zip(&column[start..start + count]) {
                    *dst = src.as_canonical_u64();
                }
                values
                    .storage
                    .buffer
                    .write(&staging[..count])
                    .offset(start)
                    .enq()
                    .map_err(|e| e.to_string())?;
                engine.stats.uploaded_bytes += count as u64 * 8;
                self.session.stats.lock().unwrap().uploaded_bytes += count as u64 * 8;
            }
            let mut events = EventBatch::for_run(engine, run, Stage::Preprocessing);
            let root = Val::TWO_ADIC_GENERATORS[plan.log_n].as_canonical_u64();
            let mut event = compute::Event::empty();
            // SAFETY: the table has two parameter cells; exactly one work-item writes them.
            unsafe {
                events
                    .engine
                    .pq
                    .kernel_builder("device_compiler_periodic_parameters")
                    .arg(&table.storage.buffer)
                    .arg(root)
                    .arg(plan.n as u32)
                    .global_work_size(1usize)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            events.record("device_compiler_periodic_parameters", event)?;
            if plan.n > 1 {
                let mut event = compute::Event::empty();
                // SAFETY: n/2 twiddles follow the two initialized parameter cells.
                unsafe {
                    events
                        .engine
                        .pq
                        .kernel_builder("device_compiler_periodic_twiddles")
                        .arg(&table.storage.buffer)
                        .arg((plan.n / 2) as u32)
                        .global_work_size(plan.n / 2)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                events.record("device_compiler_periodic_twiddles", event)?;
                let mut width = plan.n;
                while width > 1 {
                    let mut event = compute::Event::empty();
                    // SAFETY: each work-item owns one disjoint butterfly; roots index < n/2.
                    // Queue order provides the inter-stage global synchronization.
                    unsafe {
                        events
                            .engine
                            .pq
                            .kernel_builder("device_compiler_periodic_dif")
                            .arg(&values.storage.buffer)
                            .arg(&table.storage.buffer)
                            .arg(plan.n as u32)
                            .arg(width as u32)
                            .global_work_size(plan.n / 2)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    events.record("device_compiler_periodic_dif", event)?;
                    width /= 2;
                }
            }
            let mut event = compute::Event::empty();
            // SAFETY: disjoint bit-reversal pairs have one writer, including fixed points.
            unsafe {
                events
                    .engine
                    .pq
                    .kernel_builder("device_compiler_periodic_normalize")
                    .arg(&values.storage.buffer)
                    .arg(&table.storage.buffer)
                    .arg(plan.n as u32)
                    .arg(plan.log_n as u32)
                    .global_work_size(plan.n)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            events.record("device_compiler_periodic_normalize", event)?;
            // Mandatory completed-event receipts, never enqueue-only success.
            events.finish()?;
            for start in (0..plan.n).step_by(PERIOD_TILE) {
                let count = PERIOD_TILE.min(plan.n - start);
                values
                    .storage
                    .buffer
                    .read(&mut staging[..count])
                    .offset(start)
                    .enq()
                    .map_err(|e| e.to_string())?;
                if staging[..count]
                    .iter()
                    .any(|&word| word >= GOLDILOCKS_MODULUS)
                {
                    return Err("GPU compiler coefficient is not canonical".into());
                }
                for (dst, &word) in coefficients[start..start + count]
                    .iter_mut()
                    .zip(&staging[..count])
                {
                    *dst = Val::new(word);
                }
                engine.stats.downloaded_bytes += count as u64 * 8;
                self.session.stats.lock().unwrap().downloaded_bytes += count as u64 * 8;
            }
            fence.finish()?;
            // Both device allocations are local and retired before preprocessing commitment.
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
