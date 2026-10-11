//! Expand compact, static periodic columns on the device before interpolation.
use super::*;
use p3_field::PrimeField64;

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_periodic_expand(__global const ulong *source,
    __global const ulong *offset_length, __global ulong *output,
    ulong rows, ulong columns) {
    ulong index=get_global_id(0); if(index>=rows*columns)return;
    ulong row=index/columns, col=index%columns;
    ulong offset=offset_length[col*2], length=offset_length[col*2+1];
    output[index]=source[offset+(row&(length-1))];
}
"#;

impl DeviceSession {
    pub(crate) fn periodic_matrix(
        &self,
        log_rows: u32,
        columns: &[Vec<u64>],
        host_allowance: usize,
    ) -> Result<DeviceMatrix, String> {
        let output_spec = MatrixSpec::new(
            log_rows,
            columns.len(),
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        if columns
            .iter()
            .any(|c| !c.len().is_power_of_two() || c.len() > output_spec.rows())
        {
            return Err("invalid periodic column length".into());
        }
        let input_words = columns
            .iter()
            .try_fold(0usize, |n, c| n.checked_add(c.len()))
            .ok_or("periodic source size overflow")?;
        let metadata_words = columns
            .len()
            .checked_mul(2)
            .ok_or("periodic metadata overflow")?;
        let bytes = input_words
            .checked_add(metadata_words)
            .and_then(|n| n.checked_mul(8))
            .ok_or("periodic host staging overflow")?;
        let host_bytes = input_words
            .checked_mul(8)
            .and_then(|n| n.checked_add(bytes))
            .ok_or("periodic aggregate host staging overflow")?;
        if host_bytes > host_allowance
            || columns
                .iter()
                .flatten()
                .any(|&v| v >= crate::config::Val::ORDER_U64)
        {
            return Err("periodic input exceeds host allowance or field modulus".into());
        }
        let input_spec = MatrixSpec::new(0, input_words, Extension::Base, RowOrder::Natural, 1)?;
        let metadata_spec =
            MatrixSpec::new(0, metadata_words, Extension::Base, RowOrder::Natural, 1)?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (output_spec, input_spec, metadata_spec);
            return Err("owned periodic expansion is not implemented on Metal".into());
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let _plan = Self::plan(engine, &[output_spec, input_spec, metadata_spec])?;
            let output = self.allocate(engine, output_spec)?;
            let input = self.allocate(engine, input_spec)?;
            let metadata = self.allocate(engine, metadata_spec)?;
            let mut values = Vec::with_capacity(input_words);
            let mut positions = Vec::with_capacity(metadata_words);
            for column in columns {
                positions.extend([values.len() as u64, column.len() as u64]);
                values.extend_from_slice(column);
            }
            let fence = engine.fence();
            input
                .storage
                .buffer
                .write(&values[..])
                .enq()
                .map_err(|e| e.to_string())?;
            metadata
                .storage
                .buffer
                .write(&positions[..])
                .enq()
                .map_err(|e| e.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: checked power-of-two lengths, offsets and aggregate peak
            // bound every source lookup and every output field element.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_periodic_expand")
                    .arg(&input.storage.buffer)
                    .arg(&metadata.storage.buffer)
                    .arg(&output.storage.buffer)
                    .arg(output_spec.rows() as u64)
                    .arg(output_spec.columns as u64)
                    .global_work_size(output_spec.words())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.session.record_event(
                engine,
                crate::proving::Stage::Preprocessing,
                "periodic_expand",
                &event,
            )?;
            fence.finish()?;
            engine.stats.uploaded_bytes += bytes as u64;
            self.session.stats.lock().unwrap().uploaded_bytes += bytes as u64;
            Ok(output)
        })
    }
}
