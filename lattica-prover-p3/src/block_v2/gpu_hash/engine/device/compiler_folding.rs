//! Fixed-size public constant folding: six input words and four result words.
use super::*;
use crate::proving::{Backend, Run, Stage};

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_compiler_fold(__global const ulong *input,
    __global ulong *output, uint operation) {
    ulong a[3] = {input[0], input[1], input[2]};
    ulong b[3] = {input[3], input[4], input[5]};
    ulong value[3] = {0UL, 0UL, 0UL};
    ulong invertible = 1UL;
    if (operation == 0) value[0] = gl_add(a[0], b[0]);
    else if (operation == 1) value[0] = gl_mul(a[0], b[0]);
    else if (operation == 2) {
        invertible = a[0] != 0UL;
        value[0] = gl_pow(a[0], 0xfffffffeffffffffUL);
    } else if (operation == 3) opening_cubic_mul(a, b, value);
    else if (operation == 4) {
        invertible = (a[0] | a[1] | a[2]) != 0UL;
        lookup_cubic_inverse(a, value);
    }
    for (uint i = 0; i < 3; ++i) output[i] = gl_canon(value[i]);
    output[3] = invertible;
}
"#;

impl DeviceSession {
    pub(crate) fn compiler_fold(
        &self,
        input: [u64; 6],
        operation: u32,
        run: &Run,
    ) -> Result<Option<[Val; 3]>, String> {
        if operation > 4 || input.iter().any(|&n| n >= GOLDILOCKS_MODULUS) {
            return Err("GPU compiler fold operation or operand is invalid".into());
        }
        run.check_device_stage(Stage::Preprocessing, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        #[cfg(not(feature = "gpu"))]
        {
            Err("GPU compiler folding is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            // The builder's fixed cache is at most 8 KiB, and this operation
            // stages 80 bytes. Both fit the existing public-hash reservation.
            const _: () = assert!(80 <= public_hash::WORKSPACE_BYTES);
            const _: () = assert!(48 <= public_hash::MAX_ALLOCATION_BYTES);
            const _: () = assert!(8192 + 80 <= public_hash::HOST_BYTES);
            let specs = [
                MatrixSpec::new(0, 6, Extension::Base, RowOrder::Natural, 1)?,
                MatrixSpec::new(0, 4, Extension::Base, RowOrder::Natural, 1)?,
            ];
            let _plan = Self::plan(engine, &specs)?;
            let source = self.allocate(engine, specs[0])?;
            let result = self.allocate(engine, specs[1])?;
            let mut output = [0u64; 4];
            let fence = engine.fence();
            source
                .storage
                .buffer
                .write(&input[..])
                .enq()
                .map_err(|e| e.to_string())?;
            engine.stats.uploaded_bytes += 48;
            self.session.stats.lock().unwrap().uploaded_bytes += 48;
            let mut event = compute::Event::empty();
            // SAFETY: one work item owns all four result words and reads six
            // initialized source words. The fence drains before buffers drop.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_compiler_fold")
                    .arg(&source.storage.buffer)
                    .arg(&result.storage.buffer)
                    .arg(operation)
                    .global_work_size(1)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = engine.timeline.record("device_compiler_fold", &event)?;
            // Retain completed work even if readback or validation fails.
            run.observe_device(Stage::Preprocessing, Backend::OpenCl, 1, ns)
                .map_err(|e| e.to_string())?;
            result
                .storage
                .buffer
                .read(&mut output[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.downloaded_bytes += 32;
            self.session.stats.lock().unwrap().downloaded_bytes += 32;
            let expected_status = match operation {
                2 => u64::from(input[0] != 0),
                4 => u64::from(input[..3].iter().any(|&v| v != 0)),
                _ => 1,
            };
            if output[..3].iter().any(|&v| v >= GOLDILOCKS_MODULUS)
                || output[3] != expected_status
                || (output[3] == 0 && output[..3] != [0; 3])
                || (operation <= 2 && output[1..3] != [0; 2])
            {
                return Err("GPU compiler fold result is invalid".into());
            }
            Ok((output[3] == 1).then(|| [output[0], output[1], output[2]].map(Val::new)))
        })
    }
}
