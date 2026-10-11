//! Owned quadratic/cubic LogUp witness generation: base expressions, bounded batch
//! inversion, fraction columns, and a hierarchical exclusive prefix scan.

use super::*;
use crate::block_v2::gpu_quotient_prover::lookup_program::LookupProgram;

pub(crate) struct PreparedLookup {
    program: Arc<LookupProgram>,
    code: Allocation,
    tuples: Allocation,
    boundaries: Allocation,
    context: Arc<JobLease>,
}

struct Plan {
    rows: usize,
    parameters: [usize; 3],
    tile: [usize; 4],
    scan_rows: Vec<usize>,
    peak: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Val;
    use p3_air::symbolic::AirLayout;
    use p3_field::PrimeCharacteristicRing;
    use p3_lookup::{Kind, Lookup};

    #[test]
    fn lookup_plan_accounts_for_full_output_scans_and_bounded_tiles() {
        let program = LookupProgram::compile(
            AirLayout {
                main_width: 2,
                ..Default::default()
            },
            &[Lookup {
                kind: Kind::Local,
                column: 0,
                count_weight: 0,
                elements: vec![vec![Val::ONE.into()]],
                multiplicities: vec![Val::ONE.into()],
            }],
        )
        .unwrap();
        let limits = super::super::super::Limits {
            managed_bytes: 64 << 20,
            tile_bytes: 64 << 10,
            staging_bytes: 4096,
        };
        for extension in [Extension::Quadratic, Extension::Cubic] {
            let degree = extension.degree();
            for (log, levels) in [
                (0, vec![1]),
                (7, vec![128]),
                (8, vec![256, 2]),
                (14, vec![16384, 128]),
                (15, vec![32768, 256, 2]),
            ] {
                let spec = MatrixSpec::new(log, 2, extension, RowOrder::Natural, 1).unwrap();
                let plan = Plan::new(&program, spec, 4096, limits, 32 << 20).unwrap();
                assert_eq!(plan.scan_rows, levels);
                assert!(
                    plan.rows.is_power_of_two() && plan.rows <= 1024 && plan.rows <= spec.rows()
                );
                assert_eq!(
                    plan.peak,
                    4096 + spec.bytes()
                        + degree * 8
                        + (plan.parameters.iter().sum::<usize>()
                            + plan.tile.iter().sum::<usize>()
                            + plan.scan_rows.iter().sum::<usize>() * degree)
                            * 8
                );
                assert!(plan.peak <= limits.managed_bytes);
                assert!(Plan::new(&program, spec, 0, limits, spec.bytes() - 1).is_err());
                let insufficient = super::super::super::Limits {
                    managed_bytes: plan.peak - plan.tile.iter().sum::<usize>() * 8,
                    ..limits
                };
                assert!(Plan::new(&program, spec, 4096, insufficient, 32 << 20).is_err());
            }
        }
    }
}

impl Plan {
    fn new(
        program: &LookupProgram,
        output: MatrixSpec,
        live: usize,
        limits: super::super::Limits,
        max_alloc: usize,
    ) -> Result<Self, String> {
        let degree = output.extension.degree();
        if !matches!(output.extension, Extension::Quadratic | Extension::Cubic) {
            return Err("lookup output requires a quadratic or cubic extension".into());
        }
        let height = output.rows();
        let parameters = [
            program.layout.num_public_values.max(1),
            program.lookup_count() * 2 * degree,
            1,
        ];
        let mut scan_rows = vec![height];
        while *scan_rows.last().unwrap() > 128 {
            scan_rows.push(scan_rows.last().unwrap().div_ceil(128));
        }
        let mut static_words = vec![output.words(), degree]; // Full trace plus terminal.
        static_words.extend(parameters);
        static_words.extend(scan_rows.iter().map(|rows| rows * degree));
        let mut peak = live;
        for words in static_words {
            let bytes = words
                .checked_mul(8)
                .ok_or("lookup allocation size overflow")?;
            if bytes > max_alloc {
                return Err("lookup allocation exceeds device limit".into());
            }
            peak = peak
                .checked_add(bytes)
                .ok_or("lookup memory plan overflow")?;
        }
        let per_row = program
            .row_words
            .max(1)
            .checked_add(program.registers.max(1))
            .and_then(|n| n.checked_add(program.expression_words.max(1)))
            .and_then(|n| n.checked_add((program.tuple_count() * degree).max(1)))
            .and_then(|n| n.checked_mul(8))
            .ok_or("lookup row workspace overflow")?;
        let free = limits
            .managed_bytes
            .checked_sub(peak)
            .ok_or("lookup exceeds aggregate GPU budget")?;
        let capacity = (free.min(limits.tile_bytes).min(max_alloc).min(64 << 20) / per_row)
            .min(height)
            .min(1024);
        if capacity == 0 {
            return Err("lookup budget cannot fit one row".into());
        }
        let rows = 1usize << capacity.ilog2();
        let tile = [
            program.row_words,
            program.registers,
            program.expression_words,
            program.tuple_count() * degree,
        ]
        .map(|words| (words * rows).max(1));
        peak += tile.iter().sum::<usize>() * 8;
        Ok(Self {
            rows,
            parameters,
            tile,
            scan_rows,
            peak,
        })
    }
}

impl DeviceSession {
    pub(crate) fn prepare_lookup(
        &self,
        program: Arc<LookupProgram>,
    ) -> Result<PreparedLookup, String> {
        #[cfg(not(feature = "gpu"))]
        {
            let _ = program;
            Err("GPU lookup generation is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let inputs = [&program.instructions, &program.tuples, &program.boundaries];
            let mut allocations = Vec::new();
            for input in inputs {
                let mut a = allocation(
                    &engine.pq,
                    &engine.accounting,
                    engine.limits,
                    engine.max_alloc,
                    input.len().max(1),
                    compute::flags::MEM_READ_ONLY,
                )?;
                a._lease.mark_device()?;
                allocations.push(a);
            }
            let fence = engine.fence();
            for (allocation, input) in allocations.iter().zip(inputs) {
                allocation
                    .buffer
                    .write(if input.is_empty() {
                        &[0][..]
                    } else {
                        input.as_slice()
                    })
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            fence.finish()?;
            let bytes = inputs
                .iter()
                .map(|input| input.len().max(1) * 8)
                .sum::<usize>() as u64;
            engine.stats.uploaded_bytes += bytes;
            {
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += bytes;
                stats.prepared_lookup_programs += 1;
            }
            let mut allocations = allocations.into_iter();
            Ok(PreparedLookup {
                code: allocations.next().unwrap(),
                tuples: allocations.next().unwrap(),
                boundaries: allocations.next().unwrap(),
                program,
                context: self.session.context.clone(),
            })
        })
    }

    /// Inputs are original (unblinded) trace rows on the subgroup. Only the
    /// extension terminal and an eight-byte failure status leave the device.
    pub(crate) fn lookup_permutation<const D: usize>(
        &self,
        prepared: &PreparedLookup,
        main: &DeviceMatrix,
        preprocessed: Option<&DeviceMatrix>,
        public_values: &[u64],
        challenges: &[[u64; D]],
    ) -> Result<(DeviceMatrix, [u64; D]), String> {
        let extension = match D {
            2 => Extension::Quadratic,
            3 => Extension::Cubic,
            _ => return Err("GPU lookup requires a quadratic or cubic extension".into()),
        };
        if !Arc::ptr_eq(&self.session.context, &prepared.context) {
            return Err("prepared lookup belongs to another GPU context".into());
        }
        let program = &prepared.program;
        for matrix in [Some(main), preprocessed].into_iter().flatten() {
            self.check_owner(matrix)?;
        }
        if main.spec.extension != Extension::Base
            || main.spec.columns != program.layout.main_width
            || main.spec.shift != 1
            || main.spec.log_rows > 31
            || public_values.len() != program.layout.num_public_values
            || challenges.len() != program.lookup_count() * 2
            || public_values
                .iter()
                .chain(challenges.iter().flatten())
                .any(|n| *n >= GOLDILOCKS_MODULUS)
        {
            return Err("invalid GPU lookup input or challenge layout".into());
        }
        match (preprocessed, program.layout.preprocessed_width) {
            (None, 0) => {}
            (Some(pre), width)
                if width > 0
                    && pre.spec.columns == width
                    && pre.spec.extension == Extension::Base
                    && pre.spec.rows() == main.spec.rows()
                    && pre.spec.shift == 1 => {}
            _ => return Err("invalid GPU lookup preprocessing layout".into()),
        }
        let spec = MatrixSpec::new(
            main.spec.log_rows,
            program.lookup_count() + 1,
            extension,
            RowOrder::Natural,
            1,
        )?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = spec;
            Err("GPU lookup generation is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let started = std::time::Instant::now();
            engine.fence().finish()?;
            engine.lde_workspace = None;
            let plan = Plan::new(program, spec, engine.accounting.lock().unwrap().live,
                engine.limits, engine.max_alloc)?;
            let output = self.allocate(engine, spec)?;
            let alloc = |words| allocation(&engine.pq, &engine.accounting, engine.limits, engine.max_alloc,
                words, compute::flags::MEM_READ_WRITE);
            let public = alloc(plan.parameters[0])?;
            let challenge = alloc(plan.parameters[1])?;
            let status = alloc(1)?;
            let input = alloc(plan.tile[0])?;
            let scratch = alloc(plan.tile[1])?;
            let expressions = alloc(plan.tile[2])?;
            let inverses = alloc(plan.tile[3])?;
            let scans = plan.scan_rows.iter().map(|rows| alloc(rows * D)).collect::<Result<Vec<_>, _>>()?;
            let terminal = alloc(D)?;
            let fence = engine.fence();
            public.buffer.write(if public_values.is_empty() { &[0] } else { public_values }).enq().map_err(|e| e.to_string())?;
            let challenge_words: Vec<_> = challenges.iter().flatten().copied().collect();
            challenge.buffer.write(&challenge_words).enq().map_err(|e| e.to_string())?;
            status.buffer.cmd().fill(0u64, None).enq().map_err(|e| e.to_string())?;
            let uploaded = ((public_values.len().max(1) + challenge_words.len()) * 8) as u64;
            let mut device_ns = 0u128;
            let pre = preprocessed.unwrap_or(main);
            for first in (0..spec.rows()).step_by(plan.rows) {
                let rows = plan.rows.min(spec.rows() - first);
                if program.expression_words != 0 {
                    let mut event = compute::Event::empty();
                    // SAFETY: shapes/row orders and all compiler offsets are
                    // bounded above; one subgroup step selects the next row.
                    unsafe {
                        engine.pq.kernel_builder("device_quotient_gather")
                            .arg(&main.storage.buffer).arg(&pre.storage.buffer).arg(&main.storage.buffer)
                            .arg(&input.buffer).arg(program.layout.main_width as u32)
                            .arg(program.layout.preprocessed_width as u32).arg(0u32)
                            .arg(u32::from(main.spec.order == RowOrder::BitReversed))
                            .arg(u32::from(pre.spec.order == RowOrder::BitReversed)).arg(0u32)
                            .arg(main.spec.log_rows).arg(1u32).arg(first as u32).arg(rows as u32)
                            .global_work_size(rows * program.row_words).build().map_err(|e| e.to_string())?
                            .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                    }
                    device_ns += self.session.record_event(engine, crate::proving::Stage::Lookup, "device_lookup_gather", &event)?;
                    let mut event = compute::Event::empty();
                    // SAFETY: scratch slots and stores were checked by the compiler.
                    unsafe {
                        engine.pq.kernel_builder("device_lookup_expressions")
                            .arg(&prepared.code.buffer).arg((program.instructions.len() / 5) as u32)
                            .arg(&input.buffer).arg(program.row_words as u32).arg(&public.buffer)
                            .arg(&scratch.buffer).arg(&expressions.buffer).arg(program.expression_words as u32)
                            .arg(rows as u32).arg(first as u32).arg(spec.rows() as u32)
                            .global_work_size(rows).build().map_err(|e| e.to_string())?
                            .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                    }
                    device_ns += self.session.record_event(engine, crate::proving::Stage::Lookup, "device_lookup_expressions", &event)?;
                }
                let count = rows * program.tuple_count();
                if count != 0 {
                    let mut event = compute::Event::empty();
                    // SAFETY: each tuple reads its bounded scalar output slice
                    // and its own pair of extension challenges, writing one element.
                    unsafe {
                        engine.pq.kernel_builder("device_lookup_denominators")
                            .arg(&expressions.buffer).arg(program.expression_words as u32)
                            .arg(&prepared.tuples.buffer).arg(program.tuple_count() as u32)
                            .arg(&challenge.buffer).arg(&inverses.buffer).arg(rows as u32)
                            .arg(D as u32)
                            .global_work_size(count).build().map_err(|e| e.to_string())?
                            .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                    }
                    device_ns += self.session.record_event(engine, crate::proving::Stage::Lookup, "device_lookup_denominators", &event)?;
                    let mut event = compute::Event::empty();
                    // SAFETY: 128 lanes cooperatively invert a bounded block;
                    // padded lanes use one, and zero denominators set status.
                    unsafe {
                        engine.pq.kernel_builder("device_lookup_batch_inverse")
                            .arg(&inverses.buffer).arg(count as u32).arg(&status.buffer)
                            .arg(D as u32)
                            .global_work_size(count.div_ceil(128) * 128).local_work_size(128usize)
                            .build().map_err(|e| e.to_string())?.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                    }
                    device_ns += self.session.record_event(engine, crate::proving::Stage::Lookup, "device_lookup_batch_inverse", &event)?;
                }
                let mut event = compute::Event::empty();
                // SAFETY: each row writes its fraction columns and one total.
                unsafe {
                    engine.pq.kernel_builder("device_lookup_fractions")
                        .arg(&inverses.buffer).arg(&expressions.buffer).arg(program.expression_words as u32)
                        .arg(&prepared.tuples.buffer).arg(&prepared.boundaries.buffer)
                        .arg(program.lookup_count() as u32).arg(program.tuple_count() as u32)
                        .arg(&output.storage.buffer).arg(&scans[0].buffer).arg(rows as u32).arg(first as u32)
                        .arg(D as u32)
                            .global_work_size(rows).build().map_err(|e| e.to_string())?
                        .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                }
                device_ns += self.session.record_event(engine, crate::proving::Stage::Lookup, "device_lookup_fractions", &event)?;
            }
            let mut failed = [0u64];
            status.buffer.read(&mut failed[..]).enq().map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += 8;
            { let mut stats = self.session.stats.lock().unwrap(); stats.uploaded_bytes += uploaded; stats.downloaded_bytes += 8; }
            if failed[0] != 0 { return Err("active GPU lookup denominator is zero".into()); }
            for (index, values) in scans.iter().enumerate() {
                let next = scans.get(index + 1).unwrap_or(&terminal);
                let rows = plan.scan_rows[index];
                let mut event = compute::Event::empty();
                // SAFETY: each block writes one allocated parent total.
                unsafe {
                    engine.pq.kernel_builder("device_lookup_scan_blocks")
                        .arg(&values.buffer).arg(&next.buffer).arg(rows as u32)
                        .arg(D as u32)
                            .global_work_size(rows.div_ceil(128) * 128).local_work_size(128usize)
                        .build().map_err(|e| e.to_string())?.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                }
                device_ns += self.session.record_event(engine, crate::proving::Stage::Lookup, "device_lookup_scan_blocks", &event)?;
            }
            for index in (0..scans.len() - 1).rev() {
                let rows = plan.scan_rows[index];
                let mut event = compute::Event::empty();
                // SAFETY: parent prefixes cover every group in this child level.
                unsafe {
                    engine.pq.kernel_builder("device_lookup_scan_offsets")
                        .arg(&scans[index].buffer).arg(&scans[index + 1].buffer).arg(rows as u32)
                        .arg(D as u32)
                            .global_work_size(rows).build().map_err(|e| e.to_string())?
                        .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                }
                device_ns += self.session.record_event(engine, crate::proving::Stage::Lookup, "device_lookup_scan_offsets", &event)?;
            }
            let mut event = compute::Event::empty();
            // SAFETY: output column zero and every prefix row are allocated.
            unsafe {
                engine.pq.kernel_builder("device_lookup_accumulator").arg(&scans[0].buffer)
                    .arg(&output.storage.buffer).arg(spec.rows() as u32).arg(spec.columns as u32)
                    .arg(D as u32)
                            .global_work_size(spec.rows()).build().map_err(|e| e.to_string())?
                    .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
            }
            device_ns += self.session.record_event(engine, crate::proving::Stage::Lookup, "device_lookup_accumulator", &event)?;
            let mut terminal_words = [0u64; D];
            terminal.buffer.read(&mut terminal_words[..]).enq().map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.downloaded_bytes += (D * 8) as u64;
            self.session.stats.lock().unwrap().downloaded_bytes += (D * 8) as u64;
            if terminal_words.iter().any(|n| *n >= GOLDILOCKS_MODULUS) {
                return Err("GPU lookup returned noncanonical terminal".into());
            }
            {
                let mut stats = self.session.stats.lock().unwrap();
                stats.lookup_generations += 1;
                stats.lookup_device_ns += device_ns;
            }
            eprintln!("bounded_device_lookup extension_degree={D} rows={} lookups={} tuples={} tile_rows={} managed_peak_plan_bytes={} parameter_upload_bytes={uploaded} control_download_bytes={} matrix_readback_bytes=0 device_ns={device_ns} wall_ns={}",
                spec.rows(), program.lookup_count(), program.tuple_count(), plan.rows, plan.peak, (D + 1) * 8, started.elapsed().as_nanos());
            Ok((output, terminal_words))
        })
    }
}
