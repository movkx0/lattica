//! Degree-bounded opening consumer. Compression commutes with interpolation:
//! q(X)=sum_j alpha^j p_j(X). The first H/blowup bit-reversed coset rows
//! determine q; expand only its three base-field coefficient columns on-device.
//! The caller owns the degree guarantee and Fiat-Shamir ordering. No RNG is used.
use super::*;
use crate::block_v2::compute;
use p3_field::{Field, TwoAdicField};

struct CompactPlan {
    base: Plan,
    reduce_rows: usize,
    denominator_words: usize,
    transform_words: usize,
    root_words: usize,
    total_bytes: usize,
}

impl CompactPlan {
    fn new(
        inputs: &[OpeningMatrix<'_>],
        log_blowup: usize,
        tile_bytes: usize,
        max_alloc: usize,
    ) -> Result<Self, String> {
        if log_blowup != crate::block_v2::profile::LOG_BLOWUP {
            return Err("compact opening requires unchanged candidate blowup".into());
        }
        let base = Plan::new(inputs, tile_bytes, max_alloc)?;
        let height = *base.heights.last().unwrap();
        if base.heights[0] < (1 << log_blowup) || height > (1 << 25) {
            return Err("compact opening degree/domain bounds".into());
        }
        let points = inputs.iter().map(|input| input.terms.len()).max().unwrap();
        let reduce_rows = (tile_bytes.min(max_alloc) / 8 / (points * 3 + 3)).min(65536);
        if reduce_rows == 0 {
            return Err("compact opening reduction tile allowance".into());
        }
        let denominator_words = reduce_rows * points * 3;
        let transform_words = height.checked_mul(3).ok_or("compact transform overflow")?;
        let root_words = height.trailing_zeros() as usize;
        let allocations = [
            base.input_words,
            denominator_words,
            base.weight_words,
            base.term_words,
            transform_words,
            transform_words,
            root_words,
            root_words,
        ];
        let mut total_bytes = base
            .heights
            .iter()
            .try_fold(0usize, |sum, h| sum.checked_add(h.checked_mul(24)?))
            .ok_or("compact output overflow")?;
        for words in allocations {
            let bytes = words.checked_mul(8).ok_or("compact allocation overflow")?;
            if bytes > max_alloc {
                return Err("compact opening allocation limit".into());
            }
            total_bytes = total_bytes
                .checked_add(bytes)
                .ok_or("compact budget overflow")?;
        }
        Ok(Self {
            base,
            reduce_rows,
            denominator_words,
            transform_words,
            root_words,
            total_bytes,
        })
    }
}

impl Engine {
    fn compact_write(&mut self, target: &Allocation, words: &[u64]) -> Result<(), String> {
        let mut event = Event::empty();
        let start = Instant::now();
        target
            .buffer
            .write(words)
            .enew(&mut event)
            .enq()
            .map_err(|e| e.to_string())?;
        self.stats.opening_upload_api_ns += start.elapsed().as_nanos();
        self.stats.opening_upload_device_ns += self.timeline.record("opening_upload", &event)?;
        self.stats.opening_uploaded_bytes += (words.len() * 8) as u64;
        Ok(())
    }

    fn compact_kernel(&mut self, kernel: &compute::Kernel, compress: bool) -> Result<(), String> {
        let mut event = Event::empty();
        let enqueue = Instant::now();
        // SAFETY: plan bounds every range; a caller-owned queue fence drains
        // before any referenced allocation or host vector can be dropped.
        unsafe {
            let command = kernel.cmd().enew(&mut event);
            #[cfg(test)]
            let command = if let Some(gate) = &self.opening_gate {
                command.ewait(gate)
            } else {
                command
            };
            command.enq().map_err(|e| e.to_string())?;
        }
        self.stats.opening_kernel_enqueue_ns += enqueue.elapsed().as_nanos();
        #[cfg(test)]
        if let Some(unwind) = self.fail_opening_after_enqueue.take() {
            self.injected_event = Some(event.clone());
            if let Some(notify) = self.opening_submitted.take() {
                let _ = notify.send(());
            }
            if unwind {
                panic!("injected compact opening unwind after enqueue");
            }
            return Err("injected compact opening error after enqueue".into());
        }
        let wait = Instant::now();
        let ns = self.timeline.record("opening_compact", &event)?;
        self.stats.opening_kernel_wait_ns += wait.elapsed().as_nanos();
        self.stats.opening_kernel_ns += ns;
        if compress {
            self.stats.opening_compact_compress_ns += ns;
        }
        self.stats.opening_tiles += 1;
        Ok(())
    }

    pub(super) fn compact_openings(
        &mut self,
        inputs: &[OpeningMatrix<'_>],
        alpha: Challenge,
        log_blowup: usize,
    ) -> Result<Vec<Vec<Challenge>>, String> {
        let started = Instant::now();
        let plan = CompactPlan::new(inputs, log_blowup, self.limits.tile_bytes, self.max_alloc)?;
        let live = self
            .accounting
            .lock()
            .map_err(|_| "GPU accounting poisoned")?
            .live;
        let old_workspace = self.workspace.as_ref().map_or(0, |w| w.bytes());
        if live
            .checked_sub(old_workspace)
            .and_then(|n| n.checked_add(plan.total_bytes))
            .is_none_or(|n| n > self.limits.managed_bytes)
        {
            return Err("compact opening aggregate GPU allowance".into());
        }
        self.fence().finish()?;
        self.workspace = None;
        let alloc = |words| {
            allocation(
                &self.pq,
                &self.accounting,
                self.limits,
                self.max_alloc,
                words,
                compute::flags::MEM_READ_WRITE,
            )
        };
        let outputs = plan
            .base
            .heights
            .iter()
            .map(|h| alloc(h * 3))
            .collect::<Result<Vec<_>, _>>()?;
        let input_buffer = alloc(plan.base.input_words)?;
        let denominator_buffer = alloc(plan.denominator_words)?;
        let weight_buffer = alloc(plan.base.weight_words)?;
        let term_buffer = alloc(plan.base.term_words)?;
        let a = alloc(plan.transform_words)?;
        let b = alloc(plan.transform_words)?;
        let forward = alloc(plan.root_words)?;
        let inverse = alloc(plan.root_words)?;
        // One reused vector, not simultaneous wide-input/denominator/download
        // staging. Its maximum payload stays within the existing tile allowance.
        let mut words = Vec::with_capacity(
            plan.base
                .input_words
                .max(plan.denominator_words)
                .max(plan.reduce_rows * 3),
        );
        let mut weights = Vec::with_capacity(plan.base.weight_words);
        let mut terms = Vec::with_capacity(plan.base.term_words);
        // Declared after all referenced buffers: also protects NTT errors/unwinds.
        let fence = self.fence();
        for output in &outputs {
            output
                .buffer
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        words.extend(
            (1..=plan.root_words).map(|log| Val::two_adic_generator(log).as_canonical_u64()),
        );
        self.compact_write(&forward, &words)?;
        words.clear();
        words.extend(
            (1..=plan.root_words)
                .map(|log| Val::two_adic_generator(log).inverse().as_canonical_u64()),
        );
        self.compact_write(&inverse, &words)?;
        for input in inputs {
            let height = input.values.len() / input.width;
            let low_height = height >> log_blowup;
            let output_index = plan.base.heights.binary_search(&height).unwrap();
            let marshal = Instant::now();
            weights.clear();
            for weight in alpha.powers().take(input.width) {
                append_challenge(&mut weights, weight);
            }
            terms.clear();
            for term in &input.terms {
                append_challenge(&mut terms, term.alpha_offset);
                append_challenge(&mut terms, term.opened);
            }
            self.stats.opening_marshal_ns += marshal.elapsed().as_nanos();
            self.compact_write(&weight_buffer, &weights)?;
            self.compact_write(&term_buffer, &terms)?;
            // IFFT overwrites the low coefficients; the rest must remain zero.
            b.buffer
                .cmd()
                .fill(0u64, Some(height * 3))
                .enq()
                .map_err(|e| e.to_string())?;
            let compressed = if low_height == 1 {
                &b.buffer
            } else {
                &a.buffer
            };
            for row0 in (0..low_height).step_by(plan.base.rows) {
                let rows = plan.base.rows.min(low_height - row0);
                let marshal = Instant::now();
                words.clear();
                words.extend(
                    input.values[row0 * input.width..(row0 + rows) * input.width]
                        .iter()
                        .map(PrimeField64::as_canonical_u64),
                );
                self.stats.opening_marshal_ns += marshal.elapsed().as_nanos();
                self.compact_write(&input_buffer, &words)?;
                let build = Instant::now();
                let kernel = self
                    .pq
                    .kernel_builder("opening_compress_low")
                    .arg(&input_buffer.buffer)
                    .arg(&weight_buffer.buffer)
                    .arg(compressed)
                    .arg(row0 as u32)
                    .arg(rows as u32)
                    .arg(input.width as u32)
                    .arg(low_height.trailing_zeros())
                    .global_work_size(rows)
                    .build()
                    .map_err(|e| e.to_string())?;
                self.stats.opening_kernel_build_ns += build.elapsed().as_nanos();
                self.compact_kernel(&kernel, true)?;
            }
            let before_ntt = self.stats.lde_transform_ns;
            if low_height > 1 {
                self.lde_ntt(
                    &a.buffer,
                    &b.buffer,
                    &inverse.buffer,
                    low_height,
                    3,
                    Val::from_usize(low_height).inverse().as_canonical_u64(),
                    1,
                    false,
                    false,
                )?;
            }
            // Low samples already lie on g*H. Interpolate q(g*X), so no extra
            // coset shift is applied when extending to the larger subgroup.
            let in_a = self.lde_ntt(
                &b.buffer,
                &a.buffer,
                &forward.buffer,
                height,
                3,
                1,
                1,
                true,
                true,
            )?;
            self.stats.opening_compact_ntt_ns += self.stats.lde_transform_ns - before_ntt;
            let expanded = if in_a { &a.buffer } else { &b.buffer };
            for row0 in (0..height).step_by(plan.reduce_rows) {
                let rows = plan.reduce_rows.min(height - row0);
                let marshal = Instant::now();
                words.clear();
                for row in row0..row0 + rows {
                    for term in &input.terms {
                        append_challenge(&mut words, term.inverse_denominators[row]);
                    }
                }
                self.stats.opening_marshal_ns += marshal.elapsed().as_nanos();
                self.compact_write(&denominator_buffer, &words)?;
                let build = Instant::now();
                let kernel = self
                    .pq
                    .kernel_builder("opening_reduce_compact")
                    .arg(expanded)
                    .arg(&denominator_buffer.buffer)
                    .arg(&term_buffer.buffer)
                    .arg(&outputs[output_index].buffer)
                    .arg(row0 as u32)
                    .arg(rows as u32)
                    .arg(input.terms.len() as u32)
                    .global_work_size(rows)
                    .build()
                    .map_err(|e| e.to_string())?;
                self.stats.opening_kernel_build_ns += build.elapsed().as_nanos();
                self.compact_kernel(&kernel, false)?;
            }
            self.stats.opening_compact_saved_input_bytes +=
                ((height - low_height) * input.width * 8) as u64;
        }
        let mut result = Vec::with_capacity(outputs.len());
        for (height, output) in plan.base.heights.iter().zip(&outputs).rev() {
            let mut values = Vec::with_capacity(*height);
            for row0 in (0..*height).step_by(plan.reduce_rows) {
                let rows = plan.reduce_rows.min(height - row0);
                words.resize(rows * 3, 0);
                let mut event = Event::empty();
                let readback = Instant::now();
                output
                    .buffer
                    .read(&mut words[..rows * 3])
                    .offset(row0 * 3)
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
                self.stats.opening_download_api_ns += readback.elapsed().as_nanos();
                self.stats.opening_download_device_ns +=
                    self.timeline.record("opening_download", &event)?;
                let decode = Instant::now();
                for triple in words[..rows * 3].chunks_exact(3) {
                    values.push(
                        Challenge::from_basis_coefficients_slice(&[
                            Val::from_u64(triple[0]),
                            Val::from_u64(triple[1]),
                            Val::from_u64(triple[2]),
                        ])
                        .unwrap(),
                    );
                }
                self.stats.opening_decode_ns += decode.elapsed().as_nanos();
                self.stats.opening_downloaded_bytes += (rows * 24) as u64;
            }
            result.push(values);
        }
        fence.finish()?;
        self.stats.opening_calls += 1;
        self.stats.opening_compact_calls += 1;
        self.stats.opening_wall_ns += started.elapsed().as_nanos();
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
