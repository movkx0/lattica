//! Owned quadratic/cubic opening evaluation and FRI-input accumulation.
//! Only claimed values and failure status have explicit host-read interfaces.
use super::*;

const MAX_WIDTH: usize = 4096;
const MAX_POINTS: usize = 32;
const MAX_LOG_ROWS: u32 = 25;
pub(super) const TILE_LIMIT: usize = 64 << 20;
pub(crate) const GROUP_KERNEL_SRC: &str = concat!(
    "\n#define OPENING_DEGREE 3\n#define OPENING_GROUP opening_compress_group\n#define OPENING_MUL opening_cubic_mul\n",
    include_str!("opening_group.cl"),
    "\n#undef OPENING_DEGREE\n#undef OPENING_GROUP\n#undef OPENING_MUL\n",
    "#define OPENING_DEGREE 2\n#define OPENING_GROUP opening_compress_group_quadratic\n#define OPENING_MUL opening_quadratic_mul\n",
    include_str!("opening_group.cl"),
    "\n#undef OPENING_DEGREE\n#undef OPENING_GROUP\n#undef OPENING_MUL\n",
);

// Select separate kernels so the existing cubic implementation is unchanged.
macro_rules! opening_kernel {
    ($extension:expr, $name:ident) => {
        if $extension == Extension::Quadratic {
            concat!(stringify!($name), "_quadratic")
        } else {
            stringify!($name)
        }
    };
}

fn opening_degree(extension: Extension) -> Result<usize, String> {
    if !matches!(extension, Extension::Quadratic | Extension::Cubic) {
        return Err("opening challenge extension must be quadratic or cubic".into());
    }
    Ok(extension.degree())
}

#[cfg(test)]
mod tests;

pub(crate) struct DeviceOpening {
    prefix: DeviceMatrix,
    points: Allocation,
    values: Allocation,
    count: usize,
    extension: Extension,
    // Exact public point uploaded to `points`; single-point batches compare it
    // without reading device data or trusting a separate caller descriptor.
    first_point: [u64; 3],
}
impl DeviceOpening {
    pub(crate) fn can_combine(&self, other: &Self) -> bool {
        self.count == 1
            && other.count == 1
            && self.extension == other.extension
            && self.first_point == other.first_point
            && self.prefix.spec.log_rows == other.prefix.spec.log_rows
            && self.prefix.spec.shift == other.prefix.spec.shift
    }
}

/// The output cannot be read or aliased until all append operations succeed.
/// An append error consumes and drops the entire accumulator.
pub(crate) struct OpeningAccumulator {
    session: DeviceSession,
    output: DeviceMatrix,
    alpha: Allocation,
    next_power: u64,
    matrices: usize,
}

fn checked_peak(
    live: usize,
    words: &[usize],
    limits: super::super::Limits,
    max_alloc: usize,
) -> Result<usize, String> {
    let peak = words.iter().try_fold(live, |sum, words| {
        let bytes = words.checked_mul(8).ok_or("opening allocation overflow")?;
        if bytes == 0 || bytes > max_alloc {
            return Err("opening allocation exceeds device limit");
        }
        sum.checked_add(bytes).ok_or("opening memory plan overflow")
    })?;
    if peak > limits.managed_bytes {
        return Err("opening exceeds aggregate GPU budget".into());
    }
    Ok(peak)
}

#[cfg(test)]
fn validate_prefix(spec: MatrixSpec, points: &[[u64; 3]]) -> Result<(), String> {
    validate_prefix_extension(
        spec,
        Extension::Cubic,
        &points.iter().flatten().copied().collect::<Vec<_>>(),
    )
    .map(|_| ())
}

fn validate_prefix_extension(
    spec: MatrixSpec,
    extension: Extension,
    points: &[u64],
) -> Result<usize, String> {
    let degree = opening_degree(extension)?;
    if spec.extension != Extension::Base
        || spec.order != RowOrder::BitReversed
        || spec.columns > MAX_WIDTH
        || spec.log_rows + crate::block_v2::profile::LOG_BLOWUP as u32 > MAX_LOG_ROWS
        || points.is_empty()
        || points.len() % degree != 0
        || points.len() / degree > MAX_POINTS
        || points
            .chunks_exact(degree)
            .any(|p| p.iter().all(|n| *n == 0) || p.iter().any(|n| *n >= GOLDILOCKS_MODULUS))
    {
        return Err("unsupported device opening prefix or point geometry".into());
    }
    Ok(points.len() / degree)
}

pub(super) struct EvaluationPlan {
    pub(super) rows: usize,
    inverse_words: usize,
    partial_words: usize,
    pub(super) peak: usize,
}
impl EvaluationPlan {
    pub(super) fn new(
        spec: MatrixSpec,
        points: usize,
        degree: usize,
        live: usize,
        limits: super::super::Limits,
        max_alloc: usize,
    ) -> Result<Self, String> {
        let fixed = [
            points * degree,
            points * degree * 2,
            points * spec.columns * degree,
            1,
        ];
        checked_peak(live, &fixed, limits, max_alloc)?;
        // Bound the serial partial-sum reduction while amortizing per-kernel
        // submission and observation waits. The loop still admits every buffer
        // against the live aggregate, tile and individual-allocation budgets.
        let mut rows = spec.rows().min(65536);
        while rows != 0 {
            let inverse_words = rows * points * degree;
            let partial_words = rows.div_ceil(128) * points * spec.columns * degree;
            let mut words = fixed.to_vec();
            words.extend([inverse_words, partial_words]);
            if (inverse_words + partial_words) * 8 <= limits.tile_bytes.min(TILE_LIMIT) {
                if let Ok(peak) = checked_peak(live, &words, limits, max_alloc) {
                    return Ok(Self {
                        rows,
                        inverse_words,
                        partial_words,
                        peak,
                    });
                }
            }
            rows /= 2;
        }
        Err("device opening budget cannot fit one row".into())
    }
}

pub(super) struct ReductionPlan {
    pub(super) rows: usize,
    pub(super) peak: usize,
}
impl ReductionPlan {
    pub(super) fn new(
        prefix: MatrixSpec,
        log_rows: u32,
        points: usize,
        degree: usize,
        live: usize,
        limits: super::super::Limits,
        max_alloc: usize,
    ) -> Result<Self, String> {
        let height = 1usize << log_rows;
        // Compression, expanded vector plus transform scratch, roots/parameters,
        // alpha weights, reduction terms, and status; accumulator is already live.
        let fixed = [
            prefix.rows() * degree,
            height * degree,
            height * degree,
            (prefix.log_rows.max(1) + log_rows.max(1) + 2) as usize,
            prefix.columns * degree,
            points * degree * 2,
            1,
        ];
        checked_peak(live, &fixed, limits, max_alloc)?;
        // Amortize denominator/inversion dispatches while preserving aggregate,
        // scratch-tile and individual-allocation admission for every buffer.
        let mut rows = height.min(1 << 20);
        while rows != 0 {
            let inverse_words = rows * points * degree;
            let mut words = fixed.to_vec();
            words.push(inverse_words);
            if inverse_words * 8 <= limits.tile_bytes.min(TILE_LIMIT) {
                if let Ok(peak) = checked_peak(live, &words, limits, max_alloc) {
                    return Ok(Self { rows, peak });
                }
            }
            rows /= 2;
        }
        Err("opening reduction budget cannot fit one row".into())
    }
}

fn owned_allocation(engine: &Engine, words: usize) -> Result<Allocation, String> {
    let mut value = allocation(
        &engine.pq,
        &engine.accounting,
        engine.limits,
        engine.max_alloc,
        words,
        compute::flags::MEM_READ_WRITE,
    )?;
    value._lease.mark_device()?;
    Ok(value)
}

#[cfg(feature = "gpu")]
#[allow(clippy::too_many_arguments)]
fn invert_denominators(
    owner: &Session,
    engine: &mut Engine,
    points: &compute::Buffer<u64>,
    inverse: &compute::Buffer<u64>,
    status: &compute::Buffer<u64>,
    extension: Extension,
    count: usize,
    first: usize,
    rows: usize,
    log_rows: u32,
    shift: u64,
) -> Result<u128, String> {
    let mut event = compute::Event::empty();
    // SAFETY: callers reserve extension.degree() words per row/point; row ranges are bounded.
    unsafe {
        engine
            .pq
            .kernel_builder(opening_kernel!(extension, device_opening_denominators))
            .arg(points)
            .arg(inverse)
            .arg(count as u32)
            .arg(first as u32)
            .arg(rows as u32)
            .arg(log_rows)
            .arg(shift)
            .arg(super::super::fri_fold::root(log_rows))
            .global_work_size(rows * count)
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enew(&mut event)
            .enq()
            .map_err(|e| e.to_string())?;
    }
    let mut ns = owner.record_event(
        engine,
        crate::proving::Stage::Opening,
        "device_opening_denominators",
        &event,
    )?;
    let mut event = compute::Event::empty();
    // SAFETY: shared 128-lane extension product-tree inverse pads with one and flags zero.
    unsafe {
        engine
            .pq
            .kernel_builder("device_lookup_batch_inverse")
            .arg(inverse)
            .arg((rows * count) as u32)
            .arg(status)
            .arg(extension.degree() as u32)
            .global_work_size((rows * count).div_ceil(128) * 128)
            .local_work_size(128usize)
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enew(&mut event)
            .enq()
            .map_err(|e| e.to_string())?;
    }
    ns += owner.record_event(
        engine,
        crate::proving::Stage::Opening,
        "device_opening_batch_inverse",
        &event,
    )?;
    Ok(ns)
}

impl DeviceSession {
    pub(crate) fn evaluate_opening(
        &self,
        prefix: &DeviceMatrix,
        points: &[[u64; 3]],
    ) -> Result<DeviceOpening, String> {
        self.evaluate_opening_extension(
            prefix,
            Extension::Cubic,
            &points.iter().flatten().copied().collect::<Vec<_>>(),
        )
    }

    pub(crate) fn evaluate_opening_extension(
        &self,
        prefix: &DeviceMatrix,
        extension: Extension,
        point_words: &[u64],
    ) -> Result<DeviceOpening, String> {
        self.check_owner(prefix)?;
        let count = validate_prefix_extension(prefix.spec, extension, point_words)?;
        let degree = extension.degree();
        #[cfg(not(feature = "gpu"))]
        {
            Err("owned opening evaluation is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let started = std::time::Instant::now();
            engine.fence().finish()?;
            engine.lde_workspace = None;
            let spec = prefix.spec;
            let plan = EvaluationPlan::new(spec, count, degree, engine.accounting.lock().unwrap().live,
                engine.limits, engine.max_alloc)?;
            let data = DeviceOpening { prefix: self.alias_private(prefix)?,
                points: owned_allocation(engine, count * degree)?,
                values: owned_allocation(engine, count * spec.columns * degree)?, count, extension,
                first_point: { let mut point = [0; 3]; point[..degree].copy_from_slice(&point_words[..degree]); point } };
            let parameters = owned_allocation(engine, count * degree * 2)?;
            let inverse = owned_allocation(engine, plan.inverse_words)?;
            let partial = owned_allocation(engine, plan.partial_words)?;
            let status = owned_allocation(engine, 1)?;
            let fence = engine.fence();
            data.points.buffer.write(point_words).enq().map_err(|e| e.to_string())?;
            data.values.buffer.cmd().fill(0u64, None).enq().map_err(|e| e.to_string())?;
            status.buffer.cmd().fill(0u64, None).enq().map_err(|e| e.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: one two-extension-element parameter record per checked nonzero point.
            unsafe {
                engine.pq.kernel_builder(opening_kernel!(extension, device_opening_parameters))
                    .arg(&data.points.buffer).arg(&parameters.buffer).arg(count as u32)
                    .arg(spec.rows() as u32).arg(spec.shift).global_work_size(count)
                    .build().map_err(|e| e.to_string())?.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
            }
            let mut ns = 0u128;
            let mut batch = super::event_batch::EventBatch::new(engine, &self.session, crate::proving::Stage::Opening);
            batch.record("device_opening_parameters", event)?;
            for first in (0..spec.rows()).step_by(plan.rows) {
                let rows = plan.rows.min(spec.rows() - first);
                ns += invert_denominators(&self.session,batch.engine, &data.points.buffer, &inverse.buffer, &status.buffer,
                    extension, count, first, rows, spec.log_rows, spec.shift)?;
                let blocks = rows.div_ceil(128);
                let mut event = compute::Event::empty();
                // SAFETY: each group reduces 128 rows for one point/column; padding is zero.
                unsafe {
                    batch.engine.pq.kernel_builder(opening_kernel!(extension, device_opening_dot)).arg(&prefix.storage.buffer)
                        .arg(&inverse.buffer).arg(&parameters.buffer).arg(&partial.buffer)
                        .arg(spec.columns as u32).arg(count as u32).arg(first as u32).arg(rows as u32)
                        .global_work_size(blocks * count * spec.columns * 128).local_work_size(128usize)
                        .build().map_err(|e| e.to_string())?.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                }
                batch.record("device_opening_dot", event)?;
                let mut event = compute::Event::empty();
                // SAFETY: every output element has one owner, reading the checked partial blocks.
                unsafe {
                    batch.engine.pq.kernel_builder(opening_kernel!(extension, device_opening_accumulate)).arg(&partial.buffer)
                        .arg(&data.values.buffer).arg(spec.columns as u32).arg(count as u32).arg(blocks as u32)
                        .global_work_size(count * spec.columns).build().map_err(|e| e.to_string())?
                        .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                }
                batch.record("device_opening_accumulate", event)?;
            }
            let mut event = compute::Event::empty();
            // SAFETY: matching point/column shapes, scaling only the completed sums.
            unsafe {
                batch.engine.pq.kernel_builder(opening_kernel!(extension, device_opening_scale)).arg(&data.values.buffer)
                    .arg(&parameters.buffer).arg(spec.columns as u32).arg(count as u32)
                    .global_work_size(count * spec.columns).build().map_err(|e| e.to_string())?
                    .cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
            }
            batch.record("device_opening_scale", event)?;
            ns += batch.finish()?;
            let mut failed = [0u64];
            status.buffer.read(&mut failed[..]).enq().map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += (point_words.len() * 8) as u64;
            engine.stats.downloaded_bytes += 8;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += (point_words.len() * 8) as u64;
            stats.downloaded_bytes += 8;
            if failed[0] != 0 { return Err("opening point lies on the prefix coset".into()); }
            stats.opening_evaluations += 1;
            stats.opening_device_ns += ns;
            eprintln!("bounded_device_opening prefix_rows={} width={} points={} tile_rows={} managed_peak_plan_bytes={} point_upload_bytes={} control_download_bytes=8 matrix_readback_bytes=0 kernel_ns={ns} wall_ns={}",
                spec.rows(), spec.columns, count, plan.rows, plan.peak, point_words.len() * 8, started.elapsed().as_nanos());
            Ok(data)
        })
    }

    pub(crate) fn opening_values(
        &self,
        opening: &DeviceOpening,
        host_allowance: usize,
    ) -> Result<Vec<Vec<[u64; 3]>>, String> {
        if opening.extension != Extension::Cubic {
            return Err("cubic opening decoder requires a cubic opening".into());
        }
        let words = self.opening_values_words(opening, host_allowance)?;
        Ok(words
            .chunks_exact(opening.prefix.spec.columns * 3)
            .map(|point| point.chunks_exact(3).map(|v| [v[0], v[1], v[2]]).collect())
            .collect())
    }

    pub(crate) fn opening_values_words(
        &self,
        opening: &DeviceOpening,
        host_allowance: usize,
    ) -> Result<Vec<u64>, String> {
        self.check_owner(&opening.prefix)?;
        let width = opening.prefix.spec.columns;
        let words = opening.count * width * opening.extension.degree();
        if words * 8 > host_allowance {
            return Err("claimed opening values exceed host allowance".into());
        }
        self.with_engine(|engine| {
            let mut values = vec![0u64; words];
            let fence = engine.fence();
            opening
                .values
                .buffer
                .read(&mut values)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.downloaded_bytes += words as u64 * 8;
            let mut stats = self.session.stats.lock().unwrap();
            stats.downloaded_bytes += words as u64 * 8;
            stats.opening_value_bytes += words as u64 * 8;
            if values.iter().any(|n| *n >= GOLDILOCKS_MODULUS) {
                return Err("noncanonical claimed opening value".into());
            }
            Ok(values)
        })
    }

    pub(crate) fn opening_accumulator(
        &self,
        log_rows: u32,
        alpha: [u64; 3],
    ) -> Result<OpeningAccumulator, String> {
        self.opening_accumulator_extension(log_rows, Extension::Cubic, &alpha)
    }

    pub(crate) fn opening_accumulator_extension(
        &self,
        log_rows: u32,
        extension: Extension,
        alpha: &[u64],
    ) -> Result<OpeningAccumulator, String> {
        let degree = opening_degree(extension)?;
        if !(crate::block_v2::profile::LOG_BLOWUP as u32..=MAX_LOG_ROWS).contains(&log_rows)
            || alpha.len() != degree
            || alpha.iter().any(|n| *n >= GOLDILOCKS_MODULUS)
        {
            return Err("unsupported opening accumulator geometry or challenge".into());
        }
        let spec = MatrixSpec::new(log_rows, 1, extension, RowOrder::BitReversed, 1)?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = spec;
            Err("owned opening reduction is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            checked_peak(
                engine.accounting.lock().unwrap().live,
                &[spec.words(), degree],
                engine.limits,
                engine.max_alloc,
            )?;
            let output = self.allocate(engine, spec)?;
            let parameter = owned_allocation(engine, degree)?;
            let fence = engine.fence();
            output
                .storage
                .buffer
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
            parameter
                .buffer
                .write(&alpha[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += (degree * 8) as u64;
            self.session.stats.lock().unwrap().uploaded_bytes += (degree * 8) as u64;
            Ok(OpeningAccumulator {
                session: self.clone(),
                output,
                alpha: parameter,
                next_power: 0,
                matrices: 0,
            })
        })
    }
}

impl OpeningAccumulator {
    pub(crate) fn append(self, opening: &DeviceOpening) -> Result<Self, String> {
        self.append_group(&[opening])
    }

    /// Compression and interpolation are linear. Adjacent matrices at the
    /// same single point share one expansion and rational reduction, while
    /// every column retains its original Fiat-Shamir alpha exponent.
    pub(crate) fn append_group(mut self, openings: &[&DeviceOpening]) -> Result<Self, String> {
        let opening = *openings.first().ok_or("empty opening group")?;
        let prefix = opening.prefix.spec;
        let output = self.output.spec;
        let extension = output.extension;
        let degree = extension.degree();
        if prefix.log_rows + crate::block_v2::profile::LOG_BLOWUP as u32 != output.log_rows
            || opening.extension != extension
            || openings.len() > 256usize.saturating_sub(self.matrices)
        {
            return Err("opening accumulator height, extension or matrix count mismatch".into());
        }
        let mut next_power = self.next_power;
        let mut max_columns = prefix.columns;
        for member in openings {
            self.session.check_owner(&member.prefix)?;
            if openings.len() > 1 && !opening.can_combine(member) {
                return Err("opening group point or domain mismatch".into());
            }
            max_columns = max_columns.max(member.prefix.spec.columns);
            next_power = next_power
                .checked_add((member.prefix.spec.columns * member.count) as u64)
                .ok_or("opening alpha power overflow")?;
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = next_power;
            Err("owned opening reduction is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        {
            let started = std::time::Instant::now();
            let (low, weights, terms, inverse, status, plan, mut ns) =
                self.session.with_engine(|engine| {
                    engine.fence().finish()?;
                    engine.lde_workspace = None;
                    let grouped = openings.len() > 1;
                    let plan = ReductionPlan::new(
                        MatrixSpec::new(
                            prefix.log_rows,
                            max_columns,
                            prefix.extension,
                            prefix.order,
                            prefix.shift,
                        )?,
                        output.log_rows,
                        opening.count,
                        degree,
                        engine
                            .accounting
                            .lock()
                            .unwrap()
                            .live
                            .checked_add(if grouped { degree * 16 } else { 0 })
                            .ok_or("opening group storage overflow")?,
                        engine.limits,
                        engine.max_alloc,
                    )?;
                    let low = self.session.allocate(
                        engine,
                        MatrixSpec::new(
                            prefix.log_rows,
                            1,
                            extension,
                            RowOrder::Natural,
                            prefix.shift,
                        )?,
                    )?;
                    let weights = owned_allocation(engine, max_columns * degree)?;
                    let terms = owned_allocation(engine, opening.count * degree * 2)?;
                    let member_terms = if grouped {
                        Some(owned_allocation(engine, degree * 2)?)
                    } else {
                        None
                    };
                    let inverse = owned_allocation(engine, plan.rows * opening.count * degree)?;
                    let status = owned_allocation(engine, 1)?;
                    let fence = engine.fence();
                    let mut ns = 0u128;
                    let mut first_power = self.next_power;
                    for (member_index, member) in openings.iter().enumerate() {
                        let member_prefix = member.prefix.spec;
                        let mut event = compute::Event::empty();
                        // SAFETY: one cubic alpha power per bounded column.
                        unsafe {
                            engine
                                .pq
                                .kernel_builder(opening_kernel!(extension, device_opening_weights))
                                .arg(&self.alpha.buffer)
                                .arg(&weights.buffer)
                                .arg(member_prefix.columns as u32)
                                .global_work_size(member_prefix.columns)
                                .build()
                                .map_err(|e| e.to_string())?
                                .cmd()
                                .enew(&mut event)
                                .enq()
                                .map_err(|e| e.to_string())?;
                        }
                        ns += self.session.record_event(
                            engine,
                            crate::proving::Stage::Opening,
                            "device_opening_weights",
                            &event,
                        )?;
                        let mut event = compute::Event::empty();
                        // SAFETY: opened values and weights share the prefix's checked column geometry.
                        unsafe {
                            engine
                                .pq
                                .kernel_builder(opening_kernel!(extension, device_opening_terms))
                                .arg(&self.alpha.buffer)
                                .arg(&weights.buffer)
                                .arg(&member.values.buffer)
                                .arg(&member_terms.as_ref().unwrap_or(&terms).buffer)
                                .arg(member_prefix.columns as u32)
                                .arg(member.count as u32)
                                .arg(first_power)
                                .global_work_size(member.count)
                                .build()
                                .map_err(|e| e.to_string())?
                                .cmd()
                                .enew(&mut event)
                                .enq()
                                .map_err(|e| e.to_string())?;
                        }
                        ns += self.session.record_event(
                            engine,
                            crate::proving::Stage::Opening,
                            "device_opening_terms",
                            &event,
                        )?;
                        let mut event = compute::Event::empty();
                        // SAFETY: compress bit-reversed prefix rows into natural-order extension evaluations.
                        unsafe {
                            if let Some(member_terms) = &member_terms {
                                engine
                                    .pq
                                    .kernel_builder(opening_kernel!(
                                        extension,
                                        opening_compress_group
                                    ))
                                    .arg(&member.prefix.storage.buffer)
                                    .arg(&weights.buffer)
                                    .arg(&member_terms.buffer)
                                    .arg(&low.storage.buffer)
                                    .arg(&terms.buffer)
                                    .arg(member_prefix.rows() as u32)
                                    .arg(member_prefix.columns as u32)
                                    .arg(member_prefix.log_rows)
                                    .arg(u32::from(member_index == 0))
                                    .global_work_size(member_prefix.rows())
                                    .build()
                                    .map_err(|e| e.to_string())?
                                    .cmd()
                                    .enew(&mut event)
                                    .enq()
                                    .map_err(|e| e.to_string())?;
                            } else {
                                engine
                                    .pq
                                    .kernel_builder(opening_kernel!(
                                        extension,
                                        opening_compress_low
                                    ))
                                    .arg(&member.prefix.storage.buffer)
                                    .arg(&weights.buffer)
                                    .arg(&low.storage.buffer)
                                    .arg(0u32)
                                    .arg(prefix.rows() as u32)
                                    .arg(prefix.columns as u32)
                                    .arg(prefix.log_rows)
                                    .global_work_size(prefix.rows())
                                    .build()
                                    .map_err(|e| e.to_string())?
                                    .cmd()
                                    .enew(&mut event)
                                    .enq()
                                    .map_err(|e| e.to_string())?;
                            }
                        }
                        ns += self.session.record_event(
                            engine,
                            crate::proving::Stage::Opening,
                            "device_opening_compress_low",
                            &event,
                        )?;
                        first_power += (member_prefix.columns * member.count) as u64;
                    }
                    fence.finish()?;
                    Ok((low, weights, terms, inverse, status, plan, ns))
                })?;
            let expanded =
                self.session
                    .lde(&low, output.log_rows, prefix.shift, RowOrder::BitReversed)?;
            drop(low);
            drop(weights);
            self.session.with_engine(|engine| {
                let fence = engine.fence();
                status
                    .buffer
                    .cmd()
                    .fill(0u64, None)
                    .enq()
                    .map_err(|e| e.to_string())?;
                for first in (0..output.rows()).step_by(plan.rows) {
                    let rows = plan.rows.min(output.rows() - first);
                    ns += invert_denominators(
                        &self.session.session,
                        engine,
                        &opening.points.buffer,
                        &inverse.buffer,
                        &status.buffer,
                        extension,
                        opening.count,
                        first,
                        rows,
                        output.log_rows,
                        prefix.shift,
                    )?;
                    let mut event = compute::Event::empty();
                    // SAFETY: each output row owns its sum; denominators cover this row tile.
                    unsafe {
                        engine
                            .pq
                            .kernel_builder(opening_kernel!(extension, opening_reduce_compact))
                            .arg(&expanded.storage.buffer)
                            .arg(&inverse.buffer)
                            .arg(&terms.buffer)
                            .arg(&self.output.storage.buffer)
                            .arg(first as u32)
                            .arg(rows as u32)
                            .arg(opening.count as u32)
                            .global_work_size(rows)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    ns += self.session.record_event(
                        engine,
                        crate::proving::Stage::Opening,
                        "device_opening_reduce",
                        &event,
                    )?;
                }
                let mut failed = [0u64];
                status
                    .buffer
                    .read(&mut failed[..])
                    .enq()
                    .map_err(|e| e.to_string())?;
                fence.finish()?;
                engine.stats.downloaded_bytes += 8;
                let mut stats = self.session.session.stats.lock().unwrap();
                stats.downloaded_bytes += 8;
                if failed[0] != 0 {
                    return Err("opening point lies on the expanded coset".into());
                }
                stats.opening_reductions += openings.len() as u64;
                stats.opening_device_ns += ns;
                Ok(())
            })?;
            self.next_power = next_power;
            self.matrices += openings.len();
            eprintln!("bounded_device_opening_reduce rows={} prefix_rows={} width={} points={} matrices={} tile_rows={} managed_peak_plan_bytes={} control_download_bytes=8 matrix_readback_bytes=0 kernel_ns={ns} wall_ns={}",
                output.rows(), prefix.rows(), max_columns, opening.count, openings.len(), plan.rows, plan.peak, started.elapsed().as_nanos());
            Ok(self)
        }
    }

    pub(crate) fn finish(self) -> Result<DeviceMatrix, String> {
        if self.matrices == 0 {
            return Err("opening accumulator has no input matrices".into());
        }
        Ok(self.output)
    }
}
