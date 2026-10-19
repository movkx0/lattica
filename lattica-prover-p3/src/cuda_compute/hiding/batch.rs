//! Native PCS commitment storage: stream hidden LDE tiles into one binary
//! MMCS, retaining only low-coset prefixes, Merkle nodes and salt recipes.
use super::*;
use crate::{
    cuda_compute::{Commitments, ReplaySalts, RetainedTree},
    gpu_matrix::query::{geometry as query_geometry, QueryPlan},
};
const MAX_INPUTS: usize = 256;
const MAX_QUERIES: usize = 256;
const HOST_METADATA: usize = 64 << 10;

mod quotient;
pub(crate) use quotient::CommittedMatrix;

#[derive(Clone, Copy)]
enum Fault {
    None,
    #[cfg(test)]
    AfterTile,
    #[cfg(test)]
    PanicAfterTile,
    #[cfg(test)]
    AfterQuery,
}

/// Quotients expand to their complete, ordered partition. A caller cannot
/// accidentally omit the balancing final chunk through this interface.
pub(crate) enum HidingInput<'a> {
    Trace(&'a TraceHidingInput),
    Randomization(&'a RandomizationInput),
    Quotient(&'a QuotientHidingInput),
}
#[derive(Clone, Copy)]
enum Source<'a> {
    Trace(&'a TraceHidingInput),
    Randomization(&'a RandomizationInput),
    Quotient(&'a QuotientHidingInput, usize),
}
impl Source<'_> {
    fn plan(self) -> TilePlan {
        match self {
            Self::Trace(p) => p.plan,
            Self::Randomization(p) => p.plan,
            Self::Quotient(p, _) => p.plan,
        }
    }
    fn width(self) -> usize {
        self.plan().width
    }
    fn random_columns(self) -> usize {
        match self {
            Self::Trace(p) => p.shape.random_columns,
            Self::Randomization(_) => crate::config::NUM_RANDOM_CODEWORDS,
            Self::Quotient(p, _) => p.shape.random_columns,
        }
    }
    fn prefix_spec(self) -> Result<MatrixSpec> {
        let plan = self.plan();
        MatrixSpec::new(
            plan.input_log + u32::from(plan.quotient),
            plan.width,
            Extension::Base,
            RowOrder::BitReversed,
            GENERATOR,
        )
    }
    fn full_spec(self, salts: bool) -> Result<MatrixSpec> {
        MatrixSpec::new(
            self.plan().output_log,
            self.width() + if salts { 4 } else { 0 },
            Extension::Base,
            RowOrder::BitReversed,
            GENERATOR,
        )
    }
}

struct RetainedInput {
    prefix: Matrix,
    spec: MatrixSpec,
    random_columns: usize,
    salts: ReplaySalts,
}
pub(crate) struct HiddenCommitment {
    runtime: Runtime,
    tree: RetainedTree,
    matrices: Vec<RetainedInput>,
    families: Vec<DeviceRandom>,
}
pub(crate) struct MatrixOpenings {
    pub spec: MatrixSpec,
    pub random_columns: usize,
    /// Query-major rows, in the caller's order, including duplicates.
    pub values: Vec<u64>,
    pub salts: Vec<u64>,
}
pub(crate) struct HiddenOpenings {
    /// Original matrix order; quotient partitions expand in chunk order.
    pub matrices: Vec<MatrixOpenings>,
    pub paths: Vec<u64>,
    pub queries: usize,
    pub path_len: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct OpeningShape {
    pub prefix: MatrixSpec,
    pub lde: MatrixSpec,
    pub random_columns: usize,
}

/// An immutable evaluated opening can outlive its initial evaluation, but
/// every consumer must still belong to the original commitment's live family.
pub(crate) struct RetainedOpening<'a> {
    owner: &'a HiddenCommitment,
    opening: crate::cuda_compute::DeviceOpening,
    shape: OpeningShape,
}

impl RetainedOpening<'_> {
    pub(crate) fn shape(&self) -> OpeningShape {
        self.shape
    }

    pub(crate) fn with<T>(
        &self,
        consume: impl FnOnce(&crate::cuda_compute::DeviceOpening) -> Result<T>,
    ) -> Result<T> {
        check_families(&self.owner.families)?;
        let attempt = self.owner.begin_attempt(&self.owner.runtime)?;
        let result = consume(&self.opening)?;
        check_families(&self.owner.families)?;
        attempt.complete();
        Ok(result)
    }
}

fn check_families(families: &[DeviceRandom]) -> Result<()> {
    for family in families {
        if let Err(error) = family.check_live() {
            for member in families {
                member.retire();
            }
            return Err(error);
        }
    }
    Ok(())
}
pub(crate) struct Attempt<'a> {
    families: &'a [DeviceRandom],
    complete: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.complete {
            for family in self.families {
                family.retire();
            }
        }
    }
}
impl Attempt<'_> {
    pub(crate) fn complete(mut self) {
        self.complete = true;
    }
}

impl Hiding {
    pub(crate) fn commit_batch(
        &self,
        commitments: &Commitments,
        inputs: &[HidingInput<'_>],
        salts: &DeviceRandom,
        cap_height: usize,
    ) -> Result<HiddenCommitment> {
        self.commit_batch_impl(commitments, inputs, salts, cap_height, Fault::None)
    }

    fn commit_batch_impl(
        &self,
        commitments: &Commitments,
        inputs: &[HidingInput<'_>],
        salts: &DeviceRandom,
        cap_height: usize,
        _fault: Fault,
    ) -> Result<HiddenCommitment> {
        if inputs.is_empty() || inputs.len() > MAX_INPUTS {
            return Err("CUDA hiding batch requires 1..256 inputs".into());
        }
        let count = inputs.iter().try_fold(0usize, |total, input| {
            total
                .checked_add(match input {
                    HidingInput::Trace(_) | HidingInput::Randomization(_) => 1,
                    HidingInput::Quotient(p) => p.shape.chunks,
                })
                .filter(|&n| n <= MAX_INPUTS)
                .ok_or("CUDA hiding batch expands beyond 256 matrices")
        })?;
        let mut sources = Vec::with_capacity(count);
        let mut families = Vec::with_capacity(inputs.len() + 1);
        for input in inputs {
            match input {
                HidingInput::Trace(p) => {
                    self.transforms.check_owner(&p.trace)?;
                    if let Some(family) = &p.family {
                        family.check_runtime(&self.runtime)?;
                        families.push(family.clone());
                    }
                    sources.push(Source::Trace(p));
                }
                HidingInput::Randomization(p) => {
                    self.transforms.check_owner(&p.samples)?;
                    p.family.check_runtime(&self.runtime)?;
                    families.push(p.family.clone());
                    sources.push(Source::Randomization(p));
                }
                HidingInput::Quotient(p) => {
                    self.transforms.check_owner(&p.quotient)?;
                    p.family.check_runtime(&self.runtime)?;
                    families.push(p.family.clone());
                    sources.extend((0..p.shape.chunks).map(|chunk| Source::Quotient(p, chunk)));
                }
            }
        }
        salts.check_runtime(&self.runtime)?;
        families.push(salts.clone());
        let prefixes = sources
            .iter()
            .map(|s| s.prefix_spec())
            .collect::<Result<Vec<_>>>()?;
        let specs = sources
            .iter()
            .map(|s| s.full_spec(true))
            .collect::<Result<Vec<_>>>()?;
        for (source, prefix) in sources.iter().zip(&prefixes) {
            // Retained data must support the same bounded prefix-query API.
            query_geometry(*prefix, source.plan().output_log, &[0])?;
        }
        let stream = commitments.stream_plan(&self.runtime, &specs, cap_height)?;
        let mut retained: Vec<_> = prefixes.iter().map(|s| s.words()).collect();
        retained.extend(stream.words);
        for source in &sources {
            source.plan().admit(&self.runtime, &retained)?;
        }
        let salt_specs = sources
            .iter()
            .map(|s| {
                MatrixSpec::new(
                    s.plan().output_log,
                    4,
                    Extension::Base,
                    RowOrder::BitReversed,
                    1,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let pending = retained
            .iter()
            .map(|n| {
                n.checked_mul(8)
                    .ok_or_else(|| "CUDA hiding storage overflow".to_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        salts.preflight_salt_recipes(&salt_specs, &pending)?;

        // All public shapes, sampler peaks, tile peaks and recipe slots have
        // been checked. Errors from here retire every participating family.
        let mut attempt = Attempt {
            families: &families,
            complete: false,
        };
        let recipes = salts.prepare_salt_replay_specs(&salt_specs)?;
        let prefixes = prefixes
            .into_iter()
            .map(|spec| {
                Ok(Matrix {
                    buffer: self.runtime.allocate(spec.words())?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let tree = commitments.commit_streamed(&specs, cap_height, |index, sink| {
            let source = sources[index];
            for first in (0..source.width()).step_by(source.plan().columns) {
                let columns = source.plan().columns.min(source.width() - first);
                let consume = |tile: &Matrix| {
                    self.retain_columns(tile, &prefixes[index], first)?;
                    sink.append(first, tile)?;
                    #[cfg(test)]
                    match _fault {
                        Fault::AfterTile => return Err("injected hiding batch tile failure".into()),
                        Fault::PanicAfterTile => panic!("injected hiding batch tile unwind"),
                        _ => {}
                    }
                    Ok(())
                };
                match source {
                    Source::Trace(input) => {
                        self.with_trace_lde(input, first, columns, RowOrder::BitReversed, consume)?
                    }
                    Source::Randomization(input) => self.with_randomization_lde(
                        input,
                        first,
                        columns,
                        RowOrder::BitReversed,
                        consume,
                    )?,
                    Source::Quotient(input, chunk) => self.with_quotient_lde(
                        input,
                        chunk,
                        first,
                        columns,
                        RowOrder::BitReversed,
                        consume,
                    )?,
                }
            }
            recipes[index].with_materialized(|matrix| {
                let fragment = Matrix {
                    spec: MatrixSpec::new(
                        matrix.spec.log_rows,
                        4,
                        Extension::Base,
                        RowOrder::BitReversed,
                        GENERATOR,
                    )?,
                    buffer: matrix.buffer.clone(),
                };
                sink.append(source.width(), &fragment)
            })
        })?;
        let matrices = prefixes
            .into_iter()
            .zip(recipes)
            .zip(sources)
            .map(|((prefix, salts), source)| {
                Ok(RetainedInput {
                    prefix,
                    spec: source.full_spec(false)?,
                    salts,
                    random_columns: source.random_columns(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        check_families(&families)?;
        attempt.complete = true;
        drop(attempt);
        Ok(HiddenCommitment {
            runtime: self.runtime.clone(),
            tree,
            matrices,
            families,
        })
    }

    fn retain_columns(&self, tile: &Matrix, prefix: &Matrix, first: usize) -> Result<()> {
        self.transforms.check_owner(tile)?;
        self.transforms.check_owner(prefix)?;
        if tile.spec.extension != Extension::Base
            || prefix.spec.extension != Extension::Base
            || tile.spec.order != RowOrder::BitReversed
            || prefix.spec.order != RowOrder::BitReversed
            || tile.spec.shift != prefix.spec.shift
            || tile.spec.rows() < prefix.spec.rows()
            || first
                .checked_add(tile.spec.columns)
                .is_none_or(|n| n > prefix.spec.columns)
        {
            return Err("CUDA retained prefix tile differs from its declared domain".into());
        }
        // Complete prefix rows and a checked column interval give disjoint
        // writes. The source LDE tile remains live through this completion.
        unsafe {
            self.retain_prefix.launch(
                super::super::transform::linear_launch(prefix.spec.rows() * tile.spec.columns)?,
                &[
                    Argument::Buffer(&tile.buffer),
                    Argument::Buffer(&prefix.buffer),
                    Argument::U32(prefix.spec.rows() as u32),
                    Argument::U32(tile.spec.columns as u32),
                    Argument::U32(prefix.spec.columns as u32),
                    Argument::U32(first as u32),
                ],
            )?
        }
        .finish()?;
        Ok(())
    }
}

impl HiddenCommitment {
    /// Consume the unmasked trace columns inside the commitment family's
    /// guard. No retained private prefix or independently reusable alias is
    /// exposed to the caller; only the completed quotient leaves this scope.
    pub(crate) fn evaluate_quotient(
        &self,
        hiding: &Hiding,
        quotients: &crate::cuda_compute::Quotients,
        prepared: &crate::cuda_compute::PreparedQuotient,
        matrix: usize,
        width: usize,
        log_trace: u32,
        log_quotient: u32,
        periodic: Option<&Matrix>,
        alpha: &Buffer,
        parameters: Option<&Buffer>,
    ) -> Result<Matrix> {
        self.check_runtime(&hiding.runtime)?;
        let input = self
            .matrices
            .get(matrix)
            .ok_or("CUDA quotient matrix index exceeds commitment")?;
        if width == 0 || width != input.spec.columns - input.random_columns {
            return Err("CUDA quotient width differs from committed trace columns".into());
        }
        let spec = MatrixSpec::new(
            input.prefix.spec.log_rows,
            width,
            Extension::Base,
            RowOrder::BitReversed,
            GENERATOR,
        )?;
        plan::admit(
            [spec.words()],
            hiding.runtime.snapshot(),
            hiding.runtime.state.budget.limits,
        )?;
        let attempt = self.begin_attempt(&hiding.runtime)?;
        let trace = Matrix {
            spec,
            buffer: hiding.runtime.allocate(spec.words())?,
        };
        // The same column-copy kernel preserves the prefix's physical row
        // order and omits only the validated masking suffix.
        unsafe {
            hiding.randomization_columns.launch(
                crate::cuda_compute::transform::linear_launch(spec.words())?,
                &[
                    Argument::Buffer(&input.prefix.buffer),
                    Argument::Buffer(&trace.buffer),
                    Argument::U32(spec.rows() as u32),
                    Argument::U32(input.prefix.spec.columns as u32),
                    Argument::U32(0),
                    Argument::U32(width as u32),
                ],
            )?
        }
        .finish()?;
        let output = quotients.evaluate_partitioned(
            &hiding.transforms,
            prepared,
            log_trace,
            log_quotient,
            GENERATOR,
            crate::cuda_compute::QuotientInputs {
                main: Some(&trace),
                preprocessed: periodic,
                permutation: None,
            },
            alpha,
            parameters,
        )?;
        check_families(&self.families)?;
        attempt.complete();
        Ok(output)
    }

    pub(crate) fn opening_shape(&self, matrix: usize) -> Result<OpeningShape> {
        let input = self
            .matrices
            .get(matrix)
            .ok_or("CUDA PCS matrix index exceeds commitment")?;
        Ok(OpeningShape {
            prefix: input.prefix.spec,
            lde: input.spec,
            random_columns: input.random_columns,
        })
    }

    pub(crate) fn preflight_retained_opening(
        &self,
        engine: &crate::cuda_compute::Openings,
        matrix: usize,
        extension: Extension,
        points: crate::cuda_compute::FieldSpan<'_>,
        count: usize,
        retained_bytes: usize,
        retained_allocations: usize,
    ) -> Result<()> {
        check_families(&self.families)?;
        let input = self
            .matrices
            .get(matrix)
            .ok_or("CUDA PCS matrix index exceeds commitment")?;
        engine.preflight_with_retained(
            &input.prefix,
            extension,
            points,
            count,
            retained_bytes,
            retained_allocations,
        )
    }

    pub(crate) fn retain_opening(
        &self,
        engine: &crate::cuda_compute::Openings,
        matrix: usize,
        extension: Extension,
        points: crate::cuda_compute::FieldSpan<'_>,
        count: usize,
    ) -> Result<RetainedOpening<'_>> {
        self.preflight_retained_opening(engine, matrix, extension, points, count, 0, 0)?;
        let attempt = self.begin_attempt(&self.runtime)?;
        let opening = engine.evaluate(&self.matrices[matrix].prefix, extension, points, count)?;
        check_families(&self.families)?;
        let result = RetainedOpening {
            owner: self,
            opening,
            shape: self.opening_shape(matrix)?,
        };
        attempt.complete();
        Ok(result)
    }

    pub(crate) fn check_runtime(&self, runtime: &Runtime) -> Result<()> {
        if !std::sync::Arc::ptr_eq(&self.runtime.state, &runtime.state) {
            return Err("CUDA hidden commitment belongs to another runtime".into());
        }
        check_families(&self.families)
    }

    /// Scope a complete consumer, including later transcript/query failures.
    pub(crate) fn begin_attempt(&self, runtime: &Runtime) -> Result<Attempt<'_>> {
        self.check_runtime(runtime)?;
        Ok(Attempt {
            families: &self.families,
            complete: false,
        })
    }

    /// Raw query outputs and the same staging allowance used by `open`.
    pub(crate) fn query_host_bytes(&self, queries: usize) -> Result<usize> {
        if !(1..=MAX_QUERIES).contains(&queries) {
            return Err("CUDA hidden query count exceeds admission".into());
        }
        let output = self.matrices.iter().try_fold(
            queries * self.tree.path_len() * 4 * 8 + HOST_METADATA,
            |total, matrix| {
                total
                    .checked_add(queries * (matrix.spec.columns + 4) * 8)
                    .ok_or_else(|| "CUDA hidden query output overflow".to_string())
            },
        )?;
        // `open` retains every matrix output while a reconstruction tile is
        // staged. Ask the shared planner for its largest possible tile; an
        // actual device budget can only reduce that temporary host storage.
        let mut temporary = 0;
        for matrix in &self.matrices {
            let plan = QueryPlan::new(
                matrix.prefix.spec,
                matrix.spec.log_rows,
                queries,
                usize::MAX,
                usize::MAX,
                usize::MAX,
            )?;
            temporary = temporary.max(plan.host_peak_bytes - queries * matrix.spec.columns * 8);
        }
        output
            .checked_add(temporary)
            .ok_or_else(|| "CUDA hidden query staging overflow".into())
    }

    /// Evaluate an original matrix's retained prefix without exposing its private
    /// storage. A failed consumer or unwind retires all participating RNG streams.
    pub(crate) fn with_opening<T>(
        &self,
        engine: &crate::cuda_compute::Openings,
        matrix: usize,
        extension: Extension,
        points: crate::cuda_compute::FieldSpan<'_>,
        count: usize,
        consume: impl FnOnce(&crate::cuda_compute::DeviceOpening) -> Result<T>,
    ) -> Result<T> {
        check_families(&self.families)?;
        let input = self
            .matrices
            .get(matrix)
            .ok_or("CUDA opening matrix index exceeds batch")?;
        engine.preflight(&input.prefix, extension, points, count)?;
        let mut attempt = Attempt {
            families: &self.families,
            complete: false,
        };
        let opening = engine.evaluate(&input.prefix, extension, points, count)?;
        let result = consume(&opening)?;
        check_families(&self.families)?;
        attempt.complete = true;
        Ok(result)
    }

    pub(crate) fn specs(&self) -> impl ExactSizeIterator<Item = MatrixSpec> + '_ {
        self.matrices.iter().map(|m| m.spec)
    }
    pub(crate) fn cap(&self, host_bytes: usize) -> Result<Vec<u64>> {
        if self.tree.cap_bytes() > host_bytes {
            return Err("CUDA hiding cap exceeds host allowance".into());
        }
        check_families(&self.families)?;
        let mut attempt = Attempt {
            families: &self.families,
            complete: false,
        };
        let cap = self.tree.cap(host_bytes)?;
        check_families(&self.families)?;
        attempt.complete = true;
        Ok(cap)
    }

    /// Only final query rows, salts and Merkle paths are downloaded. Reducing
    /// global indices for each matrix matches upstream mixed-height MMCS.
    pub(crate) fn open(
        &self,
        commitments: &Commitments,
        transforms: &Transforms,
        indices: &[usize],
        host_bytes: usize,
    ) -> Result<HiddenOpenings> {
        self.open_impl(commitments, transforms, indices, host_bytes, Fault::None)
    }

    fn open_impl(
        &self,
        commitments: &Commitments,
        transforms: &Transforms,
        indices: &[usize],
        host_bytes: usize,
        _fault: Fault,
    ) -> Result<HiddenOpenings> {
        commitments.check_runtime(&self.runtime)?;
        transforms.check_owner(&self.matrices[0].prefix)?;
        check_families(&self.families)?;
        let max_log = self.matrices.iter().map(|m| m.spec.log_rows).max().unwrap();
        if indices.is_empty()
            || indices.len() > MAX_QUERIES
            || indices.iter().any(|&i| i >= 1usize << max_log)
        {
            return Err("CUDA hidden query indices exceed admission".into());
        }
        let paths_words = indices.len() * self.tree.path_len() * 4;
        let output_bytes = self.matrices.iter().try_fold(paths_words * 8, |total, m| {
            total
                .checked_add(indices.len() * (m.spec.columns + 4) * 8)
                .ok_or("CUDA hidden query output overflow")
        })?;
        if output_bytes
            .checked_add(HOST_METADATA)
            .is_none_or(|n| n > host_bytes)
        {
            return Err("CUDA hidden queries exceed aggregate host allowance".into());
        }
        let state = self.runtime.snapshot();
        let limits = self.runtime.state.budget.limits;
        let remaining = limits
            .managed_bytes
            .checked_sub(state.live_bytes)
            .ok_or("CUDA hidden query budget exhausted")?;
        if state
            .allocations
            .checked_add(7)
            .is_none_or(|n| n > limits.max_allocations)
        {
            return Err("CUDA hidden queries exceed allocation count".into());
        }
        let allowance = |m: &RetainedInput| {
            host_bytes - (output_bytes - indices.len() * m.spec.columns * 8) - HOST_METADATA
        };
        for m in &self.matrices {
            QueryPlan::new(
                m.prefix.spec,
                m.spec.log_rows,
                indices.len(),
                remaining,
                limits.max_allocation_bytes,
                allowance(m),
            )?;
            m.salts.check_runtime(&self.runtime)?;
            m.salts
                .preflight(&[indices.len() * 8, indices.len() * 4 * 8])?;
        }
        if paths_words != 0 {
            plan::admit([paths_words, indices.len()], state, limits)?;
        }
        let mut matrices = Vec::new();
        matrices
            .try_reserve_exact(self.matrices.len())
            .map_err(super::super::error)?;
        let mut attempt = Attempt {
            families: &self.families,
            complete: false,
        };
        for m in &self.matrices {
            let reduced: Vec<_> = indices
                .iter()
                .map(|&i| i >> (max_log - m.spec.log_rows))
                .collect();
            let values = transforms
                .query_rows(&m.prefix, m.spec.log_rows, &reduced, allowance(m))?
                .values;
            #[cfg(test)]
            if matches!(_fault, Fault::AfterQuery) {
                return Err("injected hidden query failure".into());
            }
            let salt_indices: Vec<_> = reduced.iter().map(|&i| i as u64).collect();
            let salts = m.salts.query_rows(&salt_indices, indices.len() * 4 * 8)?;
            matrices.push(MatrixOpenings {
                spec: m.spec,
                random_columns: m.random_columns,
                values,
                salts,
            });
        }
        let indices: Vec<_> = indices.iter().map(|&i| i as u64).collect();
        let paths = commitments.open(&self.tree, &indices, paths_words * 8)?;
        check_families(&self.families)?;
        attempt.complete = true;
        Ok(HiddenOpenings {
            matrices,
            paths,
            queries: indices.len(),
            path_len: self.tree.path_len(),
        })
    }
}

#[cfg(test)]
mod tests;
