//! Exact device-resident Poseidon2 commitments. The caller supplies salts as
//! per-attempt matrix fragments; no randomness or field arithmetic runs here.
mod replay;
use super::{Argument, Buffer, Kernel, Launch, Limits, Matrix, Result, Runtime};
use crate::gpu_matrix::{Extension, MatrixSpec};
use std::sync::Arc;

pub(super) const SOURCE: &str = concat!(
    include_str!("field.cuh"),
    include_str!("poseidon2.cuh"),
    include_str!("commitment.cu")
);
const CONSTANT_WORDS: usize = 32 + 22 + 32 + 8;
const MAX_FRAGMENTS: usize = 256;
const MAX_QUERIES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    height: usize,
    words: usize,
    cap_first: usize,
    cap_words: usize,
    path_len: usize,
}

impl Layout {
    fn new(log_rows: u32, cap_height: usize) -> Result<Self> {
        if log_rows > 31 {
            return Err("unsupported CUDA commitment height".into());
        }
        let height = 1usize << log_rows;
        let cap_rows = 1usize << cap_height.min(log_rows as usize);
        let words = height
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| n.checked_mul(4))
            .filter(|n| n.checked_mul(8).is_some())
            .ok_or("CUDA retained tree size overflow")?;
        Ok(Self {
            height,
            words,
            cap_first: (height - cap_rows) * 8,
            cap_words: cap_rows * 4,
            path_len: log_rows as usize - cap_rows.ilog2() as usize,
        })
    }
}

fn admit(words: &[usize], live: usize, limits: Limits) -> Result<()> {
    let mut peak = live;
    for &n in words {
        let bytes = n.checked_mul(8).ok_or("CUDA commitment size overflow")?;
        if n == 0 || bytes > limits.max_allocation_bytes {
            return Err("CUDA commitment exceeds per-allocation limit".into());
        }
        peak = peak
            .checked_add(bytes)
            .ok_or("CUDA commitment peak overflow")?;
        if peak > limits.managed_bytes {
            return Err("CUDA commitment exceeds managed memory budget".into());
        }
    }
    Ok(())
}

fn launch(items: usize) -> Result<Launch> {
    if items == 0 {
        return Err("empty CUDA commitment launch".into());
    }
    Ok(Launch {
        blocks: items
            .div_ceil(128)
            .try_into()
            .map_err(|_| "CUDA commitment grid overflow")?,
        threads: 128,
        shared_bytes: 0,
    })
}

fn host_words(words: usize, allowance: usize) -> Result<Vec<u64>> {
    if words.checked_mul(8).filter(|n| *n <= allowance).is_none() {
        return Err("CUDA commitment readback exceeds host allowance".into());
    }
    let mut result = Vec::new();
    result.try_reserve_exact(words).map_err(super::error)?;
    result.resize(words, 0);
    Ok(result)
}

/// Immutable authentication nodes. The buffer retains its runtime and private
/// allocation lease until the final clone drops, including after program drop.
#[derive(Clone)]
pub(crate) struct RetainedTree {
    storage: Buffer,
    layout: Layout,
}

impl RetainedTree {
    pub(crate) fn cap(&self, host_bytes: usize) -> Result<Vec<u64>> {
        let mut words = host_words(self.layout.cap_words, host_bytes)?;
        self.storage.read(self.layout.cap_first, &mut words)?;
        Ok(words)
    }

    pub(crate) fn path_len(&self) -> usize {
        self.layout.path_len
    }
}

pub(crate) struct Commitments {
    runtime: Runtime,
    constants: Buffer,
    permutation: Kernel,
    absorb: Kernel,
    finalize: Kernel,
    compress: Kernel,
    paths: Kernel,
}

pub(super) fn poseidon_constants(runtime: &Runtime) -> Result<Buffer> {
    let (initial, internal, final_rounds, diagonal) = crate::gpu_constants::poseidon2_consts();
    let constants = runtime.allocate(CONSTANT_WORDS)?;
    let mut first = 0;
    for words in [&initial, &internal, &final_rounds, &diagonal] {
        constants.write(first, words)?;
        first += words.len();
    }
    Ok(constants)
}

impl Commitments {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(SOURCE)?;
        let constants = poseidon_constants(runtime)?;
        Ok(Self {
            runtime: runtime.clone(),
            constants,
            permutation: module.kernel("poseidon_permutation")?,
            absorb: module.kernel("commitment_absorb")?,
            finalize: module.kernel("commitment_finalize")?,
            compress: module.kernel("commitment_compress")?,
            paths: module.kernel("commitment_paths")?,
        })
    }

    fn check_owner(&self, buffer: &Buffer) -> Result<()> {
        if !Arc::ptr_eq(&self.runtime.state, buffer.owner()) {
            return Err("CUDA commitment input belongs to another runtime".into());
        }
        Ok(())
    }

    pub(crate) fn permute(&self, input: &Matrix) -> Result<Matrix> {
        self.check_owner(&input.buffer)?;
        if input.spec.extension != Extension::Base
            || input.spec.columns != 8
            || input.spec.log_rows > 31
        {
            return Err("CUDA Poseidon2 requires eight base-field columns".into());
        }
        let output = Matrix {
            spec: input.spec,
            buffer: self.runtime.allocate(input.spec.words())?,
        };
        // Distinct matrices with exactly eight words per row, and 94 constants.
        unsafe {
            self.permutation.launch(
                launch(input.spec.rows())?,
                &[
                    Argument::Buffer(&input.buffer),
                    Argument::Buffer(&output.buffer),
                    Argument::U32(input.spec.rows() as u32),
                    Argument::Buffer(&self.constants),
                ],
            )?
        }
        .finish()?;
        Ok(output)
    }

    /// Commit concatenated row fragments without downloading the leaves or
    /// intermediate nodes. Fragments share a domain and physical row order.
    /// This primitive also serves unsalted FRI commitments; hiding callers must
    /// use commit_salted or explicitly append fresh salts as their final fragment.
    pub(crate) fn commit(&self, fragments: &[&Matrix], cap_height: usize) -> Result<RetainedTree> {
        if fragments.is_empty() || fragments.len() > MAX_FRAGMENTS {
            return Err("invalid CUDA commitment fragment count".into());
        }
        let spec = fragments[0].spec;
        let layout = Layout::new(spec.log_rows, cap_height)?;
        for fragment in fragments {
            self.check_owner(&fragment.buffer)?;
            if fragment.spec.log_rows != spec.log_rows
                || fragment.spec.order != spec.order
                || fragment.spec.shift != spec.shift
                || fragment.spec.words() / spec.rows() > u32::MAX as usize
            {
                return Err("CUDA commitment fragments have incompatible domains or widths".into());
            }
        }
        let state_words = layout
            .height
            .checked_mul(8)
            .ok_or("CUDA sponge size overflow")?;
        admit(
            &[layout.words, state_words],
            self.runtime.snapshot().live_bytes,
            self.runtime.state.budget.limits,
        )?;
        // Allocate all scratch before launching. Runtime allocation zeroes states.
        let tree = self.runtime.allocate(layout.words)?;
        let states = self.runtime.allocate(state_words)?;
        let mut pending = 0;
        for fragment in fragments {
            let width = fragment.spec.words() / layout.height;
            // All rows have width words and eight distinct state words. The
            // state never aliases a fragment. Only one thread mutates each row.
            unsafe {
                self.absorb.launch(
                    launch(layout.height)?,
                    &[
                        Argument::Buffer(&fragment.buffer),
                        Argument::Buffer(&states),
                        Argument::U32(layout.height as u32),
                        Argument::U32(width as u32),
                        Argument::U32(pending),
                        Argument::Buffer(&self.constants),
                    ],
                )?
            }
            .finish()?;
            pending = (pending + (width % 4) as u32) % 4;
        }
        // Four leaf words per row fit in the first layer of the tree allocation.
        unsafe {
            self.finalize.launch(
                launch(layout.height)?,
                &[
                    Argument::Buffer(&states),
                    Argument::Buffer(&tree),
                    Argument::U32(layout.height as u32),
                    Argument::U32(pending),
                    Argument::Buffer(&self.constants),
                ],
            )?
        }
        .finish()?;
        drop(states);
        let mut rows = layout.height;
        let mut first = 0;
        while rows > 1 {
            let next = first + rows * 4;
            rows /= 2;
            // Parent region starts immediately after its child layer and fits
            // in the pre-admitted (2*height-1)*4 words. Regions do not overlap.
            unsafe {
                self.compress.launch(
                    launch(rows)?,
                    &[
                        Argument::Buffer(&tree),
                        Argument::U64(first as u64),
                        Argument::U64(next as u64),
                        Argument::U32(rows as u32),
                        Argument::Buffer(&self.constants),
                    ],
                )?
            }
            .finish()?;
            first = next;
        }
        Ok(RetainedTree {
            storage: tree,
            layout,
        })
    }

    pub(crate) fn commit_salted(
        &self,
        input: &Matrix,
        salts: &Matrix,
        cap_height: usize,
    ) -> Result<RetainedTree> {
        let spec = input.spec;
        if salts.spec != MatrixSpec::new(spec.log_rows, 4, Extension::Base, spec.order, spec.shift)?
        {
            return Err("CUDA commitment requires four salt columns on the input domain".into());
        }
        self.commit(&[input, salts], cap_height)
    }

    /// Query-major sibling digests from the leaf level up to (excluding) the
    /// cap. Indices are physical rows; their order and duplicates are preserved.
    /// Only public indices upload and requested path words download.
    pub(crate) fn open(
        &self,
        tree: &RetainedTree,
        indices: &[u64],
        host_bytes: usize,
    ) -> Result<Vec<u64>> {
        self.check_owner(&tree.storage)?;
        if indices.len() > MAX_QUERIES || indices.iter().any(|&i| i >= tree.layout.height as u64) {
            return Err("CUDA commitment query exceeds bounds".into());
        }
        let items = indices.len() * tree.layout.path_len;
        if items == 0 {
            return Ok(Vec::new());
        }
        let words = items * 4; // bounded by MAX_QUERIES * 31 * 4
        if words * 8 > host_bytes {
            return Err("CUDA commitment paths exceed host allowance".into());
        }
        admit(
            &[words, indices.len()],
            self.runtime.snapshot().live_bytes,
            self.runtime.state.budget.limits,
        )?;
        let mut output = host_words(words, host_bytes)?;
        let queries = self.runtime.allocate(indices.len())?;
        let gathered = self.runtime.allocate(words)?;
        queries.write(0, indices)?;
        // Validated indices and layout make every sibling address fall inside
        // the retained tree. Output has exactly one digest per query and level.
        unsafe {
            self.paths.launch(
                launch(items)?,
                &[
                    Argument::Buffer(&tree.storage),
                    Argument::Buffer(&queries),
                    Argument::Buffer(&gathered),
                    Argument::U32(tree.layout.height as u32),
                    Argument::U32(tree.layout.path_len as u32),
                    Argument::U32(indices.len() as u32),
                ],
            )?
        }
        .finish()?;
        gathered.read(0, &mut output)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
