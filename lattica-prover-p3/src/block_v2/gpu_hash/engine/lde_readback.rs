//! Bounded band-major readback with a row-blocked final materialization.
//!
//! The GPU produces complete transforms in column bands. Scatter-writing every
//! band over a large spill-backed row-major matrix repeatedly dirties the same
//! pages. Append each band contiguously instead, then fill whole row blocks once.
//! An explicit direct layout decodes into the final rows when avoiding the
//! second matrix matters more than contiguous staging. Both layouts reserve
//! their complete storage before accepting any GPU output.
//! This is host layout work only: no arithmetic, randomness, or transcript change.
//! Quotient outputs use explicitly bounded heap storage, matching the CPU
//! quotient profile; retaining these outputs must not consume the separate
//! mapping budget intended for the large main/preprocessing matrices.

use crate::config::Val;
use p3_matrix::dense::RowMajorMatrix;
use rayon::prelude::*;
use std::{mem::size_of, time::Instant};

// A task covers approximately this many destination bytes, or one complete row
// if a row is larger. No per-task allocation is made. All storage is charged by
// the commit plan's host-output plus largest reorder-workspace allowance.
const ROW_TASK_BYTES: usize = 4 * 1024 * 1024;
const DECODE_TASK_ELEMENTS: usize = ROW_TASK_BYTES / size_of::<Val>();

pub(super) const MAX_QUOTIENT_OUTPUT_BYTES: usize = 2 << 30;

#[derive(Clone, Copy, Debug, Default)]
pub(super) enum OutputStorage {
    #[default]
    Global,
    /// Matches the CPU fused quotient's per-matrix bounded heap retention.
    QuotientHeap,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum ReadbackLayout {
    #[default]
    Banded,
    /// Decode each column band into its final rows without a second matrix.
    Direct,
}

impl ReadbackLayout {
    pub(super) fn from_env() -> Result<Self, String> {
        Ok(if super::switch("LATTICA_V2_GPU_DIRECT_READBACK")? {
            Self::Direct
        } else {
            Self::Banded
        })
    }
}

fn allocation_context() -> String {
    #[cfg(feature = "stream")]
    {
        crate::spill_alloc::allocation_diagnostics()
    }
    #[cfg(not(feature = "stream"))]
    {
        "spill_allocator=false".to_owned()
    }
}

fn reserve(elements: usize, storage: OutputStorage, label: &str) -> Result<Vec<Val>, String> {
    let bytes = elements
        .checked_mul(size_of::<Val>())
        .ok_or("LDE allocation overflow")?;
    let fail = |reason: String| {
        format!(
        "{label}: {reason}; requested_bytes={bytes} storage={storage:?} heap_matrix_limit_bytes={MAX_QUOTIENT_OUTPUT_BYTES} {}",
        allocation_context(),
    )
    };
    if matches!(storage, OutputStorage::QuotientHeap) {
        if bytes > MAX_QUOTIENT_OUTPUT_BYTES {
            return Err(fail("quotient heap matrix allowance exceeded".into()));
        }
        #[cfg(feature = "stream")]
        return crate::spill_alloc::reserve_heap(elements, MAX_QUOTIENT_OUTPUT_BYTES)
            .ok_or_else(|| fail("explicit heap reservation failed".into()));
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(elements)
        .map_err(|e| fail(e.to_string()))?;
    Ok(values)
}

pub(super) struct HostReadback {
    height: usize,
    width: usize,
    columns_per_band: usize,
    elements: usize,
    values: Vec<Val>,
    initialized_elements: usize,
    layout: ReadbackLayout,
    parallel_decode: bool,
    output_storage: OutputStorage,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ReorderStats {
    pub elapsed_ns: u128,
    pub bytes: usize,
    pub workspace_bytes: usize,
}

impl HostReadback {
    #[cfg(test)]
    pub fn new(height: usize, width: usize, columns_per_band: usize) -> Result<Self, String> {
        Self::with_storage(height, width, columns_per_band, OutputStorage::Global)
    }

    #[cfg(test)]
    pub fn with_storage(
        height: usize,
        width: usize,
        columns_per_band: usize,
        output_storage: OutputStorage,
    ) -> Result<Self, String> {
        Self::with_layout(
            height,
            width,
            columns_per_band,
            output_storage,
            ReadbackLayout::Banded,
        )
    }

    pub fn with_layout(
        height: usize,
        width: usize,
        columns_per_band: usize,
        output_storage: OutputStorage,
        layout: ReadbackLayout,
    ) -> Result<Self, String> {
        if height == 0 || width == 0 || columns_per_band == 0 {
            return Err("LDE readback dimensions must be nonzero".into());
        }
        let elements = height
            .checked_mul(width)
            .ok_or("LDE readback size overflow")?;
        let bytes = elements
            .checked_mul(size_of::<Val>())
            .ok_or("LDE readback byte overflow")?;
        if bytes > isize::MAX as usize {
            return Err("LDE readback exceeds allocation range".into());
        }
        if matches!(output_storage, OutputStorage::QuotientHeap) {
            if bytes > MAX_QUOTIENT_OUTPUT_BYTES {
                return Err("quotient heap matrix allowance exceeded".into());
            }
            eprintln!(
                "bounded_quotient_readback_admission requested_bytes={bytes} heap_matrix_limit_bytes={MAX_QUOTIENT_OUTPUT_BYTES} columns_per_band={columns_per_band} {}",
                allocation_context(),
            );
        }
        // Banded staging stays in spill storage. Only the final, retained
        // quotient output uses explicit heap storage; a single band is final.
        let initial_storage = if layout == ReadbackLayout::Direct || columns_per_band >= width {
            output_storage
        } else {
            OutputStorage::Global
        };
        let values = reserve(elements, initial_storage, "LDE readback reservation")?;
        Ok(Self {
            height,
            width,
            columns_per_band: columns_per_band.min(width),
            elements,
            values,
            initialized_elements: 0,
            layout,
            parallel_decode: false,
            output_storage,
        })
    }

    pub fn with_parallel_decode(mut self, enabled: bool) -> Self {
        self.parallel_decode = enabled;
        self
    }

    pub fn uses_parallel_decode(&self, elements: usize) -> bool {
        self.parallel_decode && elements >= DECODE_TASK_ELEMENTS
    }

    pub fn height(&self) -> usize {
        self.height
    }

    /// Accept only the next complete rows of the next planned column band.
    /// Validation precedes writes, so gaps, replays and partial rows cannot
    /// expose an incompletely initialized matrix to the PCS.
    pub fn append_rows(
        &mut self,
        first: usize,
        columns: usize,
        row0: usize,
        raw: &[u64],
    ) -> Result<(), String> {
        if first >= self.width
            || first % self.columns_per_band != 0
            || columns != self.columns_per_band.min(self.width - first)
            || raw.is_empty()
            || raw.len() % columns != 0
        {
            return Err("LDE readback band/row shape".into());
        }
        let rows = raw.len() / columns;
        if row0.checked_add(rows).is_none_or(|end| end > self.height)
            || first.checked_mul(self.height).and_then(|base| {
                row0.checked_mul(columns)
                    .and_then(|offset| base.checked_add(offset))
            }) != Some(self.initialized_elements)
            || self
                .initialized_elements
                .checked_add(raw.len())
                .is_none_or(|end| end > self.elements)
        {
            return Err("LDE readback rows are out of order or out of bounds".into());
        }
        if self.layout == ReadbackLayout::Direct {
            let parallel = self.uses_parallel_decode(raw.len());
            let width = self.width;
            let rows_per_task = (DECODE_TASK_ELEMENTS / width).max(1);
            let destination =
                &mut self.values.spare_capacity_mut()[row0 * width..(row0 + rows) * width];
            let decode = |destination: &mut [std::mem::MaybeUninit<Val>], source: &[u64]| {
                for (row, words) in destination
                    .chunks_exact_mut(width)
                    .zip(source.chunks_exact(columns))
                {
                    for (slot, &word) in row[first..first + columns].iter_mut().zip(words) {
                        slot.write(Val::new(word));
                    }
                }
            };
            if parallel {
                destination
                    .par_chunks_mut(rows_per_task * width)
                    .zip(raw.par_chunks(rows_per_task * columns))
                    .for_each(|(destination, source)| decode(destination, source));
            } else {
                decode(destination, raw);
            }
            // Keep Vec's length zero while row-major holes remain. Admission and
            // the ordered-band checks ensure every cell is initialized exactly
            // once before finish publishes the complete matrix.
            self.initialized_elements += raw.len();
            return Ok(());
        }
        // The full allocation was reserved at admission. extend initializes only
        // this contiguous prefix, avoiding an initial full-matrix zero write.
        if self.uses_parallel_decode(raw.len()) {
            let initialized = self.values.len();
            self.values.spare_capacity_mut()[..raw.len()]
                .par_chunks_mut(DECODE_TASK_ELEMENTS)
                .zip(raw.par_chunks(DECODE_TASK_ELEMENTS))
                .for_each(|(destination, source)| {
                    for (slot, &word) in destination.iter_mut().zip(source) {
                        slot.write(Val::new(word));
                    }
                });
            // SAFETY: Admission reserved the complete output and the bounds above
            // checked this append. Disjoint tasks initialize every new element;
            // Rayon joins before publishing the length. On unwind the original
            // length is retained, and Val has no destructor.
            unsafe { self.values.set_len(initialized + raw.len()) };
        } else {
            self.values.extend(raw.iter().map(|&word| Val::new(word)));
        }
        self.initialized_elements += raw.len();
        Ok(())
    }

    pub fn finish(mut self) -> Result<(RowMajorMatrix<Val>, ReorderStats), String> {
        if self.initialized_elements != self.elements {
            return Err("LDE readback is incomplete".into());
        }
        if self.layout == ReadbackLayout::Direct {
            // SAFETY: append_rows validates consecutive complete rows in every
            // planned band before writing. All bands now cover every row and
            // column exactly once, and parallel writers have joined. An early
            // return or panic leaves length zero; no uninitialized Val is read.
            unsafe { self.values.set_len(self.elements) };
            return Ok((
                RowMajorMatrix::new(self.values, self.width),
                ReorderStats::default(),
            ));
        }
        if self.columns_per_band == self.width {
            return Ok((
                RowMajorMatrix::new(self.values, self.width),
                ReorderStats::default(),
            ));
        }
        let started = Instant::now();
        let bytes = self.elements * size_of::<Val>();
        let mut output = reserve(
            self.elements,
            self.output_storage,
            "LDE row-major reservation",
        )?;
        let rows_per_task = (ROW_TASK_BYTES / size_of::<Val>() / self.width).max(1);
        let task_elements = rows_per_task * self.width;
        output.spare_capacity_mut()[..self.elements]
            .par_chunks_mut(task_elements)
            .enumerate()
            .for_each(|(task, destination)| {
                let row0 = task * rows_per_task;
                let rows = destination.len() / self.width;
                assert_eq!(destination.len() % self.width, 0);
                for first in (0..self.width).step_by(self.columns_per_band) {
                    let columns = self.columns_per_band.min(self.width - first);
                    let start = first * self.height + row0 * columns;
                    let source = &self.values[start..start + rows * columns];
                    for (dst, src) in destination
                        .chunks_exact_mut(self.width)
                        .zip(source.chunks_exact(columns))
                    {
                        for (slot, &value) in dst[first..first + columns].iter_mut().zip(src) {
                            slot.write(value);
                        }
                    }
                }
            });
        // SAFETY: the disjoint tasks contain whole rows and cover exactly
        // `elements` slots. Each row's bands partition 0..width, and every slot
        // is written from an initialized source value before this point. If a
        // task panics, output still has length zero; Val is Copy and no partial
        // initialization is read or dropped as a live element. Capacity/layout
        // are unchanged, including when the global spill allocator is armed.
        unsafe { output.set_len(self.elements) };
        Ok((
            RowMajorMatrix::new(output, self.width),
            ReorderStats {
                elapsed_ns: started.elapsed().as_nanos(),
                bytes,
                workspace_bytes: bytes,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeField64;

    #[test]
    fn direct_layout_matches_banded_without_reorder_storage() {
        for height in [1, 7, 64] {
            for width in [1, 3, 7, 35] {
                for band in [1, 3, 8, 64] {
                    for storage in [OutputStorage::Global, OutputStorage::QuotientHeap] {
                        let mut writer = HostReadback::with_layout(
                            height,
                            width,
                            band,
                            storage,
                            ReadbackLayout::Direct,
                        )
                        .unwrap();
                        let pointer = writer.values.as_ptr();
                        for first in (0..width).step_by(band) {
                            let columns = band.min(width - first);
                            for row0 in (0..height).step_by(3) {
                                let rows = 3.min(height - row0);
                                let raw: Vec<_> = (row0..row0 + rows)
                                    .flat_map(|row| {
                                        (first..first + columns).map(move |col| word(row, col))
                                    })
                                    .collect();
                                writer.append_rows(first, columns, row0, &raw).unwrap();
                                assert_eq!(writer.values.len(), 0);
                            }
                        }
                        let (output, stats) = writer.finish().unwrap();
                        assert_eq!(output.values.as_ptr(), pointer);
                        assert_eq!(stats.workspace_bytes, 0);
                        assert_eq!(
                            output.values,
                            filled(height, width, band, 3).finish().unwrap().0.values
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn direct_layout_rejects_holes_and_replayed_rows() {
        let mut writer =
            HostReadback::with_layout(3, 5, 2, OutputStorage::Global, ReadbackLayout::Direct)
                .unwrap();
        assert!(writer.append_rows(0, 2, 1, &[1, 2]).is_err());
        assert!(writer.append_rows(2, 2, 0, &[1, 2]).is_err());
        assert!(writer.append_rows(0, 2, usize::MAX, &[1, 2]).is_err());
        assert!(writer.append_rows(0, 2, 0, &[1]).is_err());
        assert_eq!(writer.initialized_elements, 0);
        writer.append_rows(0, 2, 0, &[1, 2]).unwrap();
        assert!(writer.append_rows(0, 2, 0, &[1, 2]).is_err());
        assert_eq!(writer.initialized_elements, 2);
        assert_eq!(writer.values.len(), 0);
        assert!(writer.finish().is_err());
    }

    #[test]
    fn direct_parallel_decode_preserves_partial_bands_and_field_edges() {
        let height = DECODE_TASK_ELEMENTS / 3 + 5;
        let width = 7;
        let edges = [0, 1, Val::ORDER_U64 - 1, Val::ORDER_U64, u64::MAX];
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let mut writer = HostReadback::with_layout(
            height,
            width,
            3,
            OutputStorage::Global,
            ReadbackLayout::Direct,
        )
        .unwrap()
        .with_parallel_decode(true);
        for first in (0..width).step_by(3) {
            let columns = 3.min(width - first);
            let raw: Vec<_> = (0..height)
                .flat_map(|row| {
                    (first..first + columns)
                        .map(move |col| edges[(row * width + col) % edges.len()])
                })
                .collect();
            pool.install(|| writer.append_rows(first, columns, 0, &raw))
                .unwrap();
        }
        let (output, stats) = writer.finish().unwrap();
        assert_eq!(stats.workspace_bytes, 0);
        for (i, value) in output.values.iter().enumerate() {
            assert_eq!(*value, Val::new(edges[i % edges.len()]));
        }
    }

    #[cfg(feature = "stream")]
    #[test]
    fn direct_layout_finishes_with_only_one_matrix_spill_reservation() {
        const FLAG: &str = "LATTICA_DIRECT_READBACK_PRESSURE_TEST";
        const NAME: &str = "block_v2::gpu_hash::engine::lde_readback::tests::direct_layout_finishes_with_only_one_matrix_spill_reservation";
        // 70 MiB exceeds the allocator's 64 MiB spill threshold.
        const HEIGHT: usize = 1 << 18;
        const WIDTH: usize = 35;
        const BYTES: usize = HEIGHT * WIDTH * 8;
        if std::env::var_os(FLAG).is_none() {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--test-threads=1"])
                .env(FLAG, "1")
                .env("LATTICA_SPILL_MAX_BYTES", (BYTES + 4096).to_string())
                .status()
                .unwrap()
                .success());
            return;
        }
        let _scope = crate::spill_alloc::SpillScope::arm();
        for layout in [ReadbackLayout::Direct, ReadbackLayout::Banded] {
            let mut writer =
                HostReadback::with_layout(HEIGHT, WIDTH, 16, OutputStorage::Global, layout)
                    .unwrap();
            for first in (0..WIDTH).step_by(16) {
                let columns = 16.min(WIDTH - first);
                for row0 in (0..HEIGHT).step_by(128) {
                    let raw: Vec<_> = (row0..row0 + 128)
                        .flat_map(|row| (first..first + columns).map(move |col| word(row, col)))
                        .collect();
                    writer.append_rows(first, columns, row0, &raw).unwrap();
                }
            }
            assert_eq!(
                crate::spill_alloc::spill_stats(),
                (1, (BYTES + 4096) as u64)
            );
            match layout {
                ReadbackLayout::Direct => {
                    let (output, stats) = writer.finish().unwrap();
                    assert_eq!(stats.workspace_bytes, 0);
                    for (i, value) in output.values.iter().enumerate() {
                        assert_eq!(*value, Val::new(word(i / WIDTH, i % WIDTH)));
                    }
                }
                ReadbackLayout::Banded => assert!(writer.finish().is_err()),
            }
            assert_eq!(crate::spill_alloc::spill_stats(), (0, 0));
        }
    }

    #[test]
    fn explicit_heap_output_matches_global_for_partial_bands() {
        for (height, width, band) in [(7, 5, 3), (8, 7, 4), (8, 7, 8)] {
            let reference = filled(height, width, band, 3).finish().unwrap().0;
            let mut heap =
                HostReadback::with_storage(height, width, band, OutputStorage::QuotientHeap)
                    .unwrap();
            for first in (0..width).step_by(band) {
                let columns = band.min(width - first);
                let raw: Vec<_> = (0..height)
                    .flat_map(|row| (first..first + columns).map(move |col| word(row, col)))
                    .collect();
                heap.append_rows(first, columns, 0, &raw).unwrap();
            }
            assert_eq!(heap.finish().unwrap().0.values, reference.values);
        }
        assert!(HostReadback::with_storage(1 << 26, 5, 4, OutputStorage::QuotientHeap).is_err());
    }

    /// Reproduce the production 2^23 x 7 output under the 34 GiB reservation
    /// ceiling. The pressure buffer reserves virtual spill space without
    /// touching its payload; actual test RSS stays below 2 GiB.
    #[cfg(feature = "stream")]
    #[test]
    fn full_size_quotient_readback_under_spill_pressure() {
        const FLAG: &str = "LATTICA_QUOTIENT_READBACK_PRESSURE_TEST";
        const NAME: &str = "block_v2::gpu_hash::engine::lde_readback::tests::full_size_quotient_readback_under_spill_pressure";
        const HEIGHT: usize = 1 << 23;
        const WIDTH: usize = 7;
        const BYTES: usize = HEIGHT * WIDTH * size_of::<Val>();
        const LIMIT: usize = 34 << 30;
        if std::env::var_os(FLAG).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--test-threads=1", "--nocapture"])
                .env(FLAG, "1")
                .env("LATTICA_SPILL_MAX_BYTES", LIMIT.to_string())
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let _armed = crate::spill_alloc::SpillScope::arm();
        let mut pressure = Vec::<u8>::new();
        pressure
            .try_reserve_exact(LIMIT - BYTES - 2 * 4096)
            .unwrap();
        let pressure_bytes = crate::spill_alloc::spill_stats().1;
        for storage in [OutputStorage::Global, OutputStorage::QuotientHeap] {
            let mut writer = HostReadback::with_storage(HEIGHT, WIDTH, 4, storage)
                .unwrap()
                .with_parallel_decode(true);
            assert_eq!(crate::spill_alloc::spill_stats().1, LIMIT as u64);
            for first in [0, 4] {
                let columns = (WIDTH - first).min(4);
                let rows = 1 << 17;
                let raw: Vec<_> = (0..rows * columns)
                    .map(|i| (first + i % columns) as u64)
                    .collect();
                for row in (0..HEIGHT).step_by(rows) {
                    writer.append_rows(first, columns, row, &raw).unwrap();
                }
            }
            let result = writer.finish();
            if matches!(storage, OutputStorage::Global) {
                let error = result.unwrap_err();
                assert!(error.contains("LDE row-major reservation"));
                assert!(error.contains("requested_bytes=469762048"));
                assert!(error.contains("spill_budget_rejections=1"));
            } else {
                let (output, _) = result.unwrap();
                assert_eq!(crate::spill_alloc::spill_stats().1, pressure_bytes);
                assert_eq!(output.values.len(), HEIGHT * WIDTH);
                assert!(output
                    .values
                    .iter()
                    .enumerate()
                    .all(|(i, v)| v.as_canonical_u64() == (i % WIDTH) as u64));
                assert!(crate::spill_alloc::is_armed());
            }
            assert_eq!(crate::spill_alloc::spill_stats().1, pressure_bytes);
        }
        drop(pressure);
        assert_eq!(crate::spill_alloc::spill_stats(), (0, 0));
    }

    fn word(row: usize, col: usize) -> u64 {
        (row as u64)
            .wrapping_mul(0x9e3779b97f4a7c15)
            .rotate_left(19)
            ^ col as u64
    }

    fn filled(height: usize, width: usize, band: usize, row_chunk: usize) -> HostReadback {
        let mut output = HostReadback::new(height, width, band).unwrap();
        for first in (0..width).step_by(band) {
            let columns = band.min(width - first);
            for row0 in (0..height).step_by(row_chunk) {
                let rows = row_chunk.min(height - row0);
                let raw: Vec<_> = (row0..row0 + rows)
                    .flat_map(|row| (first..first + columns).map(move |col| word(row, col)))
                    .collect();
                output.append_rows(first, columns, row0, &raw).unwrap();
            }
        }
        output
    }

    #[test]
    fn banded_readback_matches_every_row_and_partial_band() {
        for height in [1, 2, 7, 64, 1024] {
            for width in [1, 3, 7, 16, 35] {
                for band in [1, 3, 8, 32, 64] {
                    for row_chunk in [1, 3, 128] {
                        let (output, stats) =
                            filled(height, width, band, row_chunk).finish().unwrap();
                        assert_eq!(output.width, width);
                        assert_eq!(output.values.len(), height * width);
                        for (index, value) in output.values.iter().enumerate() {
                            assert_eq!(
                                value.as_canonical_u64(),
                                Val::new(word(index / width, index % width)).as_canonical_u64()
                            );
                        }
                        assert_eq!(
                            stats.workspace_bytes,
                            if band < width { height * width * 8 } else { 0 }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn single_band_is_moved_without_reallocation() {
        let writer = filled(7, 3, 8, 2);
        let address = writer.values.as_ptr();
        let (output, stats) = writer.finish().unwrap();
        assert_eq!(output.values.as_ptr(), address);
        assert_eq!(stats.bytes, 0);
        assert_eq!(stats.workspace_bytes, 0);
    }

    #[cfg(feature = "stream")]
    #[test]
    fn quotient_readback_retains_bounded_heap_without_spill_fallback() {
        const FLAG: &str = "LATTICA_QUOTIENT_HEAP_READBACK_TEST";
        if std::env::var_os(FLAG).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "block_v2::gpu_hash::engine::lde_readback::tests::quotient_readback_retains_bounded_heap_without_spill_fallback",
                    "--test-threads=1",
                ])
                .env(FLAG, "1")
                .env("LATTICA_SPILL_BACKING", "memory")
                .env("LATTICA_SPILL_MAX_BYTES", ((96 << 20) + 4096).to_string())
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        pool.install(|| {
            let _scope = crate::spill_alloc::SpillScope::arm();
            // 96 MiB exceeds the spill threshold. The mapping budget admits
            // one staging matrix, but not an additional mapped output.
            let height = 1 << 22;
            let width = 3;
            for band in [2, 3] {
                let mut writer =
                    HostReadback::with_storage(height, width, band, OutputStorage::QuotientHeap)
                        .unwrap()
                        .with_parallel_decode(true);
                for first in (0..width).step_by(band) {
                    let columns = band.min(width - first);
                    for row0 in (0..height).step_by(4096) {
                        let rows = 4096.min(height - row0);
                        let raw: Vec<_> = (row0..row0 + rows)
                            .flat_map(|row| (first..first + columns).map(move |col| word(row, col)))
                            .collect();
                        writer.append_rows(first, columns, row0, &raw).unwrap();
                    }
                }
                let (matrix, _) = writer.finish().unwrap();
                assert_eq!(matrix.values.len(), height * width);
                for (index, value) in matrix.values.iter().enumerate() {
                    assert_eq!(*value, Val::new(word(index / width, index % width)));
                }
                assert_eq!(crate::spill_alloc::spill_stats(), (0, 0));
                drop(matrix);
            }
            let mut ordinary = Vec::<Val>::new();
            assert!(ordinary.try_reserve_exact(height * width + 1024).is_err());
            assert!(HostReadback::with_storage(
                (2 << 30) / 8 + 1,
                1,
                1,
                OutputStorage::QuotientHeap
            )
            .is_err());
            assert_eq!(crate::spill_alloc::spill_stats(), (0, 0));
        });
    }

    #[test]
    fn parallel_decode_matches_reference_at_chunk_and_field_boundaries() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let edges = [0, 1, Val::ORDER_U64 - 1, Val::ORDER_U64, u64::MAX];
        for elements in [
            DECODE_TASK_ELEMENTS - 1,
            DECODE_TASK_ELEMENTS,
            DECODE_TASK_ELEMENTS + 1,
            2 * DECODE_TASK_ELEMENTS + 7,
        ] {
            let raw: Vec<_> = (0..elements).map(|i| edges[i % edges.len()]).collect();
            let mut reference = HostReadback::new(elements, 1, 1).unwrap();
            let mut candidate = HostReadback::new(elements, 1, 1)
                .unwrap()
                .with_parallel_decode(true);
            let pointer = candidate.values.as_ptr();
            let capacity = candidate.values.capacity();
            reference.append_rows(0, 1, 0, &raw).unwrap();
            pool.install(|| candidate.append_rows(0, 1, 0, &raw))
                .unwrap();
            assert_eq!(candidate.values.as_ptr(), pointer);
            assert_eq!(candidate.values.capacity(), capacity);
            assert_eq!(candidate.values, reference.values);
            assert_eq!(
                candidate.finish().unwrap().0.values,
                reference.finish().unwrap().0.values
            );
        }
    }

    #[test]
    fn parallel_decode_preserves_partial_bands_and_rejects_out_of_order_rows() {
        let height = DECODE_TASK_ELEMENTS / 3 + 5;
        let mut reference = HostReadback::new(height, 5, 3).unwrap();
        let mut candidate = HostReadback::new(height, 5, 3)
            .unwrap()
            .with_parallel_decode(true);
        for (first, columns) in [(0, 3), (3, 2)] {
            let raw: Vec<_> = (0..height)
                .flat_map(|row| (first..first + columns).map(move |col| word(row, col)))
                .collect();
            let initialized = candidate.values.len();
            assert!(candidate.append_rows(first, columns, 1, &raw).is_err());
            assert_eq!(candidate.values.len(), initialized);
            reference.append_rows(first, columns, 0, &raw).unwrap();
            candidate.append_rows(first, columns, 0, &raw).unwrap();
        }
        assert_eq!(
            candidate.finish().unwrap().0.values,
            reference.finish().unwrap().0.values
        );
    }

    #[test]
    fn banded_readback_rejects_bad_shape_order_and_incomplete_output() {
        for dimensions in [
            (0, 1, 1),
            (1, 0, 1),
            (1, 1, 0),
            (usize::MAX, 2, 1),
            (1, usize::MAX / 8 + 1, 1),
        ] {
            assert!(HostReadback::new(dimensions.0, dimensions.1, dimensions.2).is_err());
        }
        let mut writer = HostReadback::new(3, 5, 2).unwrap();
        for (first, columns, row0, raw) in [
            (1, 2, 0, vec![0, 1]),
            (0, 1, 0, vec![0]),
            (0, 2, 1, vec![0, 1]),
            (0, 2, 0, vec![0]),
            (0, 2, 0, vec![]),
            (0, 2, usize::MAX, vec![0, 1]),
            (0, 2, 0, vec![0; 8]),
            (5, 0, 0, vec![]),
        ] {
            assert!(writer.append_rows(first, columns, row0, &raw).is_err());
            assert!(writer.values.is_empty());
        }
        writer.append_rows(0, 2, 0, &[0, 1]).unwrap();
        assert!(writer.append_rows(0, 2, 0, &[0, 1]).is_err());
        assert_eq!(writer.values.len(), 2);
        assert!(writer.finish().is_err());
        let mut complete = filled(2, 3, 2, 1);
        assert!(complete.append_rows(2, 1, 1, &[0]).is_err());
        assert!(complete.finish().is_ok());
    }

    #[test]
    fn row_block_boundary_and_goldilocks_edges_are_exact() {
        let height = ROW_TASK_BYTES / (35 * 8) + 3;
        let (output, _) = filled(height, 35, 8, 317).finish().unwrap();
        for (index, value) in output.values.iter().enumerate() {
            assert_eq!(
                value.as_canonical_u64(),
                Val::new(word(index / 35, index % 35)).as_canonical_u64()
            );
        }
        let raw = [0, 1, Val::ORDER_U64 - 1, Val::ORDER_U64, u64::MAX];
        let mut writer = HostReadback::new(1, 5, 2).unwrap();
        writer.append_rows(0, 2, 0, &raw[..2]).unwrap();
        writer.append_rows(2, 2, 0, &raw[2..4]).unwrap();
        writer.append_rows(4, 1, 0, &raw[4..]).unwrap();
        assert_eq!(writer.finish().unwrap().0.values, raw.map(Val::new));
    }

    /// Run each layout in a fresh process: the allocator configuration and peak
    /// counters are process-global. This is a host-layout diagnostic, not a GPU
    /// or recursive-proving benchmark. The matrix alone exceeds the required
    /// 3 GiB service RAM limit; banded materialization has two live mappings.
    #[cfg(feature = "stream")]
    #[test]
    #[ignore = "requires an isolated <=3 GiB service, private spill directory, <=8 GiB spill budget, and LATTICA_V2_TEST_READBACK_LAYOUT=scatter|banded"]
    fn spill_backed_multi_band_readback_is_exact_under_pressure() {
        use crate::spill_alloc::{reset_spill_peak, spill_peak_bytes, spill_stats, SpillScope};

        let layout = std::env::var("LATTICA_V2_TEST_READBACK_LAYOUT")
            .expect("select scatter or banded in a fresh bounded test process");
        assert!(matches!(layout.as_str(), "scatter" | "banded"));
        let scratch =
            std::env::var("LATTICA_SPILL_DIR").expect("a private spill directory is required");
        assert!(std::path::Path::new(&scratch).is_absolute());
        assert!(std::path::Path::new(&scratch).is_dir());
        let budget: u64 = std::env::var("LATTICA_SPILL_MAX_BYTES")
            .expect("an explicit spill ceiling is required")
            .parse()
            .expect("spill ceiling must be an integer");

        let height = (1usize << 21) + 3;
        let width = 204;
        let band = 64;
        let row_chunk = 16_381;
        let elements = height * width;
        let bytes = elements * size_of::<Val>();
        assert!(bytes > 3usize << 30);
        assert!(budget >= 2 * bytes as u64 + 8192 && budget <= 8u64 << 30);
        assert_eq!(spill_stats(), (0, 0), "test must run alone");
        reset_spill_peak();
        let scope = SpillScope::arm();
        let started = Instant::now();
        let reserve_started = Instant::now();
        // Match the previous row-major readback's zeroed destination. Keep
        // allocation/initialization time visible instead of hiding it outside
        // the diagnostic. Only the selected layout allocates an output here.
        let mut scattered = (layout == "scatter").then(|| {
            let mut values = Vec::new();
            values.try_reserve_exact(elements).unwrap();
            values.resize(elements, Val::new(0));
            values
        });
        let mut banded =
            (layout == "banded").then(|| HostReadback::new(height, width, band).unwrap());
        let reserve_ns = reserve_started.elapsed().as_nanos();
        assert_eq!(
            spill_stats().0,
            1,
            "destination must really be spill-backed"
        );
        assert!(spill_stats().1 >= bytes as u64);

        // A small, reused staging buffer represents GPU readback chunks. Its
        // deterministic population is excluded from decode/layout time, but
        // included in test wall time. Both layouts receive identical words.
        let mut raw = vec![0u64; row_chunk * band];
        let mut decode_ns = 0u128;
        for first in (0..width).step_by(band) {
            let columns = band.min(width - first);
            for row0 in (0..height).step_by(row_chunk) {
                let rows = row_chunk.min(height - row0);
                let chunk = &mut raw[..rows * columns];
                for (row, values) in chunk.chunks_exact_mut(columns).enumerate() {
                    for (col, value) in values.iter_mut().enumerate() {
                        *value = word(row0 + row, first + col);
                    }
                }
                let decode_started = Instant::now();
                if let Some(output) = scattered.as_mut() {
                    // Preserve the previous production readback's Rayon row
                    // scatter and allocation policy, not a sequential stand-in.
                    output[row0 * width..(row0 + rows) * width]
                        .par_chunks_mut(width)
                        .zip(chunk.par_chunks(columns))
                        .for_each(|(destination, source)| {
                            for (slot, &value) in
                                destination[first..first + columns].iter_mut().zip(source)
                            {
                                *slot = Val::new(value);
                            }
                        });
                } else {
                    banded
                        .as_mut()
                        .unwrap()
                        .append_rows(first, columns, row0, chunk)
                        .unwrap();
                }
                decode_ns += decode_started.elapsed().as_nanos();
            }
        }
        let finish_started = Instant::now();
        let (output, reorder) = if let Some(writer) = banded {
            writer.finish().unwrap()
        } else {
            (
                RowMajorMatrix::new(scattered.take().unwrap(), width),
                ReorderStats::default(),
            )
        };
        // Include source unmapping/destruction in finish wall time. The reorder
        // counter is a subset of this span and must not be added a second time.
        let finish_ns = finish_started.elapsed().as_nanos();
        let layout_ns = reserve_ns + decode_ns + finish_ns;
        assert_eq!(output.width, width);
        assert_eq!(output.values.len(), elements);
        assert_eq!(spill_stats().0, 1);
        let peak = spill_peak_bytes();
        assert!(peak >= bytes as u64 * if layout == "banded" { 2 } else { 1 });
        assert!(peak <= budget);
        assert_eq!(
            reorder.workspace_bytes,
            if layout == "banded" { bytes } else { 0 }
        );

        let verify_started = Instant::now();
        for (row, values) in output.values.chunks_exact(width).enumerate() {
            for (col, value) in values.iter().enumerate() {
                assert_eq!(
                    value.as_canonical_u64(),
                    Val::new(word(row, col)).as_canonical_u64(),
                    "{layout} field at row={row} column={col}",
                );
            }
        }
        let verify_ns = verify_started.elapsed().as_nanos();
        drop(output);
        drop(raw);
        assert_eq!(
            spill_stats(),
            (0, 0),
            "all mapped output storage must be released"
        );
        drop(scope);
        eprintln!(
            "readback_pressure layout={layout} height={height} width={width} band={band} row_chunk={row_chunk} values_checked={elements} output_bytes={bytes} reserve_ns={reserve_ns} decode_ns={decode_ns} finish_ns={finish_ns} reorder_subset_ns={} layout_ns={layout_ns} verify_ns={verify_ns} test_wall_ns={} peak_mapped_spill_bytes={peak} complete=true",
            reorder.elapsed_ns, started.elapsed().as_nanos(),
        );
    }
}

/// Common bounded readback sink; public shared mappings never expose a Vec.
pub(crate) trait ColumnReadback {
    fn height(&self) -> usize;
    fn uses_parallel_decode(&self, elements: usize) -> bool;
    fn append_rows(&mut self, first: usize, columns: usize, row0: usize, raw: &[u64]) -> Result<(), String>;
}
impl ColumnReadback for HostReadback {
    fn height(&self) -> usize { self.height() }
    fn uses_parallel_decode(&self, elements: usize) -> bool { self.uses_parallel_decode(elements) }
    fn append_rows(&mut self, first: usize, columns: usize, row0: usize, raw: &[u64]) -> Result<(), String> {
        self.append_rows(first, columns, row0, raw)
    }
}
