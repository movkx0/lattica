//! Bounded band-major readback with a row-blocked final materialization.
//!
//! The GPU produces complete transforms in column bands. Scatter-writing every
//! band over a large spill-backed row-major matrix repeatedly dirties the same
//! pages. Append each band contiguously instead, then fill whole row blocks once.
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

pub(super) struct HostReadback {
    height: usize,
    width: usize,
    columns_per_band: usize,
    elements: usize,
    values: Vec<Val>,
    parallel_decode: bool,
    heap_output: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ReorderStats {
    pub elapsed_ns: u128,
    pub bytes: usize,
    pub workspace_bytes: usize,
}

impl HostReadback {
    pub fn new(height: usize, width: usize, columns_per_band: usize) -> Result<Self, String> {
        Self::new_with_storage(height, width, columns_per_band, false)
    }

    /// Match the CPU quotient profile's explicitly retained heap storage. Each
    /// matrix is bounded to 2 GiB; the commit plan charges every retained output
    /// and its reorder workspace, and the worker still enforces its RSS limit.
    pub fn new_quotient(
        height: usize,
        width: usize,
        columns_per_band: usize,
    ) -> Result<Self, String> {
        Self::new_with_storage(height, width, columns_per_band, true)
    }

    fn reserve(elements: usize, heap_output: bool) -> Result<Vec<Val>, String> {
        if heap_output {
            if elements
                .checked_mul(size_of::<Val>())
                .is_none_or(|n| n > (2 << 30))
            {
                return Err("quotient readback exceeds the 2 GiB per-matrix heap bound".into());
            }
            #[cfg(feature = "stream")]
            return crate::spill_alloc::heap_with_capacity(elements, 2 << 30)
                .ok_or_else(|| "bounded quotient heap reservation failed".into());
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(elements)
            .map_err(|e| format!("LDE readback reservation: {e}"))?;
        Ok(values)
    }

    fn new_with_storage(
        height: usize,
        width: usize,
        columns_per_band: usize,
        heap_output: bool,
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
        let values = Self::reserve(elements, heap_output)?;
        Ok(Self {
            height,
            width,
            columns_per_band: columns_per_band.min(width),
            elements,
            values,
            parallel_decode: false,
            heap_output,
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
            }) != Some(self.values.len())
            || self
                .values
                .len()
                .checked_add(raw.len())
                .is_none_or(|end| end > self.elements)
        {
            return Err("LDE readback rows are out of order or out of bounds".into());
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
        Ok(())
    }

    pub fn finish(self) -> Result<(RowMajorMatrix<Val>, ReorderStats), String> {
        if self.values.len() != self.elements {
            return Err("LDE readback is incomplete".into());
        }
        if self.columns_per_band == self.width {
            return Ok((
                RowMajorMatrix::new(self.values, self.width),
                ReorderStats::default(),
            ));
        }
        let started = Instant::now();
        let bytes = self.elements * size_of::<Val>();
        let mut output = Self::reserve(self.elements, self.heap_output)
            .map_err(|e| format!("LDE row-major reservation: {e}"))?;
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
                .env("LATTICA_SPILL_MAX_BYTES", "1")
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
            // 96 MiB exceeds the spill threshold. Exercise both a partial final
            // band and single-band ownership, under a one-byte mapping budget.
            let height = 1 << 22;
            let width = 3;
            for band in [2, 3] {
                let mut writer = HostReadback::new_quotient(height, width, band)
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
            assert!(ordinary.try_reserve_exact(height * width).is_err());
            assert!(HostReadback::new_quotient((2 << 30) / 8 + 1, 1, 1).is_err());
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
