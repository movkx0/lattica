//! Complete output and scan storage plus bounded expression tiles.
use super::LookupProgram;
use crate::gpu_matrix::{Extension, MatrixSpec};

#[derive(Clone, Copy)]
pub(crate) enum InputStorage {
    Uploaded,
    Resident,
}

pub(crate) struct Plan {
    pub(crate) rows: usize,
    pub(crate) parameters: [usize; 3],
    pub(crate) tile: [usize; 4],
    pub(crate) scan_rows: Vec<usize>,
    pub(crate) peak: usize,
}

impl Plan {
    pub(crate) fn new(
        program: &LookupProgram,
        output: MatrixSpec,
        live: usize,
        managed_bytes: usize,
        tile_bytes: usize,
        inputs: InputStorage,
        max_alloc: usize,
    ) -> Result<Self, String> {
        let degree = output.extension.degree();
        if !matches!(output.extension, Extension::Quadratic | Extension::Cubic) {
            return Err("lookup output requires a quadratic or cubic extension".into());
        }
        let height = output.rows();
        let parameters = match inputs {
            InputStorage::Uploaded => [
                program.layout.num_public_values.max(1),
                program.lookup_count() * 2 * degree,
                1,
            ],
            InputStorage::Resident => [0, 0, 1],
        };
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
        let free = managed_bytes
            .checked_sub(peak)
            .ok_or("lookup exceeds aggregate GPU budget")?;
        let capacity = (free.min(tile_bytes).min(max_alloc).min(64 << 20) / per_row)
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
