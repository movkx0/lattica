use super::*;
use crate::{
    block_v2::{machine::compiler_constants::FoldOperation, profile},
    cuda_compute::Argument,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;

const MAX_PERIOD: usize = 1 << 16;
pub(super) const PERIOD_TILE: usize = 2048;
const MAX_SELECTORS: usize = 64;
const QUOTIENT_WORDS: usize = profile::MAX_QUOTIENT_CHUNKS * (profile::MAX_QUOTIENT_CHUNKS + 1);
const _: () = assert!(QUOTIENT_WORDS <= BATCH_WORDS && MAX_SELECTORS <= QUOTIENT_WORDS);
const _: () = assert!(2 * PERIOD_TILE <= SCRATCH_WORDS);
const _: () = assert!(8192 + 16 * PERIOD_TILE + 4096 <= HOST_BYTES);
const _: () = assert!(8192 + 8 * QUOTIENT_WORDS + 4096 <= HOST_BYTES);

fn copy_canonical(words: &[u64], output: &mut [Val]) -> Result<()> {
    if words.len() != output.len() || words.iter().any(|&v| v >= MODULUS) {
        return Err("CUDA public constants returned invalid fields".into());
    }
    for (dst, &src) in output.iter_mut().zip(words) {
        *dst = Val::new(src);
    }
    Ok(())
}

impl PublicArithmetic {
    pub(crate) fn compiler_inverse_generator(&self, log_height: usize, run: &Run) -> Result<Val> {
        let root = Val::TWO_ADIC_GENERATORS
            .get(log_height)
            .ok_or("CUDA compiler subgroup height")?;
        let mut output = [Val::ZERO];
        self.compiler_constants(root.as_canonical_u64(), 0, 1, 0, &mut output, run)?;
        Ok(output[0])
    }

    pub(crate) fn compiler_selectors_into(
        &self,
        first: u64,
        last: u64,
        output: &mut [Val],
        run: &Run,
    ) -> Result<()> {
        if first > last
            || last >= MODULUS
            || last - first >= MAX_SELECTORS as u64
            || output.len() != (last - first + 1) as usize
        {
            return Err("CUDA compiler selector admission".into());
        }
        self.compiler_constants(first, 1, 0, 0, output, run)
    }

    pub(crate) fn compiler_quotient_into(
        &self,
        chunks: usize,
        log_height: usize,
        output: &mut [Val],
        run: &Run,
    ) -> Result<()> {
        if !chunks.is_power_of_two()
            || chunks > profile::MAX_QUOTIENT_CHUNKS
            || log_height > 32
            || log_height + chunks.ilog2() as usize > 32
            || output.len() != chunks * (chunks + 1)
        {
            return Err("CUDA compiler quotient admission".into());
        }
        let root =
            Val::TWO_ADIC_GENERATORS[log_height + chunks.ilog2() as usize].as_canonical_u64();
        self.compiler_constants(root, 3, chunks, 1 << log_height, output, run)
    }

    fn compiler_constants(
        &self,
        input: u64,
        operation: u32,
        size: usize,
        exponent: u64,
        output: &mut [Val],
        run: &Run,
    ) -> Result<()> {
        self.check(run, Stage::Preprocessing)?;
        let count = output.len();
        if input >= MODULUS || count == 0 || count > QUOTIENT_WORDS {
            return Err("CUDA compiler constants exceed scratch admission".into());
        }
        self.admit(&[count])?;
        let result = self.runtime.allocate(count)?;
        // One output word per lane; operation-specific geometry is checked by
        // the callers. The sole public input is passed as a kernel argument.
        self.record(run, Stage::Preprocessing, unsafe {
            self.constants.launch(
                launch(count),
                &[
                    Argument::U64(input),
                    Argument::Buffer(&result),
                    Argument::U32(operation),
                    Argument::U32(count as u32),
                    Argument::U32(size as u32),
                    Argument::U64(exponent),
                ],
            )
        })?;
        let mut staging = [0; QUOTIENT_WORDS];
        result.read(0, &mut staging[..count])?;
        copy_canonical(&staging[..count], output)
    }

    pub(crate) fn compiler_periodic_into(
        &self,
        column: &[Val],
        log_height: usize,
        output: &mut [Val],
        run: &Run,
    ) -> Result<()> {
        self.check(run, Stage::Preprocessing)?;
        let n = column.len();
        if log_height > 32
            || !n.is_power_of_two()
            || n > MAX_PERIOD
            || n > 1usize << log_height
            || output.len() != n
        {
            return Err("CUDA compiler periodic admission".into());
        }
        let root = Val::TWO_ADIC_GENERATORS[n.ilog2() as usize].as_canonical_u64();
        let tile = n.min(PERIOD_TILE);
        self.admit(&[tile, tile])?;
        let input = self.runtime.allocate(tile)?;
        let coefficients = self.runtime.allocate(tile)?;
        let mut staging = [0; PERIOD_TILE];
        for coefficient_start in (0..n).step_by(tile) {
            let count = tile.min(n - coefficient_start);
            for input_start in (0..n).step_by(tile) {
                let input_count = tile.min(n - input_start);
                for (dst, src) in staging
                    .iter_mut()
                    .zip(&column[input_start..input_start + input_count])
                {
                    *dst = src.as_canonical_u64();
                }
                input.write(0, &staging[..input_count])?;
                // Distinct lanes own coefficient words. A completion separates
                // tiles before scratch reuse or upload of the next input tile.
                self.record(run, Stage::Preprocessing, unsafe {
                    self.periodic.launch(
                        launch(count),
                        &[
                            Argument::Buffer(&input),
                            Argument::Buffer(&coefficients),
                            Argument::U64(root),
                            Argument::U32(n as u32),
                            Argument::U32(input_start as u32),
                            Argument::U32(input_count as u32),
                            Argument::U32(coefficient_start as u32),
                            Argument::U32(count as u32),
                        ],
                    )
                })?;
            }
            coefficients.read(0, &mut staging[..count])?;
            copy_canonical(
                &staging[..count],
                &mut output[coefficient_start..coefficient_start + count],
            )?;
        }
        Ok(())
    }

    pub(crate) fn compiler_fold(
        &self,
        input: [u64; 6],
        operation: FoldOperation,
        run: &Run,
    ) -> Result<Option<[Val; 3]>> {
        self.check(run, Stage::Preprocessing)?;
        if input.iter().any(|&v| v >= MODULUS) {
            return Err("CUDA compiler fold requires canonical operands".into());
        }
        self.admit(&[6, 4])?;
        let operands = self.runtime.allocate(6)?;
        let result = self.runtime.allocate(4)?;
        operands.write(0, &input)?;
        // Exactly six input words and four outputs, owned by one thread.
        self.record(run, Stage::Preprocessing, unsafe {
            self.fold.launch(
                SINGLE,
                &[
                    Argument::Buffer(&operands),
                    Argument::Buffer(&result),
                    Argument::U32(operation as u32),
                ],
            )
        })?;
        let mut output = [0; 4];
        result.read(0, &mut output)?;
        let expected_status = match operation {
            FoldOperation::Inverse => u64::from(input[0] != 0),
            FoldOperation::CubicInverse => u64::from(input[..3].iter().any(|&v| v != 0)),
            _ => 1,
        };
        if output[..3].iter().any(|&v| v >= MODULUS)
            || output[3] != expected_status
            || (output[3] == 0 && output[..3] != [0; 3])
            || ((operation as u32) <= 2 && output[1..3] != [0; 2])
        {
            return Err("CUDA compiler fold returned invalid fields or status".into());
        }
        Ok((output[3] == 1).then(|| [output[0], output[1], output[2]].map(Val::new)))
    }
}
