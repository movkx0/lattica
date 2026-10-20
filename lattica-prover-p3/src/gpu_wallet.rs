//! Shared raw wallet input encoding and AIR-owned device geometry.
//! These helpers pack witness words; all witness arithmetic remains on the selected device.
use crate::gpu_matrix::{Extension, MatrixSpec, RowOrder};
use crate::joinsplit_air as js;
use p3_field::PrimeField64;

pub(crate) mod htlc;
pub(crate) mod htlc_kernels;
pub(crate) mod joinsplit_kernels;
#[cfg(any(feature = "gpu", feature = "gpu-cuda"))]
pub(crate) mod batch;
pub(crate) mod batch_kernels;
#[cfg(any(feature = "gpu", feature = "gpu-cuda"))]
pub(crate) mod tree;

pub(crate) const INPUT_WORDS: usize = js::N_IN * (9 + js::DEPTH * 5) + js::M_OUT * 10 + 6;
pub(crate) const GEOMETRY_WORDS: usize = 28;
pub(crate) struct InputWords(pub(crate) Vec<u64>);
// Call only after the complete staging shape is admitted. Check the returned
// capacity before encoding private inputs or extending public geometry.
pub(crate) fn staging_words(count: usize) -> Result<Vec<u64>, String> {
    let mut words = Vec::new();
    words
        .try_reserve_exact(count)
        .map_err(|_| "wallet staging reservation failed")?;
    if words.capacity() != count {
        return Err("wallet staging reservation exceeds admitted capacity".into());
    }
    Ok(words)
}
impl Drop for InputWords {
    fn drop(&mut self) {
        for word in &mut self.0 {
            // SAFETY: each pointer is a uniquely borrowed initialized word. Use
            // volatile stores so private staging is not left by a dead-store pass.
            unsafe { std::ptr::write_volatile(word, 0) };
        }
    }
}
pub(crate) fn input_words(w: &js::Witness) -> Result<InputWords, String> {
    let mut words = InputWords(staging_words(INPUT_WORDS)?);
    for v in &w.inputs {
        words.0.extend(v.nk);
        words.0.extend([
            v.div.as_canonical_u64(),
            v.asset.as_canonical_u64(),
            v.value,
        ]);
        words.0.extend(v.rho.map(|x| x.as_canonical_u64()));
        words.0.extend(v.rcm.map(|x| x.as_canonical_u64()));
        for (sibling, bit) in v.sib.iter().zip(v.bits) {
            words.0.extend(sibling.map(|x| x.as_canonical_u64()));
            words.0.push(u64::from(bit));
        }
    }
    for v in &w.outputs {
        words.0.extend(v.recipient.map(|x| x.as_canonical_u64()));
        words.0.extend([v.asset.as_canonical_u64(), v.value]);
        words.0.extend(v.rho.map(|x| x.as_canonical_u64()));
        words.0.extend(v.rcm.map(|x| x.as_canonical_u64()));
    }
    words.0.extend([w.fee, w.mint]);
    words.0.extend(w.tx_binding.map(|x| x.as_canonical_u64()));
    debug_assert_eq!(words.0.len(), INPUT_WORDS);
    Ok(words)
}

#[derive(Clone, Copy)]
pub(crate) struct Plan {
    pub(crate) trace: MatrixSpec,
    pub(crate) public: MatrixSpec,
    pub(crate) regions: usize,
    pub(crate) input_words: usize,
    pub(crate) geometry_words: usize,
}
impl Plan {
    pub(crate) fn new(host_allowance: usize) -> Result<Self, String> {
        if host_allowance < (INPUT_WORDS + GEOMETRY_WORDS + 1) * 8 {
            return Err("wallet input staging exceeds host allowance".into());
        }
        let g = js::device_trace_geometry();
        // Kernel loop structure is the existing audited Poseidon2 row schedule.
        // Reject changed geometry rather than silently writing a different AIR.
        if !js::HEIGHT.is_power_of_two()
            || g[6] != 32
            || g[4] > 32
            || g[5] >= 64
            || g[7] != 4 + g[4]
            || g[8] != 2
            || g[9] != 2
            || g[10] != 2
            || g[11] != g[2] * g[7] + g[3] * g[8] + g[9] + g[10]
            || g[12] * 32 != g[0]
            || g[11] > g[12]
            || g[13..24].iter().any(|&col| col < 8 || col >= g[1])
            || g[27] != 4 + 4 * g[2] + 4 * g[3] + 6
        {
            return Err("unsupported wallet trace geometry".into());
        }
        let trace = MatrixSpec::new(
            js::HEIGHT.ilog2(),
            js::WIDTH,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        let public = MatrixSpec::new(0, js::N_PUBLIC, Extension::Base, RowOrder::Natural, 1)?;
        let regions = usize::try_from(g[2] + g[3] + 2 + g[12] - g[11])
            .map_err(|_| "wallet region count overflow")?;
        Ok(Self {
            trace,
            public,
            regions,
            input_words: INPUT_WORDS,
            geometry_words: GEOMETRY_WORDS,
        })
    }
    pub(crate) fn staging_bytes(&self) -> Result<usize, String> {
        self.input_words
            .checked_add(self.geometry_words)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(8))
            .ok_or_else(|| "wallet host staging overflow".into())
    }
    pub(crate) fn specs(&self) -> Result<[MatrixSpec; 5], String> {
        Ok([
            self.trace,
            self.public,
            MatrixSpec::new(0, self.input_words, Extension::Base, RowOrder::Natural, 1)?,
            MatrixSpec::new(
                0,
                self.geometry_words,
                Extension::Base,
                RowOrder::Natural,
                1,
            )?,
            MatrixSpec::new(0, 1, Extension::Base, RowOrder::Natural, 1)?,
        ])
    }
}
