//! Explicitly device-resident matrices; host transfers require caller bounds.
use super::{Buffer, Result, Runtime};
use crate::gpu_matrix::MatrixSpec;

#[derive(Clone)]
pub(crate) struct Matrix {
    pub(super) spec: MatrixSpec,
    pub(super) buffer: Buffer,
}

impl Matrix {
    pub(crate) fn spec(&self) -> MatrixSpec {
        self.spec
    }

    pub(crate) fn read(&self, host_bytes: usize) -> Result<Vec<u64>> {
        if self.spec.bytes() > host_bytes {
            return Err("CUDA matrix readback exceeds its host allowance".into());
        }
        let mut words = Vec::new();
        words
            .try_reserve_exact(self.spec.words())
            .map_err(super::error)?;
        words.resize(self.spec.words(), 0);
        self.buffer.read(0, &mut words)?;
        Ok(words)
    }
}

impl Runtime {
    pub(crate) fn upload_matrix(&self, spec: MatrixSpec, words: &[u64]) -> Result<Matrix> {
        if words.len() != spec.words() {
            return Err("CUDA matrix upload differs from its shape".into());
        }
        let buffer = self.allocate(spec.words())?;
        buffer.write(0, words)?;
        Ok(Matrix { spec, buffer })
    }
}
