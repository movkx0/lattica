//! Immutable, canonical shared-memory prefixes for the opt-in Metal pipeline.
use crate::config::Val;
use p3_matrix::dense::{DenseMatrix, DenseStorage, RowMajorMatrix};
use std::{borrow::Borrow, ops::Deref};

pub(crate) type PrefixMatrix = DenseMatrix<Val, PrefixStorage>;
pub(crate) enum PrefixStorage {
    Host(Vec<Val>),
    #[cfg(feature = "gpu-metal")]
    Metal(crate::metal_compute::resident::FrozenWords),
}
impl Deref for PrefixStorage {
    type Target = [Val];
    fn deref(&self) -> &[Val] {
        match self {
            Self::Host(values) => values,
            #[cfg(feature = "gpu-metal")]
            Self::Metal(values) => {
                let words = values.words();
                // Goldilocks 0.6.1 is repr(transparent) over u64, accepts every
                // word, and stores the unscaled representative. GPU stores are
                // canonical. FrozenWords has completed its writes and exposes
                // no mutable alias. Its owner retains the allocation.
                const {
                    assert!(std::mem::size_of::<Val>() == 8);
                }
                const {
                    assert!(std::mem::align_of::<Val>() == std::mem::align_of::<u64>());
                }
                unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), words.len()) }
            }
        }
    }
}
impl Borrow<[Val]> for PrefixStorage {
    fn borrow(&self) -> &[Val] {
        self
    }
}
impl DenseStorage<Val> for PrefixStorage {
    fn to_vec(self) -> Vec<Val> {
        self.deref().to_vec()
    }
}
impl PrefixStorage {
    pub fn truncate(&mut self, len: usize) -> Result<(), String> {
        if len > self.len() {
            return Err("prefix cannot grow".into());
        }
        match self {
            Self::Host(values) => {
                values.truncate(len);
                values.shrink_to_fit();
            }
            #[cfg(feature = "gpu-metal")]
            Self::Metal(values) => {
                *values = values.prefix(len)?;
            }
        }
        Ok(())
    }
}
pub(crate) fn host(matrix: RowMajorMatrix<Val>) -> PrefixMatrix {
    DenseMatrix::new(PrefixStorage::Host(matrix.values), matrix.width)
}
