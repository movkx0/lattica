//! Shared legacy-container root geometry and bounded staging.
use super::{staging_words, Plan};
use crate::gpu_matrix::{Extension, MatrixSpec, RowOrder};
use crate::joinsplit_air as js;
pub(crate) struct TreePlan {
    pub(crate) layout: crate::batch_common::DeviceBatchGeometry<'static>,
    pub(crate) specs: [MatrixSpec; 3],
    pub(crate) peak: [MatrixSpec; 8],
}

impl TreePlan {
    pub(crate) fn new(statement_words: usize, host_allowance: usize) -> Result<Self, String> {
        let layout = crate::batch_joinsplit_air::device_batch_geometry();
        if statement_words == 0
            || !statement_words.is_multiple_of(js::N_PUBLIC)
            || statement_words / js::N_PUBLIC > crate::MAX_TREE_TX
            || layout.public_width != js::N_PUBLIC
            || layout.chunks.is_empty()
            || layout.chunks.iter().flatten().flatten().any(|&column| {
                column
                    .checked_sub(layout.wallet_width)
                    .is_none_or(|c| c >= js::N_PUBLIC)
            })
        {
            return Err("legacy tree statement geometry differs from the AIR".into());
        }
        let geometry_words = layout
            .chunks
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(3))
            .ok_or("legacy tree geometry overflow")?;
        let single = Plan::new(host_allowance)?;
        // Statements and geometry stay live during canonical dummy generation.
        // Root readback is later; reserve the larger of its output and staging.
        let staging = single.staging_bytes()?.max(4 * 8);
        if statement_words
            .checked_add(geometry_words)
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(staging))
            .is_none_or(|n| n > host_allowance)
        {
            return Err("legacy tree statement host allowance".into());
        }
        let specs = [
            MatrixSpec::new(0, statement_words, Extension::Base, RowOrder::Natural, 1)?,
            MatrixSpec::new(0, geometry_words, Extension::Base, RowOrder::Natural, 1)?,
            MatrixSpec::new(0, 4, Extension::Base, RowOrder::Natural, 1)?,
        ];
        let [a, b, c, d, e] = single.specs()?;
        Ok(Self {
            layout,
            specs,
            peak: [a, b, c, d, e, specs[0], specs[1], specs[2]],
        })
    }

    pub(crate) fn words(&self) -> Result<Vec<u64>, String> {
        let mut words = staging_words(self.specs[1].words())?;
        words.extend([
            self.layout.chunks.len() as u64,
            js::N_PUBLIC as u64,
            crate::domains::DOM_TXROOT,
        ]);
        words.extend(self.layout.chunks.iter().flatten().map(|column| {
            column.map_or(u64::MAX, |column| {
                (column - self.layout.wallet_width) as u64
            })
        }));
        debug_assert_eq!(words.len(), self.specs[1].words());
        Ok(words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tree_shape_and_staging_include_dummy_frame_through_maximum_count() {
        let layout = crate::batch_joinsplit_air::device_batch_geometry();
        let dummy = Plan::new(1 << 20).unwrap().staging_bytes().unwrap();
        for count in [1, 3, crate::MAX_TREE_TX] {
            let statements = count * js::N_PUBLIC;
            let host = (statements + 3 + 4 * layout.chunks.len()) * 8 + dummy;
            assert!(TreePlan::new(statements, host - 1).is_err());
            let plan = TreePlan::new(statements, host).unwrap();
            let words = plan.words().unwrap();
            assert_eq!(words.len(), plan.specs[1].words());
            assert_eq!(words.capacity(), words.len());
        }
        for words in [
            0,
            js::N_PUBLIC - 1,
            (crate::MAX_TREE_TX + 1) * js::N_PUBLIC,
            usize::MAX,
        ] {
            assert!(TreePlan::new(words, usize::MAX).is_err());
        }
    }
}
