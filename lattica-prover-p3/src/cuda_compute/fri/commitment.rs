use super::*;
use crate::cuda_compute::{Commitments, DeviceRandom, ReplaySalts, RetainedTree};

#[derive(Clone, Copy)]
enum Fault {
    None,
    #[cfg(test)]
    AfterGather,
    #[cfg(test)]
    PanicAfterGather,
}

pub(crate) struct FriLayer {
    leaves: Matrix,
    tree: RetainedTree,
    salts: ReplaySalts,
    random: DeviceRandom,
}
pub(crate) struct FriLayerOpenings {
    pub values: Vec<u64>,
    pub salts: Vec<u64>,
    pub paths: Vec<u64>,
    pub width: usize,
    pub queries: usize,
    pub path_len: usize,
}

impl Fri {
    pub(crate) fn commit_layer(
        &self,
        commitments: &Commitments,
        input: &FriVector,
        log_arity: usize,
        random: &DeviceRandom,
        cap_height: usize,
    ) -> Result<FriLayer> {
        let leaves = self.leaves(input, log_arity)?;
        random.check_runtime(&self.runtime)?;
        let tree = commitments.stream_plan(&self.runtime, &[leaves.spec], cap_height)?;
        let salt_spec = MatrixSpec::new(
            leaves.spec.log_rows,
            4,
            Extension::Base,
            RowOrder::BitReversed,
            1,
        )?;
        let pending: Vec<_> = tree.words.into_iter().map(|n| n * 8).collect();
        random.preflight_salt_recipes(&[salt_spec], &pending)?;
        random.with_attempt(|| {
            let salts = random.prepare_salt_replay(salt_spec, 1)?.pop().unwrap();
            let tree = commitments.commit_replayed(&leaves, &salts, cap_height)?;
            Ok(FriLayer {
                leaves,
                tree,
                salts,
                random: random.clone(),
            })
        })
    }
}

impl FriLayer {
    pub(crate) fn cap(&self, host_bytes: usize) -> Result<Vec<u64>> {
        if self.tree.cap_bytes() > host_bytes {
            return Err("CUDA FRI cap exceeds host allowance".into());
        }
        self.random.with_attempt(|| self.tree.cap(host_bytes))
    }

    /// Final query egress. All stage storage and aggregate host output are
    /// checked before any private work; intermediate layers and salts stay on CUDA.
    pub(crate) fn open(
        &self,
        fri: &Fri,
        commitments: &Commitments,
        indices: &[usize],
        host_bytes: usize,
    ) -> Result<FriLayerOpenings> {
        self.open_impl(fri, commitments, indices, host_bytes, Fault::None)
    }

    fn open_impl(
        &self,
        fri: &Fri,
        commitments: &Commitments,
        indices: &[usize],
        host_bytes: usize,
        _fault: Fault,
    ) -> Result<FriLayerOpenings> {
        fri.owner(&self.leaves)?;
        commitments.check_runtime(&fri.runtime)?;
        self.random.check_runtime(&fri.runtime)?;
        self.salts.check_runtime(&fri.runtime)?;
        if indices.is_empty()
            || indices.len() > 4096
            || indices.iter().any(|&i| i >= self.leaves.spec.rows())
        {
            return Err("CUDA FRI layer query indices exceed admission".into());
        }
        let width = self.leaves.spec.columns * self.leaves.spec.extension.degree();
        let paths_words = indices.len() * self.tree.path_len() * 4;
        let values_words = indices.len() * width;
        let output_bytes = (values_words + indices.len() * 4 + paths_words) * 8;
        let staging = indices.len() * 8 + (64 << 10);
        if output_bytes
            .checked_add(staging)
            .is_none_or(|n| n > host_bytes)
        {
            return Err("CUDA FRI layer queries exceed aggregate host allowance".into());
        }
        let state = fri.runtime.snapshot();
        let limits = fri.runtime.state.budget.limits;
        shape::GatherShape::new(self.leaves.spec, indices.len(), values_words * 8)?.plan(
            state.live_bytes,
            limits.managed_bytes,
            limits.max_allocation_bytes,
        )?;
        self.salts
            .preflight(&[indices.len() * 8, indices.len() * 4 * 8])?;
        fri.allocations(2)?;
        if paths_words != 0 {
            for bytes in [paths_words * 8, indices.len() * 8] {
                if bytes > limits.max_allocation_bytes {
                    return Err("CUDA FRI path allocation exceeds allowance".into());
                }
            }
            if state
                .live_bytes
                .checked_add((paths_words + indices.len()) * 8)
                .is_none_or(|n| n > limits.managed_bytes)
            {
                return Err("CUDA FRI paths exceed managed allowance".into());
            }
        }
        self.random.with_attempt(|| {
            let values = fri.gather(&self.leaves, indices, (values_words + indices.len()) * 8)?;
            #[cfg(test)]
            match _fault {
                Fault::AfterGather => return Err("injected CUDA FRI query failure".into()),
                Fault::PanicAfterGather => panic!("injected CUDA FRI query unwind"),
                Fault::None => (),
            }
            let queries: Vec<_> = indices.iter().map(|&i| i as u64).collect();
            let salts = self.salts.query_rows(&queries, indices.len() * 4 * 8)?;
            let paths = commitments.open(&self.tree, &queries, paths_words * 8)?;
            Ok(FriLayerOpenings {
                values,
                salts,
                paths,
                width,
                queries: indices.len(),
                path_len: self.tree.path_len(),
            })
        })
    }
}

#[cfg(test)]
mod tests;
