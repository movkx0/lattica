//! Explicit prefixes of bit-reversed LDEs. Geometry describes the original
//! commitment; prefixes are never returned by the MMCS full-matrix accessor.
use super::prefix_storage::PrefixMatrix;
use super::*;
use p3_matrix::dense::RowMajorMatrixView;
use std::collections::{BTreeMap, BTreeSet};

pub struct CompactData {
    pub(super) prefixes: Vec<PrefixMatrix>,
    pub(super) height: usize,
    salts: Vec<RowMajorMatrix<Val>>,
    tree: engine::RetainedTree,
    queries: Mutex<BTreeMap<usize, Vec<Vec<Val>>>>,
}
impl CompactData {
    pub(super) fn new(
        prefixes: Vec<PrefixMatrix>,
        height: usize,
        salts: Vec<RowMajorMatrix<Val>>,
        tree: engine::RetainedTree,
    ) -> Self {
        assert!(height.is_power_of_two());
        assert_eq!(prefixes.len(), salts.len());
        for (p, s) in prefixes.iter().zip(&salts) {
            assert!(
                p.height().is_power_of_two()
                    && p.height() >= height >> super::super::profile::LOG_BLOWUP
            );
            assert!(p.height() <= height);
            assert_eq!(s.height(), height);
        }
        Self {
            prefixes,
            height,
            salts,
            tree,
            queries: Mutex::new(BTreeMap::new()),
        }
    }
    pub(super) fn open(&self, index: usize, cap: usize) -> BatchOpening<Val, CandidateMmcs> {
        assert!(index < self.height);
        let values = self
            .queries
            .lock()
            .expect("query cache poisoned")
            .get(&index)
            .expect("compact MMCS query was not prepared")
            .clone();
        let salts = self
            .salts
            .iter()
            .map(|s| s.values[index * 4..index * 4 + 4].to_vec())
            .collect();
        let path = self
            .tree
            .open(index, cap)
            .expect("compact retained tree opening failed");
        BatchOpening::new(values, (salts, path))
    }
}
impl CandidateMmcs {
    pub(crate) fn preflight_retained(
        &self,
        shapes: &[LdeInputShape],
        host: usize,
        bits: usize,
    ) -> Result<LdeCommitPlan, String> {
        if !self.gpu {
            return Err("compact data requires GPU MMCS".into());
        }
        engine::plan_retained_lde_commit(shapes, self.cap_height, host, bits)
    }
    pub(crate) fn prefix_matrices<'a>(
        &self,
        data: &'a ProverData<RowMajorMatrix<Val>>,
    ) -> Vec<(RowMajorMatrixView<'a, Val>, usize)> {
        match data {
            ProverData::Compact(d) => d.prefixes.iter().map(|p| (p.as_view(), d.height)).collect(),
            _ => self
                .get_matrices(data)
                .into_iter()
                .map(|m| (m.as_view(), m.height()))
                .collect(),
        }
    }
    /// Called after all quotient views have expired, before quotient commitment.
    /// Preprocessing data is shared between proofs and deliberately stays larger.
    pub(crate) fn release_quotient_prefix(data: &mut ProverData<RowMajorMatrix<Val>>) {
        if let ProverData::Compact(d) = data {
            for p in &mut d.prefixes {
                p.values
                    .truncate((d.height >> super::super::profile::LOG_BLOWUP) * p.width)
                    .expect("compact shared prefix retirement");
            }
        }
    }
    pub(crate) fn prepare_queries(
        &self,
        data: &ProverData<RowMajorMatrix<Val>>,
        indices: &[usize],
    ) -> Result<(), String> {
        if let ProverData::Compact(d) = data {
            let indices: Vec<_> = indices
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            if indices.iter().any(|i| *i >= d.height) {
                return Err("compact query outside commitment".into());
            }
            let rows = engine::query_reconstruct::reconstruct(&d.prefixes, d.height, &indices)?;
            *d.queries.lock().map_err(|_| "query cache poisoned")? =
                indices.into_iter().zip(rows).collect();
        }
        Ok(())
    }
}
