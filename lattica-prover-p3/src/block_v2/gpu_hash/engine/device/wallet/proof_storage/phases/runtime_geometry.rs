//! Scalar inputs to the unchanged wallet phase planner. A fresh model derives
//! retained constant/staging storage itself; callers cannot supply a smaller
//! baseline. A model is neither device evidence nor a dispatch capability.
use super::{engine, sum, Engine, Limits};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeGeometry {
    pub(super) limits: Limits,
    pub(super) max_allocation: usize,
    pub(super) transfer_slots: usize,
    pub(super) lde_cache_limit: usize,
    pub(super) needs_query_buffer: bool,
    pub(super) baseline: usize,
    pub(super) initial_hash: usize,
    pub(super) initial_lde: usize,
}

impl RuntimeGeometry {
    pub(super) fn capture(engine: &Engine, live: usize) -> Result<Self, String> {
        let initial_hash = engine.workspace.as_ref().map_or(0, engine::Workspace::bytes);
        let initial_lde = engine.lde_workspace.as_ref().map_or(0, |w| w.bytes());
        let baseline = live
            .checked_sub(sum(&[initial_hash, initial_lde])?)
            .ok_or("wallet cached workspace exceeds live bytes")?;
        Ok(Self {
            limits: engine.limits,
            max_allocation: engine.max_alloc,
            transfer_slots: engine.mode.slots(),
            lde_cache_limit: engine.lde_workspace_limit,
            needs_query_buffer: engine.query.is_none(),
            baseline,
            initial_hash,
            initial_lde,
        })
    }

    /// Allocation-free successful path, with no environment/device/context
    /// access. Hardware capacity and selected limits must later be matched to
    /// the real, exclusively owned engine before this model can support work.
    /// This constructor intentionally models an empty transform/hash cache.
    pub(crate) fn fresh(
        limits: Limits,
        max_allocation: usize,
        transfer_slots: usize,
        lde_cache_limit: usize,
    ) -> Result<Self, String> {
        limits.validate()?;
        if !cfg!(feature = "gpu")
            || limits.managed_bytes > engine::MAX_MANAGED_BYTES
            || !matches!(transfer_slots, 1 | 2)
            || limits.staging_bytes % (transfer_slots * 8) != 0
            || limits.staging_bytes / transfer_slots > max_allocation
            || lde_cache_limit > limits.managed_bytes / 4
        {
            return Err("fresh wallet runtime geometry exceeds supported bounds".into());
        }
        engine::plan_slots(1, 1, limits, max_allocation, transfer_slots)?;
        use p3_goldilocks::{
            GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
            GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
            GOLDILOCKS_POSEIDON2_RC_8_INTERNAL, MATRIX_DIAG_8_GOLDILOCKS,
        };
        let constant_words = [
            GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL.len() * 8,
            GOLDILOCKS_POSEIDON2_RC_8_INTERNAL.len(),
            GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL.len() * 8,
            MATRIX_DIAG_8_GOLDILOCKS.len(),
        ];
        let mut baseline = limits.staging_bytes;
        for words in constant_words {
            let bytes = words.checked_mul(8).ok_or("wallet constant storage overflow")?;
            if bytes > max_allocation {
                return Err("wallet constant exceeds device allocation limit".into());
            }
            baseline = sum(&[baseline, bytes])?;
        }
        if baseline > limits.managed_bytes {
            return Err("fresh wallet runtime baseline exceeds managed limit".into());
        }
        Ok(Self {
            limits,
            max_allocation,
            transfer_slots,
            lde_cache_limit,
            needs_query_buffer: true,
            baseline,
            initial_hash: 0,
            initial_lde: 0,
        })
    }

    /// Numerical/storage equality only, not a lease or selector identity. The
    /// enclosing producer must independently bind the exclusive engine lifetime
    /// and complete execution selection before it can issue a dispatch token.
    pub(crate) fn check_engine(&self, engine: &Engine, live: usize) -> Result<(), String> {
        if *self != Self::capture(engine, live)? {
            return Err("wallet runtime differs from its pre-context phase model".into());
        }
        Ok(())
    }

    pub(crate) fn managed_baseline_bytes(self) -> usize {
        self.baseline
    }
}
