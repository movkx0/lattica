//! Prepared batch AIRs bind their kind and padded height. Only public setup is
//! retained; every proof constructs fresh private frames and randomness.
use super::*;
use crate::{batch_common::BatchKind, gpu_wallet::batch::BatchPlan};

pub(crate) struct BatchProver {
    engine: Arc<WalletProver>,
    kind: BatchKind,
    tiles: usize,
    prepared: PreparedStark<Challenge>,
}

impl WalletProver {
    pub(crate) fn prepare_batch(
        self: &Arc<Self>,
        kind: BatchKind,
        count: usize,
        host_bytes: usize,
    ) -> Result<BatchProver> {
        let (layout, single) = match kind {
            BatchKind::JoinSplit => (
                crate::batch_joinsplit_air::device_batch_geometry(),
                crate::gpu_wallet::Plan::new(host_bytes)?,
            ),
            BatchKind::Htlc => (
                crate::batch_htlc_air::device_batch_geometry(),
                crate::gpu_wallet::htlc::plan(host_bytes)?,
            ),
        };
        let plan = BatchPlan::new(layout, count, single, host_bytes)?;
        self.wallets.admit_memory(&plan.peak)?;
        let prepared = match kind {
            BatchKind::JoinSplit => self.starks.prepare(
                &crate::batch_joinsplit_air::JoinSplitBatchAir,
                plan.trace.rows().ilog2(),
                host_bytes,
                Specialization::Prefer,
            )?,
            BatchKind::Htlc => self.starks.prepare(
                &crate::batch_htlc_air::HtlcBatchAir,
                plan.trace.rows().ilog2(),
                host_bytes,
                Specialization::Prefer,
            )?,
        };
        // Include retained periodic columns when admitting the complete witness
        // phase before any private words are packed.
        self.wallets.admit_memory(&plan.peak)?;
        Ok(BatchProver {
            engine: self.clone(),
            kind,
            tiles: plan.tiles,
            prepared,
        })
    }
}

impl BatchProver {
    pub(crate) fn matches(&self, kind: BatchKind, count: usize) -> bool {
        kind == self.kind
            && count <= crate::batch_common::MAX_BATCH_TILES
            && count.max(1).next_power_of_two() == self.tiles
    }

    pub(crate) fn prove_joinsplit(
        &self,
        witnesses: &[crate::joinsplit_air::Witness],
        request: Request,
        host_bytes: usize,
    ) -> Result<WalletProof> {
        if !self.matches(BatchKind::JoinSplit, witnesses.len()) {
            return Err("CUDA JoinSplit batch differs from prepared kind or height".into());
        }
        self.engine.prove(
            &self.prepared,
            "cuda_joinsplit_batch",
            request,
            host_bytes,
            Profile::LegacyQuadratic,
            None,
            |run| {
                self.engine
                    .wallets
                    .joinsplit_batch(witnesses, host_bytes, run)
            },
        )
    }

    pub(crate) fn prove_htlc(
        &self,
        witnesses: &[crate::htlc_air::Witness],
        request: Request,
        host_bytes: usize,
    ) -> Result<WalletProof> {
        if !self.matches(BatchKind::Htlc, witnesses.len()) {
            return Err("CUDA HTLC batch differs from prepared kind or height".into());
        }
        self.engine.prove(
            &self.prepared,
            "cuda_htlc_batch",
            request,
            host_bytes,
            Profile::LegacyQuadratic,
            None,
            |run| self.engine.wallets.htlc_batch(witnesses, host_bytes, run),
        )
    }
}
