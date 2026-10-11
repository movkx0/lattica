//! Owned batch assembly. Only raw witnesses and the AIR's layout enter the
//! device; padding, statement hashes, the root chain and all trace rows stay on it.
use super::super::super::Engine;
use super::*;
use crate::batch_common::{DeviceBatchGeometry, MAX_BATCH_TILES};
use crate::proving::{Backend, Run, Stage};

struct BatchPlan {
    trace: MatrixSpec,
    public: MatrixSpec,
    geometry: MatrixSpec,
    words: Vec<u64>,
    peak: Vec<MatrixSpec>,
    tiles: usize,
    height: usize,
}

impl BatchPlan {
    fn new(
        layout: DeviceBatchGeometry,
        count: usize,
        single: Plan,
        host_allowance: usize,
    ) -> Result<Self, String> {
        if count > MAX_BATCH_TILES {
            return Err("batch exceeds MAX_BATCH_TILES".into());
        }
        let tiles = count.max(1).next_power_of_two();
        let height = layout.height;
        let rows = height.checked_mul(tiles).ok_or("batch height overflow")?;
        if !height.is_power_of_two()
            || height < 32
            || layout.wallet_width < 8
            || rows > u32::MAX as usize
            || layout.wallet_width.checked_add(layout.public_width) != Some(layout.root_column)
            || layout.root_column.checked_add(4) != Some(layout.batch_width)
            || layout.fold_base.checked_add(layout.chunks.len()) != Some(layout.root_block)
            || layout.root_block >= height / 32
            || layout
                .root_block
                .checked_mul(32)
                .and_then(|r| r.checked_add(31))
                != Some(layout.root_output_row)
            || layout.chunks.is_empty()
            || layout
                .chunks
                .iter()
                .flatten()
                .flatten()
                .any(|&col| col < layout.wallet_width || col >= layout.root_column)
        {
            return Err("unsupported batch trace geometry".into());
        }
        if single.trace
            != MatrixSpec::new(
                height.ilog2(),
                layout.wallet_width,
                Extension::Base,
                RowOrder::Natural,
                1,
            )?
            || single.public
                != MatrixSpec::new(
                    0,
                    layout.public_width,
                    Extension::Base,
                    RowOrder::Natural,
                    1,
                )?
        {
            return Err("batch and wallet geometry differ".into());
        }
        let trace = MatrixSpec::new(
            rows.ilog2(),
            layout.batch_width,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        let public = MatrixSpec::new(0, 4, Extension::Base, RowOrder::Natural, 1)?;
        let mut words = vec![
            height as u64,
            layout.batch_width as u64,
            layout.wallet_width as u64,
            layout.public_width as u64,
            layout.fold_base as u64,
            layout.root_block as u64,
            layout.root_column as u64,
            layout.root_output_row as u64,
            tiles as u64,
            layout.chunks.len() as u64,
            crate::domains::DOM_TXROOT,
        ];
        words.extend(
            layout
                .chunks
                .iter()
                .flatten()
                .map(|col| col.map_or(u64::MAX, |c| c as u64)),
        );
        let host_words = words
            .len()
            .checked_add(single.input_words)
            .and_then(|n| n.checked_add(single.geometry_words + 1))
            .and_then(|n| n.checked_mul(8))
            .ok_or("batch host staging overflow")?;
        if host_words > host_allowance {
            return Err("batch input staging exceeds host allowance".into());
        }
        let geometry = MatrixSpec::new(0, words.len(), Extension::Base, RowOrder::Natural, 1)?;
        let mut peak = vec![trace, public, geometry];
        peak.extend(single.specs()?);
        Ok(Self {
            trace,
            public,
            geometry,
            words,
            peak,
            tiles,
            height,
        })
    }
}

impl DeviceSession {
    pub(crate) fn joinsplit_batch_witness(
        &self,
        witnesses: &[js::Witness],
        host_allowance: usize,
        run: &Run,
    ) -> Result<WalletTrace, String> {
        let plan = BatchPlan::new(
            crate::batch_joinsplit_air::device_batch_geometry(),
            witnesses.len(),
            Plan::new(host_allowance)?,
            host_allowance,
        )?;
        self.generate_batch(
            plan,
            witnesses,
            crate::batch_joinsplit_air::dummy_witness,
            |session, witness| session.joinsplit_witness(witness, host_allowance, run),
            run,
        )
    }

    pub(crate) fn htlc_batch_witness(
        &self,
        witnesses: &[crate::htlc_air::Witness],
        host_allowance: usize,
        run: &Run,
    ) -> Result<WalletTrace, String> {
        let plan = BatchPlan::new(
            crate::batch_htlc_air::device_batch_geometry(),
            witnesses.len(),
            super::htlc::plan(host_allowance)?,
            host_allowance,
        )?;
        self.generate_batch(
            plan,
            witnesses,
            crate::batch_htlc_air::dummy_witness,
            |session, witness| session.htlc_witness(witness, host_allowance, run),
            run,
        )
    }

    fn batch_observe(
        &self,
        engine: &mut Engine,
        run: &Run,
        stage: Stage,
        event: &compute::Event,
    ) -> Result<(), String> {
        let ns = self
            .session
            .record_event(engine, stage, "wallet_batch", event)
            .map_err(|error| {
                run.observation_failed();
                error
            })?;
        run.observe_device(stage, Backend::OpenCl, 1, ns)
            .map_err(|e| e.to_string())
    }

    fn generate_batch<W>(
        &self,
        plan: BatchPlan,
        witnesses: &[W],
        dummy: impl FnOnce() -> W,
        generate: impl Fn(&Self, &W) -> Result<WalletTrace, String>,
        run: &Run,
    ) -> Result<WalletTrace, String> {
        for stage in [Stage::WitnessTrace, Stage::PublicValues] {
            run.check_device_stage(stage, Backend::OpenCl)
                .map_err(|e| e.to_string())?;
        }
        // Reserve no buffers and read no witnesses until the complete assembly
        // peak (including one wallet generator) is admitted by the live engine.
        let (trace, public, geometry) = self.with_engine(|engine| {
            let _plan = Self::plan(engine, &plan.peak)?;
            let trace = self.allocate(engine, plan.trace)?;
            let public = self.allocate(engine, plan.public)?;
            let geometry = self.allocate(engine, plan.geometry)?;
            let fence = engine.fence();
            geometry
                .storage
                .buffer
                .write(&plan.words[..])
                .enq()
                .map_err(|e| e.to_string())?;
            trace
                .storage
                .buffer
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = (plan.words.len() * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            self.session.stats.lock().unwrap().uploaded_bytes += uploaded;
            Ok((trace, public, geometry))
        })?;
        let copy = |tile: usize, frame: &WalletTrace| -> Result<(), String> {
            self.check_owner(&frame.trace)?;
            self.check_owner(&frame.public)?;
            self.with_engine(|engine| {
                let fence = engine.fence();
                let mut event = compute::Event::empty();
                // SAFETY: the AIR geometry and aggregate peak bound every row,
                // column and tile; the frame belongs to this live session.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("device_wallet_batch_copy")
                        .arg(&frame.trace.storage.buffer)
                        .arg(&frame.public.storage.buffer)
                        .arg(&geometry.storage.buffer)
                        .arg(&trace.storage.buffer)
                        .arg(tile as u32)
                        .global_work_size(plan.height)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                self.batch_observe(engine, run, Stage::WitnessTrace, &event)?;
                fence.finish()
            })
        };
        for (tile, witness) in witnesses.iter().enumerate() {
            copy(tile, &generate(self, witness)?)?;
        }
        if witnesses.len() < plan.tiles {
            // Canonical dummy witnesses contain only raw zero fields. Hashes
            // and their trace are generated on the device once for all padding.
            let frame = generate(self, &dummy())?;
            for tile in witnesses.len()..plan.tiles {
                copy(tile, &frame)?;
            }
        }
        self.with_engine(|engine| {
            let fence = engine.fence();
            let mut event = compute::Event::empty();
            // SAFETY: all staged columns and fold blocks were checked against
            // the exact AIR layout. A single work item owns the root chain.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_wallet_batch_fold")
                    .arg(&geometry.storage.buffer)
                    .arg(&trace.storage.buffer)
                    .arg(&engine.constants[0].buffer)
                    .arg(&engine.constants[1].buffer)
                    .arg(&engine.constants[2].buffer)
                    .arg(&engine.constants[3].buffer)
                    .global_work_size(1)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.batch_observe(engine, run, Stage::WitnessTrace, &event)?;
            let mut event = compute::Event::empty();
            // SAFETY: four work items copy the final permutation output to the
            // four-element public statement, not the pre-update ROOT column.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_wallet_batch_public")
                    .arg(&trace.storage.buffer)
                    .arg(&geometry.storage.buffer)
                    .arg(&public.storage.buffer)
                    .global_work_size(4)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.batch_observe(engine, run, Stage::PublicValues, &event)?;
            fence.finish()
        })?;
        Ok(WalletTrace { trace, public })
    }
}

#[cfg(test)]
mod tests;
