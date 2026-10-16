//! GPU binding for the existing legacy tree container. Only public statements
//! from completed leaf proofs enter this operation; it is not a recursive proof.
use super::*;
use crate::proving::{Backend, Run, Stage};

struct TreePlan {
    layout: crate::batch_common::DeviceBatchGeometry<'static>,
    specs: [MatrixSpec; 3],
    peak: [MatrixSpec; 8],
}

impl TreePlan {
    fn new(statement_words: usize, host_allowance: usize) -> Result<Self, String> {
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

    fn words(&self) -> Result<Vec<u64>, String> {
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

impl DeviceSession {
    pub(crate) fn joinsplit_tree_root(
        &self,
        statements: &[u64],
        count: usize,
        host_allowance: usize,
        run: &Run,
    ) -> Result<[u64; 4], String> {
        if count == 0
            || count > crate::MAX_TREE_TX
            || count.checked_mul(js::N_PUBLIC) != Some(statements.len())
            || statements.iter().any(|&word| word >= GOLDILOCKS_MODULUS)
        {
            return Err("invalid legacy tree public statements".into());
        }
        for stage in [Stage::WitnessTrace, Stage::PublicValues] {
            run.check_device_stage(stage, Backend::OpenCl)
                .map_err(|e| e.to_string())?;
        }
        // Include canonical dummy generation in the aggregate allocation plan.
        // Its raw zero witness is public; its hashes and trace are generated on
        // GPU, even when this particular count needs no padding.
        let plan = TreePlan::new(statements.len(), host_allowance)?;
        let _plan = self.plan_outputs(&plan.peak)?;
        let words = plan.words()?;
        let specs = plan.specs;
        let dummy = self.joinsplit_witness(
            &crate::batch_joinsplit_air::dummy_witness(),
            host_allowance,
            run,
        )?;
        let output = self.with_engine(|engine| {
            let input = self.allocate(engine, specs[0])?;
            let geometry = self.allocate(engine, specs[1])?;
            let output = self.allocate(engine, specs[2])?;
            let fence = engine.fence();
            input
                .storage
                .buffer
                .write(statements)
                .enq()
                .map_err(|e| e.to_string())?;
            geometry
                .storage
                .buffer
                .write(&words)
                .enq()
                .map_err(|e| e.to_string())?;
            let bytes = ((statements.len() + words.len()) * 8) as u64;
            engine.stats.uploaded_bytes += bytes;
            self.session.stats.lock().unwrap().uploaded_bytes += bytes;
            let mut event = compute::Event::empty();
            // SAFETY: count is positive and bounded; both statement buffers
            // have exactly the AIR width, and every geometry index is checked.
            // One work item owns the entire ordered root chain and four outputs.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_wallet_tree_root")
                    .arg(&input.storage.buffer)
                    .arg(&dummy.public.storage.buffer)
                    .arg(&geometry.storage.buffer)
                    .arg(count as u32)
                    .arg(count.next_power_of_two() as u32)
                    .arg(&output.storage.buffer)
                    .arg(&engine.constants[0].buffer)
                    .arg(&engine.constants[1].buffer)
                    .arg(&engine.constants[2].buffer)
                    .arg(&engine.constants[3].buffer)
                    .global_work_size(1usize)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = self
                .session
                .record_event(engine, Stage::PublicValues, "wallet_tree_root", &event)
                .map_err(|error| {
                    run.observation_failed();
                    error
                })?;
            run.observe_device(Stage::PublicValues, Backend::OpenCl, 1, ns)
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.context_checkpoint("wallet tree root complete")?;
            Ok(output)
        })?;
        self.read(&output, host_allowance)?
            .try_into()
            .map_err(|_| "legacy tree root shape".into())
    }
}

#[cfg(test)]
mod tests;
