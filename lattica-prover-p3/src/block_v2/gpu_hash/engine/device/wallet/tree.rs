//! GPU binding for the existing legacy tree container. Only public statements
//! from completed leaf proofs enter this operation; it is not a recursive proof.
use super::*;
use crate::proving::{Backend, Run, Stage};

use crate::gpu_wallet::tree::TreePlan;
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
