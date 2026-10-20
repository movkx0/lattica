//! Public root binding for the existing LJSTREE1 container, not recursion.
use super::*;
use crate::gpu_wallet::tree::TreePlan;

impl Wallets {
    pub(crate) fn joinsplit_tree_root(
        &self,
        statements: &[u64],
        count: usize,
        host_bytes: usize,
        run: &Run,
    ) -> Result<[u64; 4]> {
        if count == 0
            || count > crate::MAX_TREE_TX
            || count.checked_mul(crate::joinsplit_air::N_PUBLIC) != Some(statements.len())
            || statements
                .iter()
                .any(|&word| word >= crate::gpu_matrix::GOLDILOCKS_MODULUS)
        {
            return Err("invalid CUDA legacy tree public statements".into());
        }
        let plan = TreePlan::new(statements.len(), host_bytes)?;
        self.admit(&plan.peak, run)?;
        let words = plan.words()?;
        // Include dummy generation even when no padding is required, so every
        // accepted root operation supplies its full arithmetic-stage inventory.
        let dummy = self.joinsplit(
            &crate::batch_joinsplit_air::dummy_witness(),
            host_bytes,
            run,
        )?;
        let input = self.runtime.allocate(plan.specs[0].words())?;
        let geometry = self.runtime.allocate(plan.specs[1].words())?;
        let output = self.runtime.allocate(plan.specs[2].words())?;
        input.write(0, statements)?;
        geometry.write(0, &words)?;
        record(run, Stage::PublicValues, unsafe {
            self.tree.launch(
                Launch {
                    blocks: 1,
                    threads: 1,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(&input),
                    Argument::Buffer(&dummy.public),
                    Argument::Buffer(&geometry),
                    Argument::U32(count as u32),
                    Argument::U32(count.next_power_of_two() as u32),
                    Argument::Buffer(&output),
                    Argument::Buffer(&self.constants[0]),
                    Argument::Buffer(&self.constants[1]),
                    Argument::Buffer(&self.constants[2]),
                    Argument::Buffer(&self.constants[3]),
                ],
            )
        })?;
        let mut root = [0; 4];
        output.read(0, &mut root)?;
        Ok(root)
    }
}
