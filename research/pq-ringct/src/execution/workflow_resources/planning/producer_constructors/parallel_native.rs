use super::*;
use crate::graph_proofs::{ComponentKind, owned_ntt::NttSource, owned_mul::MulSource,
    owned_permutation::PermutationSource};
use crate::graph_tree::metadata::verifier::Key;

impl WorkflowPlanning<'_> {
    pub(crate) fn prepare_parallel_native(&mut self, inventory: &SourceMetadataPlanningPlan<'_>)
        -> Result<(), WorkflowError>
    {
        self.check_metadata(inventory)?;
        let ceiling = lattica_prover_p3::block_v2::machine::verifier::batch::shape::metadata_cpu_worker_ceiling();
        if ceiling < 2 || !crate::preparation_options::metadata_workers_enabled("native") { return Ok(()); }
        let mut keys = [None; crate::metadata_parallel::MAX_JOBS];
        let mut count = 0usize;
        for member in inventory.members() {
            for (index, batch) in member.get().algebra().batches().iter().enumerate() {
                let key = match batch.kind() {
                    ComponentKind::Ntt { .. } => Key::Ntt(NttSource::from_original(member, index).map_err(|_| WorkflowError::Identity)?.kind()),
                    ComponentKind::Mul { .. } => Key::Mul(MulSource::from_original(member, index).map_err(|_| WorkflowError::Identity)?.kind()),
                    ComponentKind::Permutation { .. } => Key::Permutation(PermutationSource::from_original(member, index).map_err(|_| WorkflowError::Identity)?.kind()),
                    _ => continue,
                };
                if keys[..count].contains(&Some(key)) { continue; }
                if count == keys.len() { return Ok(()); }
                keys[count] = Some(key);
                count += 1;
            }
        }
        if count < 2 { return Ok(()); }
        let first = keys[0].ok_or(WorkflowError::Planning)?;
        let mut requested = [first; crate::metadata_parallel::MAX_JOBS];
        for (target, source) in requested[..count].iter_mut().zip(&keys[..count]) {
            *target = source.ok_or(WorkflowError::Planning)?;
        }
        self.failed = true;
        let result = (|| {
            let member = inventory.members().first().ok_or(WorkflowError::Identity)?;
            let metadata = member.get().metadata().map_err(|_| WorkflowError::Planning)?;
            inventory.scope().verifier_cache(metadata).prewarm(&requested[..count], self.capability.ledger(), ceiling)
                .map_err(|_| WorkflowError::Planning)
        })();
        if result.is_ok() { self.failed = false; }
        result
    }
}
