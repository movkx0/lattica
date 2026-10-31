//! Allocation-free provenance/capacity check of an already reserved graph root.
//! Numerical verification follows under the final compiler's independent claim.
use super::*;
use crate::execution::retained_resources::{Category, Requirements};

impl NodeKey {
    pub(crate) fn matches_owned_final_input(&self, plan: &super::super::Plan,
        proof: &NodeProof, reserved: Requirements) -> bool
    {
        if !plan.matches_final_inner(&self.spec.plan) || !self.spec.complete()
            || !(8..=1 << 20).contains(&self.height) || !self.height.is_power_of_two()
            || proof.public.len() != PUBLIC_VALUES
        { return false; }
        let roots = 1usize << (self.height.ilog2() as usize + 1
            + lattica_prover_p3::block_v2::profile::LOG_BLOWUP)
                .min(lattica_prover_p3::block_v2::profile::CAP_HEIGHT);
        if self.cap.len() != roots || self.cap.capacity() > roots { return false; }
        let Some(public_bytes) = proof.public.capacity().checked_mul(core::mem::size_of::<Val>())
            else { return false; };
        let Ok(proof_limit) = usize::try_from(reserved.get(Category::RecursiveProof).host)
            else { return false; };
        let Some(available) = proof_limit.checked_sub(public_bytes)
            .and_then(|bytes| bytes.checked_sub(core::mem::size_of::<owned_parent::OwnedGraphNode<'_>>()))
            else { return false; };
        if lattica_prover_p3::block_v2::machine::backend::retained_proof_capacity_bytes(
            &proof.proof, available.min(64 << 20)).is_err()
        { return false; }
        let Some(key_bytes) = self.cap.capacity().checked_mul(core::mem::size_of::<[Val; 4]>())
            .and_then(|n| n.checked_add(self.verifier.cached_metadata_bytes()))
            .and_then(|n| n.checked_add(2 * core::mem::size_of::<usize>()))
            .and_then(|n| n.checked_add(core::mem::align_of::<RegisteredVerifier>()))
            .and_then(|n| n.checked_add(core::mem::size_of::<owned_parent::OwnedGraphNode<'_>>()))
            else { return false; };
        key_bytes as u64 <= reserved.get(Category::RegisteredMetadata).host
    }
}
