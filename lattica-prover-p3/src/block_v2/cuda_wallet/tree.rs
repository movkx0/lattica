//! GPU leaves and public root folding preserve the LJSTREE1 container. This
//! compatibility format is a list of proofs, not a recursive proof.
use super::*;
use crate::{
    config::Val,
    proving::{Backend, CoverageScope, Run, Stage},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

#[derive(Debug)]
struct HostPlan {
    container_bytes: usize,
    statement_words: usize,
    leaf_allowance: usize,
    root_allowance: usize,
}
impl HostPlan {
    fn new(count: usize, host_bytes: usize) -> Result<Self, Error> {
        if count == 0 || count > crate::MAX_TREE_TX {
            return Err(Error::ComponentRejected);
        }
        let container_bytes = count
            .checked_mul(crate::JS_PUBLIC_INPUTS_LEN + 4 + crate::MAX_PROOF_LEN)
            .and_then(|n| n.checked_add(crate::TREE_MAGIC.len() + 4 + crate::DIGEST_BYTES))
            .ok_or(Error::ComponentRejected)?
            .min(crate::MAX_TREE_PROOF_LEN);
        let input_bytes = count
            .checked_mul(std::mem::size_of::<crate::joinsplit_air::Witness>())
            .ok_or(Error::ComponentRejected)?;
        let statement_words = count
            .checked_mul(crate::joinsplit_air::N_PUBLIC)
            .ok_or(Error::ComponentRejected)?;
        let root_allowance = host_bytes
            .checked_sub(container_bytes)
            .and_then(|n| n.checked_sub(input_bytes))
            .ok_or(Error::ComponentRejected)?;
        let leaf_allowance = statement_words
            .checked_mul(8)
            .and_then(|n| root_allowance.checked_sub(n))
            .and_then(|n| n.checked_sub(crate::JS_PUBLIC_INPUTS_LEN))
            .filter(|&n| n >= super::super::machine::symbolic::HOST_BYTES as usize)
            .ok_or(Error::ComponentRejected)?;
        crate::gpu_wallet::tree::TreePlan::new(statement_words, root_allowance)
            .map_err(component)?;
        Ok(Self {
            container_bytes,
            statement_words,
            leaf_allowance,
            root_allowance,
        })
    }
}

pub(crate) fn tree_abi_admission(count: usize) -> Result<Admission, Error> {
    let admission = abi_admission()?;
    HostPlan::new(count, admission.session.host_bytes)?;
    Ok(admission)
}

pub(crate) struct TreeProof {
    pub(crate) proof: Vec<u8>,
    pub(crate) root: [Val; 4],
    pub(crate) report: Report,
}

pub(crate) fn prove_joinsplit_tree(
    witnesses: &[crate::joinsplit_air::Witness],
    request: Request,
) -> Result<TreeProof, Error> {
    let admission = admit(request)?;
    let session = &admission.session;
    let plan = HostPlan::new(witnesses.len(), session.host_bytes)?;
    let mut engine = session
        .engine
        .try_lock()
        .map_err(|_| Error::ComponentRejected)?;
    // The batch cache is irrelevant to this phase and must not displace a leaf.
    engine.batch = None;
    let run = Run::new(
        "cuda_joinsplit_tree_root",
        request,
        capabilities(Profile::LegacyQuadratic).scoped(
            CoverageScope::Operation,
            &[Stage::WitnessTrace, Stage::PublicValues],
        ),
    )?;
    let result = (|| {
        let mut proof = Vec::new();
        proof
            .try_reserve_exact(plan.container_bytes)
            .map_err(|_| Error::ComponentRejected)?;
        if proof.capacity() != plan.container_bytes {
            return Err(Error::ComponentRejected);
        }
        let mut statements =
            crate::gpu_wallet::staging_words(plan.statement_words).map_err(component)?;
        run.measure(Stage::Serialization, Backend::Cpu, || {
            proof.extend_from_slice(crate::TREE_MAGIC);
            proof.extend_from_slice(&(witnesses.len() as u32).to_le_bytes());
            proof.extend_from_slice(&[0; crate::DIGEST_BYTES]);
        })?;
        for witness in witnesses {
            let output = engine
                .joinsplit
                .prove(witness, request, plan.leaf_allowance)
                .map_err(component)?;
            let output = encode(output, &[], crate::MAX_PROOF_LEN, plan.leaf_allowance)?;
            if !output.report.succeeded
                || !output.report.stage_coverage_complete
                || output.public.len() != crate::joinsplit_air::N_PUBLIC
            {
                return Err(Error::ComponentRejected);
            }
            run.measure(Stage::Serialization, Backend::Cpu, || {
                let pi = crate::encode_joinsplit_public_inputs(&output.public)
                    .ok_or(Error::ComponentRejected)?;
                proof
                    .len()
                    .checked_add(pi.len())
                    .and_then(|n| n.checked_add(4))
                    .and_then(|n| n.checked_add(output.proof.len()))
                    .filter(|&n| n <= plan.container_bytes)
                    .ok_or(Error::ComponentRejected)?;
                crate::append_tree_leaf(&mut proof, &pi, &output.proof)
                    .ok_or(Error::ComponentRejected)?;
                statements.extend(output.public.iter().map(PrimeField64::as_canonical_u64));
                Ok::<_, Error>(())
            })??;
        }
        let before = session.runtime.snapshot();
        let root = engine
            .prover
            .joinsplit_tree_root(&statements, witnesses.len(), plan.root_allowance, &run)
            .map_err(component)?;
        if session.runtime.snapshot().downloaded_bytes - before.downloaded_bytes != 40 {
            return Err(Error::ComponentRejected);
        }
        let root = root.map(Val::from_u64);
        run.measure(Stage::Serialization, Backend::Cpu, || {
            let offset = crate::TREE_MAGIC.len() + 4;
            proof[offset..offset + crate::DIGEST_BYTES]
                .copy_from_slice(&crate::encode_digest(&root));
        })?;
        Ok((proof, root))
    })();
    match result {
        Ok((proof, root)) => Ok(TreeProof {
            proof,
            root,
            report: run.finish(true)?,
        }),
        Err(error) => {
            let _ = run.finish(false);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tree_host_plan_reserves_container_and_staging_before_private_decode() {
        for count in [1, 3, crate::MAX_TREE_TX] {
            let plan = HostPlan::new(count, 1 << 30).unwrap();
            let minimum = (1 << 30) - plan.leaf_allowance
                + super::super::super::machine::symbolic::HOST_BYTES as usize;
            assert!(HostPlan::new(count, minimum - 1).is_err());
            assert!(HostPlan::new(count, minimum).is_ok());
            assert!(plan.leaf_allowance < plan.root_allowance);
            assert!(plan.container_bytes <= crate::MAX_TREE_PROOF_LEN);
        }
        for count in [0, crate::MAX_TREE_TX + 1, usize::MAX] {
            assert!(HostPlan::new(count, usize::MAX).is_err());
        }
    }
}
