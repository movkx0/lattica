//! GPU arithmetic for the existing LJSTREE1 compatibility container. Each leaf
//! is still an independently verified legacy proof; this is not recursion.
use super::*;
use crate::proving::CoverageScope;
use p3_field::PrimeField64;

pub(crate) struct TreeProof {
    pub(crate) proof: Vec<u8>,
    pub(crate) root: [Val; 4],
    pub(crate) report: Report,
}

fn output_bound(count: usize) -> Result<usize, Error> {
    if count == 0 || count > crate::MAX_TREE_TX {
        return Err(Error::ComponentRejected);
    }
    let bound = count
        .checked_mul(crate::JS_PUBLIC_INPUTS_LEN + 4 + crate::MAX_PROOF_LEN)
        .and_then(|n| n.checked_add(crate::TREE_MAGIC.len() + 4 + crate::DIGEST_BYTES))
        .ok_or(Error::ComponentRejected)?
        .min(crate::MAX_TREE_PROOF_LEN);
    if bound > resident_pcs::host_output_budget() {
        return Err(Error::ComponentRejected);
    }
    Ok(bound)
}

pub(crate) fn tree_abi_admission(count: usize) -> Result<DeviceSession, Error> {
    let context = super::abi_admission()?;
    output_bound(count)?;
    Ok(context)
}

pub(crate) fn prove_joinsplit_tree(
    witnesses: &[crate::joinsplit_air::Witness],
    request: Request,
) -> Result<TreeProof, Error> {
    let bound = output_bound(witnesses.len())?;
    request.admit(&capabilities())?;
    let _context = admission(request)?;
    // Leaves produce their own complete proof receipts. This additional receipt
    // covers only public root binding and container serialization, with GPU
    // generation of the fixed dummy statement. It cannot certify a leaf proof.
    let run = Run::new(
        "legacy_joinsplit_tree_root_gpu",
        request,
        capabilities().scoped(
            CoverageScope::Operation,
            &[Stage::WitnessTrace, Stage::PublicValues],
        ),
    )?;
    let mut proof = run.measure(Stage::Serialization, Backend::Cpu, || {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(bound)
            .map_err(|_| Error::ComponentRejected)?;
        bytes.extend_from_slice(crate::TREE_MAGIC);
        bytes.extend_from_slice(&(witnesses.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        Ok::<_, Error>(bytes)
    })??;
    let mut statements = Vec::with_capacity(witnesses.len() * crate::joinsplit_air::N_PUBLIC);
    for witness in witnesses {
        let output = super::prove_joinsplit_with_public(witness, request)?;
        if !output.report.succeeded || !output.report.stage_coverage_complete {
            return Err(Error::ComponentRejected);
        }
        run.measure(Stage::Serialization, Backend::Cpu, || {
            let public = crate::encode_joinsplit_public_inputs(&output.public)
                .ok_or(Error::ComponentRejected)?;
            crate::append_tree_leaf(&mut proof, &public, &output.proof)
                .ok_or(Error::ComponentRejected)?;
            statements.extend(output.public.iter().map(PrimeField64::as_canonical_u64));
            Ok::<_, Error>(())
        })??;
    }
    let session = DeviceSession::new().map_err(component)?;
    let before = session.stats();
    let root = session
        .joinsplit_tree_root(
            &statements,
            witnesses.len(),
            resident_pcs::host_output_budget(),
            &run,
        )
        .map_err(component)?;
    let readback = session.stats().downloaded_bytes - before.downloaded_bytes;
    // Fixed dummy generation reads one validity word; only the four public
    // root words follow it. No witness trace is read back.
    if readback != 40 {
        return Err(Error::ComponentRejected);
    }
    let root = root.map(Val::from_u64);
    run.measure(Stage::Serialization, Backend::Cpu, || {
        let offset = crate::TREE_MAGIC.len() + 4;
        proof[offset..offset + 32].copy_from_slice(&crate::encode_digest(&root));
    })?;
    eprintln!("legacy_tree_gpu_root_handoff leaves={} trace_readback_bytes=0 public_readback_bytes=32 control_readback_bytes=8", witnesses.len());
    Ok(TreeProof {
        proof,
        root,
        report: run.finish(true)?,
    })
}

#[cfg(test)]
mod tests;
