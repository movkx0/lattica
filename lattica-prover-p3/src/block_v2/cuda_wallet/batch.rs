use super::*;
use crate::batch_common::{BatchKind, MAX_BATCH_TILES};

fn proof_allowance(kind: BatchKind, count: usize, host_bytes: usize) -> Result<usize, Error> {
    if count > MAX_BATCH_TILES {
        return Err(Error::ComponentRejected);
    }
    let size = match kind {
        BatchKind::JoinSplit => std::mem::size_of::<crate::joinsplit_air::Witness>(),
        BatchKind::Htlc => std::mem::size_of::<crate::htlc_air::Witness>(),
    };
    count
        .checked_mul(size)
        .and_then(|bytes| host_bytes.checked_sub(bytes))
        .filter(|&bytes| bytes >= super::super::machine::symbolic::HOST_BYTES as usize)
        .ok_or(Error::ComponentRejected)
}

impl Engines {
    fn batch(
        &mut self,
        kind: BatchKind,
        count: usize,
        host_bytes: usize,
    ) -> Result<&wallet::BatchProver, Error> {
        if self
            .batch
            .as_ref()
            .is_none_or(|prepared| !prepared.matches(kind, count))
        {
            // Evict before preparation so two public shapes cannot silently
            // double the cache's admitted device and host storage.
            self.batch = None;
            self.batch = Some(
                self.prover
                    .prepare_batch(kind, count, host_bytes)
                    .map_err(component)?,
            );
        }
        Ok(self.batch.as_ref().unwrap())
    }
}

fn admit_batch(kind: BatchKind, count: usize, request: Request) -> Result<Admission, Error> {
    let admission = admit(request)?;
    let allowance = proof_allowance(kind, count, admission.session.host_bytes)?;
    admission
        .session
        .engine
        .try_lock()
        .map_err(|_| Error::ComponentRejected)?
        .batch(kind, count, allowance)?;
    Ok(admission)
}

pub(crate) fn batch_abi_admission(kind: BatchKind, count: usize) -> Result<Admission, Error> {
    if count == 0 {
        return Err(Error::ComponentRejected);
    }
    admit_batch(kind, count, Request::from_env()?)
}

pub(crate) fn prove_joinsplit_batch_with_public(
    witnesses: &[crate::joinsplit_air::Witness],
    request: Request,
) -> Result<WalletProof, Error> {
    let kind = BatchKind::JoinSplit;
    let admission = admit_batch(kind, witnesses.len(), request)?;
    let allowance = proof_allowance(kind, witnesses.len(), admission.session.host_bytes)?;
    let mut engine = admission
        .session
        .engine
        .try_lock()
        .map_err(|_| Error::ComponentRejected)?;
    let output = engine
        .batch(kind, witnesses.len(), allowance)?
        .prove_joinsplit(witnesses, request, allowance)
        .map_err(component)?;
    encode(output, &[], crate::MAX_PROOF_LEN, allowance)
}

pub(crate) fn prove_htlc_batch_with_public(
    witnesses: &[crate::htlc_air::Witness],
    request: Request,
) -> Result<WalletProof, Error> {
    let kind = BatchKind::Htlc;
    let admission = admit_batch(kind, witnesses.len(), request)?;
    let allowance = proof_allowance(kind, witnesses.len(), admission.session.host_bytes)?;
    let mut engine = admission
        .session
        .engine
        .try_lock()
        .map_err(|_| Error::ComponentRejected)?;
    let output = engine
        .batch(kind, witnesses.len(), allowance)?
        .prove_htlc(witnesses, request, allowance)
        .map_err(component)?;
    encode(output, &[], crate::MAX_PROOF_LEN, allowance)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_admission_charges_decoded_witnesses_and_bounds_counts() {
        for kind in [BatchKind::JoinSplit, BatchKind::Htlc] {
            let allowance = proof_allowance(kind, MAX_BATCH_TILES, 1 << 30).unwrap();
            assert!(allowance < 1 << 30);
            assert!(proof_allowance(
                kind,
                1,
                super::super::super::machine::symbolic::HOST_BYTES as usize
            )
            .is_err());
            assert!(proof_allowance(kind, MAX_BATCH_TILES + 1, usize::MAX).is_err());
            assert!(proof_allowance(kind, usize::MAX, usize::MAX).is_err());
            assert!(proof_allowance(kind, 0, 1 << 30).is_ok());
        }
    }
}
