//! Parent output storage. Retention alone earns no verification or source
//! credit; the closed parent producer must finish its actual session and then
//! authenticate through the independent source-captured verifier.
use super::*;
use crate::component_tree::owned_shake::request_merge::CapturedParentAcceptance;
use lattica_prover_p3::block_v2::machine::OuterSourceShape;

pub(in crate::component_tree::owned_shake) struct PreissuedParentOutput<'request> {
    request: &'request ReservedShakeRequest,
    storage: Storage,
    original: Reservation,
}

impl<'request> PreissuedParentOutput<'request> {
    pub(in crate::component_tree::owned_shake) fn reserve_before_native(
        shape: OuterSourceShape,
        request: &'request ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<Self, Error> {
        if !request.belongs_to(ledger) {
            return Err(Error::Authority);
        }
        let footprint = shape.output_footprint().map_err(|_| Error::Profile)?;
        let mut storage = Storage::new(footprint, 2 * (HEADER + 8))?;
        let parts = [
            bytes::<Self>(8)?,
            bytes::<Result<Self, Error>>(8)?,
            bytes::<RetainedNodeOutput<'static>>(8)?,
            bytes::<Result<RetainedNodeOutput<'static>, Error>>(8)?,
            bytes::<Storage>(8)?,
            bytes::<Result<Storage, Error>>(8)?,
            bytes::<Report>(8)?,
            bytes::<NodeKey>(8)?,
            bytes::<NodeProof>(8)?,
            bytes::<RegisteredGpuOutputFootprint>(8)?,
            bytes::<Result<RegisteredGpuOutputFootprint, String>>(8)?,
            bytes::<OuterSourceShape>(8)?,
            bytes::<Requirements>(8)?,
            bytes::<Reservation>(8)?,
            bytes::<Result<Reservation, Error>>(8)?,
            bytes::<Bytes>(8)?,
            bytes::<Result<(), Error>>(8)?,
            bytes::<Result<u64, Error>>(8)?,
            bytes::<Result<u128, Error>>(8)?,
            bytes::<
                Result<u128, crate::component_tree::owned_shake::request_merge::ParentCompileError>,
            >(8)?,
            bytes::<&CapturedParentAcceptance<'static, 'static, 'static, 'static>>(8)?,
            bytes::<&Ledger>(8)?,
            bytes::<&ReservedShakeRequest>(8)?,
            bytes::<&NodeKey>(8)?,
            bytes::<&NodeProof>(8)?,
            bytes::<u128>(16)?,
            bytes::<u64>(32)?,
            bytes::<usize>(32)?,
        ];
        let array = u64::try_from(core::mem::size_of_val(&parts)).map_err(|_| Error::Overflow)?;
        let extra = parts.into_iter().try_fold(
            add(64 << 10, array.checked_mul(16).ok_or(Error::Overflow)?)?,
            add,
        )?;
        // These wrappers also exist during later source authentication. Retain
        // their exact additive charge with the output's report, rather than
        // releasing it when the raw proof/key move into RetainedNodeOutput.
        storage
            .requirements
            .add(
                Category::Report,
                Bytes {
                    host: extra,
                    device: 0,
                },
            )
            .map_err(|_| Error::Overflow)?;
        storage.report.report_host_bytes = add(storage.report.report_host_bytes, extra)?;
        storage.report.total_claimed_host_bytes =
            add(storage.report.total_claimed_host_bytes, extra)?;
        let original = ledger
            .admit_phase(storage.requirements)
            .map_err(|_| Error::Admission)?;
        Ok(Self {
            request,
            storage,
            original,
        })
    }

    pub(in crate::component_tree::owned_shake) fn retain_after_proof(
        mut self,
        key: NodeKey,
        proof: NodeProof,
        setup_elapsed_ns: u128,
        proving_elapsed_ns: u128,
        ledger: &Ledger,
    ) -> Result<RetainedNodeOutput<'request>, Error> {
        if !self.request.belongs_to(ledger)
            || !self.original.belongs_to(ledger)
            || self.original.requirements() != self.storage.requirements
        {
            return Err(Error::Authority);
        }
        let actual_proof = self.storage.proof_bytes(&proof)?;
        let actual_key = self.storage.key_bytes(&key)?;
        let retained = retain_claims(
            &mut self.original,
            actual_proof,
            actual_key,
            self.storage.report.report_host_bytes,
        )?;
        let mut report = self.storage.report;
        report.actual_recursive_host_bytes = Some(actual_proof);
        report.actual_key_host_bytes = Some(actual_key);
        report.setup_elapsed_ns = Some(setup_elapsed_ns);
        report.proving_elapsed_ns = Some(proving_elapsed_ns);
        Ok(RetainedNodeOutput {
            key,
            proof,
            request: self.request,
            report,
            retained,
        })
    }
}

impl RetainedNodeOutput<'_> {
    pub(in crate::component_tree::owned_shake) fn authenticate_parent_source(
        &mut self,
        captured: &CapturedParentAcceptance<'_, '_, '_, '_>,
        ledger: &Ledger,
    ) -> Result<u128, Error> {
        if !self.belongs_to(ledger)
            || self.report.independent_verification_complete
            || self.report.authenticated_source_key
        {
            return Err(Error::Authority);
        }
        let elapsed = captured
            .verify_original_output(&self.key, &self.proof, self.request, ledger)
            .map_err(|_| Error::Verification)?;
        self.report.independent_verification_complete = true;
        self.report.authenticated_source_key = true;
        self.report.cpu_verification_elapsed_ns = Some(elapsed);
        Ok(elapsed)
    }
}
