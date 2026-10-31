//! Private action on a source-captured verifier; no raw key/proof getter.
use super::*;
use crate::component_tree::owned_shake::request_merge::CapturedLeafAcceptance;

mod parent;

impl RetainedNodeOutput<'_> {
    pub(in crate::component_tree::owned_shake) fn authenticate_captured_source(
        &mut self,
        captured: &CapturedLeafAcceptance<'_, '_, '_, '_>,
        ledger: &Ledger,
    ) -> Result<u128, Error> {
        if !self.belongs_to(ledger) || !self.report.independent_verification_complete {
            return Err(Error::Authority);
        }
        let elapsed = captured
            .verify_original_output(&self.key, &self.proof, self.request, ledger)
            .map_err(|_| Error::Verification)?;
        self.report.authenticated_source_key = true;
        Ok(elapsed)
    }
}
