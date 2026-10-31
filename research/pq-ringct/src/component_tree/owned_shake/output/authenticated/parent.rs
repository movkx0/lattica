//! Closed compiler action on the retained original output, without raw getters.
use super::*;
use crate::component_tree::owned_shake::request_merge::{EmittedParentChild, ParentChildEmission};
use crate::component_tree::owned_shake::request_merge::{
    InteriorOpeningAction, InteriorOpeningMeasurements,
    RootOpeningMeasurements, RootOpeningRecheckAction,
    RootTransportAction, RootTransportMeasurements,
    RootPublicRecheckAction, RootPublicRecheckReport,
};

impl RetainedNodeOutput<'_> {
    pub(in crate::component_tree::owned_shake) fn recheck_root_opening(
        &mut self,
        action: &RootOpeningRecheckAction<'_, '_, '_, '_>,
    ) -> Result<
        RootOpeningMeasurements,
        crate::component_tree::owned_shake::request_merge::ParentCompileError,
    > {
        if !self.report.independent_verification_complete
            || !self.report.authenticated_source_key
            || self.report.transaction_context_authenticated
            || self.report.workflow_admitted
        {
            return Err(
                crate::component_tree::owned_shake::request_merge::ParentCompileError::Authority,
            );
        }
        action.check_owner(self)?;
        // No other owner can supply these original fields. The action exposes
        // only shared verification while its private mutation guard is live.
        action.verify_original(&self.key, &mut self.proof, self.request)
    }
}

impl RetainedNodeOutput<'_> {
    pub(in crate::component_tree::owned_shake) fn recheck_root_publics(
        &self,
        action: &RootPublicRecheckAction<'_, '_, '_, '_>,
    ) -> Result<
        RootPublicRecheckReport,
        crate::component_tree::owned_shake::request_merge::ParentCompileError,
    > {
        if !self.report.independent_verification_complete
            || !self.report.authenticated_source_key
            || self.report.transaction_context_authenticated
            || self.report.workflow_admitted
        {
            return Err(
                crate::component_tree::owned_shake::request_merge::ParentCompileError::Authority,
            );
        }
        action.verify_original(self, &self.key, &self.proof, self.request)
    }
}

impl RetainedNodeOutput<'_> {
    pub(in crate::component_tree::owned_shake) fn emit_parent_child(
        &self,
        emission: &mut ParentChildEmission<'_, '_, '_, '_, '_>,
    ) -> Result<
        EmittedParentChild,
        crate::component_tree::owned_shake::request_merge::ParentCompileError,
    > {
        if !self.report.independent_verification_complete || !self.report.authenticated_source_key {
            return Err(
                crate::component_tree::owned_shake::request_merge::ParentCompileError::Authority,
            );
        }
        emission.emit_original(self, &self.key, &self.proof, self.request)
    }
}

// Closed transport action borrows only this retained output's original fields.
// Its private constructor binds the same consuming Component and reservations.
impl RetainedNodeOutput<'_> {
    pub(in crate::component_tree::owned_shake) fn roundtrip_root_transport(
        &self,
        action: &RootTransportAction<'_, '_, '_, '_>,
    ) -> Result<
        RootTransportMeasurements,
        crate::component_tree::owned_shake::request_merge::ParentCompileError,
    > {
        if !self.report.independent_verification_complete
            || !self.report.authenticated_source_key
            || self.report.transaction_context_authenticated
            || self.report.workflow_admitted
        {
            return Err(
                crate::component_tree::owned_shake::request_merge::ParentCompileError::Authority,
            );
        }
        action.roundtrip_original(self, &self.key, &self.proof, self.request)
    }
}

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
impl RetainedNodeOutput<'_> {
    pub(in crate::component_tree::owned_shake) fn recheck_interior_opening(
        &mut self,
        action: &InteriorOpeningAction<'_, '_, '_, '_>,
    ) -> Result<InteriorOpeningMeasurements, crate::component_tree::owned_shake::request_merge::ParentCompileError> {
        if !self.report.independent_verification_complete
            || !self.report.authenticated_source_key
            || self.report.transaction_context_authenticated
            || self.report.workflow_admitted
        {
            return Err(crate::component_tree::owned_shake::request_merge::ParentCompileError::Authority);
        }
        action.check_owner(self)?;
        action.verify_original(&self.key, &mut self.proof, self.request)
    }
}
