//! Backend-only preissue before native work; original enclosing claims remain
//! the caller's obligation. Binding a genuine compiler result admits no bytes.
use super::super::{OuterBackendAdmission, OuterBackendPlan};
use super::*;
use crate::block_v2::gpu_hash::engine::retained_storage::Selection;
use crate::block_v2::machine::gpu_backend::resources::admission::selection::ExecutionSelection;
use std::sync::Arc;

/// Single-use, non-clone backend plan issued while the engine is idle. It is
/// not a native/transaction dispatch permit or evidence of enclosing ownership.
pub struct PreissuedOuterBackend {
    envelope: OuterSourceEnvelope,
}

fn check_selection(envelope: &OuterSourceEnvelope) -> Result<(), String> {
    if Selection::from_env()? != envelope.limits.trees {
        return Err("preissued outer tree selection changed".into());
    }
    let actual = ExecutionSelection::capture()?;
    if Some(actual) != envelope.limits.execution {
        return Err("preissued outer execution selection changed".into());
    }
    actual.qualify(envelope.limits)?;
    for row in envelope.rows.iter().flatten() {
        actual.qualify_host_output(row.backend.backend_host_budget_bytes)?;
    }
    if !crate::block_v2::gpu_hash::engine::registration_preflight_idle()? {
        return Err("preissued outer requires an idle engine boundary".into());
    }
    Ok(())
}

impl OuterSourceEnvelope {
    /// The enclosing owner must hold all original phase/output/compiler claims
    /// before this call and before its first native attempt. This only fixes a
    /// source backend schedule under the captured idle execution selection.
    pub fn preissue(self) -> Result<PreissuedOuterBackend, String> {
        check_selection(&self)?;
        Ok(PreissuedOuterBackend { envelope: self })
    }
}

impl PreissuedOuterBackend {
    pub fn footprint(&self) -> OuterSourceFootprint {
        self.envelope.footprint()
    }

    /// Recheck this original plan's captured selection at an idle boundary
    /// before an enclosing native attempt. The enclosing owner must already
    /// hold the source/helper and forwarding-frame claims. This borrows the
    /// original plan; it admits no bytes and issues no execution capability.
    pub fn check_execution_selection(&self) -> Result<(), String> {
        check_selection(&self.envelope)
    }

    /// Consume the prior source plan at the exact idle boundary after native
    /// retirement. No planner is rerun, memory claimed, or allowance expanded.
    /// The enclosing consumer must present the original retired phase owners.
    pub fn bind<'inputs>(
        self,
        program: &'inputs Arc<Program>,
        public: &'inputs Vec<Val>,
        witness: &'inputs Vec<Val>,
    ) -> Result<OuterBackendAdmission<'inputs>, String> {
        self.envelope.check_compiled(program, public, witness)?;
        check_selection(&self.envelope)?;
        let row = self.envelope.rows[(program.height().ilog2() - FIRST_LOG) as usize]
            .as_ref()
            .ok_or("preissued outer missing original row plan")?;
        Ok(OuterBackendAdmission {
            plan: OuterBackendPlan {
                program,
                public,
                witness,
                limits: self.envelope.limits,
                footprint: row.backend,
            },
        })
    }

    /// Bind a genuine fixed public array without allocating, copying or
    /// repacking it. Its source shape and complete fixed backing are checked;
    /// the immutable witness borrow retains the actual Vec capacity check.
    pub fn bind_fixed_public<'inputs, const N: usize>(
        self,
        program: &'inputs Arc<Program>,
        public: &'inputs [Val; N],
        witness: &'inputs Vec<Val>,
    ) -> Result<OuterBackendAdmission<'inputs>, String> {
        self.envelope.check_compiled_fixed_public(program, public, witness)?;
        check_selection(&self.envelope)?;
        let row = self.envelope.rows[(program.height().ilog2() - FIRST_LOG) as usize]
            .as_ref()
            .ok_or("preissued outer missing original row plan")?;
        Ok(OuterBackendAdmission {
            plan: OuterBackendPlan {
                program, public, witness,
                limits: self.envelope.limits,
                footprint: row.backend,
            },
        })
    }
}
