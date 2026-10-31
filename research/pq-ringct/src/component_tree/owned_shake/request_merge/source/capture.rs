//! Original compiler-registration cap provenance only. No proof is accepted
//! here, and no captured cap is treated as correlated producer retirement.
use super::{shape, Error, ParentSourceBound, Result};
use crate::{
    component_tree::{owned_shake::OwnedCompiledShake, Val},
    execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
};
use core::mem::{size_of, size_of_val};
use lattica_prover_p3::block_v2::{
    machine::{backend::RegisteredProgram, Program},
    profile,
};
use p3_field::PrimeCharacteristicRing;

const ROOTS: usize = 1 << profile::CAP_HEIGHT;

#[cfg(test)]
mod acceptance;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use acceptance::{
    InteriorOpeningAction, InteriorOpeningMeasurements,
    RootOpeningRecheckAction, RootOpeningMeasurements,
    RootTransportAction, RootTransportMeasurements,
    RootPublicRecheckAction, RootPublicRecheckReport,
};
#[cfg(test)]
pub(in crate::component_tree::owned_shake) use acceptance::{
    authenticate_retired_hashx_leaf, authenticate_retired_leaf, AcceptedHashxLeafCompletion,
    AcceptedLeaf, AcceptedLeafCompletion, CapturedLeafAcceptance, CompiledLeafParent,
    EmittedParentChild, LeafAcceptanceReport, LeafParentCompilationReport, ParentChildEmission,
    PreissuedLeafAcceptance, PreissuedLeafParentCompiler,
};

/// One source-issued fixed cap/metadata claim. The original compiler and
/// registration retain their own independent full storage claims throughout.
pub(in crate::component_tree::owned_shake::request_merge) struct PreissuedLeafCap<
    'bound,
    'source,
    'request,
> {
    source: &'bound ParentSourceBound<'source, 'request>,
    index: usize,
    original: Reservation,
}

/// Cap words originate solely from the actual registration of the original
/// source-checked compiler allocation. No raw cap/height/hash constructor or
/// cap getter exists. This is not a verified child, proof or dispatch permit.
pub(in crate::component_tree::owned_shake::request_merge) struct CapturedLeafCap<
    'compiled,
    'bound,
    'source,
    'request,
> {
    compiled: &'compiled OwnedCompiledShake<'request>,
    source: &'bound ParentSourceBound<'source, 'request>,
    index: usize,
    cap: [[Val; 4]; ROOTS],
    original: Reservation,
}

fn requirements() -> Result<Requirements> {
    let parts = [
        4 * size_of::<PreissuedLeafCap<'static, 'static, 'static>>(),
        4 * size_of::<Result<PreissuedLeafCap<'static, 'static, 'static>>>(),
        4 * size_of::<CapturedLeafCap<'static, 'static, 'static, 'static>>(),
        4 * size_of::<Result<CapturedLeafCap<'static, 'static, 'static, 'static>>>(),
        4 * size_of::<[[Val; 4]; ROOTS]>(),
        4 * size_of::<Requirements>(),
        4 * size_of::<Reservation>(),
        4 * size_of::<Result<Requirements>>(),
        4 * size_of::<(
            &RegisteredProgram,
            &OwnedCompiledShake<'_>,
            &Ledger,
            &[Val; 4],
            usize,
        )>(),
    ];
    let helper = super::times(4, size_of_val(&parts))?;
    let bytes = parts.into_iter().try_fold(helper, super::add)?;
    Ok(Requirements::single(
        Category::RegisteredMetadata,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

fn same_program(expected: &Program, registered: &Program) -> bool {
    // Equal metadata/manifests are insufficient to bind the actual compiler
    // allocation. Both borrows keep the original allocation alive here.
    core::ptr::eq(expected, registered)
}

impl<'source, 'request> ParentSourceBound<'source, 'request> {
    pub(in crate::component_tree::owned_shake::request_merge) fn preissue_leaf_cap<'bound>(
        &'bound self,
        index: usize,
        ledger: &Ledger,
    ) -> Result<PreissuedLeafCap<'bound, 'source, 'request>> {
        if !self.is_for(self.request, ledger) || index >= super::super::LEAVES {
            return Err(Error::Authority);
        }
        let original = ledger
            .admit_phase(requirements()?)
            .map_err(|_| Error::Capacity)?;
        Ok(PreissuedLeafCap {
            source: self,
            index,
            original,
        })
    }
}

impl<'bound, 'source, 'request> PreissuedLeafCap<'bound, 'source, 'request> {
    pub(in crate::component_tree::owned_shake::request_merge) fn capture<'compiled>(
        self,
        compiled: &'compiled OwnedCompiledShake<'request>,
        registered: &RegisteredProgram,
        ledger: &Ledger,
    ) -> Result<CapturedLeafCap<'compiled, 'bound, 'source, 'request>> {
        if !self.source.is_for(self.source.request, ledger)
            || !self.original.belongs_to(ledger)
            || self.original.requirements() != requirements()?
        {
            return Err(Error::Authority);
        }
        let leaf = self
            .source
            .request
            .sources
            .get(self.index)
            .and_then(Option::as_ref)
            .ok_or(Error::Source)?;
        leaf.check_compiled(compiled, ledger)
            .map_err(|_| Error::Source)?;
        let program = &compiled.compiled.program;
        if !same_program(program, registered.air().program()) {
            return Err(Error::Source);
        }
        let geometry = shape(program.height())?;
        let commitment = registered.preprocessing_cap();
        if geometry.preprocessing_cap_roots != ROOTS
            || commitment.roots().len() != ROOTS
            || commitment.root_capacity() != ROOTS
        {
            return Err(Error::Source);
        }
        let mut cap = [[Val::ZERO; 4]; ROOTS];
        cap.copy_from_slice(commitment.roots());
        Ok(CapturedLeafCap {
            compiled,
            source: self.source,
            index: self.index,
            cap,
            original: self.original,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_prover_p3::block_v2::machine::{program::ProgramBuilder, MachineAir};
    use std::sync::Arc;

    #[test]
    fn identical_program_metadata_does_not_substitute_for_original_registration_allocation() {
        let original = Arc::new(ProgramBuilder::new(46).unwrap().finish(Some(8)).unwrap());
        let shared = MachineAir::from_shared_program(Arc::clone(&original));
        let identical = MachineAir::new(ProgramBuilder::new(46).unwrap().finish(Some(8)).unwrap());
        assert!(same_program(&original, shared.program()));
        assert!(!same_program(&original, identical.program()));
        // No RegisteredProgram, cap owner or accepted proof is fabricated.
        let requirement = requirements().unwrap();
        assert_eq!(
            requirement.total().unwrap(),
            requirement.get(Category::RegisteredMetadata)
        );
        assert!(
            requirement.total().unwrap().host > size_of::<CapturedLeafCap<'_, '_, '_, '_>>() as u64
        );
        assert_eq!(requirement.total().unwrap().device, 0);
    }
}

#[cfg(test)]
pub(in crate::component_tree::owned_shake) use acceptance::{AcceptedChild, AcceptedParent, CapturedParentAcceptance, ParentAcceptanceReport, PreissuedParentAcceptance};
