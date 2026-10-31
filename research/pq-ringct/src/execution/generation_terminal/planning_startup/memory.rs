use super::*;

pub(super) fn requirements() -> GenerationResult<(Requirements, Requirements)> {
    let generation = super::super::memory::runtime_requirements()?;
    let full = generation.get(Category::PhaseScratch);
    if full.host <= 8 << 30 || full.device == 0 || full.device >= 8 << 30 {
        return Err(GenerationError::Resource);
    }
    let mut permanent = Requirements::default();
    for category in Category::ALL {
        let original = generation.get(category);
        if category != Category::PhaseScratch && original.device != 0 {
            return Err(GenerationError::Resource);
        }
        let host = if category == Category::PhaseScratch {
            // The pristine source-only context cannot populate retained PCS
            // trees. Each later owned backend reserves its own host-tree
            // allowance. Keep ALL actual startup Rust backing permanently,
            // including source-copy/report overhead, for conservative closure.
            original.host.checked_sub(8 << 30).ok_or(GenerationError::Resource)?
        } else { original.host };
        permanent.add(category, Bytes { host, device: 0 }).map_err(|_| GenerationError::Overflow)?;
    }
    let wrappers = [size_of::<PlanningStartupPlan>(), size_of::<FreshPlanningContext<'static>>(),
        size_of::<OriginalPlanningStartup>(), size_of::<Rc<OriginalPlanningStartup>>(),
        size_of::<Option<Rc<OriginalPlanningStartup>>>(), size_of::<Option<Reservation>>(),
        size_of::<GenerationResult<FreshPlanningContext<'static>>>(),
        size_of::<GenerationResult<super::super::super::phase_lifecycle::PhaseCapability<'static>>>(),
        2 * size_of::<usize>() + core::mem::align_of::<OriginalPlanningStartup>(),
    ].into_iter().try_fold(0usize, usize::checked_add)
        .and_then(|bytes| bytes.checked_mul(8)).ok_or(GenerationError::Overflow)?;
    let wrappers = wrappers.checked_add(super::cleanup::additional_host_bytes()?)
        .ok_or(GenerationError::Overflow)?;
    permanent.add(Category::PhaseScratch, Bytes {
        host: u64::try_from(wrappers).map_err(|_| GenerationError::Overflow)?, device: 0,
    }).map_err(|_| GenerationError::Overflow)?;
    let startup = Requirements::single(Category::PhaseScratch, Bytes { host: 0, device: full.device });
    Ok((permanent, startup))
}
