//! Complete added qualification/caller frames, independently preclaimed.
use super::*;

fn result1<A, R>(_: fn(A) -> R) -> usize {
    size_of::<R>()
}
fn result3<A, B, C, R>(_: fn(A, B, C) -> R) -> usize {
    size_of::<R>()
}
fn result4<A, B, C, D, R>(_: fn(A, B, C, D) -> R) -> usize {
    size_of::<R>()
}
fn result6<A, B, C, D, E, F, R>(_: fn(A, B, C, D, E, F) -> R) -> usize {
    size_of::<R>()
}

pub(super) fn driver_requirement() -> DriverResult<Requirements> {
    let parts = [
        size_of::<[u8; 16_416]>(),
        size_of::<[u8; 137]>(),
        size_of::<Shake256>(),
        size_of::<Shake256Reader>(),
        size_of::<EndpointContext>(),
        size_of::<NativePolicy>(),
        size_of::<ShakeRequestPlan<'static>>(),
        size_of::<DriverResult<ShakeRequestPlan<'static>>>(),
        result6(ShakeRequestPlan::new_active_opt_validate_v1),
        result3(ShakeRequestPlan::construct),
        size_of::<ReservedShakeRequest>(),
        size_of::<DriverResult<ReservedShakeRequest>>(),
        size_of::<RequestClosurePlan<'static>>(),
        result1(RequestClosurePlan::requirements),
        size_of::<ReservedRequestClosure<'static>>(),
        size_of::<core::result::Result<ReservedRequestClosure<'static>, OpenRefusal>>(),
        size_of::<core::result::Result<ReservedRequestClosure<'static>, SourceRefusal<'static>>>(),
        size_of::<RefusedRequest<'static>>(),
        size_of::<core::result::Result<core::convert::Infallible, RefusedRequest<'static>>>(),
        size_of::<ParentSourcePlan<'static, 'static>>(),
        size_of::<ParentSourceBound<'static, 'static>>(),
        size_of::<core::result::Result<ParentSourcePlan<'static, 'static>, ParentCompileError>>(),
        size_of::<core::result::Result<ParentSourceBound<'static, 'static>, ParentCompileError>>(),
        size_of::<VerifierHeightEnvelope>(),
        size_of::<GroupCompilePlan<'static>>(),
        size_of::<[GroupCompilePlan<'static>; LEAVES]>(),
        size_of::<[&GroupCompilePlan<'static>; LEAVES]>(),
        size_of::<DriverResult<GroupCompilePlan<'static>>>(),
        result4(GroupCompilePlan::new),
        size_of::<SourceShapePlan<'static>>(),
        size_of::<GroupSourceBound<'static>>(),
        size_of::<core::result::Result<SourceShapePlan<'static>, SourceError>>(),
        size_of::<core::result::Result<GroupSourceBound<'static>, SourceError>>(),
        size_of::<Attempt<'static, 'static, 'static, 'static>>(),
        size_of::<Option<Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<Result<Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<DriverResult<Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<State<'static, 'static, 'static, 'static>>(),
        size_of::<Component<'static, 'static, 'static>>(),
        size_of::<core::result::Result<Component<'static, 'static, 'static>, Failure>>(),
        size_of::<Failure>(),
        size_of::<Cause>(),
        size_of::<Probe>(),
        size_of::<Option<Probe>>(),
        size_of::<(usize, usize, usize)>(),
        size_of::<bank::Failure>(),
        size_of::<ComponentReport>(),
        size_of::<PreissuedRootRecheck<'static, 'static, 'static>>(),
        size_of::<Option<PreissuedRootRecheck<'static, 'static, 'static>>>(),
        size_of::<&PreissuedRootRecheck<'static, 'static, 'static>>(),
        size_of::<Option<&PreissuedRootRecheck<'static, 'static, 'static>>>(),
        size_of::<
            core::result::Result<
                PreissuedRootRecheck<'static, 'static, 'static>,
                ParentCompileError,
            >,
        >(),
        size_of::<DriverResult<PreissuedRootRecheck<'static, 'static, 'static>>>(),
        size_of::<RootRecheckPlanReport>(),
        size_of::<core::result::Result<RootRecheckPlanReport, ParentCompileError>>(),
        size_of::<DriverResult<RootRecheckPlanReport>>(),
        size_of::<RootPublicRecheckReport>(),
        size_of::<&RootPublicRecheckReport>(),
        size_of::<core::result::Result<RootPublicRecheckReport, ParentCompileError>>(),
        size_of::<DriverResult<RootPublicRecheckReport>>(),
        size_of::<&ComponentReport>(),
        size_of::<Summary>(),
        size_of::<LeafAcceptanceReport>(),
        size_of::<LeafParentCompilationReport>(),
        size_of::<ParentAcceptanceReport>(),
        size_of::<Option<Summary>>(),
        size_of::<Option<LeafAcceptanceReport>>(),
        size_of::<Option<LeafParentCompilationReport>>(),
        size_of::<Option<ParentAcceptanceReport>>(),
        size_of::<DriverResult<Summary>>(),
        size_of::<DriverResult<LeafAcceptanceReport>>(),
        size_of::<DriverResult<LeafParentCompilationReport>>(),
        size_of::<DriverResult<ParentAcceptanceReport>>(),
        size_of::<PendingNativeHashx<'static>>(),
        size_of::<ProjectedHashxQuota>(),
        result3(PendingNativeHashx::project_outer_quota),
        size_of::<&mut Attempt<'static, 'static, 'static, 'static>>(),
        size_of::<Option<&mut Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<DriverResult<&mut Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<&mut State<'static, 'static, 'static, 'static>>(),
        size_of::<&mut PendingNativeHashx<'static>>(),
        size_of::<Option<&mut PendingNativeHashx<'static>>>(),
        size_of::<DriverResult<&mut PendingNativeHashx<'static>>>(),
        size_of::<&Component<'static, 'static, 'static>>(),
        size_of::<Snapshot>(),
        size_of::<WorkerAllowance>(),
        size_of::<Requirements>(),
        size_of::<Result<Requirements>>(),
        size_of::<Reservation>(),
        size_of::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<core::result::Result<Bytes, crate::execution::retained_resources::Error>>(),
        size_of::<DriverResult<Requirements>>(),
        size_of::<DriverResult<()>>(),
        size_of::<Result<()>>(),
        size_of::<DriverResult<u64>>(),
        size_of::<Option<u64>>(),
        size_of::<Ledger>(),
        size_of::<Mode>(),
        size_of::<std::time::Instant>(),
        size_of::<core::result::Result<String, std::env::VarError>>(),
        size_of::<std::env::VarError>(),
        size_of::<&str>(),
        size_of::<[(&str, &str); 3]>(),
        size_of::<std::array::IntoIter<(&str, &str), 3>>(),
        size_of::<[u64; 4]>(),
        size_of::<std::array::IntoIter<u64, 4>>(),
        size_of::<std::slice::Iter<'static, GroupCompilePlan<'static>>>(),
        size_of::<
            std::iter::Zip<
                std::slice::Iter<'static, crate::execution::retained_resources::CategoryCounters>,
                std::slice::Iter<'static, crate::execution::retained_resources::CategoryCounters>,
            >,
        >(),
        size_of::<std::ops::Range<usize>>(),
        size_of::<crate::execution::retained_resources::CategoryCounters>(),
        size_of::<Category>(),
        size_of::<[Category; crate::execution::retained_resources::CATEGORY_COUNT]>(),
        size_of::<
            std::array::IntoIter<
                Category,
                { crate::execution::retained_resources::CATEGORY_COUNT },
            >,
        >(),
        size_of::<std::fmt::Arguments<'static>>(),
        size_of::<std::io::Stderr>(),
        size_of::<std::io::StderrLock<'static>>(),
        size_of::<std::io::Result<()>>(),
        size_of::<[Val; 8]>(),
        size_of::<p3_goldilocks::Poseidon2Goldilocks<8>>(),
        size_of::<[u128; LEAVES]>(),
        size_of::<[usize; 32]>(),
        size_of::<[bool; 16]>(),
        // Complete fixed commitment/environment/error formatting helpers and
        // by-value array-construction closure frames, independently additive.
        32 << 10,
    ];
    let helper = core::mem::size_of_val(&parts)
        .checked_mul(8)
        .ok_or("combined driver caller overflow")?;
    let host = parts.into_iter().try_fold(helper, |sum, part| {
        part.checked_mul(8)
            .and_then(|part| sum.checked_add(part))
            .ok_or("combined driver caller overflow")
    })?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(host).map_err(|_| "combined driver caller overflow")?,
            device: 0,
        },
    ))
}
