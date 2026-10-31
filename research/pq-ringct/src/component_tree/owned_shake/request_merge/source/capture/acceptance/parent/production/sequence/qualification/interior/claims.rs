//! Preserve the complete baseline caller and add all interior-driver frames.
//! The fixed terminal observer is separate process-only, non-admitting storage.
use super::*;
use super::super::super::interior_opening::{
    PreissuedInteriorChildOpening, RetainedInteriorOpening,
};
use core::mem::{size_of, size_of_val};
use crate::execution::retained_resources::{CategoryCounters, CATEGORY_COUNT};

#[cfg(test)]
mod tests;

const FRAME_COPIES: usize = 8;
const FORMAT_ARGUMENTS: usize = 32;
const OBSERVER_OUTPUT_BYTES: usize = 4096;
const OBSERVER_FIXED_HOST_LIMIT: u64 = 1 << 20;

fn repeated_layout(parts: &[usize]) -> DriverResult<u64> {
    // Complete backing array, arithmetic, iterator and return/error helpers.
    // No inlining, move, exclusive-branch or stack-slot reuse deduction.
    let controls = size_of_val(parts)
        .checked_add(size_of::<&[usize]>())
        .and_then(|n| n.checked_add(size_of::<std::slice::Iter<'static, usize>>()))
        .and_then(|n| n.checked_add(size_of::<[usize; 16]>()))
        .and_then(|n| n.checked_add(size_of::<Option<usize>>()))
        .and_then(|n| n.checked_add(size_of::<DriverResult<usize>>()))
        .and_then(|n| n.checked_add(size_of::<DriverResult<u64>>()))
        .ok_or("interior-opening caller census overflow")?;
    let bytes = parts.iter().try_fold(controls, |sum, part| {
        sum.checked_add(*part)
            .ok_or("interior-opening caller census overflow")
    })?;
    let bytes = bytes.checked_mul(FRAME_COPIES)
        .ok_or("interior-opening caller census overflow")?;
    u64::try_from(bytes).map_err(|_| "interior-opening caller census overflow")
}

fn added_driver_host_bytes() -> DriverResult<u64> {
    let parts = [
        size_of::<InteriorMode>(),
        size_of::<(super::super::Mode, &'static str)>(),
        // The full outer driver claim exists before the closed constructor
        // can reserve its own caller. Include all pre-owner frames here too.
        size_of::<PreissuedInteriorChildOpening<'static, 'static, 'static>>(),
        size_of::<Option<PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<&PreissuedInteriorChildOpening<'static, 'static, 'static>>(),
        size_of::<Option<&PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<core::result::Result<PreissuedInteriorChildOpening<'static, 'static, 'static>, ParentCompileError>>(),
        size_of::<DriverResult<PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<RetainedInteriorOpening>(),
        size_of::<Option<RetainedInteriorOpening>>(),
        size_of::<&RetainedInteriorOpening>(),
        size_of::<Option<&RetainedInteriorOpening>>(),
        size_of::<core::result::Result<RetainedInteriorOpening, ParentCompileError>>(),
        size_of::<DriverResult<RetainedInteriorOpening>>(),
        size_of::<InteriorOpeningPlanReport>(),
        size_of::<Option<InteriorOpeningPlanReport>>(),
        size_of::<&InteriorOpeningPlanReport>(),
        size_of::<Option<&InteriorOpeningPlanReport>>(),
        size_of::<core::result::Result<InteriorOpeningPlanReport, ParentCompileError>>(),
        size_of::<DriverResult<InteriorOpeningPlanReport>>(),
        size_of::<DriverResult<&InteriorOpeningPlanReport>>(),
        size_of::<InteriorOpeningMeasurements>(),
        size_of::<Option<InteriorOpeningMeasurements>>(),
        size_of::<&InteriorOpeningMeasurements>(),
        size_of::<Option<&InteriorOpeningMeasurements>>(),
        size_of::<core::result::Result<&InteriorOpeningMeasurements, ParentCompileError>>(),
        size_of::<DriverResult<&InteriorOpeningMeasurements>>(),
        // No detached action report is retained by this driver. Count complete
        // enclosing return/move/drop/error layouts independently nevertheless.
        size_of::<Component<'static, 'static, 'static>>(),
        size_of::<&Component<'static, 'static, 'static>>(),
        size_of::<core::result::Result<Component<'static, 'static, 'static>, Failure>>(),
        size_of::<Attempt<'static, 'static, 'static, 'static>>(),
        size_of::<Option<Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<DriverResult<Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<&Attempt<'static, 'static, 'static, 'static>>(),
        size_of::<Option<&Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<DriverResult<&Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<&mut Attempt<'static, 'static, 'static, 'static>>(),
        size_of::<Option<&mut Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<DriverResult<&mut Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<ParentSourceBound<'static, 'static>>(),
        size_of::<&ParentSourceBound<'static, 'static>>(),
        size_of::<&ReservedShakeRequest>(),
        size_of::<Failure>(),
        size_of::<&Failure>(),
        size_of::<Cause>(),
        size_of::<&Cause>(),
        size_of::<bank::Failure>(),
        size_of::<ParentCompileError>(),
        size_of::<Requirements>(),
        size_of::<DriverResult<Requirements>>(),
        size_of::<Reservation>(),
        size_of::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<core::result::Result<(), crate::execution::retained_resources::Error>>(),
        size_of::<core::result::Result<Bytes, crate::execution::retained_resources::Error>>(),
        size_of::<Bytes>(),
        size_of::<Ledger>(),
        size_of::<&Ledger>(),
        size_of::<Snapshot>(),
        size_of::<DriverResult<()>>(),
        size_of::<DriverResult<u64>>(),
        size_of::<DriverResult<usize>>(),
        size_of::<Option<u64>>(),
        size_of::<Option<usize>>(),
        size_of::<Option<u128>>(),
        size_of::<[usize; 64]>(),
        size_of::<[u64; 32]>(),
        size_of::<[u128; 32]>(),
        size_of::<[bool; 32]>(),
        size_of::<&str>(),
        size_of::<String>(),
        size_of::<std::env::VarError>(),
        size_of::<core::result::Result<String, std::env::VarError>>(),
        size_of::<core::result::Result<&str, &std::env::VarError>>(),
        size_of::<std::fmt::Arguments<'static>>(),
        size_of::<std::io::Stderr>(),
        size_of::<std::io::StderrLock<'static>>(),
        size_of::<std::io::Result<()>>(),
        size_of::<[[usize; 3]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 39]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 20]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 5]; FORMAT_ARGUMENTS]>(),
        // Fixed exact-guard values, checked counters, formatting, conversion
        // and destruction helpers; every baseline byte remains additive.
        32 << 10,
    ];
    repeated_layout(&parts)
}

pub(super) fn driver_requirement() -> DriverResult<Requirements> {
    let mut complete = super::super::claims::driver_requirement()?;
    complete.add(Category::PhaseScratch, Bytes {
        host: added_driver_host_bytes()?,
        device: 0,
    }).map_err(|_| "interior-opening complete caller census overflow")?;
    Ok(complete)
}

pub(super) fn terminal_observer_bytes() -> DriverResult<u64> {
    // No Ledger parameter, Requirements or Reservation, and no invocation of
    // a constructor/admission method. This cannot lend released worker credit
    // to the bootstrap/terminal process harness or certify physical fit.
    let parts = [
        size_of::<TerminalObservation>(),
        size_of::<InteriorMode>(),
        size_of::<DriverResult<()>>(),
        size_of::<DriverResult<u64>>(),
        size_of::<Snapshot>(),
        size_of::<Ledger>(),
        size_of::<WorkerAllowance>(),
        size_of::<Bytes>(),
        size_of::<CategoryCounters>(),
        size_of::<[CategoryCounters; CATEGORY_COUNT]>(),
        size_of::<std::slice::Iter<'static, CategoryCounters>>(),
        size_of::<std::time::Instant>(),
        size_of::<std::time::Duration>(),
        size_of::<[u128; 8]>(),
        size_of::<[u64; 16]>(),
        size_of::<[usize; 16]>(),
        size_of::<[bool; 16]>(),
        size_of::<&str>(),
        size_of::<std::fmt::Arguments<'static>>(),
        size_of::<std::io::Stderr>(),
        size_of::<std::io::StderrLock<'static>>(),
        size_of::<std::io::Result<()>>(),
        size_of::<[[usize; 3]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 39]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 20]; FORMAT_ARGUMENTS]>(),
        size_of::<[[u8; 5]; FORMAT_ARGUMENTS]>(),
        OBSERVER_OUTPUT_BYTES,
        // Fixed bootstrap/scalar-formatting/timing/ordinary-drop helpers are
        // counted only as externally guarded process harness storage.
        32 << 10,
    ];
    let bytes = repeated_layout(&parts)?;
    if bytes == 0 || bytes > OBSERVER_FIXED_HOST_LIMIT {
        return Err("interior-opening terminal observer census bound");
    }
    Ok(bytes)
}
